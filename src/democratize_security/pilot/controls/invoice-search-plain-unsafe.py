"""Synthetic invoice API; every query filters by the server-derived tenant.

Run only on loopback with a disposable synthetic database. The fixed tokens are
public fixture identities and are intentionally unsuitable for production.
"""

import csv
import io
import os
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Path, Query
from fastapi.responses import JSONResponse, Response
from psycopg import Error as DatabaseError
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool, PoolTimeout
from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr, model_validator

IDENTITIES = {"fixture-alice": "org-a", "fixture-bob": "org-b", "fixture-unassigned": None}
Description = Annotated[StrictStr, Field(min_length=1, max_length=200)]
Amount = Annotated[StrictInt, Field(ge=0, le=1_000_000_000)]


class InvoiceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    description: Description
    amount_cents: Amount


class InvoiceUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    description: Description | None = None
    amount_cents: Amount | None = None

    @model_validator(mode="after")
    def changes_something(self):
        if self.description is None and self.amount_cents is None:
            raise ValueError("Provide description or amount_cents")
        return self


def tenant(authorization: Annotated[list[str] | None, Header()] = None) -> str:
    # Reject ambiguity instead of picking one identity from duplicate headers.
    if not authorization or len(authorization) != 1:
        raise HTTPException(401, "Authentication required")
    value = authorization[0]
    if not value.startswith("Bearer "):
        raise HTTPException(401, "Authentication required")
    token = value.removeprefix("Bearer ")
    if token not in IDENTITIES:
        raise HTTPException(401, "Authentication required")
    organization = IDENTITIES[token]
    if organization is None:
        raise HTTPException(403, "Organization membership required")
    return organization


def create_app() -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Only the restricted runtime DSN is available to this process.
        with ConnectionPool(
            os.environ["REFERENCE_DATABASE_URL"],
            min_size=1,
            max_size=1,
            timeout=5,
            kwargs={"row_factory": dict_row, "connect_timeout": 5},
        ) as pool:
            pool.wait(timeout=5)
            app.state.pool = pool
            yield

    app = FastAPI(title="Synthetic tenant-isolation reference", lifespan=lifespan)

    @app.exception_handler(DatabaseError)
    @app.exception_handler(PoolTimeout)
    async def database_unavailable(request, error):
        # The connection context has rolled back before the exception reaches
        # this handler. Never return SQL, connection details or invoice data.
        return JSONResponse(status_code=503, content={"detail": "Invoice service unavailable"})

    def rows(query: str, parameters: tuple) -> list[dict]:
        # This database has no row-level security: every query below must
        # filter by the organization from the trusted tenant dependency.
        with app.state.pool.connection() as connection:
            return connection.execute(query, parameters).fetchall()

    @app.get("/health")
    def health():
        return {"status": "ready"}

    @app.get("/invoices")
    def invoices(
        organization: Annotated[str, Depends(tenant)],
        q: Annotated[str, Query(max_length=100)] = "",
        limit: Annotated[int, Query(ge=1, le=100)] = 100,
        offset: Annotated[int, Query(ge=0)] = 0,
    ):
        return rows(
            """
            SELECT id, description, amount_cents FROM public.invoices
            WHERE strpos(lower(description), lower(%s)) > 0
            ORDER BY id LIMIT %s OFFSET %s
        """,
            (q, limit, offset),
        )

    @app.get("/invoices/export")
    def export(organization: Annotated[str, Depends(tenant)]):
        invoices = rows(
            "SELECT id, description, amount_cents FROM public.invoices"
            " WHERE tenant_id = %s ORDER BY id",
            (organization,),
        )
        output = io.StringIO(newline="")
        writer = csv.DictWriter(output, fieldnames=["id", "description", "amount_cents"])
        writer.writeheader()
        writer.writerows(invoices)
        return Response(output.getvalue(), media_type="text/csv")

    @app.get("/invoices/summary")
    def summary(organization: Annotated[str, Depends(tenant)]):
        (result,) = rows(
            """
            SELECT count(*) AS count, coalesce(sum(amount_cents), 0)::bigint AS total_cents
            FROM public.invoices WHERE tenant_id = %s
        """,
            (organization,),
        )
        return result

    @app.get("/invoices/{invoice_id}")
    def invoice(
        organization: Annotated[str, Depends(tenant)],
        invoice_id: Annotated[int, Path(ge=1, le=2147483647)],
    ):
        found = rows(
            "SELECT id, description, amount_cents FROM public.invoices"
            " WHERE id = %s AND tenant_id = %s",
            (invoice_id, organization),
        )
        if not found:
            raise HTTPException(404, "Invoice not found")
        return found[0]

    @app.patch("/invoices/{invoice_id}")
    def update_invoice(
        organization: Annotated[str, Depends(tenant)],
        invoice_id: Annotated[int, Path(ge=1, le=2147483647)],
        changes: InvoiceUpdate,
    ):
        updated = rows(
            """
            UPDATE public.invoices
            SET description = coalesce(%s, description),
                amount_cents = coalesce(%s, amount_cents)
            WHERE id = %s AND tenant_id = %s
            RETURNING id, description, amount_cents
        """,
            (changes.description, changes.amount_cents, invoice_id, organization),
        )
        if not updated:
            raise HTTPException(404, "Invoice not found")
        return updated[0]

    @app.post("/invoices", status_code=201)
    def create_invoice(organization: Annotated[str, Depends(tenant)], invoice: InvoiceCreate):
        (created,) = rows(
            """
            INSERT INTO public.invoices (tenant_id, description, amount_cents)
            VALUES (%s, %s, %s)
            RETURNING id, description, amount_cents
        """,
            (organization, invoice.description, invoice.amount_cents),
        )
        return created

    return app
