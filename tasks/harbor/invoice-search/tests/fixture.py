"""Provision the public synthetic invoice fixture for the reference protocol.

Shared byte-for-byte by the PostgreSQL integration tests and the Harbor
application verifiers, so both grade against the same schema, rows, grants and
policy. Creates one restricted login role and one fresh UTF-8 database owned by
the administrative connection; the runtime role can only read through forced
row-level security keyed on transaction-local `app.tenant_id`.
"""

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo


def provision(admin_dsn: str, database: str, role: str, password: str) -> str:
    """Create the role and database; return the administrative DSN for it."""
    with psycopg.connect(admin_dsn, autocommit=True, connect_timeout=5) as admin:
        admin.execute(
            sql.SQL(
                "CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOBYPASSRLS "
                "NOCREATEDB NOCREATEROLE NOREPLICATION"
            ).format(sql.Identifier(role), sql.Literal(password))
        )
        # Pin encoding and collation: cluster defaults vary (SQL_ASCII would
        # change exported values) and none of the fixture data needs a locale.
        admin.execute(
            sql.SQL(
                "CREATE DATABASE {} TEMPLATE template0 ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C'"
            ).format(sql.Identifier(database))
        )
    settings = conninfo_to_dict(admin_dsn)
    settings["dbname"] = database
    setup_dsn = make_conninfo(**settings)
    with psycopg.connect(setup_dsn, autocommit=True, connect_timeout=5) as setup:
        setup.execute(
            sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(sql.Identifier(database))
        )
        setup.execute(
            sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                sql.Identifier(database), sql.Identifier(role)
            )
        )
        setup.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
        setup.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(sql.Identifier(role)))
        setup.execute("""
            CREATE TABLE public.invoices (
                id integer PRIMARY KEY, tenant_id text NOT NULL,
                description text NOT NULL,
                amount_cents integer NOT NULL CHECK (amount_cents >= 0)
            );
            INSERT INTO public.invoices VALUES
                (1, 'org-a', 'A consulting', 1200), (2, 'org-a', 'A support', 3400),
                (3, 'org-b', 'B consulting', 5600), (4, 'org-b', 'B support', 7800);
            ALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;
            ALTER TABLE public.invoices FORCE ROW LEVEL SECURITY;
        """)
        setup.execute(sql.SQL("GRANT SELECT ON public.invoices TO {}").format(sql.Identifier(role)))
        setup.execute(
            sql.SQL("""
            CREATE POLICY tenant_read ON public.invoices FOR SELECT TO {}
            USING (tenant_id = nullif(current_setting('app.tenant_id', true), ''))
        """).format(sql.Identifier(role))
        )
    return setup_dsn
