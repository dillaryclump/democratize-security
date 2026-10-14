import pytest

pytestmark = pytest.mark.integration


def test_http_database_error_rolls_back_and_next_tenant_recovers(database, serve):
    import psycopg
    from psycopg import sql

    from democratize_security.verification.reference import EXPECTED, verify

    with (
        serve(database.runtime) as client,
        psycopg.connect(database.admin, autocommit=True) as setup,
    ):
        alice = {"Authorization": "Bearer fixture-alice"}
        bob = {"Authorization": "Bearer fixture-bob"}
        assert client.get("/invoices", headers=alice).json() == EXPECTED["fixture-alice"]

        def backend():
            return setup.execute(
                "SELECT pid FROM pg_stat_activity WHERE usename = %s", (database.role,)
            ).fetchall()

        before = backend()
        assert len(before) == 1
        setup.execute(
            sql.SQL("REVOKE SELECT ON public.invoices FROM {}").format(
                sql.Identifier(database.role)
            )
        )
        try:
            # set_config succeeds, then the invoice SELECT raises a real SQL error.
            for path in ("/invoices/1", "/invoices", "/invoices/export"):
                response = client.get(path, headers=alice)
                assert response.status_code == 503
                assert response.json() == {"detail": "Invoice service unavailable"}
        finally:
            setup.execute(
                sql.SQL("GRANT SELECT ON public.invoices TO {}").format(
                    sql.Identifier(database.role)
                )
            )
        assert backend() == before, "Recovery must reuse the same database session"
        response = client.get("/invoices", headers=bob)
        assert response.status_code == 200
        assert response.json() == EXPECTED["fixture-bob"]
        assert client.get("/invoices/1", headers=bob).status_code == 404
        assert verify(client, database.runtime)["outcome"] == "pass"


def test_concurrent_tenants_keep_their_own_data(database, serve):
    from concurrent.futures import ThreadPoolExecutor

    from democratize_security.verification.reference import EXPECTED

    with serve(database.runtime) as client:

        def request(token):
            response = client.get("/invoices", headers={"Authorization": f"Bearer {token}"})
            assert response.status_code == 200
            assert response.json() == EXPECTED[token]

        with ThreadPoolExecutor(max_workers=4) as executor:
            list(executor.map(request, ["fixture-alice", "fixture-bob"] * 10))


def test_invalid_inputs_do_not_break_following_requests(database, serve):
    from democratize_security.verification.reference import EXPECTED

    with serve(database.runtime) as client:
        headers = {"Authorization": "Bearer fixture-alice"}
        for path in (
            "/invoices/0",
            "/invoices/-1",
            "/invoices/2147483648",
            "/invoices/not-an-id",
            "/invoices?limit=0",
            "/invoices?limit=101",
            "/invoices?offset=-1",
            "/invoices?q=" + "a" * 101,
        ):
            assert client.get(path, headers=headers).status_code == 422
        response = client.get("/invoices", headers={"Authorization": "Bearer fixture-bob"})
        assert response.status_code == 200
        assert response.json() == EXPECTED["fixture-bob"]


def test_protected_reference_passes_without_application_tenant_filter(database, serve):
    from democratize_security.verification.reference import verify

    with serve(database.runtime) as client:
        result = verify(client, database.runtime)
    assert result["coverage"] == "complete", result
    assert result["outcome"] == "pass", result


@pytest.mark.parametrize(
    "fault", ["disabled_rls", "missing_policy", "allow_all", "bypass_role", "write_privilege"]
)
def test_verifier_rejects_deliberately_unsafe_variants(database, serve, fault):
    import psycopg
    from psycopg import sql

    from democratize_security.verification.reference import verify

    with psycopg.connect(database.admin, autocommit=True) as setup:
        if fault == "disabled_rls":
            setup.execute("ALTER TABLE public.invoices DISABLE ROW LEVEL SECURITY")
        elif fault == "missing_policy":
            setup.execute("DROP POLICY tenant_read ON public.invoices")
        elif fault == "allow_all":
            setup.execute("ALTER POLICY tenant_read ON public.invoices USING (true)")
        elif fault == "bypass_role":
            setup.execute(sql.SQL("ALTER ROLE {} BYPASSRLS").format(sql.Identifier(database.role)))
        else:
            setup.execute(
                sql.SQL("GRANT UPDATE ON public.invoices TO {}").format(
                    sql.Identifier(database.role)
                )
            )
    with serve(database.runtime) as client:
        result = verify(client, database.runtime)
    assert result["coverage"] == "complete", result
    assert result["outcome"] == "fail", result
    outcomes = {c["id"]: c["outcome"] for c in result["checks"]}
    assert outcomes["database_configuration"] == "fail", result
    if fault in {"disabled_rls", "allow_all", "bypass_role"}:
        for name in ("foreign_reads", "list_search", "exports"):
            assert outcomes[name] == "fail", result
    if fault == "missing_policy":
        assert outcomes["authorized_reads"] == "fail", result


def test_transaction_context_clears_after_success_and_error(database):
    import psycopg
    from psycopg_pool import ConnectionPool

    with ConnectionPool(database.runtime, min_size=1, max_size=1) as pool:
        pool.wait()
        with pool.connection() as connection:
            pid = connection.info.backend_pid
            connection.execute("SELECT set_config('app.tenant_id', 'org-a', true)")
            assert connection.execute("SELECT id FROM public.invoices ORDER BY id").fetchall() == [
                (1,),
                (2,),
            ]
        with pool.connection() as connection:
            assert connection.info.backend_pid == pid
            assert connection.execute("SELECT count(*) FROM public.invoices").fetchone() == (0,)
        with pytest.raises(psycopg.errors.DivisionByZero):
            with pool.connection() as connection:
                connection.execute("SELECT set_config('app.tenant_id', 'org-a', true)")
                connection.execute("SELECT 1 / 0")
        with pool.connection() as connection:
            assert connection.info.backend_pid == pid
            assert connection.execute("SELECT count(*) FROM public.invoices").fetchone() == (0,)
            connection.execute("SELECT set_config('app.tenant_id', 'org-b', true)")
            assert connection.execute("SELECT id FROM public.invoices ORDER BY id").fetchall() == [
                (3,),
                (4,),
            ]


def test_failed_http_transport_cannot_pass(database):
    import httpx

    from democratize_security.verification.reference import verify

    def broken(request):
        raise httpx.ConnectError("synthetic unavailable endpoint")

    with httpx.Client(
        base_url="http://reference.test", transport=httpx.MockTransport(broken)
    ) as client:
        result = verify(client, database.runtime)
    assert result["outcome"] == "incomplete"
    assert result["coverage"] == "incomplete"


def test_empty_success_responses_are_not_security_success(database):
    import httpx

    from democratize_security.verification.reference import verify

    with httpx.Client(
        base_url="http://reference.test",
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json=[])),
    ) as client:
        result = verify(client, database.runtime)
    assert result["outcome"] == "fail"
    assert next(c for c in result["checks"] if c["id"] == "authorized_reads")["outcome"] == "fail"
