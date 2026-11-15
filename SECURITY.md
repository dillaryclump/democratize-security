# Security policy

This is a research prototype. It is not ready to protect production systems, and no released version carries a security-support commitment.

## Reporting a vulnerability

Report privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**, or go straight to the [private advisory form](https://github.com/dillaryclump/democratize-security/security/advisories/new).

Do not put exploit details, credentials or private data in a public issue or pull request.

This is a small project with no dedicated security team. Reports are handled on a best-effort basis, with no guaranteed response time.

## What is worth reporting

The project's value rests on its evaluation being trustworthy, so these matter most:

- **A way for a candidate to influence its own grade.** For example reading verifier material, writing a result that is accepted, or surviving into the verifier's environment.
- **A verifier false pass.** An application that leaks or changes another tenant's data and still passes every check.
- **A break in the container boundary** beyond the gaps already documented in [docs/HARBOR_AUDIT.md](docs/HARBOR_AUDIT.md).
- **Ledger integrity.** Accepting a forged or replayed report, losing a cost reservation, or dispatching a paid attempt twice.
- **Credential exposure.** Any path by which the model provider key reaches the agent's environment, a log or a stored artifact.
- **A committed secret** anywhere in the repository or its history.

## What is intentional

- **Deliberately vulnerable applications.** Files named `*-unsafe.py` under `scripts/app_controls/` and `src/democratize_security/pilot/controls/` are negative controls. They exist so that the verifier can be shown to fail them. Do not deploy them, and do not report them as vulnerabilities.
- **Public test credentials.** The bearer strings `fixture-alice`, `fixture-bob` and `fixture-unassigned`, and database passwords such as `synthetic-local-only` and `synthetic-ci-only`, are public fixtures for disposable test databases. They are not secrets.
- **Documented limitations.** The verifier and all tasks are public, containers share the host kernel, and two verifier-side isolation gaps are recorded in [docs/STATUS.md](docs/STATUS.md).

## Scope and safe use

The security property under study and its exclusions are in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). All data is synthetic. Do not run candidate workloads with personal data, broad credentials or access to a host you care about. The dev container and Codespaces configuration are for editing the project, not for containing untrusted code.
