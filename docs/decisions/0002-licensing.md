# ADR 0002: Apache License 2.0

Status: decided by the owner on 2026-11-15. Supersedes the earlier "pending" state of this record.

## Context

The project intends to offer an open-source core and optional commercial services. Until this decision the public repository had no license, which granted no rights to anyone: publishing source is not a license. This record previously asked the owner to choose before packages were distributed or outside contributions invited.

## Decision

The repository is licensed under the **Apache License, Version 2.0**. The owner chose it on 2026-11-15 over MIT, AGPL-3.0 and staying unlicensed.

The trade-offs presented with the choice:

- It is permissive, so anyone may use, modify and redistribute the code, including commercially. That fits the goal of making security tooling widely accessible.
- It includes an explicit patent grant and a patent-retaliation clause, which MIT lacks.
- It is widely accepted by companies that avoid copyleft licenses.
- Unlike AGPL-3.0, it does not stop a third party from hosting the code as a service.

One consequence follows from the last point: a paid offering has to earn its value through services, hosting, integrations or support, not through license restrictions.

This record does not reflect legal advice.

## What was done

- `LICENSE` holds the unmodified license text. `NOTICE` holds the attribution.
- `pyproject.toml` declares `license = "Apache-2.0"` and ships both files.
- `README.md` and `CONTRIBUTING.md` state the license. Contributions are accepted under the same license, as section 5 of the license provides. There is no separate contributor agreement.
- No per-file license headers were added.

## Third-party material

Reviewed on 2026-11-15 at `c05e58d`:

- No vendored third-party source was found: no file carries another project's copyright or license notice. The tasks, fixtures, reference apps and verifiers were written for this project.
- Dependencies are installed from package indexes at build time and are not redistributed here. The pinned requirement files under `tasks/` list them.
- Container images (`python`, `postgres`, `alpine`) are pulled at run time and are not redistributed here.

An adapter for an external benchmark, such as BaxBench, would bring that benchmark's license terms with it. Audit them before adding one.

## Still open

- Whether to publish a package or tag a release. Neither is configured.
- The commercial model beyond "open core with optional paid services".
- Trademark use of the project name. The license grants none.
