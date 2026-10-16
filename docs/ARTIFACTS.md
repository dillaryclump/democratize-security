# Candidate artifact boundary v1

This is the first M2 prerequisite, not a worker sandbox. It never imports or executes candidate code. The trusted controller must stop the producer before sealing and own the destination directory. Sealing concurrently modified hostile files is not a supported workflow.

## Portable transfer format

A versioned JSON envelope holds canonically sorted relative paths, byte lengths, SHA-256 checksums and base64 bytes. The complete payload has a SHA-256 identity. Limits: 128 files, 1 MiB per file, 8 MiB total decoded bytes, 12 MiB encoded bundle. Permissions, owners, timestamps and executable bits are not transferred. No archive extraction is implemented.

Allowlisted paths use portable ASCII components beginning with a letter, number or underscore. Absolute/traversal/empty components, backslashes, dotfiles, case collisions and file/directory collisions are rejected. Unlisted files are never read. The allowlist must come from the controller, not a candidate's requested export list.

On POSIX hosts, sealing walks directory descriptors with O_NOFOLLOW, checks regular-file type and rejects hardlinks and special files. Nonblocking opens prevent FIFO hangs. Reads are bounded and file metadata changes reject a seal. The snapshot does not claim protection against a live attacker with control of the host or open descriptors; stop the worker and isolate its filesystem first.

## Commands

```bash
mkdir -p .research
uv run --locked research seal candidates/example --file app.py --file requirements.txt \
  --output .research/candidate.json
uv run --locked research inspect-artifact .research/candidate.json
```

The example assumes those input files exist; no such candidate is shipped yet. The output parent must already exist durably and remain under controller ownership throughout publication. Publication flushes and fsyncs a complete temporary file, creates an atomic no-overwrite link, removes the temporary name, and fsyncs the parent directory before returning success. An existing destination is never replaced. Permissions default to private temporary-file permissions. Durability requires a POSIX filesystem and storage stack that honor file and directory fsync; unsupported or failed syncs propagate as errors. This is not a durable artifact database or protection from a controller-owner rewriting its own files.

An error or crash after the link can leave a complete destination even though publication was not acknowledged. Do not delete or overwrite that destination on retry: load and validate it, compare its identity with the expected bundle, and reconcile persistence before recording success. A retry encountering it raises `FileExistsError`, which alone is not proof of durable publication. A crash can also leave a temporary `.artifact-*` name; it is not an accepted artifact. SQLite transactions, startup reconciliation and orphan cleanup remain future work. Fault-injection tests cover file-sync failure before publication and directory-sync failure after publication; they are not physical power-loss tests.

## Evidence binding

`bind_evidence(bundle, verifier_sha256, result)` creates a detached copy of a trusted verifier's JSON result alongside the validated artifact identity and concrete verifier hash. `validate_evidence` compares these identities and the record hash. Changed code, changed verifier or an altered result invalidates the original binding.

These helpers do not grade results, sign records or certify that the artifact was executed. A candidate able to rewrite all bytes can recompute hashes. Only a trusted, isolated verifier may supply authoritative results; controller-owned storage and execution provenance remain required. Do not wrap a candidate-authored pass report and call it verified.

## Next integration gate

Select and validate one runner version. Transfer only the sealed bundle into a fresh restricted worker; never execute candidate code in the controller. Verify the bundle before materialization, preserve worker/image provenance, run the protected verifier against that exact deployment, bind its result and store it outside candidate reach. Prove tamper rejection and clean replay on three public development tasks before paid research. No unattended execution is enabled by this module.
