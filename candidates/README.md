# Candidate product integrations

Reserved for the prompts, templates, helpers and policies that a shippable product would install. **Nothing is implemented here yet.**

The materials the pilot's `full_tool` condition uses are research fixtures, and they live with the pilot sources in `src/democratize_security/pilot/`: the instruction blocks (`instructions.py`), the RLS-backed starter (`reference_protected.py`) and the `check-isolation` self-check (`check_isolation.py`). They have not been packaged as a product, and the trials run so far show no benefit from them. See [docs/RESULTS.md](../docs/RESULTS.md).

When a candidate is added here, its bundle must exclude authoritative evaluation code and final cases. Each change needs a rationale, a parent identity, an allowed-path review and a sealed artifact hash before independent verification.
