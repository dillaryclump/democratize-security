"""Four finite model-free trials: two diagnostic controls, two sealed replays."""

import json

import harbor_spike

from democratize_security.artifacts import load
from democratize_security.policy_replay import prepare_replay, record_replay, write_record


def main():
    # Diagnostic generation and first verification; not accepted replay evidence.
    harbor_spike.main()
    output = harbor_spike.ROOT / ".research/harbor-replay"
    output.mkdir(exist_ok=False)
    records = []
    for control, expected in (("oracle", 1), ("nop", 0)):
        bundle = load(harbor_spike.ROOT / ".research/harbor-spike" / control / "policy.bundle.json")
        task = output / f"task-{control}"
        manifest = prepare_replay(bundle, harbor_spike.TASK, task)
        write_record(output / f"manifest-{control}.json", manifest)
        nonce = harbor_spike.run_trial(task, "nop", output, f"replay-{control}")
        result = harbor_spike.accept_result(
            output / f"replay-{control}", "nop", expected, nonce, expected_bundle=bundle
        )
        record = record_replay(bundle, manifest, result)
        write_record(output / f"evidence-{control}.json", record)
        records.append(record)
    write_record(output / "summary.json", {"replays": records})
    print(json.dumps({"replays": records}, indent=2))


if __name__ == "__main__":
    main()
