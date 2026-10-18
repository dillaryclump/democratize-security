#!/bin/bash
# Install only the reviewed host helper. Run manually on a dedicated Linux host.
set -euo pipefail
if [[ $(uname -s) != Linux || $EUID != 0 || $# != 3 ]]; then
  echo 'Usage (dedicated Linux, root): bootstrap.sh CHECKOUT CONTROLLER_UID CONTROLLER_GID' >&2
  exit 2
fi
for executable in python3 mkfs.ext4 mount umount losetup findmnt docker visudo; do
  command -v "$executable" >/dev/null
done
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# Do not replace another worker installation or change existing sudo rules.
for target in /etc/ds-worker-host.json /usr/local/libexec/ds-worker-host /etc/sudoers.d/ds-worker-host; do
  if [[ -e $target || -L $target ]]; then
    echo "Refusing existing installation: $target" >&2
    exit 1
  fi
done
python3 -I - "$1" "$2" "$3" <<'PY'
import json, pathlib, sys
checkout = pathlib.Path(sys.argv[1])
if not checkout.is_absolute() or checkout.resolve() != checkout or not checkout.is_dir():
    raise SystemExit('checkout must be a real absolute directory without symlinks')
uid, gid = map(int, sys.argv[2:])
if not (0 < uid < 2**31 and 0 < gid < 2**31) or uid in (999, 10001, 20001):
    raise SystemExit('controller must be non-root and differ from workload identities')
config = {'schema_version': 1, 'checkout': str(checkout), 'uid': uid, 'gid': gid}
with open('/etc/ds-worker-host.json', 'x') as stream:
    json.dump(config, stream)
PY
chmod 0644 /etc/ds-worker-host.json
install -d -m 0755 /usr/local/libexec
install -o root -g root -m 0555 "$source_dir/scripts/worker_host.py" /usr/local/libexec/ds-worker-host
install -d -o root -g root -m 0700 /var/lib/ds-worker-host
# This grants this fixed helper only, not mount, Python or a general root shell.
printf '#%s ALL=(root) NOPASSWD: /usr/local/libexec/ds-worker-host\n' "$2" > /etc/sudoers.d/ds-worker-host
chmod 0440 /etc/sudoers.d/ds-worker-host
visudo -cf /etc/sudoers.d/ds-worker-host
echo 'Installed host storage helper. No trial, container, model or VM was started.'
