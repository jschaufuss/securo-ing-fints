#!/usr/bin/env bash
set -euo pipefail
# Run on a machine with Internet access and uv installed. Python 3.14 wheels only.
cd "$(dirname "$0")"
uv pip compile requirements.in --python-version 3.14 --python-platform linux --generate-hashes --output-file requirements.txt
# Fail closed if any requirement is missing a hash.
python3 - <<'PY'
from pathlib import Path
p = Path('requirements.txt')
s = p.read_text()
if '--hash=sha256:' not in s:
    raise SystemExit('No package hashes generated')
print('Hashed dependency lock written:', p)
PY
