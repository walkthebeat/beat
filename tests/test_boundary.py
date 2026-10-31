"""The line between the open client and the service: the client package `beat` never imports the service's."""
import subprocess
import sys
from pathlib import Path

import beat


def test_the_client_never_imports_the_service():
    mods = sorted(p.stem for p in Path(beat.__file__).parent.glob("*.py") if p.stem != "__init__")
    code = ("import sys\n" + "".join(f"import beat.{m}\n" for m in mods)
            + "print(' '.join(sorted(m for m in sys.modules if m.split('.')[0] in ('beat_service', 'nats', 'duckdb'))))")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True).stdout.strip()
    assert out == "", f"beat imports {out}"
