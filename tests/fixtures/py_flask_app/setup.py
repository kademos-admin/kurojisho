# This file must never be executed by a scan.
import pathlib

pathlib.Path("PWNED_BY_SETUP_PY").write_text("executed")
raise SystemExit("setup.py was executed")
