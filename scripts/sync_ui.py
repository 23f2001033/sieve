"""Copy the console into public/ for static hosting.

The console is one self-contained file, so "building" the static site is a copy.
Kept as a script rather than a manual step so the deployed page can never drift
from ui/console.html.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
src = ROOT / "ui" / "console.html"
dst = ROOT / "public" / "index.html"
dst.parent.mkdir(exist_ok=True)
dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
print(f"copied {src.name} -> public/{dst.name} ({dst.stat().st_size:,} bytes)")
