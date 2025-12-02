import sys
from pathlib import Path

# Resolve root to import outside of tests directory
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
