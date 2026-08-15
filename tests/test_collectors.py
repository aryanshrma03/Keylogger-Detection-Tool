import sys
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from collectors.persistence import collect_windows_persistence


class CollectorTests(unittest.TestCase):

    def test_persistence_collector_is_safe_on_non_windows(self):
        # On Windows this simply reads metadata; it never writes.
        result = collect_windows_persistence()
        self.assertIsInstance(result, list)


if __name__ == "__main__":
    unittest.main()
