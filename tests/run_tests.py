import sys
from pathlib import Path

tests_dir = str(Path(__file__).parent)
root_dir = str(Path(__file__).parent.parent)

if tests_dir not in sys.path:
    sys.path.insert(0, tests_dir)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

import unittest
from test_all_functions import ComprehensiveAllFunctionsTest

if __name__ == "__main__":
    unittest.main()
