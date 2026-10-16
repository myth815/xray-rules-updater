"""Regression checks for RouterOS constructs rejected on the target host."""

from pathlib import Path
import re
import unittest


class RouterOSScriptSyntaxTests(unittest.TestCase):
    def test_return_commands_have_values(self):
        source = (Path(__file__).resolve().parents[1] /
                  "deploy/routeros/update.rsc").read_text()
        # RouterOS 7.23.5 parses an empty return, but executing it fails with
        # "missing value(s) of argument(s) value", including in recovery code.
        # Restrict this to command positions rather than comments/prose.
        self.assertIsNone(re.search(r"(?:^|[;{])\s*:return\s*;", source, re.M))


if __name__ == "__main__":
    unittest.main()
