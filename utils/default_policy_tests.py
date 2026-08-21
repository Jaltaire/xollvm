#!/usr/bin/env python3

import argparse
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


IR = """
define i32 @protected_function(i32 %value) {
entry:
  %result = add i32 %value, 7
  ret i32 %result
}

define i32 @excluded_function(i32 %value) {
entry:
  %result = add i32 %value, 7
  ret i32 %result
}
"""

POLICY_ENVIRONMENT = {
    "XOLLVM_DEFAULT_CONFIG",
    "XOLLVM_DEFAULT_INCLUDE",
    "XOLLVM_DEFAULT_EXCLUDE",
    "XOLLVM_IR_BUDGET_MULTIPLIER",
    "XOLLVM_MAX_FUNCTION_INSTRUCTIONS",
    "XOLLVM_VERIFY_IR",
    "XOLLVM_RANDOMIZE_ADEC_CONSTANTS",
    "XOLLVM_ADEC_PREFIX",
}


class DefaultPolicyTests(unittest.TestCase):
    opt: Path
    plugin: Path

    def run_opt(self, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
        process_environment = {
            key: value
            for key, value in os.environ.items()
            if key not in POLICY_ENVIRONMENT
        }
        process_environment.update(environment)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.ll"
            output = root / "output.ll"
            source.write_text(IR)
            process = subprocess.run(
                [
                    str(self.opt),
                    "-load-pass-plugin",
                    str(self.plugin),
                    "-passes=obfuscation",
                    "-S",
                    str(source),
                    "-o",
                    str(output),
                ],
                env=process_environment,
                capture_output=True,
                text=True,
            )
            if process.returncode == 0:
                process.stdout = output.read_text()
            return process

    @staticmethod
    def function_body(ir: str, name: str) -> str:
        match = re.search(rf"define i32 @{name}\(.*?^\}}", ir, re.MULTILINE | re.DOTALL)
        if match is None:
            raise AssertionError(f"The function {name} was absent from the output IR.")
        return match.group(0)

    def test_environment_policy_transforms_only_matching_functions(self) -> None:
        process = self.run_opt(
            {
                "XOLLVM_DEFAULT_CONFIG": "constenc(prob=100,minAbs=1,maxSites=16)",
                "XOLLVM_DEFAULT_INCLUDE": "^protected_function$",
                "XOLLVM_DEFAULT_EXCLUDE": "^excluded_function$",
                "XOLLVM_IR_BUDGET_MULTIPLIER": "100",
                "XOLLVM_MAX_FUNCTION_INSTRUCTIONS": "100",
                "XOLLVM_VERIFY_IR": "1",
                "XOLLVM_RANDOMIZE_ADEC_CONSTANTS": "false",
                "XOLLVM_ADEC_PREFIX": "test",
            }
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        protected = self.function_body(process.stdout, "protected_function")
        excluded = self.function_body(process.stdout, "excluded_function")
        self.assertNotIn("add i32 %value, 7", protected)
        self.assertIn("add i32 %value, 7", excluded)

    def test_absent_environment_policy_leaves_functions_unchanged(self) -> None:
        process = self.run_opt({})
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertIn(
            "add i32 %value, 7",
            self.function_body(process.stdout, "protected_function"),
        )

    def test_empty_environment_policy_leaves_functions_unchanged(self) -> None:
        process = self.run_opt({"XOLLVM_DEFAULT_CONFIG": ""})
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertIn(
            "add i32 %value, 7",
            self.function_body(process.stdout, "protected_function"),
        )

    def test_invalid_environment_number_is_rejected(self) -> None:
        process = self.run_opt(
            {
                "XOLLVM_DEFAULT_CONFIG": "constenc",
                "XOLLVM_IR_BUDGET_MULTIPLIER": "invalid",
            }
        )
        self.assertNotEqual(process.returncode, 0)
        self.assertIn("Invalid unsigned integer", process.stderr)

    def test_invalid_environment_boolean_is_rejected(self) -> None:
        process = self.run_opt(
            {
                "XOLLVM_DEFAULT_CONFIG": "constenc",
                "XOLLVM_VERIFY_IR": "sometimes",
            }
        )
        self.assertNotEqual(process.returncode, 0)
        self.assertIn("Invalid boolean", process.stderr)

    def test_invalid_include_expression_is_rejected(self) -> None:
        process = self.run_opt(
            {
                "XOLLVM_DEFAULT_CONFIG": "constenc",
                "XOLLVM_DEFAULT_INCLUDE": "[",
            }
        )
        self.assertNotEqual(process.returncode, 0)
        self.assertIn("Invalid -obf-default-include", process.stderr)

    def test_invalid_exclude_expression_is_rejected(self) -> None:
        process = self.run_opt(
            {
                "XOLLVM_DEFAULT_CONFIG": "constenc",
                "XOLLVM_DEFAULT_EXCLUDE": "[",
            }
        )
        self.assertNotEqual(process.returncode, 0)
        self.assertIn("Invalid -obf-default-exclude", process.stderr)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--opt", type=Path, required=True)
    parser.add_argument("--plugin", type=Path, required=True)
    arguments, remaining = parser.parse_known_args()
    DefaultPolicyTests.opt = arguments.opt
    DefaultPolicyTests.plugin = arguments.plugin
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(DefaultPolicyTests)
    return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
