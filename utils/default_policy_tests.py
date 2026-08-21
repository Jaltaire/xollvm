#!/usr/bin/env python3

import argparse
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


IR = """
target triple = "arm64-apple-macosx14.0.0"

@c_string = private unnamed_addr constant [9 x i8] c"c-marker\\00"
@rust_string = private unnamed_addr constant [11 x i8] c"rust-marker"
@unreachable_string = private unnamed_addr constant [18 x i8] c"unreachable-marker"
@indirect_string = private unnamed_addr constant [16 x i8] c"indirect-marker!"
@indirect_descriptor = private constant { ptr, i64 } { ptr @indirect_string, i64 16 }

declare void @consume(ptr, i64)

define i32 @protected_function(i32 %value) {
entry:
  %result = add i32 %value, 7
  ret i32 %result
}

define i32 @protected_large_cfg(i1 %condition) {
entry:
  br i1 %condition, label %left, label %right

left:
  ret i32 1

right:
  ret i32 2
}

define i32 @protected_cross_block(i32 %value) {
entry:
  %result = add i32 %value, 7
  br label %exit

exit:
  ret i32 %result
}

define void @protected_c_string() {
entry:
  call void @consume(ptr @c_string, i64 8)
  ret void
}

define void @protected_rust_string() {
entry:
  call void @consume(ptr @rust_string, i64 11)
  ret void
}

define void @protected_unreachable_string() {
entry:
  ret void

unreachable:
  call void @consume(ptr @unreachable_string, i64 18)
  ret void
}

define void @protected_indirect_string() {
entry:
  %value = load ptr, ptr @indirect_descriptor
  call void @consume(ptr %value, i64 16)
  ret void
}

define i32 @excluded_function(i32 %value) {
entry:
  %result = add i32 %value, 7
  ret i32 %result
}
"""

RUNTIME_IR = """
target triple = "arm64-apple-macosx14.0.0"

@message = private unnamed_addr constant [16 x i8] c"runtime-marker!\\00"
@descriptor = private constant { ptr, i64 } { ptr @message, i64 15 }

declare i32 @puts(ptr)

define i32 @main() {
entry:
  %value = load ptr, ptr @descriptor
  %result = call i32 @puts(ptr %value)
  ret i32 0
}
"""

POLICY_ENVIRONMENT = {
    "XOLLVM_DEFAULT_CONFIG",
    "XOLLVM_DEFAULT_INCLUDE",
    "XOLLVM_DEFAULT_EXCLUDE",
    "XOLLVM_IR_BUDGET_MULTIPLIER",
    "XOLLVM_IR_BUDGET_MAX",
    "XOLLVM_MAX_FUNCTION_INSTRUCTIONS",
    "XOLLVM_VERIFY_IR",
    "XOLLVM_RANDOMIZE_ADEC_CONSTANTS",
    "XOLLVM_ADEC_PREFIX",
}


class DefaultPolicyTests(unittest.TestCase):
    opt: Path
    plugin: Path

    @staticmethod
    def process_environment(environment: dict[str, str]) -> dict[str, str]:
        process_environment = {
            key: value
            for key, value in os.environ.items()
            if key not in POLICY_ENVIRONMENT
        }
        process_environment.update(environment)
        return process_environment

    def run_opt(self, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
        process_environment = self.process_environment(environment)
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
                "XOLLVM_DEFAULT_CONFIG": (
                    "constenc(prob=100,minAbs=1,maxSites=16),"
                    "strenc(minlen=4,cipher=chacha)"
                ),
                "XOLLVM_DEFAULT_INCLUDE": "^protected_",
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
        self.assertNotIn("c-marker", process.stdout)
        self.assertNotIn("rust-marker", process.stdout)
        self.assertNotIn("unreachable-marker", process.stdout)
        self.assertNotIn("indirect-marker", process.stdout)
        self.assertNotIn('section ".strenc', process.stdout)
        self.assertIn('section "__DATA,__strenc_', process.stdout)
        self.assertIn("@llvm.global_ctors", process.stdout)

    def test_indirect_string_encryption_preserves_runtime_behavior(self) -> None:
        environment = self.process_environment(
            {
                "XOLLVM_DEFAULT_CONFIG": "strenc(minlen=4,cipher=chacha)",
                "XOLLVM_DEFAULT_INCLUDE": "^main$",
                "XOLLVM_VERIFY_IR": "1",
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "runtime.ll"
            bitcode = root / "runtime.bc"
            object_file = root / "runtime.o"
            executable = root / "runtime"
            source.write_text(RUNTIME_IR)
            transformed = subprocess.run(
                [
                    str(self.opt),
                    "-load-pass-plugin",
                    str(self.plugin),
                    "-passes=obfuscation",
                    str(source),
                    "-o",
                    str(bitcode),
                ],
                env=environment,
                capture_output=True,
                text=True,
            )
            self.assertEqual(transformed.returncode, 0, transformed.stderr)
            lowered = subprocess.run(
                [
                    str(self.opt.parent / "llc"),
                    "-filetype=obj",
                    str(bitcode),
                    "-o",
                    str(object_file),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(lowered.returncode, 0, lowered.stderr)
            clang = shutil.which("clang")
            self.assertIsNotNone(clang)
            compiled = subprocess.run(
                [clang, str(object_file), "-o", str(executable)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            executed = subprocess.run(
                [str(executable)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(executed.returncode, 0, executed.stderr)
            self.assertEqual(executed.stdout, "runtime-marker!\n")
            self.assertNotIn(b"runtime-marker", executable.read_bytes())

    def test_absent_environment_policy_leaves_functions_unchanged(self) -> None:
        process = self.run_opt({})
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertIn(
            "add i32 %value, 7",
            self.function_body(process.stdout, "protected_function"),
        )

    def test_flattening_instruction_ceiling_skips_large_functions(self) -> None:
        process = self.run_opt(
            {
                "XOLLVM_DEFAULT_CONFIG": (
                    "flattening(minBlocks=2,maxBlocks=10,maxInstructions=2)"
                ),
                "XOLLVM_DEFAULT_INCLUDE": "^protected_large_cfg$",
            }
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        body = self.function_body(process.stdout, "protected_large_cfg")
        self.assertIn("br i1 %condition, label %left, label %right", body)

    def test_flattening_runs_below_instruction_ceiling(self) -> None:
        process = self.run_opt(
            {
                "XOLLVM_DEFAULT_CONFIG": (
                    "flattening(minBlocks=2,maxBlocks=10,maxInsts=10)"
                ),
                "XOLLVM_DEFAULT_INCLUDE": "^protected_large_cfg$",
            }
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        body = self.function_body(process.stdout, "protected_large_cfg")
        self.assertNotIn("br i1 %condition, label %left, label %right", body)

    def test_flattening_skips_when_demotion_cannot_run(self) -> None:
        process = self.run_opt(
            {
                "XOLLVM_DEFAULT_CONFIG": (
                    "flattening(minBlocks=2,maxBlocks=10,maxDemotionRounds=0)"
                ),
                "XOLLVM_DEFAULT_INCLUDE": "^protected_cross_block$",
                "XOLLVM_VERIFY_IR": "1",
            }
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        body = self.function_body(process.stdout, "protected_cross_block")
        self.assertIn("br label %exit", body)
        self.assertNotIn("fla.dispatch", body)

    def test_absolute_ir_budget_ceiling_stops_function_growth(self) -> None:
        process = self.run_opt(
            {
                "XOLLVM_DEFAULT_CONFIG": "constenc(prob=100,minAbs=1,maxSites=16)",
                "XOLLVM_DEFAULT_INCLUDE": "^protected_function$",
                "XOLLVM_IR_BUDGET_MULTIPLIER": "100",
                "XOLLVM_IR_BUDGET_MAX": "1",
            }
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        body = self.function_body(process.stdout, "protected_function")
        self.assertIn("add i32 %value, 7", body)

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

    def test_invalid_flattening_demotion_ceiling_disables_the_pass(self) -> None:
        process = self.run_opt(
            {
                "XOLLVM_DEFAULT_CONFIG": (
                    "flattening(minBlocks=2,maxBlocks=10,maxDemoteRounds=1025)"
                ),
                "XOLLVM_DEFAULT_INCLUDE": "^protected_large_cfg$",
            }
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertIn(
            "Flattening: MaxDemotionRounds must not exceed 1024.",
            process.stderr,
        )
        body = self.function_body(process.stdout, "protected_large_cfg")
        self.assertIn("br i1 %condition, label %left, label %right", body)

    def test_invalid_flattening_instruction_ceiling_disables_the_pass(self) -> None:
        process = self.run_opt(
            {
                "XOLLVM_DEFAULT_CONFIG": (
                    "flattening(minBlocks=2,maxBlocks=10,maxInstructions=1000001)"
                ),
                "XOLLVM_DEFAULT_INCLUDE": "^protected_large_cfg$",
            }
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertIn(
            "Flattening: MaxInstructions must not exceed 1000000.",
            process.stderr,
        )
        body = self.function_body(process.stdout, "protected_large_cfg")
        self.assertIn("br i1 %condition, label %left, label %right", body)


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
