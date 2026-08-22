#!/usr/bin/env python3

import argparse
import json
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
@address_string = private unnamed_addr constant [15 x i8] c"address-marker!"
@external_string = dso_local constant [16 x i8] c"external-marker!"

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

define i32 @protected_internal_cfg(i32 %value) {
entry:
  %first = add i32 %value, 7
  br label %middle

middle:
  %second = mul i32 %first, 3
  br label %exit

exit:
  ret i32 %second
}

define i8 @protected_narrow_bool(i64 %value) {
entry:
  %condition = icmp ugt i64 %value, 7
  %result = zext i1 %condition to i8
  ret i8 %result
}

define i1 @protected_truncated_bool(i8 %value) {
entry:
  %result = trunc i8 %value to i1
  ret i1 %result
}

define i8 @protected_compared_bool(i64 %value) {
entry:
  %condition = icmp ugt i64 %value, 7
  %checked = icmp ule i1 %condition, true
  %result = zext i1 %checked to i8
  ret i8 %result
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

define void @protected_address_string() {
entry:
  %address = ptrtoint ptr @address_string to i64
  %value = inttoptr i64 %address to ptr
  call void @consume(ptr %value, i64 15)
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
@address_message = private unnamed_addr constant [16 x i8] c"address-marker!\\00"
@escaped_message = private unnamed_addr constant [16 x i8] c"escaped-marker!\\00"
@escaped_pointer = private global ptr null

declare i32 @puts(ptr)

define void @capture_message() {
entry:
  store ptr @escaped_message, ptr @escaped_pointer
  ret void
}

define i32 @main() {
entry:
  %value = load ptr, ptr @descriptor
  %result = call i32 @puts(ptr %value)
  %address = ptrtoint ptr @address_message to i64
  %address_value = inttoptr i64 %address to ptr
  %address_result = call i32 @puts(ptr %address_value)
  call void @capture_message()
  %escaped_value = load ptr, ptr @escaped_pointer
  %escaped_result = call i32 @puts(ptr %escaped_value)
  ret i32 0
}
"""

MULTI_MODULE_IR = """
target triple = "arm64-apple-macosx14.0.0"

@message_SUFFIX = private unnamed_addr constant [13 x i8] c"hello-world!\\00"

declare void @consume(ptr, i64)

define i32 @protected_SUFFIX(i32 %value) {
entry:
  call void @consume(ptr @message_SUFFIX, i64 12)
  %result = add i32 %value, 7
  ret i32 %result
}
"""

POLICY_ENVIRONMENT = {
    "XOLLVM_DEFAULT_CONFIG",
    "XOLLVM_DEFAULT_INCLUDE",
    "XOLLVM_DEFAULT_EXCLUDE",
    "XOLLVM_FUNCTION_RULES",
    "XOLLVM_IR_BUDGET_MULTIPLIER",
    "XOLLVM_IR_BUDGET_MAX",
    "XOLLVM_MAX_FUNCTION_INSTRUCTIONS",
    "XOLLVM_VERIFY_IR",
    "XOLLVM_RANDOMIZE_ADEC_CONSTANTS",
    "XOLLVM_ADEC_PREFIX",
    "XOLLVM_REPORT_JSON",
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

    def run_opt(
        self,
        environment: dict[str, str],
        arguments: tuple[str, ...] = (),
        source_ir: str = IR,
    ) -> subprocess.CompletedProcess[str]:
        process_environment = self.process_environment(environment)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.ll"
            output = root / "output.ll"
            source.write_text(source_ir)
            process = subprocess.run(
                [
                    str(self.opt),
                    "-load-pass-plugin",
                    str(self.plugin),
                    *arguments,
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

    def test_runtime_injection_interlocks_without_corrupting_abi_results(self) -> None:
        process = self.run_opt(
            {
                "XOLLVM_DEFAULT_CONFIG": (
                    "rasp(prob=100,minInstructions=1,maxExitSites=2)"
                ),
                "XOLLVM_DEFAULT_INCLUDE": "^protected_function$",
                "XOLLVM_VERIFY_IR": "1",
            },
            ("--obf-seed=41",),
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        protected = self.function_body(process.stdout, "protected_function")
        excluded = self.function_body(process.stdout, "excluded_function")
        self.assertEqual(protected.count("call i64 @obscura_rasp_probe_"), 2)
        self.assertEqual(protected.count("call void @obscura_rasp_interlock_"), 2)
        self.assertNotIn("select i1", protected)
        self.assertNotIn("obscura_rasp_probe_", excluded)

    def test_runtime_injection_covers_multiple_function_exits(self) -> None:
        process = self.run_opt(
            {
                "XOLLVM_DEFAULT_CONFIG": (
                    "rasp(prob=100,minInstructions=1,maxExitSites=2)"
                ),
                "XOLLVM_DEFAULT_INCLUDE": "^protected_large_cfg$",
                "XOLLVM_VERIFY_IR": "1",
            },
            ("--obf-seed=42",),
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        protected = self.function_body(process.stdout, "protected_large_cfg")
        self.assertEqual(protected.count("call i64 @obscura_rasp_probe_"), 3)
        self.assertEqual(protected.count("call void @obscura_rasp_interlock_"), 3)
        self.assertNotIn("select i1", protected)

    def test_runtime_injection_distributes_checks_into_internal_blocks(self) -> None:
        process = self.run_opt(
            {
                "XOLLVM_DEFAULT_CONFIG": (
                    "rasp(prob=100,minInstructions=1,maxExitSites=1,maxBlockSites=2)"
                ),
                "XOLLVM_DEFAULT_INCLUDE": "^protected_internal_cfg$",
                "XOLLVM_VERIFY_IR": "1",
            },
            ("--obf-seed=142",),
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        protected = self.function_body(process.stdout, "protected_internal_cfg")
        self.assertEqual(protected.count("call i64 @obscura_rasp_probe_"), 3)
        self.assertEqual(protected.count("call void @obscura_rasp_interlock_"), 3)
        self.assertIn("obscura_rasp_probe_", protected.split("middle:", 1)[1])

    def test_runtime_injection_can_semantically_interlock_integer_results(self) -> None:
        process = self.run_opt(
            {
                "XOLLVM_DEFAULT_CONFIG": (
                    "rasp(prob=100,minInstructions=1,maxExitSites=1,"
                    "maxBlockSites=0,semanticReturns=1)"
                ),
                "XOLLVM_DEFAULT_INCLUDE": "^protected_function$",
                "XOLLVM_VERIFY_IR": "1",
            },
            ("--obf-seed=143",),
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        protected = self.function_body(process.stdout, "protected_function")
        self.assertIn("icmp ne i64", protected)
        self.assertRegex(protected, r"xor i32 %result, %[^\n]+")
        self.assertGreaterEqual(protected.count("store i64"), 2)
        self.assertIn("load i64", protected)

    def test_runtime_injection_excludes_the_runtime_abi_module(self) -> None:
        runtime_ir = IR + """
define i64 @obscura_rasp_probe_0(i64 %site, i64 %challenge, i64 %caller) {
entry:
  ret i64 %challenge
}

define void @obscura_rasp_interlock_0(i64 %site, i64 %observed, i64 %expected) {
entry:
  ret void
}
"""
        process = self.run_opt(
            {
                "XOLLVM_DEFAULT_CONFIG": (
                    "rasp(prob=100,minInstructions=1,maxExitSites=2)"
                ),
                "XOLLVM_DEFAULT_INCLUDE": "^protected_function$",
                "XOLLVM_VERIFY_IR": "1",
            },
            source_ir=runtime_ir,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        protected = self.function_body(process.stdout, "protected_function")
        self.assertNotIn("obscura_rasp_probe_", protected)
        self.assertNotIn("obscura_rasp_interlock_", protected)

    def test_runtime_injection_respects_probability_and_size_gates(self) -> None:
        disabled = self.run_opt(
            {
                "XOLLVM_DEFAULT_CONFIG": "rasp(prob=0,minInstructions=1)",
                "XOLLVM_DEFAULT_INCLUDE": "^protected_function$",
            }
        )
        oversized_minimum = self.run_opt(
            {
                "XOLLVM_DEFAULT_CONFIG": (
                    "rasp(prob=100,minInstructions=1000)"
                ),
                "XOLLVM_DEFAULT_INCLUDE": "^protected_function$",
            }
        )
        self.assertEqual(disabled.returncode, 0, disabled.stderr)
        self.assertEqual(oversized_minimum.returncode, 0, oversized_minimum.stderr)
        self.assertNotIn(
            "obscura_rasp_probe",
            self.function_body(disabled.stdout, "protected_function"),
        )
        self.assertNotIn(
            "obscura_rasp_probe",
            self.function_body(oversized_minimum.stdout, "protected_function"),
        )

    def test_runtime_injection_is_reproducible_and_release_specific(self) -> None:
        environment = {
            "XOLLVM_DEFAULT_CONFIG": (
                "rasp(prob=100,minInstructions=1,maxExitSites=1)"
            ),
            "XOLLVM_DEFAULT_INCLUDE": "^protected_function$",
        }
        first = self.run_opt(environment, ("--obf-seed=43",))
        repeated = self.run_opt(environment, ("--obf-seed=43",))
        different = self.run_opt(environment, ("--obf-seed=44",))
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(repeated.returncode, 0, repeated.stderr)
        self.assertEqual(different.returncode, 0, different.stderr)
        first_body = self.function_body(first.stdout, "protected_function")
        repeated_body = self.function_body(repeated.stdout, "protected_function")
        different_body = self.function_body(different.stdout, "protected_function")
        self.assertEqual(first_body, repeated_body)
        self.assertNotEqual(first_body, different_body)

    def test_virtualization_precedes_runtime_injection(self) -> None:
        process = self.run_opt(
            {
                "XOLLVM_DEFAULT_CONFIG": (
                    "rasp(prob=100,minInstructions=1,maxExitSites=1),"
                    "vm(preset=max,budget=4096,budgetMax=30000)"
                ),
                "XOLLVM_DEFAULT_INCLUDE": "^protected_function$",
                "XOLLVM_VERIFY_IR": "1",
                "XOLLVM_IR_BUDGET_MULTIPLIER": "10000",
                "XOLLVM_IR_BUDGET_MAX": "30000",
            },
            ("--obf-seed=145",),
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        protected = self.function_body(process.stdout, "protected_function")
        self.assertIn("__vm_", process.stdout)
        self.assertIn("obscura_rasp_probe_", protected)
        self.assertIn("obscura_rasp_interlock_", protected)

    @staticmethod
    def function_body(ir: str, name: str) -> str:
        match = re.search(rf"define [^\n]* @{name}\(.*?^\}}", ir, re.MULTILINE | re.DOTALL)
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
        self.assertNotIn("address-marker", process.stdout)
        self.assertIn("external-marker", process.stdout)
        self.assertNotIn('section ".strenc', process.stdout)
        self.assertIn('section "__DATA,__strenc_', process.stdout)
        self.assertIn("@llvm.global_ctors", process.stdout)

    def run_runtime_policy(self, specification: str) -> bytes:
        environment = self.process_environment(
            {
                "XOLLVM_DEFAULT_CONFIG": specification,
                "XOLLVM_DEFAULT_INCLUDE": "^main$",
                "XOLLVM_VERIFY_IR": "1",
                "XOLLVM_IR_BUDGET_MULTIPLIER": "100",
                "XOLLVM_IR_BUDGET_MAX": "20000",
                "XOLLVM_MAX_FUNCTION_INSTRUCTIONS": "20000",
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
            self.assertEqual(
                executed.stdout,
                "runtime-marker!\naddress-marker!\nescaped-marker!\n",
            )
            return executable.read_bytes()

    def test_indirect_string_encryption_preserves_runtime_behavior(self) -> None:
        executable = self.run_runtime_policy("strenc(minlen=4,cipher=chacha)")
        self.assertNotIn(b"runtime-marker", executable)
        self.assertNotIn(b"address-marker", executable)
        self.assertNotIn(b"escaped-marker", executable)

    def test_indirect_string_encryption_survives_the_severe_policy(self) -> None:
        executable = self.run_runtime_policy(
            "constenc(prob=100,minAbs=1,maxSites=128),"
            "mba(preset=high,prob=70,maxSites=120),"
            "substitution(loop=2,maxSites=160),"
            "vcall(prob=25,indexStrength=2),split(num=3),"
            "bcf(prob=20,loop=1,maxBlocks=2000),"
            "flattening(minBlocks=3,maxBlocks=120,maxInstructions=250,"
            "maxDemotionRounds=8,fakeTransitions=1,fakeCases=2),"
            "shield(maxSites=160),adec(prob=40,strength=2,maxSites=32),"
            "strenc(minlen=4,cipher=chacha)"
        )
        self.assertNotIn(b"runtime-marker", executable)
        self.assertNotIn(b"address-marker", executable)
        self.assertNotIn(b"escaped-marker", executable)

    def test_absent_environment_policy_leaves_functions_unchanged(self) -> None:
        process = self.run_opt({})
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertIn(
            "add i32 %value, 7",
            self.function_body(process.stdout, "protected_function"),
        )

    def test_function_rule_replaces_a_conflicting_default_policy(self) -> None:
        process = self.run_opt(
            {
                "XOLLVM_DEFAULT_CONFIG": (
                    "mba(prob=100),flattening(minBlocks=2,maxBlocks=100)"
                ),
                "XOLLVM_DEFAULT_INCLUDE": "^protected_",
                "XOLLVM_FUNCTION_RULES": (
                    "replace\t^protected_function$\tvm(preset=high)"
                ),
                "XOLLVM_VERIFY_IR": "1",
                "XOLLVM_IR_BUDGET_MULTIPLIER": "10000",
                "XOLLVM_IR_BUDGET_MAX": "20000",
            }
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        replaced = self.function_body(process.stdout, "protected_function")
        defaulted = self.function_body(process.stdout, "protected_large_cfg")
        self.assertNotIn("add i32 %value, 7", replaced)
        self.assertIn("__vm_", process.stdout)
        self.assertNotIn("br i1 %condition, label %left, label %right", defaulted)

    def test_vm_virtualizes_boolean_extensions_into_narrow_integer_results(self) -> None:
        process = self.run_opt(
            {
                "XOLLVM_DEFAULT_CONFIG": "vm(preset=high)",
                "XOLLVM_DEFAULT_INCLUDE": "^protected_narrow_bool$",
                "XOLLVM_VERIFY_IR": "1",
                "XOLLVM_IR_BUDGET_MULTIPLIER": "10000",
                "XOLLVM_IR_BUDGET_MAX": "20000",
            }
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        body = self.function_body(process.stdout, "protected_narrow_bool")
        self.assertNotIn("zext i1 %condition to i8", body)
        self.assertIn("__vm_", process.stdout)

    def test_vm_virtualizes_boolean_truncation_from_narrow_integer_values(self) -> None:
        process = self.run_opt(
            {
                "XOLLVM_DEFAULT_CONFIG": "vm(preset=high)",
                "XOLLVM_DEFAULT_INCLUDE": "^protected_truncated_bool$",
                "XOLLVM_VERIFY_IR": "1",
                "XOLLVM_IR_BUDGET_MULTIPLIER": "10000",
                "XOLLVM_IR_BUDGET_MAX": "20000",
            }
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        body = self.function_body(process.stdout, "protected_truncated_bool")
        self.assertNotIn("trunc i8 %value to i1", body)
        self.assertIn("__vm_", process.stdout)

    def test_vm_virtualizes_boolean_comparisons(self) -> None:
        process = self.run_opt(
            {
                "XOLLVM_DEFAULT_CONFIG": "vm(preset=high)",
                "XOLLVM_DEFAULT_INCLUDE": "^protected_compared_bool$",
                "XOLLVM_VERIFY_IR": "1",
                "XOLLVM_IR_BUDGET_MULTIPLIER": "10000",
                "XOLLVM_IR_BUDGET_MAX": "20000",
            }
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        body = self.function_body(process.stdout, "protected_compared_bool")
        self.assertNotIn("icmp ule i1 %condition, true", body)
        self.assertIn("__vm_", process.stdout)

    def test_vm_runtime_symbols_do_not_collide_between_modules(self) -> None:
        environment = self.process_environment(
            {
                "XOLLVM_DEFAULT_CONFIG": "strenc(minlen=4,cipher=chacha)",
                "XOLLVM_DEFAULT_INCLUDE": "^protected_",
                "XOLLVM_FUNCTION_RULES": (
                    "merge\t^protected_.*$\tvm(preset=high)"
                ),
                "XOLLVM_VERIFY_IR": "1",
                "XOLLVM_IR_BUDGET_MULTIPLIER": "100",
                "XOLLVM_IR_BUDGET_MAX": "20000",
                "XOLLVM_MAX_FUNCTION_INSTRUCTIONS": "20000",
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            objects = []
            for suffix in ["alpha", "beta"]:
                source = root / f"{suffix}.ll"
                bitcode = root / f"{suffix}.bc"
                object_file = root / f"{suffix}.o"
                source.write_text(MULTI_MODULE_IR.replace("SUFFIX", suffix))
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
                objects.append(object_file)
            clang = shutil.which("clang")
            self.assertIsNotNone(clang)
            linked = subprocess.run(
                [clang, "-r", *map(str, objects), "-o", str(root / "combined.o")],
                capture_output=True,
                text=True,
            )
            self.assertEqual(linked.returncode, 0, linked.stderr)

    def test_function_rule_merges_with_the_default_policy(self) -> None:
        process = self.run_opt(
            {
                "XOLLVM_DEFAULT_CONFIG": "constenc(prob=100,minAbs=1,maxSites=16)",
                "XOLLVM_DEFAULT_INCLUDE": "^protected_function$",
                "XOLLVM_FUNCTION_RULES": (
                    "merge\t^protected_function$\tmba(prob=100,maxSites=16)"
                ),
            }
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        body = self.function_body(process.stdout, "protected_function")
        self.assertNotIn("add i32 %value, 7", body)
        self.assertIn("obf.constenc", process.stdout)

    def test_invalid_function_rules_are_rejected(self) -> None:
        for rule, message in [
            ("invalid", "Invalid -obf-function-rules entry"),
            ("unknown\tprotected\tvm", "Invalid -obf-function-rules mode"),
            ("replace\t[\tvm", "Invalid -obf-function-rules regular expression"),
        ]:
            with self.subTest(rule=rule):
                process = self.run_opt(
                    {
                        "XOLLVM_DEFAULT_CONFIG": "constenc",
                        "XOLLVM_FUNCTION_RULES": rule,
                    }
                )
                self.assertNotEqual(process.returncode, 0)
                self.assertIn(message, process.stderr)

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

    def test_environment_report_path_writes_a_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.json"
            process = self.run_opt(
                {
                    "XOLLVM_DEFAULT_CONFIG": "constenc",
                    "XOLLVM_REPORT_JSON": str(report),
                }
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            payload = json.loads(report.read_text())
            self.assertIn("functions", payload)

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
