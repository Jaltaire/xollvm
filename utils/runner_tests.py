import contextlib
import io
import subprocess
import threading
import unittest
from pathlib import Path
from unittest import mock

from runner import cross, pipeline, util
from runner.targets import TARGETS
from runner.config import Tools
from cases._common import TestCase
import default_policy_tests as policy
import mba_fold_check as fold


class ProcessTests(unittest.TestCase):
    def test_policy_transformations_use_a_fixed_seed_unless_one_is_supplied(self):
        case = policy.DefaultPolicyTests()
        case.opt, case.plugin = Path("opt"), Path("plugin")

        def run(arguments, **options):
            Path(arguments[arguments.index("-o") + 1]).write_text("Transformed IR.")
            return subprocess.CompletedProcess(arguments, 0, "", "")

        for arguments, expected in [({}, str(policy.TEST_SEED)), ({"arguments": ("--obf-seed=17",)}, "17")]:
            with self.subTest(expected=expected):
                with mock.patch.object(policy.subprocess, "run", side_effect=run) as execute:
                    self.assertEqual(case.run_opt({}, **arguments).stdout, "Transformed IR.")
                    seeds = [argument for argument in execute.call_args.args[0] if argument.startswith("--obf-seed=")]
                    self.assertEqual(seeds, [f"--obf-seed={expected}"])

    def test_execution_waits_for_completion_without_a_wall_clock_limit(self):
        self.check_execution(util.exec_prog, ["program", "13", "29"])

    def test_cross_execution_waits_for_completion_without_a_wall_clock_limit(self):
        self.check_execution(
            lambda exe, x, y: cross.exec_target(TARGETS["aarch64"], exe, x, y),
            ["qemu-aarch64", "program", "13", "29"],
        )

    def check_execution(self, execute_program, expected_arguments):
        entered = threading.Event()
        release = threading.Event()
        completed = threading.Event()
        results = []
        calls = []

        def run(arguments, **options):
            calls.append((arguments, options))
            entered.set()
            if not release.wait(600):
                raise RuntimeError("The test did not release the child process.")
            return subprocess.CompletedProcess(arguments, 7, "answer\n", "diagnostic\n")

        def execute():
            results.append(execute_program(Path("program"), 13, 29))
            completed.set()

        with mock.patch.object(util.subprocess, "run", side_effect=run):
            worker = threading.Thread(target=execute)
            worker.start()
            try:
                self.assertTrue(entered.wait(600))
                self.assertFalse(completed.is_set())
                self.assertIsNone(calls[0][1].get("timeout"))
            finally:
                release.set()
                worker.join(600)
            self.assertFalse(worker.is_alive())
        self.assertEqual(calls[0][0], expected_arguments)
        self.assertEqual(results, [(7, "answer\n", "diagnostic\n")])

    def test_execution_errors_cannot_become_comparable_program_results(self):
        for error in [OSError("The executable is missing."), subprocess.TimeoutExpired("program", 30)]:
            with self.subTest(error=type(error).__name__):
                with mock.patch.object(util.subprocess, "run", side_effect=error):
                    with self.assertRaises(type(error)):
                        util.exec_prog(Path("program"), 0, 0)

    def test_cross_execution_errors_cannot_become_comparable_program_results(self):
        for error in [OSError("The emulator is missing."), subprocess.TimeoutExpired("emulator", 30)]:
            with self.subTest(error=type(error).__name__):
                with mock.patch.object(util.subprocess, "run", side_effect=error):
                    with self.assertRaises(type(error)):
                        cross.exec_target(TARGETS["aarch64"], Path("program"), 0, 0)

    def test_fold_resistance_commands_wait_for_completion(self):
        result = subprocess.CompletedProcess("opt", 0, "ret i32 %input", "")
        with mock.patch.object(fold.os.path, "isfile", return_value=True), mock.patch.object(
            fold.subprocess, "run", return_value=result
        ) as run, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(fold.main(), 0)
        self.assertEqual(run.call_count, len(fold.IDENTITIES) + len(fold.ZERO_FORMS))
        for call in run.call_args_list:
            self.assertIsNone(call.kwargs.get("timeout"))

    def test_comparison_preserves_each_observable(self):
        baseline = (0, "answer\n", "diagnostic\n")
        self.assertIsNone(util.compare(baseline, baseline))
        for changed, expected in [
            ((1, baseline[1], baseline[2]), "exit:"),
            ((0, "different\n", baseline[2]), "stdout:"),
            ((0, baseline[1], "different\n"), "stderr mismatch"),
        ]:
            with self.subTest(expected=expected):
                self.assertIn(expected, util.compare(baseline, changed))

    def test_compiler_commands_have_no_default_wall_clock_limit(self):
        command = ["compiler", "input"]
        result = subprocess.CompletedProcess(command, 0, "", "")
        with mock.patch.object(util.subprocess, "run", return_value=result) as run:
            self.assertIs(util.run_cmd(command), result)
            self.assertIsNone(run.call_args.kwargs["timeout"])

    def test_explicit_command_limits_and_failures_remain_errors(self):
        with mock.patch.object(util.subprocess, "run", side_effect=subprocess.TimeoutExpired("compiler", 900)):
            with self.assertRaisesRegex(RuntimeError, "TIMEOUT"):
                util.run_cmd(["compiler"], timeout=900)
        with mock.patch.object(util.subprocess, "run", return_value=subprocess.CompletedProcess("compiler", 1, "", "The compiler failed.")):
            with self.assertRaisesRegex(RuntimeError, "The compiler failed"):
                util.run_cmd(["compiler"])

    def test_pipeline_and_cases_do_not_restore_short_command_limits(self):
        tools = Tools(Path("clang"), Path("opt"))
        source, output = Path("input.ll"), Path("output")
        operations = [
            lambda: pipeline.compile_ll_to_exe(tools, source, output, "O0", is_cpp=False),
            lambda: pipeline.run_obfuscation(tools, source, output, 1),
            lambda: pipeline.run_o2(tools, source, output),
            lambda: pipeline.run_metrics(tools, source, "main"),
        ]
        for operation in operations:
            with self.subTest(operation=operation):
                with mock.patch.object(pipeline, "run_cmd", return_value=subprocess.CompletedProcess("opt", 0, "{}", "")) as run:
                    operation()
                    self.assertIsNone(run.call_args.kwargs["timeout"])
        self.assertIsNone(TestCase(name="case", passes=[]).command_timeout)


if __name__ == "__main__":
    unittest.main()
