import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest


SOURCE_IR = r'''
source_filename = "census-fixture"
@route = private constant [14 x i8] c"route/example\00"
declare void @consume(ptr)
define i32 @compute(i32 %value) {
  call void @consume(ptr @route)
  %result = add i32 %value, 41
  ret i32 %result
}
'''


class ReportCensusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        cls.unit_binary = cls.directory / "census-unit-tests"
        root = Path(__file__).resolve().parents[1]

        def llvm_flags(*arguments: str) -> list[str]:
            return shlex.split(
                subprocess.check_output(
                    [str(cls.llvm_config), *arguments], text=True
                )
            )

        library_directory = subprocess.check_output(
            [str(cls.llvm_config), "--libdir"], text=True
        ).strip()
        compilation = subprocess.run(
            [
                str(cls.cxx),
                *llvm_flags("--cxxflags"),
                "-std=c++17",
                "-fno-rtti",
                "-I",
                str(root / "include"),
                str(root / "utils" / "report_census_tests.cpp"),
                str(root / "ObfReport.cpp"),
                str(root / "ObfuscationOptions.cpp"),
                *llvm_flags("--ldflags", "--link-shared", "--libs", "--system-libs"),
                f"-Wl,-rpath,{library_directory}",
                "-o",
                str(cls.unit_binary),
            ],
            capture_output=True,
            text=True,
        )
        if compilation.returncode:
            raise AssertionError(
                f"The census unit-test executable must compile.\n{compilation.stderr}"
            )

    def run_pipeline(
        self,
        recipe: str = "",
        source: str = SOURCE_IR,
        environment: dict[str, str] | None = None,
        pipeline: str = "obfuscation",
        reporting: bool = True,
        evidence_name: str | None = None,
    ) -> tuple[dict | None, str]:
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "report.json"
            process_environment = {
                key: value
                for key, value in os.environ.items()
                if not key.startswith("XOLLVM_")
            }
            process_environment.update(
                {
                    "XOLLVM_DEFAULT_CONFIG": recipe,
                    "XOLLVM_DEFAULT_INCLUDE": "^compute$",
                    **(environment or {}),
                }
            )
            if reporting:
                process_environment["XOLLVM_REPORT_JSON"] = str(report_path)
            process = subprocess.run(
                [
                    str(self.opt),
                    "-load-pass-plugin",
                    str(self.plugin),
                    "--obf-seed=1301",
                    f"-passes={pipeline}",
                    "-S",
                    "-o",
                    "-",
                    "-",
                ],
                input=source,
                env=process_environment,
                capture_output=True,
                text=True,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            payload = json.loads(report_path.read_text()) if reporting else None
            if self.evidence_dir is not None and evidence_name is not None:
                self.evidence_dir.mkdir(parents=True, exist_ok=True)
                (self.evidence_dir / f"{evidence_name}.input.ll").write_text(source)
                (self.evidence_dir / f"{evidence_name}.output.ll").write_text(process.stdout)
                if reporting:
                    (self.evidence_dir / f"{evidence_name}.json").write_text(report_path.read_text())
            return payload, process.stdout

    def require_unmeasured_sites(self, census: dict) -> None:
        self.assertEqual(
            census["original_site_transform_attribution"],
            {
                "status": "unmeasured",
                "reason": "original_site_attribution_unavailable",
            },
        )
        self.assertEqual(
            census["module_string_coverage"],
            {"status": "unmeasured", "reason": "string_selection_not_reported"},
        )

    def require_partition(self, census: dict) -> None:
        inputs = {function["id"]: function for function in census["input_functions"]}
        self.assertEqual(len(inputs), len(census["input_functions"]))
        self.assertEqual(
            sum(function["instructions"] for function in census["input_functions"]),
            census["input"]["instructions"],
        )
        self.assertEqual(
            sum(function["instructions"] for function in census["output_functions"]),
            census["output"]["instructions"],
        )
        for kind, count in census["output"].items():
            self.assertEqual(
                count,
                census["output_input_objects"][kind]
                + census["output_created_or_recreated_objects"][kind],
                kind,
            )
        for function in census["output_functions"]:
            if function["origin"] == "created_or_recreated_object":
                self.assertNotIn("input_id", function)
            else:
                original = inputs[function["input_id"]]
                self.assertEqual(original["disposition"], "present_in_output_module")
                self.assertEqual(
                    function["origin"],
                    "input_declaration_object" if original["declaration"] else "input_definition_object",
                )
            self.assertEqual(
                function["instructions"],
                function["input_instruction_objects"]
                + function["created_or_recreated_instruction_objects"],
            )

    def test_object_lifetime_and_provenance(self) -> None:
        cases = (
            "unmeasured_and_empty",
            "complete_unchanged_census",
            "in_place_mutation_and_rename",
            "cloned_metadata_does_not_confer_origin",
            "restored_body_is_recreated",
            "detached_objects_are_absent",
            "declarations_and_generated_objects",
            "replaced_global_objects",
            "definition_becomes_declaration",
            "repeated_entry_resets_the_sink",
        )
        for case in cases:
            with self.subTest(case=case):
                result = subprocess.run(
                    [str(self.unit_binary), case], capture_output=True, text=True
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_capture_emits_no_invented_counts(self) -> None:
        result = subprocess.run(
            [str(self.unit_binary), "uncaptured_json"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        census = json.loads(result.stdout)["module"]["ir_census"]
        self.assertEqual(census["status"], "unmeasured")
        self.assertEqual(census["reason"], "module_input_not_captured")
        self.assertNotIn("input", census)
        self.assertNotIn("output", census)
        self.require_unmeasured_sites(census)

    def test_no_config_still_has_a_complete_input_census(self) -> None:
        payload, _ = self.run_pipeline()
        self.assertEqual(payload["schema_version"], 3)
        self.assertEqual(payload["functions"], [])
        census = payload["module"]["ir_census"]
        self.assertEqual(census["status"], "measured")
        self.assertEqual(
            census["input"],
            {
                "definitions": 1,
                "declarations": 1,
                "instructions": 3,
                "global_variables": 1,
                "aliases": 0,
                "ifuncs": 0,
            },
        )
        self.assertEqual(census["input"], census["output"])
        self.assertEqual(census["output"], census["output_input_objects"])
        self.assertEqual(len(census["input_functions"]), 2)
        self.require_partition(census)
        self.require_unmeasured_sites(census)

    def test_empty_module_is_measured_not_missing(self) -> None:
        payload, _ = self.run_pipeline(source='source_filename = "empty"\n')
        census = payload["module"]["ir_census"]
        self.assertEqual(census["status"], "measured")
        self.assertEqual(census["input_functions"], [])
        self.assertTrue(all(value == 0 for value in census["input"].values()))
        self.require_partition(census)

    def test_no_op_recipe_does_not_fabricate_generated_objects(self) -> None:
        for recipe in ("constenc(prob=0)", "rasp(prob=0,minInstructions=1)"):
            with self.subTest(recipe=recipe):
                payload, _ = self.run_pipeline(recipe)
                census = payload["module"]["ir_census"]
                self.assertTrue(
                    all(value == 0 for value in census["output_created_or_recreated_objects"].values())
                )
                self.assertTrue(
                    all(not entry.get("changed", False) for function in payload["functions"] for entry in function["passes"])
                )
                self.require_partition(census)

    def test_budget_exhaustion_keeps_the_pre_transform_census(self) -> None:
        payload, _ = self.run_pipeline(
            "constenc(prob=100,minAbs=1,maxSites=4)",
            environment={"XOLLVM_IR_BUDGET_MAX": "1", "XOLLVM_IR_BUDGET_MULTIPLIER": "100"},
        )
        census = payload["module"]["ir_census"]
        self.assertEqual(census["input"]["instructions"], 3)
        self.assertEqual(census["output"]["instructions"], 3)
        self.assertTrue(
            any(entry["status"] == "skipped" for function in payload["functions"] for entry in function["passes"])
        )
        self.require_unmeasured_sites(census)
        self.require_partition(census)

    def test_module_string_transform_is_outside_function_before_counts(self) -> None:
        payload, _ = self.run_pipeline("strenc(minlen=4,cipher=chacha),constenc(prob=0)")
        census = payload["module"]["ir_census"]
        self.assertEqual(census["input"]["instructions"], 3)
        self.assertEqual(census["input"]["global_variables"], 1)
        self.assertGreater(census["output_created_or_recreated_objects"]["instructions"], 0)
        report = next(function for function in payload["functions"] if function["name"] == "compute")
        self.assertGreater(report["insts"]["before"], 3)
        original = next(function for function in census["input_functions"] if function["name"] == "compute")
        self.assertEqual(original["instructions"], 3)
        self.require_unmeasured_sites(census)
        self.require_partition(census)

    def test_reporting_does_not_change_transformed_ir(self) -> None:
        recipe = "strenc(minlen=4,cipher=chacha),constenc(prob=100,minAbs=1,maxSites=1)"
        _, reported = self.run_pipeline(recipe, evidence_name="reported")
        _, unreported = self.run_pipeline(recipe, reporting=False, evidence_name="unreported")
        self.assertEqual(reported, unreported)

    def test_same_input_has_deterministic_census(self) -> None:
        recipe = "strenc(minlen=4,cipher=chacha),constenc(prob=0)"
        first, _ = self.run_pipeline(recipe)
        second, _ = self.run_pipeline(recipe)
        self.assertEqual(first["module"]["ir_census"], second["module"]["ir_census"])

    def test_repeated_module_entry_does_not_accumulate_input_ledger(self) -> None:
        payload, _ = self.run_pipeline(pipeline="obfuscation,obfuscation")
        census = payload["module"]["ir_census"]
        self.assertEqual(len(census["input_functions"]), 2)
        self.assertEqual(census["input"]["instructions"], 3)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--opt", type=Path, required=True)
    parser.add_argument("--plugin", type=Path, required=True)
    parser.add_argument("--llvm-config", type=Path, required=True)
    parser.add_argument("--cxx", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path)
    arguments = parser.parse_args()
    for name in ("opt", "plugin", "llvm_config", "cxx"):
        setattr(ReportCensusTests, name, getattr(arguments, name).absolute())
    ReportCensusTests.evidence_dir = arguments.evidence_dir
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ReportCensusTests)
    return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
