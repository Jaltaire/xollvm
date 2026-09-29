# Module-input IR census

Report schema version 3 adds `module.ir_census`. The census is captured at entry to each obfuscation module pipeline, before function merging, string encryption, and function transformations. It is also captured when no obfuscation configuration selects the module. An input that was not captured is explicitly unmeasured; it is not represented by fabricated zero counts.

The census contains function definitions, function declarations, instruction objects, global variables, aliases, and indirect functions. Every input function appears in the input ledger, including declarations and functions that have no function-pass report. Function identifiers are local to this input ledger, not stable identifiers across builds or modules.

At pipeline output, deletion-aware LLVM handles distinguish surviving input objects from objects that were created or recreated during the pipeline. The handles do not follow replacement-of-all-uses operations. Names and metadata are not identity evidence. A cloned function is recreated even if it carries the same name and metadata; restoring an original function's body from a snapshot preserves the function object but recreates its instructions. Objects that remain alive outside the output module count as absent from that module.

`output_input_objects` and `output_created_or_recreated_objects` partition the output census by **output object kind**. A surviving input declaration can become an output definition, or a surviving input definition can become an output declaration. Consequently, per-kind input/output conservation is not valid across those transitions. `input_objects_not_present_in_output` uses the original input kinds. The function ledgers preserve both the original declaration kind and the current output kind.

Instruction origin is relative to the complete input module, not an individual input function. Moving an input instruction between functions preserves its module-input identity. Creating a replacement instruction does not. Object survival says nothing about whether an instruction's operands or a global's initializer changed in place. Neither survival nor recreation proves protection, semantic equivalence, or increased resistance to analysis.

Two measurements remain explicitly unavailable:

- `original_site_transform_attribution` is unmeasured because passes do not report which original operations were transformed. Generated scaffolding, cloned application operations, rollback restorations, and other recreated instructions are not distinguished by this census.
- `module_string_coverage` is unmeasured because string-selection candidates, exclusions, transformations, and bytes are not reported. Global counts are not string-coverage counts, and no conclusion about runtime plaintext secrecy follows from them.

Existing top-level `functions` entries remain function-pass reports. Their before counts are taken after module transformations and may already include string-decryption scaffolding. A module-input count must not be substituted for the function driver's actual budget input, or used to claim that changed scaffolding represents transformed original operations. This reporting change does not modify recipes, selection, budgets, or transformation semantics.

This is a pre-link compiler census, not final-linked-artifact coverage or an inventory of the Cargo dependency graph. Re-entering the obfuscation pipeline resets the census and pass reports to that invocation's input; the report does not accumulate historical pipeline invocations.

## Validation

Build the plugin with its matching LLVM installation, and run the focused suite with that same installation:

```sh
python3 utils/report_census_tests.py \
  --opt /path/to/llvm/bin/opt \
  --plugin /path/to/build/Obfuscator.dylib \
  --llvm-config /path/to/llvm/bin/llvm-config \
  --cxx /path/to/llvm/bin/clang++
```

The suite compiles a small test executable from the reporting implementation against LLVM, and separately runs the actual plugin pipeline. It exercises object lifetimes, replacement, copied metadata, rollback-style restoration, both declaration-kind transitions, detached objects, complete object-category accounting, and repeated capture. Pipeline tests cover unconfigured modules, no-op recipes, budget exhaustion, module string transformations, deterministic output, and reporting-disabled IR equivalence. The optional `--evidence-dir` preserves the comparison fixture's real JSON report and both IR outputs.
