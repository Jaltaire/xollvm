#include "llvm/Transforms/Obfuscator/ObfReport.h"
#include "llvm/Transforms/Obfuscator/ObfuscationOptions.h"
#include "llvm/AsmParser/Parser.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/GlobalAlias.h"
#include "llvm/IR/GlobalIFunc.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassInstrumentation.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include <cstdlib>
#include <memory>

using namespace llvm;
using namespace llvm::obf;

static void require(bool Condition, StringRef Message) {
	if (!Condition) {
		errs() << Message << "\n";
		std::exit(1);
	}
}

static std::unique_ptr<Module> fixture(LLVMContext& Context) {
	SMDiagnostic Diagnostic;
	auto M = parseAssemblyString(R"(
@value = global i32 7
@external = external global i32
@alias = alias i32, ptr @value
@indirect = ifunc i32 (i32), ptr @resolve
declare void @outside()
define ptr @resolve() {
  ret ptr @compute
}
define i32 @compute(i32 %value) {
  %result = add i32 %value, 3
  ret i32 %result
}
)", Diagnostic, Context);
	require(bool(M), "The census fixture must parse successfully.");
	return M;
}

static void requireCounts(const IrObjectCounts& Actual, const IrObjectCounts& Expected) {
	require(Actual.Definitions == Expected.Definitions, "The definition count must match.");
	require(Actual.Declarations == Expected.Declarations, "The declaration count must match.");
	require(Actual.Instructions == Expected.Instructions, "The instruction count must match.");
	require(Actual.GlobalVariables == Expected.GlobalVariables, "The global-variable count must match.");
	require(Actual.Aliases == Expected.Aliases, "The alias count must match.");
	require(Actual.IFuncs == Expected.IFuncs, "The indirect-function count must match.");
}

static const IrOutputFunction& outputFunction(const ModuleIrCensusReport& Report, StringRef Name) {
	for (const auto& F : Report.OutputFunctions)
		if (F.Name == Name) return F;
	require(false, "The requested output function must exist.");
	llvm_unreachable("The missing output function has already failed the test.");
}

static const IrInputFunction& inputFunction(const ModuleIrCensusReport& Report, StringRef Name) {
	for (const auto& F : Report.InputFunctions)
		if (F.Name == Name) return F;
	require(false, "The requested input function must exist.");
	llvm_unreachable("The missing input function has already failed the test.");
}

static void unmeasuredAndEmpty() {
	LLVMContext Context;
	Module M("empty", Context);
	ModuleIrCensus Census;
	auto Missing = Census.observe(M);
	require(Missing.Status == IrCensusStatus::Unmeasured, "An uncaptured input must remain unmeasured.");
	Census.capture(M);
	auto Empty = Census.observe(M);
	require(Empty.Status == IrCensusStatus::Measured, "A captured empty module must be measured.");
	requireCounts(Empty.Input, {});
	requireCounts(Empty.Output, {});
	requireCounts(Empty.InputObjectsNotPresentInOutput, {});
	requireCounts(Empty.OutputInputObjects, {});
	requireCounts(Empty.OutputCreatedOrRecreatedObjects, {});
	require(Empty.InputFunctions.empty() && Empty.OutputFunctions.empty(), "An empty module must have empty function ledgers.");
}

static void completeUnchangedCensus() {
	LLVMContext Context;
	auto M = fixture(Context);
	ModuleIrCensus Census;
	Census.capture(*M);
	auto Report = Census.observe(*M);
	IrObjectCounts Expected{2, 1, 3, 2, 1, 1};
	requireCounts(Report.Input, Expected);
	requireCounts(Report.Output, Expected);
	requireCounts(Report.OutputInputObjects, Expected);
	requireCounts(Report.InputObjectsNotPresentInOutput, {});
	requireCounts(Report.OutputCreatedOrRecreatedObjects, {});
	require(Report.InputFunctions.size() == 3 && Report.OutputFunctions.size() == 3, "Both ledgers must include declarations and definitions.");
	for (const auto& Input : Report.InputFunctions) {
		const auto& Output = outputFunction(Report, Input.Name);
		require(Input.Disposition == IrInputDisposition::PresentInOutputModule, "Unchanged input functions must remain present.");
		require(Output.InputId == Input.Id, "A surviving function must retain its input ledger identity.");
		require(Output.InputInstructionObjects == Input.Instructions, "Unchanged instructions must retain object identity.");
		require(Output.CreatedOrRecreatedInstructionObjects == 0, "An unchanged function must contain no recreated instructions.");
		require(Output.Origin == (Input.Declaration ? IrFunctionOrigin::InputDeclarationObject : IrFunctionOrigin::InputDefinitionObject), "The input declaration kind must determine the origin.");
	}
}

static void inPlaceMutationAndRename() {
	LLVMContext Context;
	auto M = fixture(Context);
	ModuleIrCensus Census;
	Census.capture(*M);
	Function* F = M->getFunction("compute");
	F->front().front().setOperand(1, ConstantInt::get(Type::getInt32Ty(Context), 11));
	F->setName("renamed");
	M->getNamedGlobal("value")->setInitializer(ConstantInt::get(Type::getInt32Ty(Context), 19));
	auto Report = Census.observe(*M);
	const auto& Output = outputFunction(Report, "renamed");
	require(Output.InputId == inputFunction(Report, "compute").Id, "Renaming must not erase object provenance.");
	require(Output.InputInstructionObjects == 2, "In-place edits must remain original objects, without implying semantic coverage.");
	requireCounts(Report.OutputCreatedOrRecreatedObjects, {});
}

static void clonedMetadataDoesNotConferOrigin() {
	LLVMContext Context;
	auto M = fixture(Context);
	Function* F = M->getFunction("compute");
	MDNode* Marker = MDNode::get(Context, MDString::get(Context, "input"));
	F->front().front().setMetadata("census.marker", Marker);
	ModuleIrCensus Census;
	Census.capture(*M);
	ValueToValueMapTy Map;
	Function* Clone = CloneFunction(F, Map);
	F->replaceAllUsesWith(Clone);
	auto BeforeDeletion = Census.observe(*M);
	require(outputFunction(BeforeDeletion, F->getName()).Origin == IrFunctionOrigin::InputDefinitionObject, "Replacing uses must preserve the old live function's identity.");
	require(outputFunction(BeforeDeletion, Clone->getName()).Origin == IrFunctionOrigin::CreatedOrRecreatedObject, "Replacing uses must not transfer input identity to the clone.");
	F->eraseFromParent();
	Clone->setName("compute");
	require(Clone->front().front().getMetadata("census.marker") == Marker, "The cloned instruction must carry the original metadata for this test.");
	auto Report = Census.observe(*M);
	const auto& Output = outputFunction(Report, "compute");
	require(Output.Origin == IrFunctionOrigin::CreatedOrRecreatedObject, "Copied names and metadata must not confer input identity.");
	require(Output.InputInstructionObjects == 0 && Output.CreatedOrRecreatedInstructionObjects == 2, "Cloned instructions must be reported as recreated objects.");
	require(inputFunction(Report, "compute").Disposition == IrInputDisposition::NotPresentInOutputModule, "A deleted function must not follow replacement uses.");
	requireCounts(Report.InputObjectsNotPresentInOutput, {1, 0, 2, 0, 0, 0});
	requireCounts(Report.OutputCreatedOrRecreatedObjects, {1, 0, 2, 0, 0, 0});
}

static void restoredBodyIsRecreated() {
	LLVMContext Context;
	auto M = fixture(Context);
	Function* F = M->getFunction("compute");
	MDNode* Marker = MDNode::get(Context, MDString::get(Context, "input"));
	F->front().front().setMetadata("census.marker", Marker);
	ModuleIrCensus Census;
	Census.capture(*M);
	ValueToValueMapTy SnapshotMap;
	std::unique_ptr<Function> Snapshot(CloneFunction(F, SnapshotMap));
	Snapshot->removeFromParent();
	F->deleteBody();
	ValueToValueMapTy RestoreMap;
	RestoreMap[Snapshot->getArg(0)] = F->getArg(0);
	SmallVector<ReturnInst*, 2> Returns;
	CloneFunctionInto(F, Snapshot.get(), RestoreMap, CloneFunctionChangeType::LocalChangesOnly, Returns);
	Snapshot.reset();
	require(F->front().front().getMetadata("census.marker") == Marker, "The restored instruction must preserve the copied metadata.");
	auto Report = Census.observe(*M);
	const auto& Output = outputFunction(Report, "compute");
	require(Output.Origin == IrFunctionOrigin::InputDefinitionObject, "Restoring a body must not recreate its function object.");
	require(Output.InputInstructionObjects == 0 && Output.CreatedOrRecreatedInstructionObjects == 2, "A restored body must not claim survival of deleted input instructions.");
	requireCounts(Report.InputObjectsNotPresentInOutput, {0, 0, 2, 0, 0, 0});
	requireCounts(Report.OutputCreatedOrRecreatedObjects, {0, 0, 2, 0, 0, 0});
}

static void detachedObjectsAreAbsent() {
	LLVMContext Context;
	auto M = fixture(Context);
	ModuleIrCensus Census;
	Census.capture(*M);
	std::unique_ptr<Function> Detached(M->getFunction("compute"));
	Detached->replaceAllUsesWith(PoisonValue::get(Detached->getType()));
	Detached->removeFromParent();
	auto Report = Census.observe(*M);
	requireCounts(Report.InputObjectsNotPresentInOutput, {1, 0, 2, 0, 0, 0});
	require(inputFunction(Report, "compute").Disposition == IrInputDisposition::NotPresentInOutputModule, "A live object outside the output module must not count as retained.");
}

static void declarationsAndGeneratedObjects() {
	LLVMContext Context;
	auto M = fixture(Context);
	ModuleIrCensus Census;
	Census.capture(*M);
	Function* Outside = M->getFunction("outside");
	ReturnInst::Create(Context, BasicBlock::Create(Context, "entry", Outside));
	Function::Create(Outside->getFunctionType(), GlobalValue::ExternalLinkage, "introduced", *M);
	auto Report = Census.observe(*M);
	const auto& Output = outputFunction(Report, "outside");
	require(Output.Origin == IrFunctionOrigin::InputDeclarationObject && !Output.Declaration, "A new body must retain its declaration object's original kind.");
	require(Output.CreatedOrRecreatedInstructionObjects == 1, "A declaration's new body must contain generated instruction objects.");
	requireCounts(Report.Output, {3, 1, 4, 2, 1, 1});
	requireCounts(Report.OutputInputObjects, {3, 0, 3, 2, 1, 1});
	requireCounts(Report.OutputCreatedOrRecreatedObjects, {0, 1, 1, 0, 0, 0});
	requireCounts(Report.InputObjectsNotPresentInOutput, {});
}

static void replacedGlobalObjects() {
	LLVMContext Context;
	auto M = fixture(Context);
	ModuleIrCensus Census;
	Census.capture(*M);
	GlobalVariable* Previous = M->getNamedGlobal("value");
	auto* Next = new GlobalVariable(*M, Previous->getValueType(), false, Previous->getLinkage(), Previous->getInitializer(), "next");
	Previous->replaceAllUsesWith(Next);
	auto BeforeDeletion = Census.observe(*M);
	requireCounts(BeforeDeletion.InputObjectsNotPresentInOutput, {});
	requireCounts(BeforeDeletion.OutputCreatedOrRecreatedObjects, {0, 0, 0, 1, 0, 0});
	Previous->eraseFromParent();
	M->getNamedGlobal("external")->eraseFromParent();
	M->getNamedAlias("alias")->eraseFromParent();
	M->getNamedIFunc("indirect")->eraseFromParent();
	Next->setName("value");
	GlobalAlias::create("alias", Next);
	GlobalIFunc::create(M->getFunction("compute")->getFunctionType(), 0, GlobalValue::ExternalLinkage, "indirect", M->getFunction("resolve"), M.get());
	auto Report = Census.observe(*M);
	requireCounts(Report.InputObjectsNotPresentInOutput, {0, 0, 0, 2, 1, 1});
	requireCounts(Report.OutputCreatedOrRecreatedObjects, {0, 0, 0, 1, 1, 1});
	requireCounts(Report.OutputInputObjects, {2, 1, 3, 0, 0, 0});
}

static void definitionBecomesDeclaration() {
	LLVMContext Context;
	auto M = fixture(Context);
	ModuleIrCensus Census;
	Census.capture(*M);
	M->getFunction("compute")->deleteBody();
	auto Report = Census.observe(*M);
	const auto& Output = outputFunction(Report, "compute");
	require(Output.Origin == IrFunctionOrigin::InputDefinitionObject && Output.Declaration, "A removed body must retain the definition object's original kind.");
	requireCounts(Report.Output, {1, 2, 1, 2, 1, 1});
	requireCounts(Report.OutputInputObjects, {1, 2, 1, 2, 1, 1});
	requireCounts(Report.InputObjectsNotPresentInOutput, {0, 0, 2, 0, 0, 0});
	requireCounts(Report.OutputCreatedOrRecreatedObjects, {});
}

static void repeatedEntryResetsTheSink() {
	LLVMContext Context;
	auto M = fixture(Context);
	ObfReportSink Sink;
	Sink.beginModule(*M);
	Sink.ModuleTransformed = true;
	Sink.add(FunctionReport{});
	Function::Create(M->getFunction("outside")->getFunctionType(), GlobalValue::ExternalLinkage, "introduced", *M);
	Sink.beginModule(*M);
	require(!Sink.ModuleTransformed && Sink.Functions.empty(), "Each module entry must reset the prior pass reports and transform flag.");
	auto Report = Sink.Census.observe(*M);
	requireCounts(Report.Input, {2, 2, 3, 2, 1, 1});
	requireCounts(Report.OutputCreatedOrRecreatedObjects, {});
	require(Report.InputFunctions.size() == 4, "A repeated capture must replace the prior ledger rather than append to it.");
}

static void uncapturedJson() {
	LLVMContext Context;
	Module M("uncaptured", Context);
	ModuleAnalysisManager Manager;
	Manager.registerPass([] { return PassInstrumentationAnalysis(); });
	Manager.registerPass([] { return ObfReportAnalysis(); });
	ObfReportJson = "-";
	if (Error E = maybeWriteObfReportJson(M, Manager)) {
		logAllUnhandledErrors(std::move(E), errs());
		std::exit(1);
	}
}

int main(int Argc, char** Argv) {
	struct Test { StringRef Name; void (*Run)(); };
	const Test Tests[] = {
		{"unmeasured_and_empty", unmeasuredAndEmpty},
		{"complete_unchanged_census", completeUnchangedCensus},
		{"in_place_mutation_and_rename", inPlaceMutationAndRename},
		{"cloned_metadata_does_not_confer_origin", clonedMetadataDoesNotConferOrigin},
		{"restored_body_is_recreated", restoredBodyIsRecreated},
		{"detached_objects_are_absent", detachedObjectsAreAbsent},
		{"declarations_and_generated_objects", declarationsAndGeneratedObjects},
		{"replaced_global_objects", replacedGlobalObjects},
		{"definition_becomes_declaration", definitionBecomesDeclaration},
		{"repeated_entry_resets_the_sink", repeatedEntryResetsTheSink},
		{"uncaptured_json", uncapturedJson},
	};
	require(Argc == 2, "Exactly one census test name is required.");
	for (const Test& T : Tests)
		if (T.Name == Argv[1]) {
			T.Run();
			return 0;
		}
	require(false, "The census test name must be recognized.");
}
