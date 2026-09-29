#pragma once

#include "llvm/ADT/DenseMap.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/ValueHandle.h"
#include "llvm/Support/Error.h"
#include <cstdint>
#include <string>
#include <vector>



namespace llvm::obf {

	// Stable schema version for the JSON obfuscation map.
	constexpr unsigned kObfReportSchemaVersion = 3;

	enum class IrCensusStatus { Measured, Unmeasured };
	enum class IrCensusReason {
		ModuleInputNotCaptured,
		OriginalSiteAttributionUnavailable,
		StringSelectionNotReported
	};
	enum class IrObjectKind {
		Definition, Declaration, Instruction, GlobalVariable, Alias, IFunc
	};
	enum class IrFunctionOrigin {
		InputDefinitionObject, InputDeclarationObject, CreatedOrRecreatedObject
	};
	enum class IrInputDisposition { PresentInOutputModule, NotPresentInOutputModule };

	struct IrObjectCounts {
		uint64_t Definitions = 0;
		uint64_t Declarations = 0;
		uint64_t Instructions = 0;
		uint64_t GlobalVariables = 0;
		uint64_t Aliases = 0;
		uint64_t IFuncs = 0;

		void add(IrObjectKind Kind);
	};

	struct IrInputFunction {
		uint64_t Id = 0;
		std::string Name;
		bool Declaration = false;
		uint64_t Instructions = 0;
		IrInputDisposition Disposition = IrInputDisposition::NotPresentInOutputModule;
	};

	struct IrOutputFunction {
		std::string Name;
		bool Declaration = false;
		IrFunctionOrigin Origin = IrFunctionOrigin::CreatedOrRecreatedObject;
		uint64_t InputId = 0;
		uint64_t Instructions = 0;
		uint64_t InputInstructionObjects = 0;
		uint64_t CreatedOrRecreatedInstructionObjects = 0;
	};

	struct ModuleIrCensusReport {
		IrCensusStatus Status = IrCensusStatus::Unmeasured;
		IrObjectCounts Input;
		IrObjectCounts Output;
		IrObjectCounts InputObjectsNotPresentInOutput;
		IrObjectCounts OutputInputObjects;
		IrObjectCounts OutputCreatedOrRecreatedObjects;
		std::vector<IrInputFunction> InputFunctions;
		std::vector<IrOutputFunction> OutputFunctions;
	};

	class ModuleIrCensus {
		struct InputObject {
			WeakVH Object;
			IrObjectKind Kind;
		};
		struct InputFunction {
			WeakVH Object;
			IrInputFunction Description;
		};
		IrCensusStatus Status = IrCensusStatus::Unmeasured;
		IrObjectCounts InputCounts;
		std::vector<InputObject> InputObjects;
		std::vector<InputFunction> InputFunctions;

	public:
		void capture(Module& M);
		ModuleIrCensusReport observe(const Module& M) const;
	};

	struct DifficultyComponents {
		unsigned Insts = 0;
		unsigned Blocks = 0;
		unsigned Edges = 0;
		unsigned Cyclomatic = 0;
		unsigned ConditionalBranches = 0;
		unsigned OpaquePredicates = 0;
		unsigned IndirectBrs = 0;
		unsigned CallBrs = 0;
		unsigned IndirectCalls = 0;
		unsigned MbaNodes = 0;
		unsigned MbaMaxDepth = 0;
		double MbaAvgDepth = 0.0;
	};

	struct DifficultyScore {
		double Score = 0.0; // [0,100]

		unsigned CyclomaticBefore = 0;
		unsigned CyclomaticAfter = 0;
		int64_t CyclomaticDelta = 0;
		unsigned OpaquePredicates = 0;
		double OpaquePer100Insts = 0.0;
		unsigned MbaNodes = 0;
		unsigned MbaMaxDepth = 0;
		double MbaAvgDepth = 0.0;
		unsigned IndirectBrs = 0;
		unsigned CallBrs = 0;
		unsigned IndirectCalls = 0;
	};

	struct PassReport {
		std::string Id;
		uint64_t Seed = 0;
		bool Skipped = false;
		std::string SkipReason;
		bool Changed = false;
		unsigned InstsBefore = 0;
		unsigned InstsAfter = 0;
		double BudgetUtilAfter = 0.0;
	};

	struct CfgStageArtifact {
		std::string Pass;
		std::string DotAfter;
		std::string DotDiff; // "after" graph with diff coloring (relative to previous stage)
	};

	struct FunctionReport {
		std::string Name;
		bool Declaration = false;
		bool Skipped = false;
		std::string SkipReason;
		uint64_t BaseSeed = 0;
		uint64_t ModuleSeed = 0;
		uint64_t FunctionSeed = 0;
		unsigned InstsBefore = 0;
		unsigned InstsAfter = 0;
		bool BudgetEnabled = false;
		unsigned BudgetLimit = 0;
		unsigned BudgetRemaining = 0;
		double BudgetUtilization = 0.0;
		std::vector<PassReport> Passes;
		DifficultyScore Difficulty;
		std::string CfgBeforeDot;
		std::string CfgAfterDot;
		std::vector<CfgStageArtifact> CfgPerPass;
	};

	struct ObfReportSink {
		std::vector<FunctionReport> Functions;
		bool ModuleTransformed = false;
		ModuleIrCensus Census;

		void beginModule(Module& M);
		void add(FunctionReport&& R);

		// Never invalidate: report is a side-channel sink.
		bool invalidate(Module&, const PreservedAnalyses&,
			ModuleAnalysisManager::Invalidator&) {
			return false;
		}
	};

	/// True when any report output option is enabled.
	bool isReportEnabled();

	/// Absolute report directory (may be empty).
	std::string getReportDir();

	/// Absolute JSON output path (may be empty). If -obf-report-json is empty and
	/// -obf-report-dir is set, this returns "<dir>/obf_report.json".
	std::string getReportJsonPath();

	/// Sanitizes an arbitrary name for use as a path component.
	std::string sanitizePathComponent(StringRef S);

	/// Compute component metrics for the difficulty score.
	DifficultyComponents computeDifficultyComponents(const Function& F);

	/// Combine pre/post components into a single difficulty score.
	DifficultyScore scoreDifficulty(const DifficultyComponents& Before,
		const DifficultyComponents& After);

	/// Writes a DOT CFG snapshot.
	///
	/// If \p PrevInsts is provided, blocks that are new/changed relative to the
	/// previous snapshot are highlighted.
	///
	/// On success, \p OutInsts is populated with the current snapshot's per-block
	/// instruction counts.
	Error writeCfgDotSnapshot(const Function& F, StringRef AbsDotPath,
		const DenseMap<const BasicBlock*, unsigned>* PrevInsts,
		DenseMap<const BasicBlock*, unsigned>& OutInsts);

	/// Writes JSON to the configured output path. If reporting is disabled, this is
	/// a no-op returning success.
	Error maybeWriteObfReportJson(Module& M, ModuleAnalysisManager& MAM);

} // namespace llvm::obf

namespace llvm {

	class ObfReportAnalysis : public AnalysisInfoMixin<ObfReportAnalysis> {
	public:
		using Result = obf::ObfReportSink;

		Result run(Module& M, ModuleAnalysisManager& MAM);

	private:
		friend AnalysisInfoMixin<ObfReportAnalysis>;
		static AnalysisKey Key;
	};

} // namespace llvm
