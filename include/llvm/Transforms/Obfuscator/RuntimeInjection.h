#pragma once

#include "llvm/IR/PassManager.h"

namespace llvm {
	class RuntimeInjectionPass : public PassInfoMixin<RuntimeInjectionPass> {
	public:
		PreservedAnalyses run(Function& F, FunctionAnalysisManager& AM);
		static bool isRequired() { return true; }
	};
}
