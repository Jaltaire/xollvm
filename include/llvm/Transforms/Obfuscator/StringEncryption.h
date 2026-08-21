#pragma once

#include "llvm/ADT/StringRef.h"
#include "llvm/IR/PassManager.h"

namespace llvm {
	namespace obf {
		bool isStubFunctionName(StringRef Name);
		void internalizeStubFunctions(Module& M);
	}

	class StringEncryptionPass : public PassInfoMixin<StringEncryptionPass> {
	public:
		PreservedAnalyses run(Module& M, ModuleAnalysisManager& AM);
		static bool isRequired() { return true; }
	};

} // namespace llvm
