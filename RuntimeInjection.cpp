#include "llvm/Transforms/Obfuscator/RuntimeInjection.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/Transforms/Obfuscator/FunctionObfContextAnalysis.h"
#include "llvm/Transforms/Obfuscator/ObfuscationAnnotationAnalysis.h"
#include "llvm/Transforms/Obfuscator/ObfuscationConfig.h"
#include "llvm/Transforms/Obfuscator/PassRng.h"

#include <algorithm>

using namespace llvm;

namespace {
	uint64_t mix64(uint64_t value) {
		value ^= value >> 30;
		value *= UINT64_C(0xbf58476d1ce4e5b9);
		value ^= value >> 27;
		value *= UINT64_C(0x94d049bb133111eb);
		return value ^ (value >> 31);
	}

	uint64_t rotateLeft(uint64_t value, unsigned amount) {
		return (value << amount) | (value >> (64 - amount));
	}

	uint64_t expectedResponse(uint64_t site, uint64_t challenge) {
		return mix64(site ^ rotateLeft(challenge, 17) ^ UINT64_C(0x6a09e667f3bcc909));
	}

}

PreservedAnalyses RuntimeInjectionPass::run(Function& F, FunctionAnalysisManager& AM) {
	if (F.isDeclaration() || F.empty() || F.getName().contains("obscura_rasp_") ||
		F.hasFnAttribute(Attribute::Naked))
		return PreservedAnalyses::all();

	const auto& cache = getObfCache(F, AM);
	auto passConfig = cache.getConfig(F).getPassConfig("rasp");
	if (!passConfig)
		return PreservedAnalyses::all();
	RuntimeInjectionConfig config = RuntimeInjectionConfig::fromPassConfig(*passConfig);
	if (!config.enable || !config.validate())
		return PreservedAnalyses::all();

	auto& context = *AM.getResult<FunctionObfContextAnalysis>(F);
	if (context.NumInsts < config.minimumInstructions || context.HasMustTail)
		return PreservedAnalyses::all();

	uint64_t functionSeed = cache.getFunctionSeed(F);
	uint64_t passSeed = obf::deriveSeed(functionSeed, "rasp");
	if ((passSeed % 100) >= config.probability)
		return PreservedAnalyses::all();

	LLVMContext& llvmContext = F.getContext();
	Module& module = *F.getParent();
	Type* i64 = Type::getInt64Ty(llvmContext);
	FunctionType* probeType = FunctionType::get(i64, {i64, i64, i64}, false);
	FunctionType* interlockType = FunctionType::get(Type::getVoidTy(llvmContext), {i64, i64, i64}, false);
	FunctionCallee probe = module.getOrInsertFunction("obscura_rasp_probe", probeType);
	FunctionCallee interlock = module.getOrInsertFunction("obscura_rasp_interlock", interlockType);
	if (auto* function = dyn_cast<Function>(probe.getCallee()))
		function->addFnAttr(Attribute::NoUnwind);
	if (auto* function = dyn_cast<Function>(interlock.getCallee()))
		function->addFnAttr(Attribute::NoUnwind);

	uint64_t entrySite = mix64(passSeed ^ UINT64_C(0x243f6a8885a308d3));
	uint64_t entryChallenge = mix64(passSeed ^ UINT64_C(0x13198a2e03707344));
	uint64_t entryExpected = expectedResponse(entrySite, entryChallenge);
	IRBuilder<> entryBuilder(&*F.getEntryBlock().getFirstInsertionPt());
	Function* returnAddress = Intrinsic::getOrInsertDeclaration(&module, Intrinsic::returnaddress);
	Value* callerPointer = entryBuilder.CreateCall(
		returnAddress, {ConstantInt::get(Type::getInt32Ty(llvmContext), 0)});
	Value* callerAddress = entryBuilder.CreatePtrToInt(callerPointer, i64);
	Value* entryObserved = entryBuilder.CreateCall(probe, {
		ConstantInt::get(i64, entrySite), ConstantInt::get(i64, entryChallenge), callerAddress});
	entryBuilder.CreateCall(interlock, {
		ConstantInt::get(i64, entrySite), entryObserved, ConstantInt::get(i64, entryExpected)});
	SmallVector<ReturnInst*, 8> returns;
	for (BasicBlock& block : F)
		if (auto* returnInstruction = dyn_cast<ReturnInst>(block.getTerminator()))
			returns.push_back(returnInstruction);

	unsigned exitCount = std::min<unsigned>(config.maximumExitSites, returns.size());
	for (unsigned index = 0; index < exitCount; ++index) {
		ReturnInst* returnInstruction = returns[index];
		IRBuilder<> builder(returnInstruction);
		uint64_t exitSite = mix64(passSeed ^ UINT64_C(0xa4093822299f31d0) ^ index);
		uint64_t exitChallenge = mix64(passSeed ^ UINT64_C(0x082efa98ec4e6c89) ^ index);
		uint64_t exitExpected = expectedResponse(exitSite, exitChallenge);
		Value* exitObserved = builder.CreateCall(probe, {
			ConstantInt::get(i64, exitSite), ConstantInt::get(i64, exitChallenge), callerAddress});
		builder.CreateCall(interlock, {
			ConstantInt::get(i64, exitSite), exitObserved, ConstantInt::get(i64, exitExpected)});
	}

	return PreservedAnalyses::none();
}
