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

	Value* emitExpectedResponse(IRBuilder<>& builder, Value* site, Value* challenge) {
		Value* rotated = builder.CreateOr(
			builder.CreateShl(challenge, 17), builder.CreateLShr(challenge, 47));
		Value* value = builder.CreateXor(site, rotated);
		value = builder.CreateXor(value, UINT64_C(0x6a09e667f3bcc909));
		value = builder.CreateXor(value, builder.CreateLShr(value, 30));
		value = builder.CreateMul(
			value, ConstantInt::get(value->getType(), UINT64_C(0xbf58476d1ce4e5b9)));
		value = builder.CreateXor(value, builder.CreateLShr(value, 27));
		value = builder.CreateMul(
			value, ConstantInt::get(value->getType(), UINT64_C(0x94d049bb133111eb)));
		return builder.CreateXor(value, builder.CreateLShr(value, 31));
	}

	Value* semanticMask(IRBuilder<>& builder, Value* difference, Type* type) {
		Value* compromised = builder.CreateICmpNE(
			difference, ConstantInt::get(difference->getType(), 0));
		if (type->isIntegerTy(1))
			return compromised;
		return builder.CreateZExt(compromised, type);
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
	Function* runtimeProbe = F.getParent()->getFunction("obscura_rasp_probe_0");
	if (runtimeProbe && !runtimeProbe->isDeclaration() && !config.allowRuntimeModule)
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
	FunctionType* interlockType = FunctionType::get(
		Type::getVoidTy(llvmContext), {i64, i64, i64}, false);
	SmallVector<FunctionCallee, 8> probes;
	for (unsigned lane = 0; lane < 8; ++lane)
		probes.push_back(module.getOrInsertFunction(
			("obscura_rasp_probe_" + Twine(lane)).str(), probeType));
	SmallVector<FunctionCallee, 4> interlocks;
	for (unsigned lane = 0; lane < 4; ++lane)
		interlocks.push_back(module.getOrInsertFunction(
			("obscura_rasp_interlock_" + Twine(lane)).str(), interlockType));
	for (FunctionCallee probe : probes)
		if (auto* function = dyn_cast<Function>(probe.getCallee()))
			function->addFnAttr(Attribute::NoUnwind);
	for (FunctionCallee interlock : interlocks)
		if (auto* function = dyn_cast<Function>(interlock.getCallee()))
			function->addFnAttr(Attribute::NoUnwind);

	IRBuilder<> entryBuilder(&*F.getEntryBlock().getFirstInsertionPt());
	Function* returnAddress = Intrinsic::getOrInsertDeclaration(
		&module, Intrinsic::returnaddress);
	Value* callerPointer = entryBuilder.CreateCall(
		returnAddress, {ConstantInt::get(Type::getInt32Ty(llvmContext), 0)});
	Value* callerAddress = entryBuilder.CreatePtrToInt(callerPointer, i64);
	uint64_t entrySite = mix64(passSeed ^ UINT64_C(0x243f6a8885a308d3));
	uint64_t entryChallenge = mix64(passSeed ^ UINT64_C(0x13198a2e03707344));
	uint64_t entryExpected = expectedResponse(entrySite, entryChallenge);
	Value* entryObserved = entryBuilder.CreateCall(probes[mix64(passSeed) & 7], {
		ConstantInt::get(i64, entrySite), ConstantInt::get(i64, entryChallenge), callerAddress});
	entryBuilder.CreateCall(interlocks[mix64(passSeed) & 3], {
		ConstantInt::get(i64, entrySite), entryObserved, ConstantInt::get(i64, entryExpected)});
	Value* entryDifference = entryBuilder.CreateXor(
		entryObserved, ConstantInt::get(i64, entryExpected));
	AllocaInst* accumulatedDifference = entryBuilder.CreateAlloca(i64);
	entryBuilder.CreateStore(entryDifference, accumulatedDifference);

	auto emitSite = [&](IRBuilder<>& builder, uint64_t salt, unsigned ordinal) -> Value* {
		uint64_t baseSite = mix64(passSeed ^ UINT64_C(0xa4093822299f31d0) ^ salt);
		uint64_t baseChallenge = mix64(passSeed ^ UINT64_C(0x082efa98ec4e6c89) ^ salt);
		Value* site = builder.CreateXor(
			ConstantInt::get(i64, baseSite),
			builder.CreateMul(entryDifference,
				ConstantInt::get(i64, std::max<uint64_t>(mix64(baseSite), 1))));
		Value* challenge = builder.CreateXor(
			ConstantInt::get(i64, baseChallenge),
			builder.CreateOr(builder.CreateShl(entryObserved, 23),
				builder.CreateLShr(entryObserved, 41)));
		Value* expected = emitExpectedResponse(builder, site, challenge);
		Value* observed = builder.CreateCall(
			probes[mix64(passSeed ^ salt ^ ordinal) & 7], {site, challenge, callerAddress});
		builder.CreateCall(interlocks[mix64(passSeed ^ salt ^ ordinal) & 3], {
			site, observed, expected});
		Value* difference = builder.CreateXor(observed, expected);
		Value* priorDifference = builder.CreateLoad(i64, accumulatedDifference);
		builder.CreateStore(
			builder.CreateOr(priorDifference, difference), accumulatedDifference);
		return difference;
	};

	SmallVector<std::pair<uint64_t, BasicBlock*>, 16> rankedInternalBlocks;
	uint64_t blockOrdinal = 0;
	for (BasicBlock& block : F) {
		if (&block != &F.getEntryBlock() && !isa<ReturnInst>(block.getTerminator()) &&
			block.getFirstInsertionPt() != block.end())
			rankedInternalBlocks.push_back({mix64(passSeed ^ blockOrdinal), &block});
		++blockOrdinal;
	}
	std::sort(rankedInternalBlocks.begin(), rankedInternalBlocks.end(),
		[](const auto& left, const auto& right) { return left.first < right.first; });
	unsigned blockCount = std::min<unsigned>(
		config.maximumBlockSites, rankedInternalBlocks.size());
	for (unsigned index = 0; index < blockCount; ++index) {
		IRBuilder<> builder(&*rankedInternalBlocks[index].second->getFirstInsertionPt());
		emitSite(builder, UINT64_C(0x452821e638d01377) ^ index, index);
	}

	SmallVector<std::pair<uint64_t, ReturnInst*>, 8> rankedReturns;
	uint64_t returnOrdinal = 0;
	for (BasicBlock& block : F)
		if (auto* returnInstruction = dyn_cast<ReturnInst>(block.getTerminator()))
			rankedReturns.push_back({mix64(passSeed ^ returnOrdinal++), returnInstruction});
	std::sort(rankedReturns.begin(), rankedReturns.end(),
		[](const auto& left, const auto& right) { return left.first < right.first; });
	unsigned exitCount = std::min<unsigned>(config.maximumExitSites, rankedReturns.size());
	for (unsigned index = 0; index < exitCount; ++index) {
		ReturnInst* returnInstruction = rankedReturns[index].second;
		IRBuilder<> builder(returnInstruction);
		Value* difference = emitSite(
			builder, UINT64_C(0xbe5466cf34e90c6c) ^ index, blockCount + index);
		Value* returnValue = returnInstruction->getReturnValue();
		if (config.semanticReturns && returnValue && returnValue->getType()->isIntegerTy()) {
			Value* accumulated = builder.CreateLoad(i64, accumulatedDifference);
			returnInstruction->setOperand(
				0, builder.CreateXor(returnValue,
					semanticMask(builder, builder.CreateOr(accumulated, difference),
						returnValue->getType())));
		}
	}

	return PreservedAnalyses::none();
}
