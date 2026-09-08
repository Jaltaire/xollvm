# WebAssembly runtime portability

The embedded fixed-width cryptographic runtime adopts the destination module's data layout and target triple. Its build-host CPU attributes and module flags are removed before linking. WebAssembly also removes native stack-protector requirements because the freestanding target does not provide those runtime symbols. Native destinations retain their stack-protector attributes.

Encrypted data uses compiler-selected sections on WebAssembly. Sharing an explicitly named section between arbitrary ciphertext arrays can incorrectly combine mergeable-string and ordinary-data flags when one array happens to end in a zero byte.

Targets without block-address or indirect-branch support use integer handler identifiers and switch dispatch. The per-function encrypted dispatch map, opcode permutation, bytecode encryption, and handler-variant selection still apply. Both central and threaded dispatch generate structurally valid IR without native block addresses.

The final application must test transformed code in its actual interpreter. Large hardened or threaded VM engines can exceed interpreter translation limits even when LLVM produces valid WebAssembly. Bounded central-dispatch virtualization and target-aware arithmetic and string recipes are the conservative starting point. Native debugger, timing, and operating-system predicates do not become guest-side platform protection simply by compiling them to WebAssembly.

The standard Rust WebAssembly compiler-builtins archive provides floating-point and wide-integer helpers used by VM handlers. Standalone bitcode probes must link it explicitly; normal Rust linking includes it already.
