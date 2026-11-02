# ADR-017: bounded AArch64 decoding and exact unwind extents

- Date: 2026-11-02
- Status: technical decoder gate passed for the explicit subset below; adopt this contract for subsequent M3-B work. Product integration and its lockfile checks remain Task 7, not this decision's implementation.
- Baseline: `f1ea809b3a8f9e86b36092f5580b9777f206c4c1`, after accepted Task 1 fixtures.
- Scope: issue #48 Task 2, revisiting ADR-005's decoder/unwind choice. This does not complete M3-B, M3-C or issue #48.
- Reproduction: [standalone gate](ADR-017-gate/README.md), [compact evidence](ADR-017-gate/results.json), [adapter](ADR-017-gate/src/main.rs).

## Decision and contract

Select these exact dependencies for later M3-B integration:

```toml
yaxpeax-arm = { version = "=0.5.0", default-features = false, features = ["std", "non-exhaustive-enums"] }
yaxpeax-arch = { version = "=0.3.3", default-features = false, features = ["std"] }
```

The accepted decoder interface is the complete `prefilter` plus `yax` adapter in the standalone gate, including its raw constraints and complete typed instruction equality. Decoder success alone is insufficient. The adapter returns no semantic result before the raw class and every opcode/operand/width/immediate/address mode agree. `None` maps to an unsupported-instruction gap; `Err` maps to an adapter-inconsistency gap. The caller must roll back that function's records under the existing transactional contract. A decoded `BR` still needs a separately proved target; its classification alone does not establish an import or a complete CFG. PAC, authenticated control flow and BTI remain unsupported in this initial subset.

Feed the decoder exactly four bytes from a local array, after the charged reader has verified slice/file/executable bounds and instruction alignment. Never give a decoder the file descriptor or let it read a fifth byte. Charge every attempted instruction before the prefilter, including rejected words. Respect the existing 200,000-instruction function cap and aggregate budgets. Compute PC-relative destinations with checked signed addition from the instruction address; ADRP first clears the low 12 bits. Require a valid aligned executable destination where control-flow semantics require it. Address overflow, incomplete bytes, ambiguous mappings and unsupported forms produce gaps. Do not call `well_defined()` or candidate instruction formatters as a proof, and do not use `catch_unwind` to recover malformed inputs.

The scratch adapter demonstrates input classification, typed semantics and checked target arithmetic; it does not implement value propagation, relocations, import witnesses, CFG reachability or the engine's reader/budget integration. Later code must preserve W-write zero extension, discard writes to ZR, distinguish SP, invalidate all pair-load destinations and writeback bases, and stop or invalidate on unsupported writes. In particular, accepting STP/LDP here does not approve stack-memory value propagation.

## Audited raw subset

`w` is a little-endian u32. Every row is implemented by the same `prefilter` that the hostile harness exercises. No general decoder fallback exists. X/W width comes from the encoding, with integer load/store width separately taken from `size[31:30]`.

| Class | Exact initial predicate | Additional constraints / operands |
|---|---|---|
| B, BL | `w & 0x7c000000 == 0x14000000` | Bit31 selects BL. Signed imm26 times four; PC is this instruction. |
| B.cond | `w & 0xff000010 == 0x54000000` | Condition 0–13 only. Signed imm19 times four; HBC bit4 excluded. |
| CBZ, CBNZ | `w & 0x7e000000 == 0x34000000` | Bit24 selects nonzero; bit31 selects W/X; Rt31 is ZR. |
| TBZ, TBNZ | `w & 0x7e000000 == 0x36000000` | Bit24 selects nonzero. Bit number combines b5/b40; signed imm14 times four. |
| BR, BLR, RET | `w & 0xfffffc1f` equals `0xd61f0000`, `0xd63f0000`, `0xd65f0000` | Rn must be 0–30; all authenticated/reserved variants excluded. |
| ADR, ADRP | `w & 0x1f000000 == 0x10000000` | Signed immhi:immlo (21 bits), scaled by 4096 only for ADRP; Rd31 is ZR. |
| MOVN, MOVZ, MOVK | `w & 0x1f800000 == 0x12800000` | opc 0/2/3 only; W permits hw0/1, X hw0–3. Imm16 and shift remain separate. |
| ORR register-copy form | `w & 0x7fe0ffe0 == 0x2a0003e0` | Rn=ZR, shift=LSL0, N=0; width preserved for Rd and Rm. |
| ADD, SUB immediate | `w & 0x3f800000 == 0x11000000` | S=0, bit23=0; shift bit22 is 0 or 12 bits. Both register31 operands denote SP. |
| Integer LDR, STR unsigned offset | `w & 0xbfc00000` equals `0xb9400000` or `0xb9000000` | W/X only, no writeback; unsigned imm12 scaled by 4/8; base31 is SP, Rt31 is ZR. |
| Integer STP, LDP | `w & 0x7e000000 == 0x28000000` | Mode[24:23] 1/2/3 only (post/offset/pre); signed imm7 scaled 4/8. Reject equal LDP destinations and non-SP writeback base overlapping either destination/source. Excludes SIMD and LDPSW. |
| NOP | `w == 0xd503201f` | yaxpeax exposes HINT with ControlReg(0), Immediate(0); no generic HINT support. |

Every other word is unsupported. Fixture exclusions are `00000000` (UDF), `d503233f` (PACIASP), and `18000050` (literal LDR in the lazy helper). Literal loads, flag-setting arithmetic, general shifted logical operations, extended-register arithmetic, SIMD/SVE/SME, arbitrary hints and additional memory modes require a new audited predicate. If encountered in a queried reachable function they leave a gap; they are not assumed to have no side effects. Existing fixtures deliberately contain unsupported functions, so excluding these words does not silently expand the advertised semantics.

## Reachable source paths and bounds

Archive SHA-256 pins identify the inspected releases, and registry source was compared byte-for-byte with the prior extracted copies:

| Crate | Version | Archive SHA-256 |
|---|---|---|
| yaxpeax-arm | 0.5.0 | `79f8d9808ad0b7e434882c66e50704138e7c0bdf3408a9f3159c50603dc3168c` |
| yaxpeax-arch | 0.3.3 | `fb869f86d5a365bf741d9df773f7a5347757b1c466b7383b74989324785ef36b` |
| disarm64 | 0.2.0 | `b40cb278f87c9a57ef6bc51a7b04d4b6097fea24ef50921e8de4a51f06304be0` |
| smda | 0.6.5 | `374fe88e1f8d49797cd9ce32ca320ae0b345b29f40903688394becb6a6bc4070` |

The following line numbers refer to `yaxpeax-arm-0.5.0/src/armv8/a64.rs`, SHA-256 `58ffca1c27c5c4f0f12c2afb1253e4a6f735891746c0d7fa63e997c7262ba0d9`. The audit covers every decoder branch reachable from the predicates, rather than every decoder instruction family.

- Entry at 3253 uses a four-element local buffer and `Reader::next_n`. Section dispatch at 3309 indexes a 16-element table with `section_bits & 15`. Instruction operand indices are fixed 0–3 and arrays have four entries. `Instruction::default` plus `decode_into` preserves no stale instruction on a successful result; the adapter discards errors.
- B/BL, B.cond, CB/TB and register branches enter BranchExceptionSystem at 10287. The group comes from bounded high-bit fields, and each selected case only constructs fixed operands. The register masks fix reserved bits before the BR/BLR/RET switch. NOP takes only the fixed HINT path at 10595. No panic or computed table index is reachable in these selected cases.
- ADR/P, ADD/SUB and wide moves enter DataProcessingImmediate at 8012. Dispatch group is `(word >> 23) & 7`; its fallback `unreachable!` at 8335 is excluded by the eight possible group values. `unreachable!` sites at 8085 and 8220 match `word >> 29`, which is at most 7. ADD shift at 8106 is masked to two bits and the prefilter fixes bit23=0, allowing 0/1. No arithmetic helper for logical immediates is reached. The crate's W-wide-move check uses `hw >= 0x10` despite hw being two bits; this does **not** enforce the ISA's W shift restriction. The prefilter's explicit `hw <= 1` is required and independently checked with reserved mutations.
- ORR enters DataProcessingReg's logical-register path at 7876. The eight-element opcode table index is `(opc | n)`, bounded by 7 and fixed to ORR's index 2 here. `DecodeShift` at 142 asserts `op <= 3` then indexes four entries; this predicate fixes its argument to zero. imm6=0 excludes W shifts beyond its width. Other register-processing paths and their `unreachable!` branches cannot be selected.
- Pair load/stores take LoadStore groups 10001/10010/10011. `opc_L = ((word >> 22) & 1) | ((word >> 29) & 6)` is three bits, specifically 0/1/4/5 for this mask. The fallback `unreachable!` at 8884/8990/9096 cannot be selected. Signed imm7 is −64…63; its i16 scaling remains −512…504 at the largest size. Pair constraints are enforced before decoding, rather than relying on decoder acceptance for constrained-unpredictable overlaps.
- Unsigned integer loads/stores take groups 11010/11011. `size_opc` is four bits (8/9/12/13 here); the fallback `unreachable!` at 9827 is excluded. imm12≤4095, scaled by at most eight, fits i32. All other load/store groups, including SIMD and PAC loads, are excluded.
- `yaxpeax-arch`'s `Decoder::decode` at lib.rs:154 creates a default instruction and calls `decode_into` once. `U8Reader::new` and `next_n` at reader.rs:67/156 operate on the valid four-byte local array. `buf.len() * size_of::<u8>()` is exactly four, the availability check precedes the pointer copy, and advancement remains within the same array. No address-indexed ReaderBuilder or filesystem reader is used. Its unsafe pointer operations do not depend on hostile instruction fields.
- Formatter-only `unreachable!` sites (including 339–642, 2973 and 3132), SIMD helpers, `DecodeBitMasks`/`Ones`, and all other instruction families are outside this call graph. The adapter never invokes Display; its fixed-size instruction/operand equality neither formats nor allocates. The audit deliberately does not bless an unfiltered decoder call.

For disarm64, `decoder_full.rs` SHA-256 is `6115df768d82c33bbd3f53781292f95d6c9e0e0ac7fd2abaa77aac9523213644`. `decode_index` is an acyclic mask/comparison decision tree with no calls, loops, allocation, assertions or array access. The mechanical source audit checks every one of its 3,774 literal successful returns: 0…3773. `decode` checks negative failure before indexing both 3,774-element `INSNS` and `INSN_IDS` arrays. Its two computed accesses are therefore bounded. Definitions and operand/bitfield slices are static; iteration is finite. The adapter validates field extents before shifting and matches a generated `InsnId`, then independently extracts W/X, SP/ZR, displacement, shift and memory-mode semantics from its bits. Its library does not supply that semantic extraction layer itself. No formatting/macro-generated register accessor runs on this path. The audit does not extend to its formatting API or every proc-macro expansion.

## Differential and hostile evidence

The original eight-word smoke passes on both native compilers and both wasm32 compile gates. For `d503233f`, yaxpeax reports `PACIASP`; disarm64 reports `HINT_UIMM7`. This difference is preserved, and the accepted adapter rejects the word for both candidates.

Final deterministic seed is `0x48c0ffee` with xorshift64 shifts 13/7/17. The corpus contains 1,000,000 uniform words, 100,000 structured low-24-bit mutations and 3,289 explicit mask, signed-immediate, width, zero/SP and shift boundary cases: **1,103,289 total**, **179,358 eligible** visits. The actual prefilter, typed comparison and checked-target helper run without recovery under `panic=abort`. Checked-target probes include zero, page boundaries and u64 overflow/underflow; an unaligned PC is rejected. Both candidates report zero errors, zero counted allocations and no process failure. Combined adapter-loop durations were 136 ms on Rust 1.93 and 121 ms on Rust 1.99. Individual Rust 1.93 adapter runs took 85 ms for yaxpeax and 88 ms for disarm64 over the identical corpus, with zero errors/allocations for both. Recorded measurements are in `results.json`. These are local unoptimized wall-clock observations, not portable performance guarantees or full-ISA safety proofs.

The independent oracle unions all 641 Task 1 arm64 instruction rows with eligible hostile words: 178,915 distinct words, of which 178,912 pass the subset and three fixture words are excluded above. Each eligible word is reassembled into an ELF object and decoded independently with LLVM 21.1.8 and GNU binutils 2.46. Both tool outputs have **178,912 rows and zero semantic differences**. Checks include register width/role, raw operation identity, immediate/shift, memory mode/writeback, signed byte displacement, and instruction-PC/page-PC target. GNU's unaliased MOVN/Z/K fields also check raw class/immediate/shift; LLVM still prints some MOV aliases with `no-aliases`, so its effective constant is compared. Original-address comparisons also pass for 625 LLVM and 348 GNU fixture rows. GNU renders 15 relocatable BL words `94000000` using relocation-symbol destinations (for example at PC0x14 it prints `bl 0 <connect>` although the encoded displacement is zero). The oracle records these cases, removes only `.rela.text` metadata in scratch copies, verifies unchanged raw instruction words, and compares GNU's encoded branch destinations at their original PCs. These are tool rendering differences, not decoder semantic mismatches. The oracle corpus SHA-256 is `981c8768f63b928c6ac39af449083b74dc125fc8fa87133e79dedb5d587224d1`. Reserved mutations rejected by the prefilter never reach a candidate. This establishes sampled differential evidence for the classified subset, not oracle agreement for all rejected words.

Rust 1.93.0 is `254b59607d4417e9dffbc307138ae5c86280fe4c` (LLVM 21.1.8); 1.99.0 is `b940084d7eb6a299eb4bfeb8e34901bc051e7ac4` (LLVM 23.1.1). Local `stable` still aliases 1.93, so 1.99 provides the independent newer compiler check. Neither candidate declares an MSRV; successful checks are evidence for these exact graphs, not an upstream promise.

## Candidate/dependency comparison

Both candidates passed the same bounded input/typed semantics gate. Select yaxpeax because it directly exposes opcode and complete typed operands, giving a smaller adapter surface and a smaller graph. Do not silently switch candidates or versions later.

The standalone lockfile pins all registry checksums (SHA-256 `2f89a254c7187466ba58ab20f550b7d4404c320702c25805d1d98e7a47527018`). The selected yaxpeax graph is arm0.5.0, arch0.3.3, bitvec1.1.1, funty2.0.0, radium0.7.0, tap1.0.1, wyz0.5.1, num-traits0.2.19 and its build helper autocfg1.5.1. `std` on arch enables `alloc`; runtime allocation is still absent on the audited paths. Arm defaults (`alloc`, `fmt`, serde, etc.) and arch defaults are disabled. The explicit non-exhaustive-enums feature requires defensive pattern handling in future integration. No loader, target mapping or process-execution package appears in this graph.

The evaluated fallback is `disarm64 = { version = "=0.2.0", default-features = false, features = ["full"] }`. Its generated decoder source is about 3.6 MiB. Its graph adds disarm64_defn0.2.0, bitfield-struct0.13.0, bitflags2.13.2, serde/serde_core/serde_derive1.0.229, strum/strum_macros0.28.0, heck0.5.0, proc-macro2 1.0.107, quote1.0.47, syn2.0.119 and syn3.0.9, and unicode-ident1.0.27. The matching `InsnId` plus raw extractor in this harness is necessary because static operand definitions do not supply validated transfer semantics. It is a viable bounded comparison candidate for this subset, with more extraction and dependency review work.

Reject smda0.6.5 for this milestone: its manifest declares Rust 1.95, above the 1.93 floor, and uses disarm64 0.1 rather than this evaluated 0.2.0 graph. Its whole-image loaders/CFG do not establish SIGIL's charged same-fd query-only contract. No smda execution or same-fd integration was attempted or accepted.

No project dependency or product lockfile changed. The `cargo deny` command was initially unavailable; a pinned standalone cargo-deny0.20.2 binary was subsequently supplied by the controller for later integration. No product bans check is claimed in this Task 2 research gate. Task 7/M3-B must resolve the actual product graph, review its differences, commit the product lockfile, then run the exact 1.93/current-stable engine checks and `cargo deny check bans`. This technical gate does not waive those integration checks.

## Unwind decision and evidence limits

Keep the existing `gimli = =0.34.0` read/std configuration for bounded FDE parsing. A validated FDE records an exact half-open interval. The accepted object fixture's relocated compact entries independently supply lengths; native linked compact lookup boundaries supply no individual function lengths.

The [pinned LLVM header](https://github.com/llvm/llvm-project/blob/llvmorg-21.1.8/libunwind/include/mach-o/compact_unwind_encoding.h) defines pointer-sized object addresses with 32-bit length/encoding (32 bytes per 64-bit entry). Linked pages use kind2 regular address/encoding pairs or kind3 compressed entries, whose low24 bits are a page-base delta and high8 bits index common/local encodings. ARM64 DWARF mode is `0x03000000`; x86-64 uses `0x04000000`, with low24 bits relative to `__eh_frame`. The same numeric `0x04000000` is native ARM64 frame mode, so architecture is mandatory. Header SHA-256: `06f58e9d0058583b6da91ca2328fa663f80d089496a4979754ee7608fe9bd877`.

The [pinned LLD writer](https://github.com/llvm/llvm-project/blob/llvmorg-21.1.8/lld/MachO/UnwindInfoSection.cpp) folds adjacent compatible encodings and omits intervening starts; the final sentinel covers the final lookup range. It can replace an oversized FDE offset hint with zero. SIGIL's stricter rule must validate an actual FDE record at the encoded offset and matching function start; runtime fallback searching cannot justify a guessed interval. Writer SHA-256: `6878f7e98aed118613370ceadb8cb73fd0021af60defb1cadc5a966f85ad6365`.

Observed fixture evidence establishes these exact distinctions:

| Source | Accepted interval or gap |
|---|---|
| `code-macho/compact-object.o` | Two native ARM64 frame encodings, each explicit length0x24, with unique ARM64_RELOC_UNSIGNED non-PC-relative 8-byte local relocations to executable `__text`, checked function symbols and bounds. Section-relative `[0,0x24)` and `[0x24,0x48)` translate to artifact-file `[0x188,0x1ac)` and `[0x1ac,0x1d0)`. No FDE is retained. These are exact object intervals, not inferred adjacent-symbol lengths. |
| `code-macho/arm64-classic` | DWARF entries `0x03000014` and `0x03000048` point to FDE offsets0x14/0x48, independently recording `[0x520,0x544)` and `[0x544,0x568)`. Each start agrees with its compact entry and executable mapping. |
| `code-macho/unwind-folded` | Real linked compressed page contains one native entry at0x4c0 and sentinel0x508 although `_one` starts at0x4e4. No FDE or LC_FUNCTION_STARTS exists. Exact function intervals remain absent; emit missing-exact-bounds gaps. `[0x4c0,0x508)` is only a lookup span. |
| Research regular-page derivative | Change only the folded fixture's second-level representation to kind2; LLVM reads the same0x4c0/0x04000000 pair. This is synthetic regular-page evidence, not a claim that Task 1's linker emitted a regular page. It still supplies no function extent. |
| Research compressed-local derivative | The same entry is represented by an index after the common array into one local encoding. LLVM and the research reader agree. It still supplies no exact extent. |

The research reader rejects 15 malformed header/count/extent/kind/encoding-index/delta/truncation cases. Task 1's separate oracle regression passed ten originals and rejected seventeen actual binary mutations, including invalid compact relocation target, width, PC-relative/external/type bits, relocation position/duplication, oversized lengths and nonfunction starts. These are metadata validation evidence, not production parser tests. Later M3-C must add charged bounds checks, overlaps, FDE parsing failures and all malformed-session cases to its actual reader; it must never infer exact function lengths from compact adjacency, sentinels, symbols or LC_FUNCTION_STARTS alone. Native linked compact-only support remains partial unless a separately recorded exact extent exists.
