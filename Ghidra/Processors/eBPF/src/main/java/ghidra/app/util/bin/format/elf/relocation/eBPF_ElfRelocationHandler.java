/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.util.bin.format.elf.relocation;

import ghidra.app.util.bin.format.elf.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationResult;

public class eBPF_ElfRelocationHandler
		extends AbstractElfRelocationHandler<eBPF_ElfRelocationType, ElfRelocationContext<?>> {

	/**
	 * Constructor
	 */
	public eBPF_ElfRelocationHandler() {
		super(eBPF_ElfRelocationType.class);
	}

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_BPF;
	}

	@Override
	protected RelocationResult relocate(ElfRelocationContext<?> elfRelocationContext,
			ElfRelocation relocation, eBPF_ElfRelocationType type, Address relocationAddress,
			ElfSymbol symbol, Address symbolAddr, long symbolValue, String symbolName)
			throws MemoryAccessException {

		Program program = elfRelocationContext.getProgram();
		Memory memory = program.getMemory();

		// eBPF ELF files are using Elf64_Rel (not Elf64_Rela) so addend must be extracted.
		// If this changes in the future, proper support for addend should be added.
		if (!elfRelocationContext.extractAddend() || relocation.getAddend() != 0) {
			return RelocationResult.FAILURE;
		}

		long addend;
		long newValue;
		int byteLength;

		// Handle relative relocations that do not require symbolAddr or symbolValue
		switch (type) {
			case R_BPF_64_RELATIVE:
				// R_BPF_64_RELATIVE does not exist in Linux's libbpf but was introduced in a LLVM fork:
				// https://github.com/anza-xyz/llvm-project/blob/bpf-tools-v1.2/llvm/include/llvm/BinaryFormat/ELFRelocs/BPF.def#L8
				// https://github.com/anza-xyz/llvm-project/blob/bpf-tools-v1.2/lld/ELF/Arch/BPF.cpp#L38
				if (memory.getBlock(relocationAddress).isExecute()) {
					if (memory.getByte(relocationAddress) == 0x18) {
						// Adjust the value of instruction LDDW by program base
						addend = getLddwImm64(memory, relocationAddress);
						newValue = elfRelocationContext.getImageBaseWordAdjustmentOffset() + addend;
						setLddwImm64(memory, relocationAddress, newValue);
						byteLength = 16;
					}
					else {
						return RelocationResult.UNSUPPORTED;
					}
				}
				else {
					// Adjust a pointer value in a non-executable section by program base
					addend = memory.getLong(relocationAddress);
					if ((addend & 0xffffffffL) == 0) {
						// A known bug in a LLVM fork made the compiler produce data relocations shifted by 32 bits:
						// https://github.com/anza-xyz/llvm-project/pull/35
						// (https://github.com/anza-xyz/llvm-project/commit/fb7188bcf651fdaa2d2c522f4b7444e2c574a822).
						// For more details, cf. this comment in the relevant eBPF virtual machine:
						// https://github.com/solana-labs/rbpf/blob/v0.8.5/src/elf.rs#L1061-L1070
						// This assumes R_BPF_64_RELATIVE relocations do not use addend above 4GB.
						addend = (addend >> 32) & 0xffffffffL;
					}
					newValue = elfRelocationContext.getImageBaseWordAdjustmentOffset() + addend;
					memory.setLong(relocationAddress, newValue);
					byteLength = 8;
				}
				return new RelocationResult(Status.APPLIED, byteLength);
			default:
				break;
		}

		// Check for unresolved symbolAddr and symbolValue required by remaining relocation types handled below
		if (handleUnresolvedSymbol(elfRelocationContext, relocation, relocationAddress)) {
			return RelocationResult.FAILURE;
		}

		switch (type) {
			case R_BPF_64_64: {
				if (memory.getBlock(relocationAddress).isExecute()) {
					if (memory.getByte(relocationAddress) == 0x18) {
						// Relocate the symbol used by instruction LDDW
						// (instructions start with an opcode byte, in both Big Endian and Little Endian encodings)
						addend = getLddwImm64(memory, relocationAddress);
						newValue = symbolValue + addend;
						setLddwImm64(memory, relocationAddress, newValue);
						byteLength = 16;

						String blockName = memory.getBlock(symbolAddr).getName();
						if (blockName.equals(".maps") || blockName.startsWith("maps")) {
							// libbpf loader transforms LDDW instructions targeting section .maps (MAPS_ELF_SEC) to use src=BPF_PSEUDO_MAP_FD
							// cf. https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/lib/bpf/libbpf.c?h=v6.16#n6106
							// Legacy maps (without BTF) used dedicated sections starting with "maps". For example:
							// https://github.com/vbpf/ebpf-samples/blob/65b12c682368e4030a683f60b959ff6b5f3b3d6e/src/map_in_map_legacy.c#L19
							// More documentation is available on https://docs.ebpf.io/linux/concepts/maps/#legacy-maps
							byte src_dst = memory.getByte(relocationAddress.add(0x1));
							if (memory.isBigEndian()) {
								src_dst = (byte) ((src_dst & 0xf0) | 1);
							}
							else {
								src_dst = (byte) ((src_dst & 0x0f) | 0x10);
							}
							memory.setByte(relocationAddress.add(0x1), src_dst);
						}
					}
					else {
						return RelocationResult.UNSUPPORTED;
					}
				}
				else {
					// Relocate a pointer to symbol in a non-executable section.
					// Using R_BPF_64_64 for such relocations was actually a bug in a LLVM fork, fixed in
					// https://github.com/anza-xyz/llvm-project/pull/35
					// (https://github.com/anza-xyz/llvm-project/commit/fb7188bcf651fdaa2d2c522f4b7444e2c574a822)
					addend = memory.getLong(relocationAddress);
					newValue = symbolValue + addend;
					memory.setLong(relocationAddress, newValue);
					byteLength = 8;
				}
				break;
			}
			case R_BPF_64_ABS64: {
				// Relocate 64-bit addresses
				addend = memory.getLong(relocationAddress);
				newValue = symbolValue + addend;
				memory.setLong(relocationAddress, newValue);
				byteLength = 8;
				break;
			}
			case R_BPF_64_ABS32:
			case R_BPF_64_NODYLD32: {
				// Relocate 32-bit addresses
				// Relocate R_BPF_64_NODYLD32 too. This relocation type is used in sections .BTF and .BTF.ext.
				addend = memory.getInt(relocationAddress);
				newValue = symbolValue + addend;
				memory.setInt(relocationAddress, (int) newValue);
				byteLength = 4;
				break;
			}
			case R_BPF_64_32: {
				if (memory.getBlock(relocationAddress).isExecute()) {
					// Relocate the 32-bit displacement offset used by internal CALL.
					// Linux kernel documents the formula in
					// https://www.kernel.org/doc/html/v6.14/bpf/llvm_reloc.html#different-relocation-types
					// (S + A) / 8 - 1
					// To understand this formula:
					// - The immediate operand of instruction CALL, called offset, encodes the number of 8-byte instructions from the end of the instruction (inst_next)
					// - To call a function at address S + A, the offset is (S + A - inst_next) / 8
					// - As inst_next = inst + 8, offset = (S + A - inst) / 8 - 1.
					//
					// As using inst_next is easier to understand than using the relocation address (inst), the code here uses (S + A - inst_next) / 8.
					// The addend A is computed by decoding the existing offset of instruction CALL.
					// Compilers usually write "-1" (the instruction bytes are 85 10 00 00 FF FF FF FF), to encode an instruction which calls itself.
					// This offset is decoded as A = 0.
					// If the encoded offset was -1 + value, the addend would be A = value * 8
					// Therefore A = (encoded_offset + 1) * 8.
					//
					// By the way, memory.getInt and memory.setInt respect the endianness of the processor.
					// This enables to support Little Endian and Big Endian eBPF at the same time.
					long inst_next = relocationAddress.add(0x8).getAddressableWordOffset();
					addend = (((long) memory.getInt(relocationAddress.add(0x4))) + 1) * 8;
					int offset = (int) ((symbolValue + addend - inst_next) / 8);
					memory.setInt(relocationAddress.add(0x4), offset);
					byteLength = 8;
				}
				else {
					return RelocationResult.UNSUPPORTED;
				}
				break;
			}
			default: {
// TODO: it may be appropriate to bookmark unsupported relocations
// Relocation treatment for .BTF sections may differ
//    			markAsUnhandled(program, relocationAddress, type, relocation.getSymbolIndex(), 
//	    		symbolName, elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;
			}
		}
		return new RelocationResult(Status.APPLIED, byteLength);
	}

	/**
	 * Get the 64-bit immediate value of eBPF instruction LDDW
	 *
	 * @param memory memory
	 * @param addr   address in memory
	 * @return value from memory as a long
	 * @throws MemoryAccessException if memory access failed
	 */
	private long getLddwImm64(Memory memory, Address addr) throws MemoryAccessException {
		return (((long) memory.getInt(addr.add(0x4))) & 0xffffffffL) +
			(((long) memory.getInt(addr.add(0xC))) << 32);
	}

	/**
	 * Set the 64-bit immediate value of eBPF instruction LDDW
	 *
	 * @param memory memory
	 * @param addr   address in memory
	 * @param value  value
	 * @throws MemoryAccessException if memory access failed
	 */
	private void setLddwImm64(Memory memory, Address addr, long value)
			throws MemoryAccessException {
		memory.setInt(addr.add(0x4), (int) value);
		memory.setInt(addr.add(0xC), (int) (value >> 32));
	}
}
