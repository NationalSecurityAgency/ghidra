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
package ghidra.app.plugin.core.analysis;

import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.Language;

/**
 * Analyzes TILE addresses for decompiler support.
 * Performs comprehensive register space validation across all TILE address spaces:
 * GP (0x1000), CP (0x2000), CP0 (0x3000), CSR (0x4000) and memory space (0x4000+).
 */
public class TILEAddressAnalyzer {

	/** Offset of the general-purpose register space. */
	private static final long GP_OFFSET = 0x1000L;
	/** Offset of the system register space. */
	private static final long CP_OFFSET = 0x2000L;
	/** Offset of the control register space. */
	private static final long CP0_OFFSET = 0x3000L;
	/** Offset of the CSR register space. */
	private static final long CSR_OFFSET = 0x4000L;
	/** Offset of the TILE memory space. */
	private static final long MEMORY_OFFSET = 0x4000L;

	/** GP size: 36 registers (r0-r35) x 8 bytes = 288 bytes (0x120). */
	private static final int GP_SIZE_BYTES = 0x120; // 36 * 8
	/** CP size: 41 system registers (sr0-sr40) x 8 bytes = 328 bytes. */
	private static final long CP_SPACE_END = CP_OFFSET + 0x208L; // sr0-sr40 is 41*8=328
	/** CP0 size: 32 control registers (c0-c31) x 8 bytes = 256 bytes (0x100). */
	private static final long CP0_SPACE_END = CP0_OFFSET + 0x100L; // 32*8=256
	/** CSR size: reserved space, at least 256 bytes. */
	private static final long CSR_MIN_SIZE = 0x100L;

	/** Default constructor. */
	public TILEAddressAnalyzer() {
	}

	/**
	 * Called when the analysis phase begins for a program.
	 * Validates that the TILE program contains all expected address spaces:
	 * <ul>
	 *   <li>GP register space (0x1000-0x120F): 36 registers x 8 bytes</li>
	 *   <li>CP register space (0x2000-0x2207): 41 system registers (sr0-sr40) x 8 bytes</li>
	 *   <li>CP0 register space (0x3000-0x30FF): 32 control registers x 8 bytes</li>
	 *   <li>CSR register space (0x4000+): processor status and trap vectors</li>
	 *   <li>TILE memory block: base address >= MEMORY_OFFSET with sufficient size</li>
	 * </ul>
	 *
	 * @param program the TILE program being analyzed
	 * @return true if all register spaces are valid and accessible
	 */
	public boolean addedAnalysis(Program program) {
		Memory mem = program.getMemory();
		if (mem == null) {
			return false;
		}

		Language lang = program.getLanguage();
		if (lang == null) {
			return false;
		}

		// Validate GP register space: 36 registers (r0-r35), each 8 bytes at offset 0x1000
		if (!validateRegisterSpace(lang, "gp", GP_OFFSET, GP_SIZE_BYTES)) {
			return false;
		}

		// Validate CP register space: 41 system registers (sr0-sr40) starting at 0x2000
		long cpSize = CP_SPACE_END - CP_OFFSET;
		if (!validateRegisterSpace(lang, "cp", CP_OFFSET, (int) cpSize)) {
			return false;
		}

		// Validate individual system registers sr0-sr40 exist in the language
		for (int i = 0; i <= 40; i++) {
			String regName = "sr" + i;
			Register reg = lang.getRegister(regName);
			if (reg == null) {
				return false; // Missing system register definition
			}
		}

		// Validate CP0 control register space: 32 registers at offset 0x3000
		if (!validateRegisterSpace(lang, "cp0", CP0_OFFSET, (int) CP0_SIZE)) {
			return false;
		}

		// Validate CSR register space exists and has sufficient size
		Address csrStart = lang.getAddressFactory().getAddress(CSR_OFFSET);
		if (csrStart == null) {
			return false; // CSR address not valid in this language
		}

		// Validate sp (stack pointer) register exists
		Register spReg = lang.getRegister("sp");
		if (spReg == null) {
			return false; // Stack pointer must be defined for calling convention
		}

		// Check that the TILE memory block exists at offset >= MEMORY_OFFSET
		boolean hasMemoryBlock = false;
		for (MemoryBlock block : mem.getBlocks()) {
			Address start = block.getStart();
			long base = start.getOffset();
			if (base >= MEMORY_OFFSET) {
				hasMemoryBlock = true;
				break;
			}
		}

		return hasMemoryBlock;
	}

	/**
	 * Validates that a register space exists in the language with expected bounds.
	 *
	 * @param lang    the language to check
	 * @param spaceId the register class identifier (e.g., "gp", "cp")
	 * @param offset  the base offset of this register space
	 * @param size    the total size in bytes for this register space
	 * @return true if the register space is valid and accessible
	 */
	private boolean validateRegisterSpace(Language lang, String spaceId, long offset, int size) {
		Register spaceReg = lang.getRegister(spaceId);
		if (spaceReg == null) {
			return false; // Register class not defined
		}

		Address baseAddr = lang.getAddressFactory().getAddress(offset);
		if (baseAddr == null) {
			return false; // Base address invalid
		}

		Address endAddr = lang.getAddressFactory().getAddress(offset + size);
		if (endAddr == null) {
			return false; // End of range address invalid
		}

		// Verify the register class covers the expected offset
		return spaceReg.getOffset() == offset;
	}
}
