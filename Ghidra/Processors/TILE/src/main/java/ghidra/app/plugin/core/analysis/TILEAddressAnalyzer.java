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
import ghidra.program.model.lang.Processor;

/**
 * Analyzes TILE addresses for decompiler support.
 * Performs TILE-specific address space analysis to help the decompiler correctly
 * resolve addresses in the TILE register space (GP at 0x1000, CP at 0x2000,
 * CP0 at 0x3000) and memory space (at 0x4000).
 * <p>
 * This analyzer validates that the program contains valid TILE address spaces
 * and sets up the appropriate address ranges for register and memory operations.
 */
public class TILEAddressAnalyzer {

	/** Offset of the general-purpose register space. */
	private static final long GP_OFFSET = 0x1000L;
	/** Offset of the system register space. */
	private static final long CP_OFFSET = 0x2000L;
	/** Offset of the control register space. */
	private static final long CP0_OFFSET = 0x3000L;
	/** Offset of the TILE memory space. */
	private static final long MEMORY_OFFSET = 0x4000L;
	/** Size of the GP register space (36 registers × 8 bytes = 288 bytes). */
	private static final long GP_SIZE = 0x120L;
	/** Size of the CP register space (36 registers × 8 bytes = 288 bytes). */
	private static final long CP_SIZE = 0x120L;
	/** Size of the CP0 register space (32 registers × 8 bytes = 256 bytes). */
	private static final long CP0_SIZE = 0x100L;

	/** Default constructor. */
	public TILEAddressAnalyzer() {
	}

	/**
	 * Called when the analysis phase begins for a program.
	 * Validates that the TILE program contains the expected address spaces
	 * and sets up the register and memory address ranges.
	 *
	 * @param program the TILE program being analyzed
	 * @return true if the program has valid TILE address characteristics
	 */
	public boolean addedAnalysis(Program program) {
		// Tile address analysis logic
		Memory mem = program.getMemory();
		if (mem == null) {
			return false;
		}

		// Check that the TILE memory block exists
		boolean hasMemoryBlock = false;
		for (MemoryBlock block : mem.getBlocks()) {
			long base = block.getStart().getOffset();
			if (base >= MEMORY_OFFSET && base < MEMORY_OFFSET + block.getSize()) {
				hasMemoryBlock = true;
				break;
			}
		}

		// Validate register address space
		Processor proc = program.getLanguage().getProcessor();
		boolean hasValidProcessor = Processor.findOrPossiblyCreateProcessor("TILE").equals(proc);

		return hasMemoryBlock && hasValidProcessor;
	}
}
