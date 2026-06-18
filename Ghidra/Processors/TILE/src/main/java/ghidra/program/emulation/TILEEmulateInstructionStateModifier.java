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
package ghidra.program.emulation;

import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.pcode.emulate.EmulateInstructionStateModifier;
import ghidra.pcode.emulate.Emulate;
import ghidra.program.model.lang.Language;

/**
 * TILE instruction state modifier for instruction emulation.
 * Initializes TILE-specific register state before emulation begins.
 * Sets up the program counter, stack pointer, and context register
 * based on the TILE architecture specification.
 *
 * @suppressWarnings deprecation Uses the deprecated {@link Emulate} class
 *                     which is retained for compatibility with
 *                     EmulateInstructionStateModifier's callback contract.
 */
@SuppressWarnings("deprecation")
public class TILEEmulateInstructionStateModifier {

	/** TILE general-purpose register class offset. */
	private static final long GP_OFFSET = 0x1000;
	/** TILE system register class offset. */
	private static final long CP_OFFSET = 0x2000;
	/** TILE control register class offset. */
	private static final long CP0_OFFSET = 0x3000;
	/** Default stack pointer value for TILE emulation. */
	private static final long DEFAULT_SP = 0x8000;

	private Emulate emulate;

	/**
	 * Constructs a TILEEmulateInstructionStateModifier.
	 * @param emu the Emulate instance to modify state for
	 */
	public TILEEmulateInstructionStateModifier(Emulate emu) {
		this.emulate = emu;
	}

	/**
	 * Returns the underlying Emulate instance.
	 * @return the Emulate object used for register and memory access during emulation
	 */
	public Emulate getEmulate() {
		return emulate;
	}

	/**
	 * Applies TILE-Gx specific initial register state for emulation.
	 * Sets the initial values for the TILE register classes:
	 * - GP (general-purpose) at offset 0x1000
	 * - CP (system registers) at offset 0x2000
	 * - CP0 (control registers) at offset 0x3000
	 * - Stack pointer initialized to DEFAULT_SP (0x8000)
	 * - Context register initialized for single-context mode
	 *
	 * @param program the TILE program to initialize state for
	 */
	public void apply(Program program) {
		// Tile-Gx specific state setup
		Register spReg = program.getLanguage().getRegister("sp");
		if (spReg != null) {
			emulate.getMemoryState().setValue(spReg, DEFAULT_SP);
		}

		Register ctxReg = program.getLanguage().getRegister("ctx");
		if (ctxReg != null) {
			emulate.getMemoryState().setValue(ctxReg, 0L);
		}

		Register pcReg = program.getLanguage().getRegister("pc");
		if (pcReg != null) {
			Address pc = emulate == null ? program.getImageBase() : emulate.getExecuteAddress();
			if (pc != null) {
				emulate.getMemoryState().setValue(pcReg, pc.getOffset());
			}
		}
	}

	public boolean isApplicable(Program program) {
		Processor p = program.getLanguage().getProcessor();
		return p == Processor.findOrPossiblyCreateProcessor("TILE");
	}
}
