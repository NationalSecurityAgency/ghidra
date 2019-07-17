/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.app.util.opinion.ElfLoader;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;

public class ElfScalarOperandAnalyzer extends ScalarOperandAnalyzer {
	private static final String NAME = "ELF Scalar Operand References";
	private static final String DESCRIPTION =
		"For ELF shared objects (.so) files that are based at zero, "
			+ "offsets relative to the .got offsets appear to be valid addresses "
			+ "and therefore invalid memory references get created by the analyzer. "
			+ "This analyzer will remove those bad references.";

	public ElfScalarOperandAnalyzer() {
		super(NAME, DESCRIPTION);
	}

	@Override
	public boolean canAnalyze(Program program) {
		boolean elf = isELF(program);

		return elf;
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		if (!isELF(program)) {
			return false;
		}
		return getDefaultEnablement2(program);
	}

	/**
	 * 1) If the instruction's min address plus the scalar equals 
	 *    an address inside the ".got" section, then the scalar 
	 *    is NOT an address and a reference should not be created.
	 * 
	 * 2) If the instruction is a push and it's min address is inside the ".plt"
	 *    section, then the scalar is not a memory reference.
	 */
	@Override
	protected boolean addReference(Program program, Instruction instr, int opIndex,
			AddressSpace space, Scalar scalar) {
		if (program.getExecutableFormat().equals(ElfLoader.ELF_NAME)) {
			if (instr.getMnemonicString().equalsIgnoreCase("add")) {
				try {
					Address gotAddr = instr.getMinAddress().add(scalar.getUnsignedValue());
					MemoryBlock block = program.getMemory().getBlock(gotAddr);
					if (block != null) {
						if (block.getName().indexOf(".got") >= 0) {
							return false;
						}
					}
				}
				catch (AddressOutOfBoundsException e) {
				}
			}
			else if (instr.getMnemonicString().equalsIgnoreCase("push")) {
				MemoryBlock block = program.getMemory().getBlock(instr.getMinAddress());
				if (block.getName().indexOf(".plt") >= 0) {
					return false;
				}
			}
		}
		return super.addReference(program, instr, opIndex, space, scalar);
	}
}
