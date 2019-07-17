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
package ghidra.app.util.disassemble;

/**
 * Holds the disassembled string of an instruction and the extra information
 * (type, number of bytes disassembled to produce instruction, etc.) of bytes
 * disassembled by the GNU disassembler.
 */
public class GnuDisassembledInstruction {

	private final String instruction;
	private final int bytesInInstruction;

	private final int branchDelayInstructions;
	private final int dataSize;
	private final DIS_INSN_TYPE instructionType;
	private final boolean isValid;

	// from GNU binutils include/dis-asm.h
	enum DIS_INSN_TYPE {
		dis_noninsn, /* Not a valid instruction. */
		dis_nonbranch, /* Not a branch instruction. */
		dis_branch, /* Unconditional branch. */
		dis_condbranch, /* Conditional branch. */
		dis_jsr, /* Jump to subroutine. */
		dis_condjsr, /* Conditional jump to subroutine. */
		dis_dref, /* Data reference instruction. */
		dis_dref2 /* Two data references in instruction. */
	}

	public GnuDisassembledInstruction(String instructionLine, int bytesInInstruction,
			boolean isValid, int branchDelayInstructions, int dataSize, int disInsnTypeOrdinal) {

		this.instruction = instructionLine.trim();
		this.bytesInInstruction = bytesInInstruction;

		this.isValid = isValid;
		this.branchDelayInstructions = branchDelayInstructions;
		this.dataSize = dataSize;
		this.instructionType = DIS_INSN_TYPE.values()[disInsnTypeOrdinal];
	}

	public int getNumberOfBytesInInstruction() {
		return bytesInInstruction;
	}

	public DIS_INSN_TYPE getInstructionType() {
		return isValid ? instructionType : null;
	}

	public int getBranchDelayInstructions() {
		return isValid ? branchDelayInstructions : null;
	}

	public int getDataSize() {
		return isValid ? dataSize : null;
	}

	public String getInstruction() {
		return instruction;
	}

	@Override
	public String toString() {
		return instruction;
	}

}
