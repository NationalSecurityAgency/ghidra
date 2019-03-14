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
package ghidra.program.model.lang;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.util.InstructionUtils;
import ghidra.util.Msg;

public class InstructionError {

	private InstructionBlock block;
	private InstructionErrorType type;
	private Address conflictAddress; // address of other code unit which conflicts with new instruction (only applies to CODE_UNIT or DUPLICATE conflict error only)
	private Address instructionAddress; // address of intended instruction which failed to be created
	private RegisterValue parseContext; // disassembly context at intendedInstructionAddress (applies to PARSE error only)
	private Address flowFromAddress; // flow-from address (null if unknown)
	private String message;

	public enum InstructionErrorType {

		/**
		 * Duplicate instruction detected 
		 * while instructions were being added to program.
		 * This should not be marked but should prevent additional
		 * instructions from being added unnecessarily.
		 */
		DUPLICATE(true),

		/**
		 * Conflict with existing instruction detected 
		 * while instructions were being added to program.
		 * Conflict address corresponds to existing code unit.
		 * The first instruction within the block whose range
		 * overlaps the conflict code-unit should terminate the
		 * block prior to being added.
		 */
		INSTRUCTION_CONFLICT(true),

		/**
		 * Conflict with existing data detected 
		 * while instructions were being added to program.
		 * Conflict address corresponds to existing code unit.
		 * The first instruction within the block whose range
		 * overlaps the conflict code-unit should terminate the
		 * block prior to being added.
		 */
		DATA_CONFLICT(true),

		/**
		 * Offcut conflict with existing instruction detected 
		 * while instructions were being added to program.
		 * Conflict address corresponds to existing code unit.
		 * The first instruction within the block whose range
		 * overlaps the conflict code-unit should terminate the
		 * block prior to being added.
		 */
		OFFCUT_INSTRUCTION(true),

		/**
		 * Instruction parsing failed at the conflict address.
		 * This conflict should only have a conflict address which 
		 * immediately follows the last instruction within the 
		 * block or matches the block-start if the block is empty.
		 */
		PARSE(false),

		/**
		 * Instruction parsing failed at the conflict address due
		 * to a memory error.
		 * This conflict should only have a conflict address which 
		 * immediately follows the last instruction within the 
		 * block or matches the block-start if the block is empty.
		 */
		MEMORY(false),

		/**
		 * Instruction contains an unaligned flow which is indicative
		 * of a language problem.  The conflict address corresponds to the 
		 * instruction containing the flow.  While the instruction at the 
		 * conflict address may be added it should be the last.
		 */
		FLOW_ALIGNMENT(false);

		/**
		 * Instruction error associated with a conflict with an existing
		 * code unit (instruction or data).
		 */
		public final boolean isConflict;

		InstructionErrorType(boolean isConflict) {
			this.isConflict = isConflict;
		}

	}

	/**
	 * Construct an instruction error/conflict
	 * @param block instruction block which corresponds to this error
	 * @param type type of instruction error/conflict
	 * @param instructionAddress address of new intended instruction which failed to be created
	 * @param conflictAddress address of another code unit which conflicts with new intended instruction
	 * @param flowFromAddress flow from address
	 * @param message
	 */
	InstructionError(InstructionBlock block, InstructionErrorType type, Address instructionAddress,
			Address conflictAddress, Address flowFromAddress, String message) {
		this.block = block;
		this.type = type;
		this.instructionAddress = instructionAddress;
		this.conflictAddress = conflictAddress;
		this.flowFromAddress = flowFromAddress;
		this.message = message;
	}

	/**
	 * Construct PARSE error
	 * @param block instruction block which corresponds to this error
	 * @param contextValue disassembler context used during instruction parse
	 * @param instructionAddress address of new intended instruction which failed to be created
	 * @param flowFromAddress flow from address
	 * @param message
	 */
	InstructionError(InstructionBlock block, RegisterValue contextValue,
			Address instructionAddress, Address flowFromAddress, String message) {
		this.block = block;
		this.type = InstructionErrorType.PARSE;
		this.parseContext = contextValue;
		this.instructionAddress = instructionAddress;
		this.flowFromAddress = flowFromAddress;
		this.message = message;
	}

	/**
	 * @return instruction block which corresponds to this error
	 */
	public InstructionBlock getInstructionBlock() {
		return block;
	}

	/**
	 * @return type of instruction error
	 */
	public InstructionErrorType getInstructionErrorType() {
		return type;
	}

	public boolean isInstructionConflict() {
		return (type == InstructionErrorType.OFFCUT_INSTRUCTION) ||
			(type == InstructionErrorType.INSTRUCTION_CONFLICT);
	}

	public boolean isOffcutError() {
		return type == InstructionErrorType.OFFCUT_INSTRUCTION;
	}

	/**
	 * @return address of new intended instruction which failed to be created (never null)
	 */
	public Address getInstructionAddress() {
		return instructionAddress;
	}

	/**
	 * @return address of another code unit which conflicts
	 * with intended instruction (required for CODE_UNIT 
	 * and DUPLCIATE errors, null for others)
	 */
	public Address getConflictAddress() {
		return conflictAddress;
	}

	/**
	 * @return disassembler context at intended instruction
	 * address (required for PARSE error, null for others)
	 */
	public RegisterValue getParseContextValue() {
		return parseContext;
	}

	/**
	 * @return flow-from address if know else null
	 */
	public Address getFlowFromAddress() {
		return flowFromAddress;
	}

	/**
	 * @return instruction error message
	 */
	public String getConflictMessage() {
		return message;
	}

	public static void dumpInstructionDifference(Instruction newInst, Instruction existingInstr) {
		StringBuilder buf =
			new StringBuilder("Instruction conflict details at " + newInst.getAddress());
		buf.append("\n  New Instruction: ");
		buf.append(getInstructionDetails(newInst));
		buf.append("\n  Existing Instruction: ");
		buf.append(getInstructionDetails(existingInstr));
		Msg.debug(InstructionError.class, buf.toString());
	}

	private static String getInstructionDetails(Instruction instr) {
		StringBuilder buf = new StringBuilder();
		buf.append(instr.toString());
		buf.append("\n");
		buf.append(InstructionUtils.getFormattedContextRegisterValueBreakout(instr, "     "));
		return buf.toString();
	}

}
