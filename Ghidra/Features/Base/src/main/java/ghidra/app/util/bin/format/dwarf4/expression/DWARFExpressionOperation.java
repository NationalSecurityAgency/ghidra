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
package ghidra.app.util.bin.format.dwarf4.expression;

import java.util.Arrays;

/**
 * An immutable representation of a single {@link DWARFExpression} instruction and its operands.
 * <p>
 * A DWARF expression operation can take 0, 1, or 2 operands.
 * <p>
 */
class DWARFExpressionOperation {
	protected final int offset;
	protected final int opcode;
	protected final DWARFExpressionOperandType[] operandTypes;
	protected final long operands[];
	protected final byte[] blob;

	/**
	 * Create a new DWARF expression opcode element.
	 *
	 * @param opcode numeric value of the opcode, ie. DW_OP_not from {@link DWARFExpressionOpCodes}
	 * @param operandTypes 'datatype' of the operands
	 * @param operands value of the operands, pre-converted into longs.
	 * @param blob if an operand is a byte array (ie. for DW_OP_implicit_value), this is the bytes
	 * @param offset byte offset of this operation from the start of the DWARF expression.
	 */
	public DWARFExpressionOperation(int opcode, DWARFExpressionOperandType[] operandTypes,
			long[] operands, byte[] blob, int offset) {
		this.opcode = opcode;
		this.operandTypes = operandTypes;
		this.operands = operands;
		this.blob = blob;
		this.offset = offset;
	}

	/**
	 * See {@link DWARFExpressionOpCodes} for list of opcodes.
	 * @return
	 */
	public int getOpCode() {
		return opcode;
	}

	/**
	 * Get the operand value.
	 *
	 * @param opindex which operand to fetch.
	 * @return value of operand as a long.
	 */
	public long getOperandValue(int opindex) {
		return operands[opindex];
	}

	/**
	 * Calculates the relative opcode number of this opcode, as compared to a base opcode.
	 * <p>
	 * Ie. If this opcode was DW_OP_reg12 (0x5c), and the base op code was DW_OP_reg0 (0x50),
	 * the result value would be 12.
	 * <p>
	 * @param baseOpCode Ordinal value of the opcode that this opcode is being compared ot.
	 * @return numeric difference between this opcode and the base opcode.
	 */
	public int getRelativeOpCodeOffset(int baseOpCode) {
		return opcode - baseOpCode;
	}

	/**
	 * Return the byte array that contains the bytes of the blob operand.
	 *
	 * @return byte array
	 */
	public byte[] getBlob() {
		return blob;
	}

	/**
	 * The offset of this opcode, relative to the start of the {@link DWARFExpression}.
	 * @return
	 */
	public int getOffset() {
		return offset;
	}

	@Override
	public String toString() {
		return DWARFExpressionOpCodes.toString(opcode) + " " + Arrays.toString(operands);
	}
}
