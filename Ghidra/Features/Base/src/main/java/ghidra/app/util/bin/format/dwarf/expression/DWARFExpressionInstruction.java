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
package ghidra.app.util.bin.format.dwarf.expression;

import static ghidra.app.util.bin.format.dwarf.expression.DWARFExpressionOpCode.*;
import static ghidra.app.util.bin.format.dwarf.expression.DWARFExpressionOperandType.*;

import java.io.IOException;
import java.util.Arrays;
import java.util.Objects;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.LEB128;
import ghidra.util.NumericUtilities;

/**
 * An immutable representation of a single {@link DWARFExpression} instruction and its operands.
 * <p>
 * An instruction can take 0, 1, or 2 operands, only the last can be a blob.
 */
public class DWARFExpressionInstruction {

	/**
	 * Reads a single instruction from the stream.
	 * 
	 * @param reader {@link BinaryReader} stream
	 * @param addrSize size of pointers
	 * @param intSize size of ints
	 * @return new {@link DWARFExpressionInstruction}, never null.  Problematic instructions
	 * will have an opcode of {@link DWARFExpressionOpCode#DW_OP_unknown_opcode DW_OP_unknown_opcode}
	 * and will contain the remainder of the stream as its blob operand
	 * @throws IOException if error reading a primitive value from the stream
	 */
	public static DWARFExpressionInstruction read(BinaryReader reader, byte addrSize, int intSize)
			throws IOException {
		long opcodeoffset = reader.getPointerIndex();
		int opcode = reader.readNextUnsignedByte();
		DWARFExpressionOpCode op = DWARFExpressionOpCode.parse(opcode);
		if (op == null) {
			// back up so the raw opcode byte is included and
			// consume the remainder of the bytes in the expression because
			// we've hit an invalid/unknown opcode and can not proceed any further.
			reader.setPointerIndex(opcodeoffset);
			int bytesLeft = (int) (reader.length() - reader.getPointerIndex());
			byte[] remainingBytes = readSizedBlobOperand(reader, bytesLeft);

			return new DWARFExpressionInstruction(DW_OP_unknown_opcode,
				new DWARFExpressionOperandType[] { SIZED_BLOB }, EMPTY_OPERANDS_VALUE,
				remainingBytes, (int) opcodeoffset);
		}
		else {
			DWARFExpressionOperandType[] operandTypes = op.getOperandTypes();

			long[] operandValues =
				(operandTypes.length != 0) ? new long[operandTypes.length] : EMPTY_OPERANDS_VALUE;
			byte[] blob = null;
			for (int i = 0; i < operandTypes.length; i++) {
				DWARFExpressionOperandType optype = operandTypes[i];
				if (optype == SIZED_BLOB) {
					blob = readSizedBlobOperand(reader, operandValues[i - 1]);
				}
				else {
					operandValues[i] = readOperandValue(optype, reader, addrSize, intSize);
				}
			}

			return new DWARFExpressionInstruction(op, operandTypes, operandValues, blob,
				(int) opcodeoffset);
		}

	}

	protected final DWARFExpressionOpCode opcode;
	protected final int offset;
	protected final DWARFExpressionOperandType[] operandTypes;
	protected final long operands[];
	protected final byte[] blob;

	/**
	 * Create a new DWARF expression instruction.
	 *
	 * @param op enum opcode, ie. DW_OP_not from {@link DWARFExpressionOpCode}
	 * @param operandTypes 'datatype' of each operands
	 * @param operands value of the operands, pre-converted into longs.
	 * @param blob if an operand is a byte array (ie. for DW_OP_implicit_value), this is the bytes
	 * @param offset byte offset of this operation from the start of the DWARF expression.
	 */
	public DWARFExpressionInstruction(DWARFExpressionOpCode op,
			DWARFExpressionOperandType[] operandTypes, long[] operands, byte[] blob, int offset) {
		this.opcode = op;
		this.operandTypes = operandTypes;
		this.operands = operands;
		this.blob = blob;
		this.offset = offset;
	}

	/**
	 * {@return a new instruction instance that is a copy of this instruction, but has had all 
	 * it's operands removed}
	 */
	public DWARFExpressionInstruction toGenericForm() {
		return new DWARFExpressionInstruction(opcode, DW_OP_unknown_opcode.getOperandTypes(),
			EMPTY_OPERANDS_VALUE, null, 0);
	}

	/**
	 * {@return {@link DWARFExpressionOpCode} of this instruction}
	 */
	public DWARFExpressionOpCode getOpCode() {
		return opcode;
	}

	/**
	 * {@return the specified operand's value.  Not valid for blob operands}
	 *
	 * @param opindex which operand to fetch.
	 */
	public long getOperandValue(int opindex) {
		return operands[opindex];
	}

	/**
	 * {@return number of operands this instruction has}
	 */
	public int getOperandCount() {
		return operandTypes.length;
	}

	/**
	 * {@return the byte array that contains the bytes of the blob operand}
	 */
	public byte[] getBlob() {
		return blob;
	}

	/**
	 * {@return offset of this opcode, relative to the start of the {@link DWARFExpression}}
	 */
	public int getOffset() {
		return offset;
	}

	@Override
	public String toString() {
		return opcode.toString() + (operands.length > 0 ? " " + Arrays.toString(operands) : "") +
			(blob != null ? " blob: [" + NumericUtilities.convertBytesToString(blob) + "]" : "");
	}

	/**
	 * {@return formatted string representation of the specified operand, patterned after readelf's
	 * format}
	 *  
	 * @param opIndex operand index
	 */
	public String getOperandRepresentation(int opIndex) {
		return switch (operandTypes[opIndex]) {
			case ADDR -> Long.toHexString(operands[opIndex]);
			case S_BYTE, S_SHORT, S_INT, S_LONG, S_LEB128 -> // force a leading "+" for positive
					(operands[opIndex] > 0 ? "+" : "") + Long.toString(operands[opIndex]);
			case U_BYTE, U_SHORT, U_INT, U_LONG, U_LEB128, DWARF_INT -> Long
					.toUnsignedString(operands[opIndex]);
			case SIZED_BLOB -> NumericUtilities.convertBytesToString(blob, " ");
		};
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(blob);
		result = prime * result + Arrays.hashCode(operandTypes);
		result = prime * result + Arrays.hashCode(operands);
		result = prime * result + Objects.hash(offset, opcode);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof DWARFExpressionInstruction)) {
			return false;
		}
		DWARFExpressionInstruction other = (DWARFExpressionInstruction) obj;
		return Arrays.equals(blob, other.blob) && offset == other.offset &&
			opcode == other.opcode && Arrays.equals(operandTypes, other.operandTypes) &&
			Arrays.equals(operands, other.operands);
	}

	//--------------------------------------------------------------------------------------------

	private static final long EMPTY_OPERANDS_VALUE[] = {};

	private static byte[] readSizedBlobOperand(BinaryReader reader, long blobSize)
			throws IOException {
		return reader.readNextByteArray((int) blobSize);
	}

	private static long readOperandValue(DWARFExpressionOperandType operandType,
			BinaryReader reader, byte addrSize, int intSize) throws IOException {
		return switch (operandType) {
			case ADDR -> reader.readNextUnsignedValue(addrSize);
			case S_BYTE -> reader.readNextByte();
			case S_SHORT -> reader.readNextShort();
			case S_INT -> reader.readNextInt();
			case S_LONG -> reader.readNextLong();
			case U_BYTE -> reader.readNextUnsignedByte();
			case U_SHORT -> reader.readNextUnsignedShort();
			case U_INT -> reader.readNextUnsignedInt();
			case U_LONG -> reader.readNextLong(); /* & there is no mask for ulong */
			case S_LEB128 -> reader.readNext(LEB128::signed);
			case U_LEB128 -> reader.readNext(LEB128::unsigned);
			case SIZED_BLOB -> throw new IOException("Can't read SIZED_BLOB as a Long value");
			case DWARF_INT -> reader.readNextUnsignedValue(intSize);
			default -> throw new IOException("Unknown DWARFExpressionOperandType " + operandType);
		};
	}

}
