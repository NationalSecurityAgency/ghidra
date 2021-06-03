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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.dwarf4.*;
import ghidra.util.NumericUtilities;

/**
 * A {@link DWARFExpression} is an immutable list of {@link DWARFExpressionOperation operations} and some factory methods to read
 * an expression from its binary representation.
 * <p>
 * Use a {@link DWARFExpressionEvaluator} to execute a {@link DWARFExpression}.
 */
public class DWARFExpression {
	static long EMPTY_OPERANDS_VALUE[] = {};

	private final List<DWARFExpressionOperation> operations;

	private final int lastActiveOpIndex;

	public static String exprToString(byte[] exprBytes, DIEAggregate diea) {
		try {
			DWARFExpression expr =
				DWARFExpressionEvaluator.create(diea.getHeadFragment()).readExpr(exprBytes);
			return expr.toString();
		}
		catch (DWARFExpressionException e) {
			return "Unable to parse DWARF expression.  Raw bytes: " +
				NumericUtilities.convertBytesToString(exprBytes, " ");
		}
	}

	public static DWARFExpression read(byte[] exprBytes, byte addrSize, boolean isLittleEndian,
			int dwarf_format) throws DWARFExpressionException {
		ByteProvider provider = new ByteArrayProvider(exprBytes);
		BinaryReader reader = new BinaryReader(provider, isLittleEndian);

		return read(reader, addrSize, dwarf_format);
	}

	public static DWARFExpression read(BinaryReader reader, byte addrSize, int dwarf_format)
			throws DWARFExpressionException {
		List<DWARFExpressionOperation> operations = new ArrayList<>();

		try {
			long opcodeoffset;
			boolean invalidOpCodeEncountered = false;

			while ((opcodeoffset = reader.getPointerIndex()) < reader.length()) {
				int opcode = reader.readNextUnsignedByte();
				if (!DWARFExpressionOpCodes.isValidOpcode(opcode)) {
					// consume the remainder of the bytes in the expression because
					// we've hit an invalid opcode and can not proceed any further.
					int bytesLeft = (int) (reader.length() - reader.getPointerIndex());
					operations.add(new DWARFExpressionOperation(opcode,
						DWARFExpressionOpCodes.BLOBONLY_OPERANDTYPES, new long[] { 0 },
						readSizedBlobOperand(reader, bytesLeft), (int) opcodeoffset));
					invalidOpCodeEncountered = true;
				}
				else {
					DWARFExpressionOperandType[] operandTypes =
						DWARFExpressionOpCodes.getOperandTypesFor(opcode);

					long[] operandValues =
						(operandTypes.length != 0) ? new long[operandTypes.length]
								: EMPTY_OPERANDS_VALUE;
					byte[] blob = null;
					for (int i = 0; i < operandTypes.length; i++) {
						DWARFExpressionOperandType optype = operandTypes[i];
						if (optype == DWARFExpressionOperandType.SIZED_BLOB) {
							blob = readSizedBlobOperand(reader, operandValues[i - 1]);
						}
						else {
							operandValues[i] =
								readOperandValue(optype, reader, addrSize, dwarf_format);
						}
					}

					DWARFExpressionOperation op = new DWARFExpressionOperation(opcode, operandTypes,
						operandValues, blob, (int) opcodeoffset);
					operations.add(op);
				}
			}

			if (invalidOpCodeEncountered) {
				throw new IOException("Unknown DWARF opcode(s) encountered");
			}

			return new DWARFExpression(operations);
		}
		catch (IOException ioe) {
			DWARFExpression badExpr = new DWARFExpression(operations);
			String s = badExpr.toString();
			throw new DWARFExpressionException(
				"Error reading DWARF expression, partial expression is: ", badExpr, -1, ioe);
		}
	}

	private static long readOperandValue(DWARFExpressionOperandType operandType,
			BinaryReader reader, byte addrSize, int dwarf_format) throws IOException {
		try {
			switch (operandType) {
				case ADDR:
					return DWARFUtil.readAddressAsLong(reader, addrSize);
				case S_BYTE:
					return reader.readNextByte();
				case S_SHORT:
					return reader.readNextShort();
				case S_INT:
					return reader.readNextInt();
				case S_LONG:
					return reader.readNextLong();
				case U_BYTE:
					return reader.readNextUnsignedByte();
				case U_SHORT:
					return reader.readNextUnsignedShort();
				case U_INT:
					return reader.readNextUnsignedInt();
				case U_LONG:
					return reader.readNextLong(); /* & there is no mask for ulong */
				case S_LEB128:
					return LEB128.readAsLong(reader, true);
				case U_LEB128:
					return LEB128.readAsLong(reader, false);
				case SIZED_BLOB:
					throw new IOException("Can't read SIZED_BLOB as a Long value");
				case DWARF_INT:
					return (dwarf_format == DWARFCompilationUnit.DWARF_32)
							? reader.readNextUnsignedInt()
							: reader.readNextLong();
			}
		}
		catch (ArrayIndexOutOfBoundsException aioob) {
			throw new IOException("Not enough bytes to read " + operandType);
		}
		throw new IOException("Unknown DWARFExpressionOperandType " + operandType);
	}

	private static byte[] readSizedBlobOperand(BinaryReader reader, long previousOperandValue)
			throws IOException {
		return reader.readNextByteArray((int) previousOperandValue);
	}

	private DWARFExpression(List<DWARFExpressionOperation> operations) {
		this.operations = operations;
		this.lastActiveOpIndex = findLastActiveOpIndex();
	}

	public DWARFExpressionOperation getOp(int i) {
		return operations.get(i);
	}

	public int getOpCount() {
		return operations.size();
	}

	/**
	 * Returns the index of the last operation that is not a NOP.
	 * @return
	 */
	public int getLastActiveOpIndex() {
		return lastActiveOpIndex;
	}

	private int findLastActiveOpIndex() {
		for (int i = operations.size() - 1; i >= 0; i--) {
			if (operations.get(i).getOpCode() != DWARFExpressionOpCodes.DW_OP_nop) {
				return i;
			}
		}
		return operations.size() - 1;
	}

	/**
	 * Finds the index of an {@link DWARFExpressionOperation operation} by its offset
	 * from the beginning of the expression.
	 * <p>
	 * @param offset
	 * @return -1 if there is no op at the specified offset
	 */
	public int findOpByOffset(long offset) {
		for (int i = 0; i < operations.size(); i++) {
			DWARFExpressionOperation op = getOp(i);
			if (op.getOffset() == offset) {
				return i;
			}
		}
		return -1;
	}

	@Override
	public String toString() {
		return toString(-1, false, false);
	}

	public String toString(int caretPosition, boolean newlines, boolean offsets) {
		StringBuilder sb = new StringBuilder();
		for (int step = 0; step < operations.size(); step++) {
			DWARFExpressionOperation op = operations.get(step);

			if (step != 0) {
				sb.append("; ");
				if (newlines) {
					sb.append('\n');
				}
			}
			if (offsets) {
				sb.append(String.format("%3d [%03x]: ", step, op.getOffset()));
			}
			if (caretPosition == step) {
				sb.append(" ==> [");
			}
			int opcode = op.getOpCode();
			if (DWARFExpressionOpCodes.isValidOpcode(opcode)) {
				sb.append(DWARFExpressionOpCodes.toString(opcode));
			}
			else {
				if (opcode >= DWARFExpressionOpCodes.DW_OP_lo_user &&
					opcode <= DWARFExpressionOpCodes.DW_OP_hi_user) {
					int relOpCode = opcode - DWARFExpressionOpCodes.DW_OP_lo_user;
					sb.append(
						DWARFExpressionOpCodes.toString(DWARFExpressionOpCodes.DW_OP_lo_user) +
							"+" + relOpCode + "[" + opcode + "]");
				}
				else {
					sb.append("DW_OP_UNKNOWN[" + opcode + "]");
				}
			}
			for (int operandIndex = 0; operandIndex < op.operands.length; operandIndex++) {
				if (operandIndex == 0) {
					sb.append(':');
				}
				sb.append(' ');
				DWARFExpressionOperandType operandType = op.operandTypes[operandIndex];
				if (operandType != DWARFExpressionOperandType.SIZED_BLOB) {
					long operandValue = op.operands[operandIndex];

					sb.append(DWARFExpressionOperandType.valueToString(operandValue, operandType));
				}
				else {
					sb.append(NumericUtilities.convertBytesToString(op.blob, " "));
				}
			}
			if (caretPosition == step) {
				sb.append(" ] <==");
			}
			if (opcode == DWARFExpressionOpCodes.DW_OP_bra ||
				opcode == DWARFExpressionOpCodes.DW_OP_skip) {
				long destOffset = op.getOperandValue(0) + op.getOffset();
				int destIndex = findOpByOffset(destOffset);
				sb.append(String.format(" /* dest index: %d, offset: %03x */", destIndex,
					(int) destOffset));
			}
		}

		return sb.toString();
	}
}
