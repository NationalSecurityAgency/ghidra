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

import java.io.IOException;
import java.util.*;

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.dwarf.DWARFCompilationUnit;
import ghidra.app.util.bin.format.dwarf.DWARFRegisterMappings;

/**
 * A {@link DWARFExpression} is an immutable list of {@link DWARFExpressionInstruction operations}
 * and some factory methods to read an expression from its binary representation.
 * <p>
 * Use a {@link DWARFExpressionEvaluator} to execute a {@link DWARFExpression}.
 */
public class DWARFExpression {
	public static final int MAX_SANE_EXPR = 256;

	/**
	 * Deserializes a {@link DWARFExpression} from its raw bytes.
	 * 
	 * @param exprBytes bytes containing the expression
	 * @param cu the {@link DWARFCompilationUnit} that contained the expression
	 * @return new {@link DWARFExpression}, never null
	 * @throws DWARFExpressionException if error reading the expression, check 
	 * {@link DWARFExpressionException#getExpression()} for the partial results of the read 
	 */
	public static DWARFExpression read(byte[] exprBytes, DWARFCompilationUnit cu)
			throws DWARFExpressionException {
		return read(exprBytes, cu.getPointerSize(), cu.getProgram().isLittleEndian(),
			cu.getIntSize());
	}

	private static DWARFExpression read(byte[] exprBytes, byte addrSize, boolean isLittleEndian,
			int intSize) throws DWARFExpressionException {
		ByteProvider provider = new ByteArrayProvider(exprBytes);
		BinaryReader reader = new BinaryReader(provider, isLittleEndian);

		return read(reader, addrSize, intSize);
	}

	private static DWARFExpression read(BinaryReader reader, byte addrSize, int intSize)
			throws DWARFExpressionException {
		List<DWARFExpressionInstruction> instructions = new ArrayList<>();

		try {
			while (reader.hasNext()) {
				DWARFExpressionInstruction instr =
					DWARFExpressionInstruction.read(reader, addrSize, intSize);
				instructions.add(instr);
				if (instr.getOpCode() == DW_OP_unknown_opcode) {
					throw new IOException("Unknown DWARF opcode(s) encountered");
				}
			}

			return new DWARFExpression(instructions);
		}
		catch (IOException ioe) {
			DWARFExpression badExpr = new DWARFExpression(instructions);
			throw new DWARFExpressionException(
				"Error reading DWARF expression, partial expression is: ", badExpr, -1, ioe);
		}
	}

	private final List<DWARFExpressionInstruction> instructions;

	/**
	 * Private constructor for {@link DWARFExpression}... use one of the static 
	 * {@link #read(byte[], DWARFCompilationUnit) read} methods to create an instance.
	 * 
	 * @param instructions list of instructions
	 */
	private DWARFExpression(List<DWARFExpressionInstruction> instructions) {
		this.instructions = instructions;
	}

	/**
	 * Converts this {@link DWARFExpression} into a generic form, lacking any operand values.
	 * <p>
	 * Useful for aggregating statistics about unsupported/problematic expressions encountered in
	 * a binary.
	 * 
	 * @return new {@link DWARFExpression} instance where each instruction has been stripped of all
	 * operands
	 */
	public DWARFExpression toGenericForm() {
		List<DWARFExpressionInstruction> genericInstrs =
			instructions.stream().map(DWARFExpressionInstruction::toGenericForm).toList();
		return new DWARFExpression(genericInstrs);
	}

	/**
	 * {@return the requested instruction}
	 * @param i instruction index
	 */
	public DWARFExpressionInstruction getInstruction(int i) {
		return instructions.get(i);
	}

	/**
	 * {@return number of instructions in this expression}
	 */
	public int getInstructionCount() {
		return instructions.size();
	}

	/**
	 * {@return true if there are no instructions}
	 */
	public boolean isEmpty() {
		return instructions.isEmpty();
	}

	/**
	 * Finds the index of an {@link DWARFExpressionInstruction operation} by its offset
	 * from the beginning of the expression.
	 * 
	 * @param offset byte offset of instruction to find
	 * @return index of instruction at specified byte offset, or -1 if there is no instruction
	 * at the specified offset
	 */
	public int findInstructionByOffset(long offset) {
		for (int i = 0; i < instructions.size(); i++) {
			DWARFExpressionInstruction instr = getInstruction(i);
			if (instr.getOffset() == offset) {
				return i;
			}
		}
		return -1;
	}

	@Override
	public String toString() {
		return toString(-1, false, false, null);
	}

	public String toString(DWARFCompilationUnit cu) {
		return toString(-1, false, false, cu.getProgram().getRegisterMappings());
	}

	/**
	 * Returns a formatted string representing this expression.
	 * 
	 * @param caretPosition index of which instruction to highlight as being the current
	 * instruction, or -1 to not highlight any instruction
	 * @param newlines boolean flag, if true each instruction will be on its own line
	 * @param offsets boolean flag, if true the byte offset in the expression will be listed
	 * next to each instruction
	 * @param regMapping mapping of dwarf to ghidra registers
	 * @return formatted string
	 */
	public String toString(int caretPosition, boolean newlines, boolean offsets,
			DWARFRegisterMappings regMapping) {

		StringBuilder sb = new StringBuilder();
		for (int instrIndex = 0; instrIndex < instructions.size(); instrIndex++) {
			DWARFExpressionInstruction instr = instructions.get(instrIndex);

			if (instrIndex != 0) {
				sb.append(newlines ? "\n" : "; ");
			}
			if (offsets) {
				sb.append("%3d [%03x]: ".formatted(instrIndex, instr.getOffset()));
			}
			if (caretPosition == instrIndex) {
				sb.append(" ==> [");
			}
			sb.append(instr.getOpCode().toString(regMapping));
			for (int operandIndex = 0; operandIndex < instr.getOperandCount(); operandIndex++) {
				if (operandIndex == 0) {
					sb.append(':');
				}
				sb.append(' ');
				sb.append(instr.getOperandRepresentation(operandIndex));
			}
			if (caretPosition == instrIndex) {
				sb.append(" ] <==");
			}
			if (instr.opcode == DW_OP_bra || instr.opcode == DW_OP_skip) {
				long destOffset = instr.getOperandValue(0) + instr.getOffset();
				int destIndex = findInstructionByOffset(destOffset);
				sb.append(String.format(" /* dest index: %d, offset: %03x */", destIndex,
					(int) destOffset));
			}
		}

		return sb.toString();
	}

	@Override
	public int hashCode() {
		return Objects.hash(instructions);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof DWARFExpression)) {
			return false;
		}
		DWARFExpression other = (DWARFExpression) obj;
		return Objects.equals(instructions, other.instructions);
	}


}
