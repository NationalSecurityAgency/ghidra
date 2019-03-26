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

/**
 * Enumeration that represents the different type of operands that a 
 * {@link DWARFExpressionOpCodes opcode} can take.
 */
public enum DWARFExpressionOperandType {
	U_LEB128,	// UNSIGNED LEB128 (variable len)
	S_LEB128,	// SIGNED LEB128 (variable len)
	S_BYTE,		// SIGNED BYTE (1 byte)
	S_SHORT,		// SIGNED SHORT (2 bytes)
	S_INT,		// SIGNED INT (4 bytes)
	S_LONG,		// SIGNED LONG (8 bytes)
	U_BYTE,		// UNSIGNED BYTE (1 byte)
	U_SHORT,		// UNSIGNED SHORT (2 bytes)
	U_INT,		// UNSIGNED INT (4 bytes)
	U_LONG,		// UNSIGNED LONG (8 bytes)
	ADDR,		// ADDRESS (1, 2, 4, 8 from DWARFCompilationUnit.pointerSize)
	SIZED_BLOB,	// raw bytes (length specified by other operand)
	DWARF_INT;	// U_INT or U_LONG based on dwarf native size

	public static String valueToString(long value, DWARFExpressionOperandType operandType) {
		return operandType == U_LONG || operandType == ADDR || operandType == DWARF_INT
				? Long.toUnsignedString(value, 16)
				: Long.toString(value, 16);
	}
}
