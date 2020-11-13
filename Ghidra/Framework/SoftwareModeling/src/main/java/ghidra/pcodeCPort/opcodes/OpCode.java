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
package ghidra.pcodeCPort.opcodes;
// Names of ops associated with their opcode number
// Some of the names have been replaced with special placeholder
// ops for the sleigh compiler and interpreter these are as follows:
//    MULTIEQUAL = BUILD
//    INDIRECT   = DELAY_SLOT
//    PTRADD     = LABEL
//    PTRSUB     = CROSSBUILD

public enum OpCode {
	DO_NOT_USE_ME_I_AM_ENUM_ELEMENT_ZERO, CPUI_COPY, // Copy one operand to another
	CPUI_LOAD, // Dereference a pointer into specified space
	CPUI_STORE, // Store at a pointer into specified space

	CPUI_BRANCH, // Always branch
	CPUI_CBRANCH, // Conditional branch
	CPUI_BRANCHIND, // An indirect branch (jumptable)

	CPUI_CALL, // A call with absolute address
	CPUI_CALLIND, // An indirect call
	CPUI_CALLOTHER, // Other unusual subroutine calling conventions
	CPUI_RETURN, // A return from subroutine

	// Integer/bit operations

	CPUI_INT_EQUAL, // Return TRUE if operand1 == operand2
	CPUI_INT_NOTEQUAL, // Return TRUE if operand1 != operand2
	CPUI_INT_SLESS, // Return TRUE if signed op1 < signed op2
	CPUI_INT_SLESSEQUAL, // Return TRUE if signed op1 <= signed op2
	CPUI_INT_LESS, // Return TRUE if unsigned op1 < unsigned op2
	// This also indicates a borrow on unsigned substraction
	CPUI_INT_LESSEQUAL, // Return TRUE if unsigned op1 <= unsigned op2
	CPUI_INT_ZEXT, // Zero extend operand
	CPUI_INT_SEXT, // Sign extend operand
	CPUI_INT_ADD, // Unsigned addition of operands of same size
	CPUI_INT_SUB, // Unsigned subtraction of operands of same size
	CPUI_INT_CARRY, // TRUE if adding two operands has overflow (carry)
	CPUI_INT_SCARRY, // TRUE if there is a carry in signed addition of two ops
	CPUI_INT_SBORROW, // TRUE if there is a borrow in signed subtraction of two ops
	CPUI_INT_2COMP, // Twos complement (for subtracting) of operand
	CPUI_INT_NEGATE,
	CPUI_INT_XOR, // Exclusive OR of two operands of same size
	CPUI_INT_AND,
	CPUI_INT_OR,
	CPUI_INT_LEFT, // Left shift
	CPUI_INT_RIGHT, // Right shift zero fill
	CPUI_INT_SRIGHT, // Signed right shift
	CPUI_INT_MULT, // Integer multiplication
	CPUI_INT_DIV, // Unsigned integer division
	CPUI_INT_SDIV, // Signed integer division
	CPUI_INT_REM, // Unsigned mod (remainder)
	CPUI_INT_SREM, // Signed mod (remainder)

	CPUI_BOOL_NEGATE, // Boolean negate or not
	CPUI_BOOL_XOR, // Boolean xor
	CPUI_BOOL_AND, // Boolean and (&&)
	CPUI_BOOL_OR, // Boolean or (||)

	// Floating point operations

	CPUI_FLOAT_EQUAL, // Return TRUE if operand1 == operand2
	CPUI_FLOAT_NOTEQUAL, // Return TRUE if operand1 != operand2
	CPUI_FLOAT_LESS, // Return TRUE if op1 < op2
	CPUI_FLOAT_LESSEQUAL, // Return TRUE if op1 <= op2
	CPUI_UNUSED1, // Slot 45 is unused
	CPUI_FLOAT_NAN, // Return TRUE if op1 is NaN

	CPUI_FLOAT_ADD, // float addition
	CPUI_FLOAT_DIV, // float division
	CPUI_FLOAT_MULT, // float multiplication
	CPUI_FLOAT_SUB, // float subtraction
	CPUI_FLOAT_NEG, // float negation
	CPUI_FLOAT_ABS, // float absolute value
	CPUI_FLOAT_SQRT, // float square root

	CPUI_FLOAT_INT2FLOAT, // convert int type to float type
	CPUI_FLOAT_FLOAT2FLOAT, // convert between float sizes
	CPUI_FLOAT_TRUNC, // round towards zero
	CPUI_FLOAT_CEIL, // round towards +infinity
	CPUI_FLOAT_FLOOR, // round towards -infinity
	CPUI_FLOAT_ROUND, // round towards nearest

	// Internal opcodes for simplification. Not
	// typically generated in a direct translation.

	// Dataflow operations
	CPUI_MULTIEQUAL, // Output is equal to one of its inputs, depending on execution  // BUILD
	CPUI_INDIRECT, // Output probably equals input but may be indirectly affected     // DELAY_SLOT
	CPUI_PIECE, // Output is constructed from multiple pieces
	CPUI_SUBPIECE, // Output is a subpiece of input0, input1=offset into input0

	CPUI_CAST, // Cast from one type to another                 // MACROBUILD
	CPUI_PTRADD, // outptr = ptrbase, offset, (size multiplier) // LABELBUILD
	CPUI_PTRSUB, // outptr = &(ptr->subfield)                   // CROSSBUILD
	CPUI_SEGMENTOP,
	CPUI_CPOOLREF,
	CPUI_NEW,
	CPUI_INSERT,
	CPUI_EXTRACT,
	CPUI_POPCOUNT,

	CPUI_MAX;

	private OpCode() {
	}

	public String getName() {
		return get_opname(this);
	}

	public OpCode getOpCodeFlip()

	{ // Return the complimentary opcode for boolean operations
		// (or CPUI_MAX if not boolean) Set reorder to true if
		// the complimentary operation would involve reordering
		// the input parameters
		switch (this) {
			case CPUI_INT_EQUAL:
				return CPUI_INT_NOTEQUAL;
			case CPUI_INT_NOTEQUAL:
				return CPUI_INT_EQUAL;
			case CPUI_INT_SLESS:
				return CPUI_INT_SLESSEQUAL;
			case CPUI_INT_SLESSEQUAL:
				return CPUI_INT_SLESS;
			case CPUI_INT_LESS:
				return CPUI_INT_LESSEQUAL;
			case CPUI_INT_LESSEQUAL:
				return CPUI_INT_LESS;
			case CPUI_BOOL_NEGATE:
				return CPUI_COPY;
			case CPUI_FLOAT_EQUAL:
				return CPUI_FLOAT_NOTEQUAL;
			case CPUI_FLOAT_NOTEQUAL:
				return CPUI_FLOAT_EQUAL;
			case CPUI_FLOAT_LESS:
				return CPUI_FLOAT_LESSEQUAL;
			case CPUI_FLOAT_LESSEQUAL:
				return CPUI_FLOAT_LESS;
			default:
				break;
		}
		return CPUI_MAX;
	}

	public boolean getBooleanFlip()

	{ // Return the complimentary opcode for boolean operations
		// (or CPUI_MAX if not boolean) Set reorder to true if
		// the complimentary operation would involve reordering
		// the input parameters
		switch (this) {
			case CPUI_INT_EQUAL:
				return false;
			case CPUI_INT_NOTEQUAL:
				return false;
			case CPUI_INT_SLESS:
				return true;
			case CPUI_INT_SLESSEQUAL:
				return true;
			case CPUI_INT_LESS:
				return true;
			case CPUI_INT_LESSEQUAL:
				return true;
			case CPUI_BOOL_NEGATE:
				return false;
			case CPUI_FLOAT_EQUAL:
				return false;
			case CPUI_FLOAT_NOTEQUAL:
				return false;
			case CPUI_FLOAT_LESS:
				return true;
			case CPUI_FLOAT_LESSEQUAL:
				return true;
			default:
				break;
		}
		return false;
	}

	static final String opcode_name[] = { "BLANK", "COPY", "LOAD", "STORE", "BRANCH", "CBRANCH",
		"BRANCHIND", "CALL", "CALLIND", "CALLOTHER", "RETURN", "INT_EQUAL", "INT_NOTEQUAL",
		"INT_SLESS", "INT_SLESSEQUAL", "INT_LESS", "INT_LESSEQUAL", "INT_ZEXT", "INT_SEXT",
		"INT_ADD", "INT_SUB", "INT_CARRY", "INT_SCARRY", "INT_SBORROW", "INT_2COMP", "INT_NEGATE",
		"INT_XOR", "INT_AND", "INT_OR", "INT_LEFT", "INT_RIGHT", "INT_SRIGHT", "INT_MULT",
		"INT_DIV", "INT_SDIV", "INT_REM", "INT_SREM", "BOOL_NEGATE", "BOOL_XOR", "BOOL_AND",
		"BOOL_OR", "FLOAT_EQUAL", "FLOAT_NOTEQUAL", "FLOAT_LESS", "FLOAT_LESSEQUAL",
		"UNUSED1", "FLOAT_NAN", "FLOAT_ADD", "FLOAT_DIV", "FLOAT_MULT", "FLOAT_SUB",
		"FLOAT_NEG", "FLOAT_ABS", "FLOAT_SQRT", "INT2FLOAT", "FLOAT2FLOAT", "TRUNC", "CEIL",
		"FLOOR", "ROUND", "BUILD", "DELAY_SLOT", "PIECE", "SUBPIECE", "CAST", "LABEL",
		"CROSSBUILD", "SEGMENTOP", "CPOOLREF", "NEW", "INSERT", "EXTRACT", "POPCOUNT" };

	public static String get_opname(OpCode op) {
		return opcode_name[op.ordinal()];
	}

	static final int opcode_indices[] = { 0, 39, 37, 40, 38, 4, 6, 60, 7, 8, 9, 64, 5, 57, 1, 68, 66,
			61, 71, 55, 52, 47, 48, 41, 43, 44, 49, 46, 51, 42, 53, 50, 58, 70, 54, 24, 19, 27, 21,
			33, 11, 29, 15, 16, 32, 25, 12, 28, 35, 30, 23, 22, 34, 18, 13, 14, 36, 31, 20, 26, 17,
			65, 2, 69, 62, 72, 10, 59, 67, 3, 63, 56, 45 };

	public static OpCode get_opcode(String nm) { // Use binary search to find name
		int min = 1; // Don't include BLANK
		int max = OpCode.CPUI_MAX.ordinal() - 1;
		int cur, ind;

		while (min <= max) { // Binary search
			cur = (min + max) / 2;
			ind = opcode_indices[cur]; // Get opcode in cur's sort slot
			int result = opcode_name[ind].compareTo(nm);
			if (result < 0) {
				min = cur + 1; // Everything equal or below cur is less
			}
			else if (result > 0) {
				max = cur - 1; // Everything equal or above cur is greater
			}
			else {
				return OpCode.values()[ind]; // Found the match
			}
		}
		return null; // Name isn't an op
	}

}
