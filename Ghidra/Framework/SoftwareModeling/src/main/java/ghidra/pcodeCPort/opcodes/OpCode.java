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

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

// Some of the names have been replaced with special placeholder
// ops for the sleigh compiler and interpreter these are as follows:
//    MULTIEQUAL = BUILD
//    INDIRECT   = DELAY_SLOT
//    PTRADD     = LABEL
//    PTRSUB     = CROSSBUILD

public enum OpCode {
	DO_NOT_USE_ME_I_AM_ENUM_ELEMENT_ZERO("BLANK"),
	CPUI_COPY("COPY"), // Copy one operand to another
	CPUI_LOAD("LOAD"), // Dereference a pointer into specified space
	CPUI_STORE("STORE"), // Store at a pointer into specified space

	CPUI_BRANCH("BRANCH"), // Always branch
	CPUI_CBRANCH("CBRANCH"), // Conditional branch
	CPUI_BRANCHIND("BRANCHIND"), // An indirect branch (jumptable)

	CPUI_CALL("CALL"), // A call with absolute address
	CPUI_CALLIND("CALLIND"), // An indirect call
	CPUI_CALLOTHER("CALLOTHER"), // Other unusual subroutine calling conventions
	CPUI_RETURN("RETURN"), // A return from subroutine

	// Integer/bit operations

	CPUI_INT_EQUAL("INT_EQUAL"), // Return TRUE if operand1 == operand2
	CPUI_INT_NOTEQUAL("INT_NOTEQUAL"), // Return TRUE if operand1 != operand2
	CPUI_INT_SLESS("INT_SLESS"), // Return TRUE if signed op1 < signed op2
	CPUI_INT_SLESSEQUAL("INT_SLESSEQUAL"), // Return TRUE if signed op1 <= signed op2
	CPUI_INT_LESS("INT_LESS"), // Return TRUE if unsigned op1 < unsigned op2
	// This also indicates a borrow on unsigned substraction
	CPUI_INT_LESSEQUAL("INT_LESSEQUAL"), // Return TRUE if unsigned op1 <= unsigned op2
	CPUI_INT_ZEXT("INT_ZEXT"), // Zero extend operand
	CPUI_INT_SEXT("INT_SEXT"), // Sign extend operand
	CPUI_INT_ADD("INT_ADD"), // Unsigned addition of operands of same size
	CPUI_INT_SUB("INT_SUB"), // Unsigned subtraction of operands of same size
	CPUI_INT_CARRY("INT_CARRY"), // TRUE if adding two operands has overflow (carry)
	CPUI_INT_SCARRY("INT_SCARRY"), // TRUE if there is a carry in signed addition of two ops
	CPUI_INT_SBORROW("INT_SBORROW"), // TRUE if there is a borrow in signed subtraction of two ops
	CPUI_INT_2COMP("INT_2COMP"), // Twos complement (for subtracting) of operand
	CPUI_INT_NEGATE("INT_NEGATE"),
	CPUI_INT_XOR("INT_XOR"), // Exclusive OR of two operands of same size
	CPUI_INT_AND("INT_AND"),
	CPUI_INT_OR("INT_OR"),
	CPUI_INT_LEFT("INT_LEFT"), // Left shift
	CPUI_INT_RIGHT("INT_RIGHT"), // Right shift zero fill
	CPUI_INT_SRIGHT("INT_SRIGHT"), // Signed right shift
	CPUI_INT_MULT("INT_MULT"), // Integer multiplication
	CPUI_INT_DIV("INT_DIV"), // Unsigned integer division
	CPUI_INT_SDIV("INT_SDIV"), // Signed integer division
	CPUI_INT_REM("INT_REM"), // Unsigned mod (remainder)
	CPUI_INT_SREM("INT_SREM"), // Signed mod (remainder)

	CPUI_BOOL_NEGATE("BOOL_NEGATE"), // Boolean negate or not
	CPUI_BOOL_XOR("BOOL_XOR"), // Boolean xor
	CPUI_BOOL_AND("BOOL_AND"), // Boolean and (&&)
	CPUI_BOOL_OR("BOOL_OR"), // Boolean or (||)

	// Floating point operations

	CPUI_FLOAT_EQUAL("FLOAT_EQUAL"), // Return TRUE if operand1 == operand2
	CPUI_FLOAT_NOTEQUAL("FLOAT_NOTEQUAL"), // Return TRUE if operand1 != operand2
	CPUI_FLOAT_LESS("FLOAT_LESS"), // Return TRUE if op1 < op2
	CPUI_FLOAT_LESSEQUAL("FLOAT_LESSEQUAL"), // Return TRUE if op1 <= op2
	CPUI_UNUSED1("UNUSED1"), // Slot 45 is unused
	CPUI_FLOAT_NAN("FLOAT_NAN"), // Return TRUE if op1 is NaN

	CPUI_FLOAT_ADD("FLOAT_ADD"), // float addition
	CPUI_FLOAT_DIV("FLOAT_DIV"), // float division
	CPUI_FLOAT_MULT("FLOAT_MULT"), // float multiplication
	CPUI_FLOAT_SUB("FLOAT_SUB"), // float subtraction
	CPUI_FLOAT_NEG("FLOAT_NEG"), // float negation
	CPUI_FLOAT_ABS("FLOAT_ABS"), // float absolute value
	CPUI_FLOAT_SQRT("FLOAT_SQRT"), // float square root

	CPUI_FLOAT_INT2FLOAT("INT2FLOAT"), // convert int type to float type
	CPUI_FLOAT_FLOAT2FLOAT("FLOAT2FLOAT"), // convert between float sizes
	CPUI_FLOAT_TRUNC("TRUNC"), // round towards zero
	CPUI_FLOAT_CEIL("CEIL"), // round towards +infinity
	CPUI_FLOAT_FLOOR("FLOOR"), // round towards -infinity
	CPUI_FLOAT_ROUND("ROUND"), // round towards nearest

	// Internal opcodes for simplification. Not
	// typically generated in a direct translation.

	// Dataflow operations
	CPUI_MULTIEQUAL("BUILD"), // Output is equal to one of its inputs, depending on execution
	CPUI_INDIRECT("DELAY_SLOT"), // Output probably equals input but may be indirectly affected
	CPUI_PIECE("PIECE"), // Output is constructed from multiple pieces
	CPUI_SUBPIECE("SUBPIECE"), // Output is a subpiece of input0, input1=offset into input0

	CPUI_CAST("CAST"), // Cast from one type to another                 // MACROBUILD
	CPUI_PTRADD("LABEL"), // outptr = ptrbase, offset, (size multiplier)
	CPUI_PTRSUB("CROSSBUILD"), // outptr = &(ptr->subfield)
	CPUI_SEGMENTOP("SEGMENTOP"),
	CPUI_CPOOLREF("CPOOLREF"),
	CPUI_NEW("NEW"),
	CPUI_INSERT("INSERT"),
	CPUI_EXTRACT("EXTRACT"),
	CPUI_POPCOUNT("POPCOUNT"),
	CPUI_LZCOUNT("LZCOUNT"),

	CPUI_MAX(null);

	private final String name;

	private OpCode(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}

	/**
	 * {@return the complimentary opcode for boolean operations}
	 * 
	 * (or {@link #CPUI_MAX} if not boolean.) Set reorder to true if the complimentary operation
	 * would involve reordering the input parameters
	 */
	public OpCode getOpCodeFlip() {
		return switch (this) {
			case CPUI_INT_EQUAL -> CPUI_INT_NOTEQUAL;
			case CPUI_INT_NOTEQUAL -> CPUI_INT_EQUAL;
			case CPUI_INT_SLESS -> CPUI_INT_SLESSEQUAL;
			case CPUI_INT_SLESSEQUAL -> CPUI_INT_SLESS;
			case CPUI_INT_LESS -> CPUI_INT_LESSEQUAL;
			case CPUI_INT_LESSEQUAL -> CPUI_INT_LESS;
			case CPUI_BOOL_NEGATE -> CPUI_COPY;
			case CPUI_FLOAT_EQUAL -> CPUI_FLOAT_NOTEQUAL;
			case CPUI_FLOAT_NOTEQUAL -> CPUI_FLOAT_EQUAL;
			case CPUI_FLOAT_LESS -> CPUI_FLOAT_LESSEQUAL;
			case CPUI_FLOAT_LESSEQUAL -> CPUI_FLOAT_LESS;
			default -> CPUI_MAX;
		};
	}

	/**
	 * {@return the complimentary opcode for boolean operations}
	 * 
	 * (or {@link #CPUI_MAX} if not boolean.) Set reorder to true if the complimentary operation
	 * would involve reordering the input parameters
	 */
	public boolean getBooleanFlip() {
		return switch (this) {
			case CPUI_INT_EQUAL -> false;
			case CPUI_INT_NOTEQUAL -> false;
			case CPUI_INT_SLESS -> true;
			case CPUI_INT_SLESSEQUAL -> true;
			case CPUI_INT_LESS -> true;
			case CPUI_INT_LESSEQUAL -> true;
			case CPUI_BOOL_NEGATE -> false;
			case CPUI_FLOAT_EQUAL -> false;
			case CPUI_FLOAT_NOTEQUAL -> false;
			case CPUI_FLOAT_LESS -> true;
			case CPUI_FLOAT_LESSEQUAL -> true;
			default -> false;
		};
	}

	static final List<OpCode> opsByOrdinal = List.of(OpCode.values());
	static final Map<String, OpCode> opsByName =
		Stream.of(OpCode.values())
				.filter(op -> op != DO_NOT_USE_ME_I_AM_ENUM_ELEMENT_ZERO && op != CPUI_MAX)
				.collect(Collectors.toUnmodifiableMap(OpCode::getName, op -> op));

	public static OpCode getOpcode(int ordinal) {
		return opsByOrdinal.get(ordinal);
	}

	public static OpCode getOpcode(String nm) {
		return opsByName.get(nm);
	}
}
