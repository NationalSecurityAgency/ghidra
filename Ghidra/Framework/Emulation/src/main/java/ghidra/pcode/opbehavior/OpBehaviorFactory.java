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
package ghidra.pcode.opbehavior;

import ghidra.program.model.pcode.PcodeOp;

public class OpBehaviorFactory {

	public static OpBehavior getOpBehavior(int opcode) {
		// TODO: should pass float format factory?
		return switch (opcode) {
			case PcodeOp.COPY -> OpBehavior.COPY;
			case PcodeOp.LOAD -> OpBehavior.LOAD;
			case PcodeOp.STORE -> OpBehavior.STORE;
			case PcodeOp.BRANCH -> OpBehavior.BRANCH;
			case PcodeOp.CBRANCH -> OpBehavior.CBRANCH;
			case PcodeOp.BRANCHIND -> OpBehavior.BRANCHIND;
			case PcodeOp.CALL -> OpBehavior.CALL;
			case PcodeOp.CALLIND -> OpBehavior.CALLIND;
			case PcodeOp.CALLOTHER -> OpBehavior.CALLOTHER;
			case PcodeOp.RETURN -> OpBehavior.RETURN;

			case PcodeOp.MULTIEQUAL -> OpBehavior.MULTIEQUAL;
			case PcodeOp.INDIRECT -> OpBehavior.INDIRECT;

			case PcodeOp.PIECE -> OpBehavior.PIECE;
			case PcodeOp.SUBPIECE -> OpBehavior.SUBPIECE;
			case PcodeOp.INT_EQUAL -> OpBehavior.INT_EQUAL;
			case PcodeOp.INT_NOTEQUAL -> OpBehavior.INT_NOTEQUAL;
			case PcodeOp.INT_SLESS -> OpBehavior.INT_SLESS;
			case PcodeOp.INT_SLESSEQUAL -> OpBehavior.INT_SLESSEQUAL;
			case PcodeOp.INT_LESS -> OpBehavior.INT_LESS;
			case PcodeOp.INT_LESSEQUAL -> OpBehavior.INT_LESSEQUAL;
			case PcodeOp.INT_ZEXT -> OpBehavior.INT_ZEXT;
			case PcodeOp.INT_SEXT -> OpBehavior.INT_SEXT;
			case PcodeOp.INT_ADD -> OpBehavior.INT_ADD;
			case PcodeOp.INT_SUB -> OpBehavior.INT_SUB;
			case PcodeOp.INT_CARRY -> OpBehavior.INT_CARRY;
			case PcodeOp.INT_SCARRY -> OpBehavior.INT_SCARRY;
			case PcodeOp.INT_SBORROW -> OpBehavior.INT_SBORROW;
			case PcodeOp.INT_2COMP -> OpBehavior.INT_2COMP;
			case PcodeOp.INT_NEGATE -> OpBehavior.INT_NEGATE;
			case PcodeOp.INT_XOR -> OpBehavior.INT_XOR;
			case PcodeOp.INT_AND -> OpBehavior.INT_AND;
			case PcodeOp.INT_OR -> OpBehavior.INT_OR;
			case PcodeOp.INT_LEFT -> OpBehavior.INT_LEFT;
			case PcodeOp.INT_RIGHT -> OpBehavior.INT_RIGHT;
			case PcodeOp.INT_SRIGHT -> OpBehavior.INT_SRIGHT;
			case PcodeOp.INT_MULT -> OpBehavior.INT_MULT;
			case PcodeOp.INT_DIV -> OpBehavior.INT_DIV;
			case PcodeOp.INT_SDIV -> OpBehavior.INT_SDIV;
			case PcodeOp.INT_REM -> OpBehavior.INT_REM;
			case PcodeOp.INT_SREM -> OpBehavior.INT_SREM;

			case PcodeOp.BOOL_NEGATE -> OpBehavior.BOOL_NEGATE;
			case PcodeOp.BOOL_XOR -> OpBehavior.BOOL_XOR;
			case PcodeOp.BOOL_AND -> OpBehavior.BOOL_AND;
			case PcodeOp.BOOL_OR -> OpBehavior.BOOL_OR;

			case PcodeOp.CAST -> OpBehavior.CAST;
			case PcodeOp.PTRADD -> OpBehavior.PTRADD;
			case PcodeOp.PTRSUB -> OpBehavior.PTRSUB;

			case PcodeOp.FLOAT_EQUAL -> OpBehavior.FLOAT_EQUAL;
			case PcodeOp.FLOAT_NOTEQUAL -> OpBehavior.FLOAT_NOTEQUAL;
			case PcodeOp.FLOAT_LESS -> OpBehavior.FLOAT_LESS;
			case PcodeOp.FLOAT_LESSEQUAL -> OpBehavior.FLOAT_LESSEQUAL;
			case PcodeOp.FLOAT_NAN -> OpBehavior.FLOAT_NAN;

			case PcodeOp.FLOAT_ADD -> OpBehavior.FLOAT_ADD;
			case PcodeOp.FLOAT_DIV -> OpBehavior.FLOAT_DIV;
			case PcodeOp.FLOAT_MULT -> OpBehavior.FLOAT_MULT;
			case PcodeOp.FLOAT_SUB -> OpBehavior.FLOAT_SUB;
			case PcodeOp.FLOAT_NEG -> OpBehavior.FLOAT_NEG;
			case PcodeOp.FLOAT_ABS -> OpBehavior.FLOAT_ABS;
			case PcodeOp.FLOAT_SQRT -> OpBehavior.FLOAT_SQRT;

			case PcodeOp.FLOAT_INT2FLOAT -> OpBehavior.FLOAT_INT2FLOAT;
			case PcodeOp.FLOAT_FLOAT2FLOAT -> OpBehavior.FLOAT_FLOAT2FLOAT;
			case PcodeOp.FLOAT_TRUNC -> OpBehavior.FLOAT_TRUNC;
			case PcodeOp.FLOAT_CEIL -> OpBehavior.FLOAT_CEIL;
			case PcodeOp.FLOAT_FLOOR -> OpBehavior.FLOAT_FLOOR;
			case PcodeOp.FLOAT_ROUND -> OpBehavior.FLOAT_ROUND;
			case PcodeOp.SEGMENTOP -> OpBehavior.SEGMENTOP;
			case PcodeOp.CPOOLREF -> OpBehavior.CPOOLREF;
			case PcodeOp.NEW -> OpBehavior.NEW;
			case PcodeOp.INSERT -> OpBehavior.INSERT;
			case PcodeOp.ZPULL -> OpBehavior.ZPULL;
			case PcodeOp.POPCOUNT -> OpBehavior.POPCOUNT;
			case PcodeOp.LZCOUNT -> OpBehavior.LZCOUNT;
			case PcodeOp.SPULL -> OpBehavior.SPULL;

			default -> null;
		};
	}
}
