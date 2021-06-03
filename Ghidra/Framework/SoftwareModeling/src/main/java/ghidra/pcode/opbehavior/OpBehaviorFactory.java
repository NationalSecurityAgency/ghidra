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

import java.util.HashMap;
import java.util.Map;

import ghidra.program.model.pcode.PcodeOp;

public class OpBehaviorFactory {

	private static Map<Integer, OpBehavior> opBehaviorMap = new HashMap<Integer, OpBehavior>();
	static {
		// TODO: should pass float format factory

		opBehaviorMap.put(PcodeOp.COPY, new OpBehaviorCopy());
		opBehaviorMap.put(PcodeOp.LOAD, new SpecialOpBehavior(PcodeOp.LOAD));
		opBehaviorMap.put(PcodeOp.STORE, new SpecialOpBehavior(PcodeOp.STORE));
		opBehaviorMap.put(PcodeOp.BRANCH, new SpecialOpBehavior(PcodeOp.BRANCH));
		opBehaviorMap.put(PcodeOp.CBRANCH, new SpecialOpBehavior(PcodeOp.CBRANCH));
		opBehaviorMap.put(PcodeOp.BRANCHIND, new SpecialOpBehavior(PcodeOp.BRANCHIND));
		opBehaviorMap.put(PcodeOp.CALL, new SpecialOpBehavior(PcodeOp.CALL));
		opBehaviorMap.put(PcodeOp.CALLIND, new SpecialOpBehavior(PcodeOp.CALLIND));
		opBehaviorMap.put(PcodeOp.CALLOTHER, new SpecialOpBehavior(PcodeOp.CALLOTHER));
		opBehaviorMap.put(PcodeOp.RETURN, new SpecialOpBehavior(PcodeOp.RETURN));

		opBehaviorMap.put(PcodeOp.MULTIEQUAL, new SpecialOpBehavior(PcodeOp.MULTIEQUAL));
		opBehaviorMap.put(PcodeOp.INDIRECT, new SpecialOpBehavior(PcodeOp.INDIRECT));

		opBehaviorMap.put(PcodeOp.PIECE, new OpBehaviorPiece());
		opBehaviorMap.put(PcodeOp.SUBPIECE, new OpBehaviorSubpiece());
		opBehaviorMap.put(PcodeOp.INT_EQUAL, new OpBehaviorEqual());
		opBehaviorMap.put(PcodeOp.INT_NOTEQUAL, new OpBehaviorNotEqual());
		opBehaviorMap.put(PcodeOp.INT_SLESS, new OpBehaviorIntSless());
		opBehaviorMap.put(PcodeOp.INT_SLESSEQUAL, new OpBehaviorIntSlessEqual());
		opBehaviorMap.put(PcodeOp.INT_LESS, new OpBehaviorIntLess());
		opBehaviorMap.put(PcodeOp.INT_LESSEQUAL, new OpBehaviorIntLessEqual());
		opBehaviorMap.put(PcodeOp.INT_ZEXT, new OpBehaviorIntZext());
		opBehaviorMap.put(PcodeOp.INT_SEXT, new OpBehaviorIntSext());
		opBehaviorMap.put(PcodeOp.INT_ADD, new OpBehaviorIntAdd());
		opBehaviorMap.put(PcodeOp.INT_SUB, new OpBehaviorIntSub());
		opBehaviorMap.put(PcodeOp.INT_CARRY, new OpBehaviorIntCarry());
		opBehaviorMap.put(PcodeOp.INT_SCARRY, new OpBehaviorIntScarry());
		opBehaviorMap.put(PcodeOp.INT_SBORROW, new OpBehaviorIntSborrow());
		opBehaviorMap.put(PcodeOp.INT_2COMP, new OpBehaviorInt2Comp());
		opBehaviorMap.put(PcodeOp.INT_NEGATE, new OpBehaviorIntNegate());
		opBehaviorMap.put(PcodeOp.INT_XOR, new OpBehaviorIntXor());
		opBehaviorMap.put(PcodeOp.INT_AND, new OpBehaviorIntAnd());
		opBehaviorMap.put(PcodeOp.INT_OR, new OpBehaviorIntOr());
		opBehaviorMap.put(PcodeOp.INT_LEFT, new OpBehaviorIntLeft());
		opBehaviorMap.put(PcodeOp.INT_RIGHT, new OpBehaviorIntRight());
		opBehaviorMap.put(PcodeOp.INT_SRIGHT, new OpBehaviorIntSright());
		opBehaviorMap.put(PcodeOp.INT_MULT, new OpBehaviorIntMult());
		opBehaviorMap.put(PcodeOp.INT_DIV, new OpBehaviorIntDiv());
		opBehaviorMap.put(PcodeOp.INT_SDIV, new OpBehaviorIntSdiv());
		opBehaviorMap.put(PcodeOp.INT_REM, new OpBehaviorIntRem());
		opBehaviorMap.put(PcodeOp.INT_SREM, new OpBehaviorIntSrem());

		opBehaviorMap.put(PcodeOp.BOOL_NEGATE, new OpBehaviorBoolNegate());
		opBehaviorMap.put(PcodeOp.BOOL_XOR, new OpBehaviorBoolXor());
		opBehaviorMap.put(PcodeOp.BOOL_AND, new OpBehaviorBoolAnd());
		opBehaviorMap.put(PcodeOp.BOOL_OR, new OpBehaviorBoolOr());

		opBehaviorMap.put(PcodeOp.CAST, new SpecialOpBehavior(PcodeOp.CAST));
		opBehaviorMap.put(PcodeOp.PTRADD, new SpecialOpBehavior(PcodeOp.PTRADD));
		opBehaviorMap.put(PcodeOp.PTRSUB, new SpecialOpBehavior(PcodeOp.PTRSUB));

		opBehaviorMap.put(PcodeOp.FLOAT_EQUAL, new OpBehaviorFloatEqual());
		opBehaviorMap.put(PcodeOp.FLOAT_NOTEQUAL, new OpBehaviorFloatNotEqual());
		opBehaviorMap.put(PcodeOp.FLOAT_LESS, new OpBehaviorFloatLess());
		opBehaviorMap.put(PcodeOp.FLOAT_LESSEQUAL, new OpBehaviorFloatLessEqual());
		opBehaviorMap.put(PcodeOp.FLOAT_NAN, new OpBehaviorFloatNan());

		opBehaviorMap.put(PcodeOp.FLOAT_ADD, new OpBehaviorFloatAdd());
		opBehaviorMap.put(PcodeOp.FLOAT_DIV, new OpBehaviorFloatDiv());
		opBehaviorMap.put(PcodeOp.FLOAT_MULT, new OpBehaviorFloatMult());
		opBehaviorMap.put(PcodeOp.FLOAT_SUB, new OpBehaviorFloatSub());
		opBehaviorMap.put(PcodeOp.FLOAT_NEG, new OpBehaviorFloatNeg());
		opBehaviorMap.put(PcodeOp.FLOAT_ABS, new OpBehaviorFloatAbs());
		opBehaviorMap.put(PcodeOp.FLOAT_SQRT, new OpBehaviorFloatSqrt());

		opBehaviorMap.put(PcodeOp.FLOAT_INT2FLOAT, new OpBehaviorFloatInt2Float());
		opBehaviorMap.put(PcodeOp.FLOAT_FLOAT2FLOAT, new OpBehaviorFloatFloat2Float());
		opBehaviorMap.put(PcodeOp.FLOAT_TRUNC, new OpBehaviorFloatTrunc());
		opBehaviorMap.put(PcodeOp.FLOAT_CEIL, new OpBehaviorFloatCeil());
		opBehaviorMap.put(PcodeOp.FLOAT_FLOOR, new OpBehaviorFloatFloor());
		opBehaviorMap.put(PcodeOp.FLOAT_ROUND, new OpBehaviorFloatRound());
		opBehaviorMap.put(PcodeOp.SEGMENTOP, new SpecialOpBehavior(PcodeOp.SEGMENTOP));
		opBehaviorMap.put(PcodeOp.CPOOLREF, new SpecialOpBehavior(PcodeOp.CPOOLREF));
		opBehaviorMap.put(PcodeOp.NEW, new SpecialOpBehavior(PcodeOp.NEW));
		opBehaviorMap.put(PcodeOp.INSERT, new SpecialOpBehavior(PcodeOp.INSERT));
		opBehaviorMap.put(PcodeOp.EXTRACT, new SpecialOpBehavior(PcodeOp.EXTRACT));
		opBehaviorMap.put(PcodeOp.POPCOUNT, new OpBehaviorPopcount());
	}

	private OpBehaviorFactory() {
	}

	public static OpBehavior getOpBehavior(int opcode) {
		return opBehaviorMap.get(opcode);
	}

}
