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

/**
 * The implementation of a p-code opcode
 */
public interface OpBehavior {
	OpBehaviorCopy COPY = OpBehaviorCopy.OP_COPY;
	SpecialOpBehavior LOAD = SpecialOpBehavior.OP_LOAD;
	SpecialOpBehavior STORE = SpecialOpBehavior.OP_STORE;
	SpecialOpBehavior BRANCH = SpecialOpBehavior.OP_BRANCH;
	SpecialOpBehavior CBRANCH = SpecialOpBehavior.OP_CBRANCH;
	SpecialOpBehavior BRANCHIND = SpecialOpBehavior.OP_BRANCHIND;
	SpecialOpBehavior CALL = SpecialOpBehavior.OP_CALL;
	SpecialOpBehavior CALLIND = SpecialOpBehavior.OP_CALLIND;
	SpecialOpBehavior CALLOTHER = SpecialOpBehavior.OP_CALLOTHER;
	SpecialOpBehavior RETURN = SpecialOpBehavior.OP_RETURN;

	SpecialOpBehavior MULTIEQUAL = SpecialOpBehavior.OP_BRANCH;
	SpecialOpBehavior INDIRECT = SpecialOpBehavior.OP_BRANCH;

	OpBehaviorPiece PIECE = OpBehaviorPiece.OP_PIECE;
	OpBehaviorSubpiece SUBPIECE = OpBehaviorSubpiece.OP_SUBPIECE;
	OpBehaviorEqual INT_EQUAL = OpBehaviorEqual.OP_INT_EQUAL;
	OpBehaviorNotEqual INT_NOTEQUAL = OpBehaviorNotEqual.OP_INT_NOTEQUAL;
	OpBehaviorIntLess INT_LESS = OpBehaviorIntLess.OP_INT_LESS;
	OpBehaviorIntLessEqual INT_LESSEQUAL = OpBehaviorIntLessEqual.OP_INT_LESSEQUAL;
	OpBehaviorIntSless INT_SLESS = OpBehaviorIntSless.OP_INT_SLESS;
	OpBehaviorIntSlessEqual INT_SLESSEQUAL = OpBehaviorIntSlessEqual.OP_INT_SLESSEQUAL;
	OpBehaviorIntZext INT_ZEXT = OpBehaviorIntZext.OP_INT_ZEXT;
	OpBehaviorIntSext INT_SEXT = OpBehaviorIntSext.OP_INT_SEXT;
	OpBehaviorIntAdd INT_ADD = OpBehaviorIntAdd.OP_INT_ADD;
	OpBehaviorIntSub INT_SUB = OpBehaviorIntSub.OP_INT_SUB;
	OpBehaviorIntCarry INT_CARRY = OpBehaviorIntCarry.OP_INT_CARRY;
	OpBehaviorIntScarry INT_SCARRY = OpBehaviorIntScarry.OP_INT_SCARRY;
	OpBehaviorIntSborrow INT_SBORROW = OpBehaviorIntSborrow.OP_INT_SBORROW;
	OpBehaviorInt2Comp INT_2COMP = OpBehaviorInt2Comp.OP_INT_2COMP;
	OpBehaviorIntNegate INT_NEGATE = OpBehaviorIntNegate.OP_INT_NEGATE;
	OpBehaviorIntXor INT_XOR = OpBehaviorIntXor.OP_INT_XOR;
	OpBehaviorIntAnd INT_AND = OpBehaviorIntAnd.OP_INT_AND;
	OpBehaviorIntOr INT_OR = OpBehaviorIntOr.OP_INT_OR;
	OpBehaviorIntLeft INT_LEFT = OpBehaviorIntLeft.OP_INT_LEFT;
	OpBehaviorIntRight INT_RIGHT = OpBehaviorIntRight.OP_INT_RIGHT;
	OpBehaviorIntSright INT_SRIGHT = OpBehaviorIntSright.OP_INT_SRIGHT;
	OpBehaviorIntMult INT_MULT = OpBehaviorIntMult.OP_INT_MULT;
	OpBehaviorIntDiv INT_DIV = OpBehaviorIntDiv.OP_INT_DEV;
	OpBehaviorIntSdiv INT_SDIV = OpBehaviorIntSdiv.OP_INT_SDIV;
	OpBehaviorIntRem INT_REM = OpBehaviorIntRem.OP_INT_REM;
	OpBehaviorIntSrem INT_SREM = OpBehaviorIntSrem.OP_INT_SREM;

	OpBehaviorBoolNegate BOOL_NEGATE = OpBehaviorBoolNegate.OP_BOOL_NEGATE;
	OpBehaviorBoolXor BOOL_XOR = OpBehaviorBoolXor.OP_BOOL_XOR;
	OpBehaviorBoolAnd BOOL_AND = OpBehaviorBoolAnd.OP_BOOL_AND;
	OpBehaviorBoolOr BOOL_OR = OpBehaviorBoolOr.OP_BOOL_OR;

	SpecialOpBehavior CAST = SpecialOpBehavior.OP_CAST;
	SpecialOpBehavior PTRADD = SpecialOpBehavior.OP_PTRADD;
	SpecialOpBehavior PTRSUB = SpecialOpBehavior.OP_PTRSUB;

	OpBehaviorFloatEqual FLOAT_EQUAL = OpBehaviorFloatEqual.OP_FLOAT_EQUAL;
	OpBehaviorFloatNotEqual FLOAT_NOTEQUAL = OpBehaviorFloatNotEqual.OP_FLOAT_NOTEQUAL;
	OpBehaviorFloatLess FLOAT_LESS = OpBehaviorFloatLess.OP_FLOAT_LESS;
	OpBehaviorFloatLessEqual FLOAT_LESSEQUAL = OpBehaviorFloatLessEqual.OP_FLOAT_LESSEQUAL;
	OpBehaviorFloatNan FLOAT_NAN = OpBehaviorFloatNan.OP_FLOAT_NAN;

	OpBehaviorFloatAdd FLOAT_ADD = OpBehaviorFloatAdd.OP_FLOAT_ADD;
	OpBehaviorFloatDiv FLOAT_DIV = OpBehaviorFloatDiv.OP_FLOAT_DIV;
	OpBehaviorFloatMult FLOAT_MULT = OpBehaviorFloatMult.OP_FLOAT_MULT;
	OpBehaviorFloatSub FLOAT_SUB = OpBehaviorFloatSub.OP_FLOAT_SUB;
	OpBehaviorFloatNeg FLOAT_NEG = OpBehaviorFloatNeg.OP_FLOAT_NEG;
	OpBehaviorFloatAbs FLOAT_ABS = OpBehaviorFloatAbs.OP_FLOAT_ABS;
	OpBehaviorFloatSqrt FLOAT_SQRT = OpBehaviorFloatSqrt.OP_FLOAT_SQRT;

	OpBehaviorFloatInt2Float FLOAT_INT2FLOAT = OpBehaviorFloatInt2Float.OP_FLOAT_INT2FLOAT;
	OpBehaviorFloatFloat2Float FLOAT_FLOAT2FLOAT = OpBehaviorFloatFloat2Float.OP_FLOAT_FLOAT2FLOAT;
	OpBehaviorFloatTrunc FLOAT_TRUNC = OpBehaviorFloatTrunc.OP_FLOAT_TRUNC;
	OpBehaviorFloatCeil FLOAT_CEIL = OpBehaviorFloatCeil.OP_FLOAT_CEIL;
	OpBehaviorFloatFloor FLOAT_FLOOR = OpBehaviorFloatFloor.OP_FLOAT_FLOOR;
	OpBehaviorFloatRound FLOAT_ROUND = OpBehaviorFloatRound.OP_FLOAT_ROUND;

	OpBehaviorLzcount LZCOUNT = OpBehaviorLzcount.OP_LZCOUNT;
	OpBehaviorPopcount POPCOUNT = OpBehaviorPopcount.OP_POPCOUNT;

	SpecialOpBehavior SEGMENTOP = SpecialOpBehavior.OP_SEGMENTOP;
	SpecialOpBehavior CPOOLREF = SpecialOpBehavior.OP_CPOOLREF;
	SpecialOpBehavior NEW = SpecialOpBehavior.OP_NEW;
	SpecialOpBehavior INSERT = SpecialOpBehavior.OP_INSERT;
	SpecialOpBehavior ZPULL = SpecialOpBehavior.OP_ZPULL;
	SpecialOpBehavior SPULL = SpecialOpBehavior.OP_SPULL;

	/** {@return the opcode implemented} */
	int opcode();
}
