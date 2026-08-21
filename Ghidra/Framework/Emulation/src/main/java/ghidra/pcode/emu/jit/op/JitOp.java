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
package ghidra.pcode.emu.jit.op;

import java.util.List;

import ghidra.pcode.emu.jit.JitPassage.NopPcodeOp;
import ghidra.pcode.emu.jit.analysis.JitTypeBehavior;
import ghidra.pcode.emu.jit.gen.op.OpGen;
import ghidra.pcode.emu.jit.var.*;
import ghidra.program.model.pcode.PcodeOp;

/**
 * A p-code operator use-def node.
 * 
 * <p>
 * For a table of p-code ops, use-def nodes, and code generators, see {@link OpGen}.
 */
public interface JitOp {
	/**
	 * Create a use-def node for a nop or unimplemented op.
	 * 
	 * @param op the p-code op
	 * @return the use-def node
	 */
	static JitOp stubOp(PcodeOp op) {
		if (op instanceof NopPcodeOp) {
			return new JitNopOp(op);
		}
		return switch (op.getOpcode()) {
			case PcodeOp.UNIMPLEMENTED -> new JitUnimplementedOp(op);
			default -> throw new UnsupportedOperationException(
				"Unrecognized stub op: " + op.getMnemonic());
		};
	}

	/**
	 * Create a use-def node for a unary p-coe op
	 * 
	 * @param op the p-code op
	 * @param out the (pre-made) output operand use-def node
	 * @param u the input operand use-def node
	 * @return the use-def node
	 */
	static JitUnOp unOp(PcodeOp op, JitOutVar out, JitVal u) {
		return switch (op.getOpcode()) {
			case PcodeOp.COPY -> new JitCopyOp(op, out, u);

			case PcodeOp.INT_ZEXT -> new JitIntZExtOp(op, out, u);
			case PcodeOp.INT_SEXT -> new JitIntSExtOp(op, out, u);
			case PcodeOp.INT_2COMP -> new JitInt2CompOp(op, out, u);
			case PcodeOp.INT_NEGATE -> new JitIntNegateOp(op, out, u);

			case PcodeOp.POPCOUNT -> new JitPopCountOp(op, out, u);
			case PcodeOp.LZCOUNT -> new JitLzCountOp(op, out, u);

			case PcodeOp.BOOL_NEGATE -> new JitBoolNegateOp(op, out, u);

			case PcodeOp.FLOAT_NAN -> new JitFloatNaNOp(op, out, u);
			case PcodeOp.FLOAT_NEG -> new JitFloatNegOp(op, out, u);
			case PcodeOp.FLOAT_ABS -> new JitFloatAbsOp(op, out, u);
			case PcodeOp.FLOAT_SQRT -> new JitFloatSqrtOp(op, out, u);

			case PcodeOp.FLOAT_INT2FLOAT -> new JitFloatInt2FloatOp(op, out, u);
			case PcodeOp.FLOAT_FLOAT2FLOAT -> new JitFloatFloat2FloatOp(op, out, u);
			case PcodeOp.FLOAT_TRUNC -> new JitFloatTruncOp(op, out, u);
			case PcodeOp.FLOAT_CEIL -> new JitFloatCeilOp(op, out, u);
			case PcodeOp.FLOAT_FLOOR -> new JitFloatFloorOp(op, out, u);
			case PcodeOp.FLOAT_ROUND -> new JitFloatRoundOp(op, out, u);

			default -> throw new UnsupportedOperationException(
				"Unrecognized un op: " + op.getMnemonic());
		};
	}

	/**
	 * Create a use-def node for a binary p-coe op
	 * 
	 * @param op the p-code op
	 * @param out the (pre-made) output operand use-def node
	 * @param l the left input operand use-def node
	 * @param r the right input operand use-def node
	 * @return the use-def node
	 */
	static JitDefOp binOp(PcodeOp op, JitOutVar out, JitVal l, JitVal r) {
		return switch (op.getOpcode()) {
			case PcodeOp.INT_EQUAL -> new JitIntEqualOp(op, out, l, r);
			case PcodeOp.INT_NOTEQUAL -> new JitIntNotEqualOp(op, out, l, r);
			case PcodeOp.INT_SLESS -> new JitIntSLessOp(op, out, l, r);
			case PcodeOp.INT_SLESSEQUAL -> new JitIntSLessEqualOp(op, out, l, r);
			case PcodeOp.INT_LESS -> new JitIntLessOp(op, out, l, r);
			case PcodeOp.INT_LESSEQUAL -> new JitIntLessEqualOp(op, out, l, r);
			case PcodeOp.INT_ADD -> new JitIntAddOp(op, out, l, r);
			case PcodeOp.INT_SUB -> new JitIntSubOp(op, out, l, r);
			case PcodeOp.INT_CARRY -> new JitIntCarryOp(op, out, l, r);
			case PcodeOp.INT_SCARRY -> new JitIntSCarryOp(op, out, l, r);
			case PcodeOp.INT_SBORROW -> new JitIntSBorrowOp(op, out, l, r);
			case PcodeOp.INT_XOR -> new JitIntXorOp(op, out, l, r);
			case PcodeOp.INT_AND -> new JitIntAndOp(op, out, l, r);
			case PcodeOp.INT_OR -> new JitIntOrOp(op, out, l, r);
			case PcodeOp.INT_LEFT -> new JitIntLeftOp(op, out, l, r);
			case PcodeOp.INT_RIGHT -> new JitIntRightOp(op, out, l, r);
			case PcodeOp.INT_SRIGHT -> new JitIntSRightOp(op, out, l, r);
			case PcodeOp.INT_MULT -> new JitIntMultOp(op, out, l, r);
			case PcodeOp.INT_DIV -> new JitIntDivOp(op, out, l, r);
			case PcodeOp.INT_SDIV -> new JitIntSDivOp(op, out, l, r);
			case PcodeOp.INT_REM -> new JitIntRemOp(op, out, l, r);
			case PcodeOp.INT_SREM -> new JitIntSRemOp(op, out, l, r);

			case PcodeOp.BOOL_XOR -> new JitBoolXorOp(op, out, l, r);
			case PcodeOp.BOOL_AND -> new JitBoolAndOp(op, out, l, r);
			case PcodeOp.BOOL_OR -> new JitBoolOrOp(op, out, l, r);

			case PcodeOp.FLOAT_EQUAL -> new JitFloatEqualOp(op, out, l, r);
			case PcodeOp.FLOAT_NOTEQUAL -> new JitFloatNotEqualOp(op, out, l, r);
			case PcodeOp.FLOAT_LESS -> new JitFloatLessOp(op, out, l, r);
			case PcodeOp.FLOAT_LESSEQUAL -> new JitFloatLessEqualOp(op, out, l, r);

			case PcodeOp.FLOAT_ADD -> new JitFloatAddOp(op, out, l, r);
			case PcodeOp.FLOAT_DIV -> new JitFloatDivOp(op, out, l, r);
			case PcodeOp.FLOAT_MULT -> new JitFloatMultOp(op, out, l, r);
			case PcodeOp.FLOAT_SUB -> new JitFloatSubOp(op, out, l, r);

			case PcodeOp.SUBPIECE -> new JitSubPieceOp(op, out, l,
				((JitConstVal) r).value().intValue());

			default -> throw new UnsupportedOperationException(
				"Unrecognized bin op: " + op.getMnemonic());
		};
	}

	/**
	 * The p-code op represented by this use-def node
	 * 
	 * @return the p-code op
	 */
	PcodeOp op();

	/**
	 * Indicates the operation can be removed if its output is never used.
	 * 
	 * @return true if removable
	 */
	boolean canBeRemoved();

	/**
	 * The input operand use-def nodes in some defined order
	 * 
	 * @return the list of inputs
	 */
	List<JitVal> inputs();

	/**
	 * Get the required type behavior for the input at the given position in {@link #inputs()}
	 * 
	 * @param position the input position
	 * @return the behavior
	 */
	JitTypeBehavior typeFor(int position);

	/**
	 * Add this op to the {@link JitVal#uses()} of each input operand, and (if applicable) set the
	 * {@link JitOutVar#definition()} of the output operand to this op.
	 */
	void link();

	/**
	 * Remove this op from the {@link JitVal#uses()} of each input operand, and (if applicable)
	 * unset the {@link JitOutVar#definition()} of the output operand.
	 */
	void unlink();
}
