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
package ghidra.lisa.pcode.expressions;

import ghidra.lisa.pcode.contexts.BinaryExprContext;
import ghidra.lisa.pcode.statements.PcodeBinaryOperator;
import ghidra.program.model.pcode.PcodeOp;
import it.unive.lisa.analysis.*;
import it.unive.lisa.interprocedural.InterproceduralAnalysis;
import it.unive.lisa.program.cfg.CFG;
import it.unive.lisa.program.cfg.statement.Expression;
import it.unive.lisa.program.cfg.statement.Statement;
import it.unive.lisa.symbolic.SymbolicExpression;
import it.unive.lisa.symbolic.value.BinaryExpression;
import it.unive.lisa.symbolic.value.operator.binary.*;

public class PcodeBinaryExpression extends it.unive.lisa.program.cfg.statement.BinaryExpression {

	private BinaryOperator operator;

	public PcodeBinaryExpression(
			CFG cfg,
			BinaryExprContext ctx,
			Expression left,
			Expression right) {
		super(cfg, ctx.location(), ctx.mnemonic(),
			cfg.getDescriptor().getUnit().getProgram().getTypes().getIntegerType(), left, right);

		this.operator = switch (ctx.op.getOpcode()) {
			case PcodeOp.BOOL_AND -> LogicalAnd.INSTANCE;
			case PcodeOp.BOOL_OR -> LogicalOr.INSTANCE;
			case PcodeOp.INT_EQUAL, PcodeOp.FLOAT_EQUAL -> ComparisonEq.INSTANCE;
			case PcodeOp.INT_NOTEQUAL, PcodeOp.FLOAT_NOTEQUAL -> ComparisonNe.INSTANCE;
			case PcodeOp.INT_LESSEQUAL, PcodeOp.INT_SLESSEQUAL, PcodeOp.FLOAT_LESSEQUAL -> ComparisonLe.INSTANCE;
			// NB: Some chance we're going to get burned by including SBORROW here
			case PcodeOp.INT_LESS, PcodeOp.INT_SLESS, PcodeOp.INT_SBORROW, PcodeOp.FLOAT_LESS -> ComparisonLt.INSTANCE;
			default -> new PcodeBinaryOperator(ctx.op);
		};
	}

	@Override
	protected int compareSameClassAndParams(
			Statement o) {
		return 0; // no extra fields to compare
	}

	@Override
	public <A extends AbstractState<A>> AnalysisState<A> fwdBinarySemantics(
			InterproceduralAnalysis<A> interprocedural,
			AnalysisState<A> state,
			SymbolicExpression left,
			SymbolicExpression right,
			StatementStore<A> expressions)
			throws SemanticException {

		return state.smallStepSemantics(
			new BinaryExpression(
				getStaticType(),
				left,
				right,
				getOperator(),
				getLocation()),
			this);
	}

	public BinaryOperator getOperator() {
		return operator;
	}
}
