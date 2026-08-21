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

import ghidra.lisa.pcode.contexts.TernaryExprContext;
import ghidra.lisa.pcode.statements.PcodeTernaryOperator;
import it.unive.lisa.analysis.*;
import it.unive.lisa.interprocedural.InterproceduralAnalysis;
import it.unive.lisa.program.cfg.CFG;
import it.unive.lisa.program.cfg.statement.Expression;
import it.unive.lisa.program.cfg.statement.Statement;
import it.unive.lisa.symbolic.SymbolicExpression;
import it.unive.lisa.symbolic.value.TernaryExpression;
import it.unive.lisa.symbolic.value.operator.ternary.TernaryOperator;

public class PcodeTernaryExpression extends it.unive.lisa.program.cfg.statement.TernaryExpression {

	private TernaryOperator operator;

	public PcodeTernaryExpression(
			CFG cfg,
			TernaryExprContext ctx,
			Expression left,
			Expression middle,
			Expression right) {
		super(cfg, ctx.location(), ctx.mnemonic(), cfg.getDescriptor().getUnit().getProgram().getTypes().getIntegerType(), left, middle, right);

		this.operator = switch (ctx.op.getOpcode()) {
			default -> new PcodeTernaryOperator(ctx.op);
		};
	}

	@Override
	protected int compareSameClassAndParams(
			Statement o) {
		return 0; // no extra fields to compare
	}

	@Override
	public <A extends AbstractState<A>> AnalysisState<A> fwdTernarySemantics(
			InterproceduralAnalysis<A> interprocedural,
			AnalysisState<A> state,
			SymbolicExpression left,
			SymbolicExpression middle,
			SymbolicExpression right,
			StatementStore<A> expressions)
			throws SemanticException {

		return state.smallStepSemantics(
				new TernaryExpression(
						getStaticType(),
						left,
						middle,
						right,
						operator,
						getLocation()),
				this);
	}
}
