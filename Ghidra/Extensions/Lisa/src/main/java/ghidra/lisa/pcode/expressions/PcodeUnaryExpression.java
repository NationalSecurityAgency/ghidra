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

import ghidra.lisa.pcode.contexts.UnaryExprContext;
import ghidra.lisa.pcode.statements.PcodeUnaryOperator;
import it.unive.lisa.analysis.*;
import it.unive.lisa.interprocedural.InterproceduralAnalysis;
import it.unive.lisa.program.cfg.CFG;
import it.unive.lisa.program.cfg.statement.Expression;
import it.unive.lisa.program.cfg.statement.Statement;
import it.unive.lisa.symbolic.SymbolicExpression;
import it.unive.lisa.symbolic.value.UnaryExpression;
import it.unive.lisa.symbolic.value.operator.unary.UnaryOperator;

public class PcodeUnaryExpression extends it.unive.lisa.program.cfg.statement.UnaryExpression {

	private UnaryOperator operator;

	public PcodeUnaryExpression(
			CFG cfg,
			UnaryExprContext ctx,
			Expression expression) {
		super(cfg, ctx.location(), ctx.mnemonic(), expression);
		this.operator = new PcodeUnaryOperator(ctx.op);
	}

	@Override
	protected int compareSameClassAndParams(
			Statement o) {
		return 0; // no extra fields to compare
	}

	@Override
	public <A extends AbstractState<A>> AnalysisState<A> fwdUnarySemantics(
			InterproceduralAnalysis<A> interprocedural,
			AnalysisState<A> state,
			SymbolicExpression expr,
			StatementStore<A> expressions)
			throws SemanticException {

		return state.smallStepSemantics(
			new UnaryExpression(
				expr.getStaticType(),
				expr,
				operator,
				getLocation()),
			this);
	}
}
