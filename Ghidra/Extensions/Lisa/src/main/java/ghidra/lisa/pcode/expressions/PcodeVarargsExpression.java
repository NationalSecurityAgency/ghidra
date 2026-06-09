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

import ghidra.lisa.pcode.contexts.VarargsExprContext;
import it.unive.lisa.analysis.*;
import it.unive.lisa.analysis.lattices.ExpressionSet;
import it.unive.lisa.interprocedural.InterproceduralAnalysis;
import it.unive.lisa.program.cfg.CFG;
import it.unive.lisa.program.cfg.statement.Expression;
import it.unive.lisa.program.cfg.statement.Statement;
import it.unive.lisa.symbolic.SymbolicExpression;
import it.unive.lisa.symbolic.value.BinaryExpression;
import it.unive.lisa.symbolic.value.operator.binary.LogicalOr;

public class PcodeVarargsExpression extends it.unive.lisa.program.cfg.statement.NaryExpression {

	public PcodeVarargsExpression(CFG cfg, 
			VarargsExprContext ctx, 
			Expression[] exps) {
		super(cfg, ctx.location(), ctx.mnemonic(), cfg.getDescriptor().getUnit().getProgram().getTypes().getIntegerType(), exps);
	}

	@Override
	protected int compareSameClassAndParams(
			Statement o) {
		return 0; // no extra fields to compare
	}

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
				LogicalOr.INSTANCE,
				getLocation()),
			this);
	}

	@Override
	public <A extends AbstractState<A>> AnalysisState<A> forwardSemanticsAux(
			InterproceduralAnalysis<A> interprocedural,
			AnalysisState<A> state,
			ExpressionSet[] params,
			StatementStore<A> expressions)
			throws SemanticException {
		AnalysisState<A> result = state.bottom();
		for (SymbolicExpression expBase : params[0]) {
			for (int i = 1; i < params.length; i++) {
				for (SymbolicExpression exp : params[i]) {
					//result = result.lub(state.smallStepSemantics(exp, this));
					result = result.lub(
						fwdBinarySemantics(interprocedural, state, expBase, exp, expressions));
				}
			}
		}
		return result;
	}
	
}
