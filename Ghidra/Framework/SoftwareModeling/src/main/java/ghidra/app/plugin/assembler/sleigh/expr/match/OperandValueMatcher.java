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
package ghidra.app.plugin.assembler.sleigh.expr.match;

import java.util.Map;

import ghidra.app.plugin.assembler.sleigh.expr.OperandValueSolver;
import ghidra.app.plugin.processors.sleigh.expression.OperandValue;
import ghidra.app.plugin.processors.sleigh.expression.PatternExpression;
import ghidra.app.plugin.processors.sleigh.symbol.OperandSymbol;

/**
 * A matcher for a constructor's operand value, constrained by its defining expression
 */
public class OperandValueMatcher extends AbstractExpressionMatcher<OperandValue> {
	protected final ExpressionMatcher<?> defMatcher;

	public OperandValueMatcher(ExpressionMatcher<?> defMatcher) {
		super(OperandValue.class);
		this.defMatcher = defMatcher;
	}

	@Override
	protected boolean matchDetails(OperandValue expression,
			Map<ExpressionMatcher<?>, PatternExpression> result) {
		OperandSymbol opSym = expression.getConstructor().getOperand(expression.getIndex());
		return defMatcher.match(OperandValueSolver.getDefiningExpression(opSym), result);
	}
}
