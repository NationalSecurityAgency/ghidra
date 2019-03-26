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
package ghidra.app.plugin.assembler.sleigh.expr;

import ghidra.app.plugin.processors.sleigh.expression.MinusExpression;

/**
 * Solves expressions of the form -A
 */
public class MinusExpressionSolver extends AbstractUnaryExpressionSolver<MinusExpression> {

	public MinusExpressionSolver() {
		super(MinusExpression.class);
	}

	@Override
	public MaskedLong compute(MaskedLong val) {
		return val.negate();
	}
}
