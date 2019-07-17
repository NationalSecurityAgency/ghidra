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

import ghidra.app.plugin.processors.sleigh.expression.DivExpression;

/**
 * Solves expressions of the form A / B
 */
public class DivExpressionSolver extends AbstractBinaryExpressionSolver<DivExpression> {

	public DivExpressionSolver() {
		super(DivExpression.class);
	}

	@Override
	public MaskedLong computeLeft(MaskedLong rval, MaskedLong goal) throws SolverException {
		return goal.multiply(rval);
	}

	@Override
	public MaskedLong computeRight(MaskedLong lval, MaskedLong goal) throws SolverException {
		if (lval.equals(goal)) {
			return MaskedLong.fromLong(1);
		}
		throw new SolverException(
			"Encountered a division of the form A / x = B, where A != B. x has many solutions not easily expressed with masking.");
	}

	@Override
	public MaskedLong compute(MaskedLong lval, MaskedLong rval) {
		return lval.divideSigned(rval);
	}
}
