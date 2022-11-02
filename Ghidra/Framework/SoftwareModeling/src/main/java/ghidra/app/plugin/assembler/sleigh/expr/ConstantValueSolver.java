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

import java.util.Map;
import java.util.Set;

import ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolution;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns;
import ghidra.app.plugin.processors.sleigh.expression.ConstantValue;

/**
 * "Solves" constant expressions
 * 
 * <p>
 * Essentially, this either evaluates successfully when asked for a constant value, or checks that
 * the goal is equal to the constant. Otherwise, there is no solution.
 */
public class ConstantValueSolver extends AbstractExpressionSolver<ConstantValue> {

	public ConstantValueSolver() {
		super(ConstantValue.class);
	}

	@Override
	public AssemblyResolution solve(ConstantValue cv, MaskedLong goal, Map<String, Long> vals,
			AssemblyResolvedPatterns cur, Set<SolverHint> hints,
			String description) {
		MaskedLong value = getValue(cv, vals, cur);
		return checkConstAgrees(value, goal, description);
	}

	@Override
	public MaskedLong getValue(ConstantValue cv, Map<String, Long> vals,
			AssemblyResolvedPatterns cur) {
		return MaskedLong.fromLong(cv.getValue());
	}

	@Override
	public int getInstructionLength(ConstantValue cv) {
		return 0;
	}

	@Override
	public MaskedLong valueForResolution(ConstantValue cv, Map<String, Long> vals,
			AssemblyResolvedPatterns rc) {
		return MaskedLong.fromLong(cv.getValue());
	}

	static AssemblyResolution checkConstAgrees(MaskedLong value, MaskedLong goal,
			String description) {
		if (!value.agrees(goal)) {
			return AssemblyResolution.error(
				"Constant value " + value + " does not agree with child requirements", description);
		}
		return AssemblyResolution.nop(description, null, null);
	}
}
