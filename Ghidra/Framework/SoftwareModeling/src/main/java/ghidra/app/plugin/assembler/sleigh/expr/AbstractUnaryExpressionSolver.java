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
import ghidra.app.plugin.processors.sleigh.expression.UnaryExpression;

/**
 * A solver that handles expressions of the form {@code [OP]A}
 * 
 * @param <T> the type of expression solved (the operator)
 */
public abstract class AbstractUnaryExpressionSolver<T extends UnaryExpression>
		extends AbstractExpressionSolver<T> {

	public AbstractUnaryExpressionSolver(Class<T> tcls) {
		super(tcls);
	}

	@Override
	public AssemblyResolution solve(T exp, MaskedLong goal, Map<String, Long> vals,
			AssemblyResolvedPatterns cur, Set<SolverHint> hints, String description)
			throws NeedsBackfillException {
		MaskedLong uval = solver.getValue(exp.getUnary(), vals, cur);
		try {
			if (uval != null && uval.isFullyDefined()) {
				MaskedLong cval = compute(uval);
				if (cval != null) {
					return ConstantValueSolver.checkConstAgrees(cval, goal, description);
				}
			}
			return solver.solve(exp.getUnary(), computeInverse(goal), vals, cur, hints,
				description);
		}
		/*
		 * catch (NeedsBackfillException e) { throw e; } catch (SolverException e) { return
		 * AssemblyResolvedConstructor.error(e.getMessage(), description, null); }
		 */
		catch (AssertionError e) {
			dbg.println("While solving: " + exp + " (" + description + ")");
			throw e;
		}
	}

	@Override
	public MaskedLong getValue(T exp, Map<String, Long> vals, AssemblyResolvedPatterns cur)
			throws NeedsBackfillException {
		MaskedLong val = solver.getValue(exp.getUnary(), vals, cur);
		if (val != null) {
			return compute(val);
		}
		return null;
	}

	/**
	 * Compute the input value given that the result is known
	 * 
	 * <p>
	 * <b>NOTE:</b> Assumes an involution by default
	 * 
	 * @param goal the result
	 * @return the input value solution
	 */
	public MaskedLong computeInverse(MaskedLong goal) {
		return compute(goal);
	}

	/**
	 * Compute the result of applying the operator to the given value
	 * 
	 * @param val the input value
	 * @return the result
	 */
	public abstract MaskedLong compute(MaskedLong val);

	@Override
	public int getInstructionLength(T exp) {
		return solver.getInstructionLength(exp.getUnary());
	}

	@Override
	public MaskedLong valueForResolution(T exp, Map<String, Long> vals,
			AssemblyResolvedPatterns rc) {
		MaskedLong val = solver.valueForResolution(exp.getUnary(), vals, rc);
		return compute(val);
	}
}
