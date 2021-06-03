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
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedConstructor;
import ghidra.app.plugin.processors.sleigh.expression.BinaryExpression;
import ghidra.app.plugin.processors.sleigh.expression.PatternExpression;

/**
 * A solver that handles expressions of the form A [OP] B
 *
 * @param <T> the type of expression solved (the operator)
 */
public abstract class AbstractBinaryExpressionSolver<T extends BinaryExpression>
		extends AbstractExpressionSolver<T> {

	public AbstractBinaryExpressionSolver(Class<T> tcls) {
		super(tcls);
	}

	@Override
	public AssemblyResolution solve(T exp, MaskedLong goal, Map<String, Long> vals,
			Map<Integer, Object> res, AssemblyResolvedConstructor cur, Set<SolverHint> hints,
			String description) throws NeedsBackfillException {
		MaskedLong lval = solver.getValue(exp.getLeft(), vals, res, cur);
		MaskedLong rval = solver.getValue(exp.getRight(), vals, res, cur);

		if (lval != null && !lval.isFullyDefined()) {
			if (!lval.isFullyUndefined()) {
				dbg.println("Partially-defined left value for binary solver: " + lval);
			}
			lval = null;
		}
		if (rval != null && !rval.isFullyDefined()) {
			if (!rval.isFullyUndefined()) {
				dbg.println("Partially-defined right value for binary solver: " + rval);
			}
			rval = null;
		}

		try {
			if (lval != null && rval != null) {
				MaskedLong cval = compute(lval, rval);
				return ConstantValueSolver.checkConstAgrees(cval, goal, description);
			}
			else if (lval != null) {
				return solveRightSide(exp.getRight(), lval, goal, vals, res, cur, hints,
					description);
			}
			else if (rval != null) {
				return solveLeftSide(exp.getLeft(), rval, goal, vals, res, cur, hints, description);
			}
			else {
				// Each solver may provide a strategy for solving expression where both sides are
				// variable, e.g., two fields being concatenated via OR.
				return solveTwoSided(exp, goal, vals, res, cur, hints, description);
			}
		}
		catch (NeedsBackfillException e) {
			throw e;
		}
		catch (SolverException e) {
			return AssemblyResolution.error(e.getMessage(), description, null);
		}
		catch (AssertionError e) {
			dbg.println("While solving: " + exp + " (" + description + ")");
			throw e;
		}
	}

	protected AssemblyResolution solveLeftSide(PatternExpression lexp, MaskedLong rval,
			MaskedLong goal, Map<String, Long> vals, Map<Integer, Object> res,
			AssemblyResolvedConstructor cur, Set<SolverHint> hints, String description)
			throws NeedsBackfillException, SolverException {
		return solver.solve(lexp, computeLeft(rval, goal), vals, res, cur, hints, description);
	}

	protected AssemblyResolution solveRightSide(PatternExpression rexp, MaskedLong lval,
			MaskedLong goal, Map<String, Long> vals, Map<Integer, Object> res,
			AssemblyResolvedConstructor cur, Set<SolverHint> hints, String description)
			throws NeedsBackfillException, SolverException {
		return solver.solve(rexp, computeRight(lval, goal), vals, res, cur, hints, description);
	}

	protected AssemblyResolution solveTwoSided(T exp, MaskedLong goal, Map<String, Long> vals,
			Map<Integer, Object> res, AssemblyResolvedConstructor cur, Set<SolverHint> hints,
			String description) throws NeedsBackfillException, SolverException {
		throw new NeedsBackfillException("_two_sided_");
	}

	@Override
	public MaskedLong getValue(T exp, Map<String, Long> vals, Map<Integer, Object> res,
			AssemblyResolvedConstructor cur) throws NeedsBackfillException {
		MaskedLong lval = solver.getValue(exp.getLeft(), vals, res, cur);
		MaskedLong rval = solver.getValue(exp.getRight(), vals, res, cur);
		if (lval != null && rval != null) {
			MaskedLong cval = compute(lval, rval);
			return cval;
		}
		return null;
	}

	/**
	 * Compute the left-hand-side value given that the result and the right are known
	 * 
	 * @param rval the right-hand-side value
	 * @param goal the result
	 * @return the left-hand-side value solution
	 * @throws SolverException if the expression cannot be solved
	 */
	public abstract MaskedLong computeLeft(MaskedLong rval, MaskedLong goal) throws SolverException;

	/**
	 * Compute the right-hand-side value given that the result and the left are known
	 * 
	 * NOTE: Assumes commutativity by default
	 * @param lval the left-hand-side value
	 * @param goal the result
	 * @return the right-hand-side value solution
	 * @throws SolverException if the expression cannot be solved
	 */
	public MaskedLong computeRight(MaskedLong lval, MaskedLong goal) throws SolverException {
		return computeLeft(lval, goal);
	}

	/**
	 * Compute the result of applying the operator to the two given values
	 * 
	 * @param lval the left-hand-side value
	 * @param rval the right-hand-side value
	 * @return the result
	 */
	public abstract MaskedLong compute(MaskedLong lval, MaskedLong rval);

	@Override
	public int getInstructionLength(T exp, Map<Integer, Object> res) {
		int ll = solver.getInstructionLength(exp.getLeft(), res);
		int lr = solver.getInstructionLength(exp.getRight(), res);
		return Math.max(ll, lr);
	}

	@Override
	public MaskedLong valueForResolution(T exp, AssemblyResolvedConstructor rc) {
		MaskedLong lval = solver.valueForResolution(exp.getLeft(), rc);
		MaskedLong rval = solver.valueForResolution(exp.getRight(), rc);
		return compute(lval, rval);
	}
}
