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
import ghidra.app.plugin.processors.sleigh.expression.RightShiftExpression;
import ghidra.util.Msg;

/**
 * {@literal Solves expressions of the form A >> B}
 */
public class RightShiftExpressionSolver
		extends AbstractBinaryExpressionSolver<RightShiftExpression> {

	public RightShiftExpressionSolver() {
		super(RightShiftExpression.class);
	}

	@Override
	public MaskedLong compute(MaskedLong lval, MaskedLong rval) {
		return lval.shiftRight(rval);
	}

	@Override
	public MaskedLong computeLeft(MaskedLong rval, MaskedLong goal) throws SolverException {
		return goal.invShiftRight(rval);
	}

	@Override
	public MaskedLong computeRight(MaskedLong lval, MaskedLong goal) throws SolverException {
		long acc = 0;
		long bit = 1;
		for (int i = 0; i < 64; i++) {
			if (lval.shiftRight(i).agrees(goal)) {
				acc |= bit;
			}
			bit <<= 1;
		}
		if (Long.bitCount(acc) == 1) {
			return MaskedLong.fromLong(Long.numberOfTrailingZeros(acc));
		}
		throw new SolverException(
			"Cannot solve for the right shift amount: " + goal + " = " + lval + " >> R");
	}

	@Override
	protected AssemblyResolution solveTwoSided(RightShiftExpression exp, MaskedLong goal,
			Map<String, Long> vals, Map<Integer, Object> res, AssemblyResolvedConstructor cur,
			Set<SolverHint> hints, String description)
			throws NeedsBackfillException, SolverException {
		// Do the similar thing as in {@link LeftShiftExpressionSolver}

		// Do not guess the same parameter recursively
		if (hints.contains(DefaultSolverHint.GUESSING_RIGHT_SHIFT_AMOUNT)) {
			// NOTE: Nested right shifts ought to be written as a right shift by a sum
			return super.solveTwoSided(exp, goal, vals, res, cur, hints, description);
		}

		int maxShift = Long.numberOfLeadingZeros(goal.val);
		Set<SolverHint> hintsWithRShift =
			SolverHint.with(hints, DefaultSolverHint.GUESSING_RIGHT_SHIFT_AMOUNT);
		for (int shift = 0; shift <= maxShift; shift++) {
			try {
				MaskedLong reqr = MaskedLong.fromLong(shift);
				MaskedLong reql = computeLeft(reqr, goal);

				AssemblyResolution lres =
					solver.solve(exp.getLeft(), reql, vals, res, cur, hintsWithRShift, description);
				if (lres.isError()) {
					throw new SolverException("Solving left failed");
				}
				AssemblyResolution rres =
					solver.solve(exp.getRight(), reqr, vals, res, cur, hints, description);
				if (rres.isError()) {
					throw new SolverException("Solving right failed");
				}
				AssemblyResolvedConstructor lsol = (AssemblyResolvedConstructor) lres;
				AssemblyResolvedConstructor rsol = (AssemblyResolvedConstructor) rres;
				AssemblyResolvedConstructor sol = lsol.combine(rsol);
				if (sol == null) {
					throw new SolverException(
						"Left and right solutions conflict for shift=" + shift);
				}
				return sol;
			}
			catch (SolverException | UnsupportedOperationException e) {
				Msg.trace(this, "Shift of " + shift + " resulted in " + e);
				// try the next
			}
		}
		return super.solveTwoSided(exp, goal, vals, res, cur, hints, description);
	}
}
