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
import ghidra.app.plugin.processors.sleigh.expression.MultExpression;
import ghidra.app.plugin.processors.sleigh.expression.PatternExpression;

/**
 * Solves expressions of the form A * B
 */
public class MultExpressionSolver extends AbstractBinaryExpressionSolver<MultExpression> {

	private interface SolverFunc {
		AssemblyResolution solve() throws NeedsBackfillException, SolverException;
	}

	private static class ResultTracker {
		// Only one of these backfill things may be set, and only once
		AssemblyResolution firstBackfillRes = null;
		NeedsBackfillException firstBackfillExc = null;
		// Only one of these error things may be set, and only once
		AssemblyResolution firstErrorRes = null;
		Throwable firstErrorExc = null;

		AssemblyResolution trySolverFunc(SolverFunc func) {
			try {
				AssemblyResolution sol = func.solve();
				if (sol == null) {
					return null;
				}
				if (sol.isBackfill()) {
					if (firstBackfillRes == null && firstBackfillExc == null) {
						firstBackfillRes = sol;
					}
				}
				else if (sol.isError()) {
					if (firstErrorRes == null && firstErrorExc == null) {
						firstErrorRes = sol;
					}
				}
				else {
					return sol;
				}
			}
			catch (NeedsBackfillException e) {
				if (firstBackfillRes == null && firstBackfillExc == null) {
					firstBackfillExc = e;
				}
			}
			catch (SolverException | UnsupportedOperationException e) {
				if (firstErrorRes == null && firstErrorExc == null) {
					firstErrorExc = e;
				}
			}
			return null;
		}

		AssemblyResolution returnBest(MaskedLong rval, MaskedLong goal)
				throws NeedsBackfillException, SolverException {
			if (firstBackfillExc != null) {
				throw firstBackfillExc;
			}
			if (firstBackfillRes != null) {
				return firstBackfillRes;
			}
			if (firstErrorExc != null && firstErrorExc instanceof SolverException) {
				throw (SolverException) firstErrorExc;
			}
			if (firstErrorExc != null && firstErrorExc instanceof UnsupportedOperationException) {
				throw (UnsupportedOperationException) firstErrorExc;
			}
			if (firstErrorExc != null) {
				throw new AssertionError();
			}
			if (firstErrorRes != null) {
				return firstErrorRes;
			}
			throw new SolverException(
				"Encountered unsolvable multiplication: " + rval + "*x = " + goal);
		}
	}

	public MultExpressionSolver() {
		super(MultExpression.class);
	}

	protected AssemblyResolution tryRep(PatternExpression lexp, MaskedLong rval, MaskedLong repGoal,
			MaskedLong goal, Map<String, Long> vals, Map<Integer, Object> res,
			AssemblyResolvedConstructor cur, Set<SolverHint> hints, String description)
			throws NeedsBackfillException {
		MaskedLong lval = repGoal.divideUnsigned(rval);
		if (lval.multiply(rval).agrees(goal)) {
			return solver.solve(lexp, lval, vals, res, cur, hints, description);
		}
		return null;
	}

	@Override
	protected AssemblyResolution solveLeftSide(PatternExpression lexp, MaskedLong rval,
			MaskedLong goal, Map<String, Long> vals, Map<Integer, Object> res,
			AssemblyResolvedConstructor cur, Set<SolverHint> hints, String description)
			throws NeedsBackfillException, SolverException {
		// Try the usual case first
		ResultTracker tracker = new ResultTracker();
		AssemblyResolution sol = tracker.trySolverFunc(() -> {
			return super.solveLeftSide(lexp, rval, goal, vals, res, cur, hints, description);
		});
		if (sol != null) {
			return sol;
		}

		if (hints.contains(DefaultSolverHint.GUESSING_REPETITION)) {
			return tracker.returnBest(rval, goal);
		}

		// Handle case of using multiplication for repeating fields
		int unksToRight = Long.numberOfTrailingZeros(goal.msk);
		int unksToLeft = Long.numberOfLeadingZeros(goal.msk);
		int numBitsKnown = Long.SIZE - unksToRight - unksToLeft;
		if (Long.bitCount(goal.msk) == numBitsKnown) { // All bits counted
			Set<SolverHint> hintsWithRepetition =
				SolverHint.with(hints, DefaultSolverHint.GUESSING_REPETITION);
			// Assume right truncation
			// Need to fill all bits to the right in order to divide
			int reps = (unksToRight + numBitsKnown - 1) / numBitsKnown;
			long repMsk = goal.msk;
			long repVal = goal.val;

			for (int i = 0; i < reps; i++) {
				repMsk = (repMsk >>> numBitsKnown) | repMsk;
				repVal = (repVal >>> numBitsKnown) | repVal;
			}
			if (reps > 0) {
				MaskedLong repRightGoal = MaskedLong.fromMaskAndValue(repMsk, repVal);
				sol = tracker.trySolverFunc(() -> {
					return tryRep(lexp, rval, repRightGoal, goal, vals, res, cur,
						hintsWithRepetition, description);
				});
				if (sol != null) {
					return sol;
				}
			}

			// Assume right and left truncation
			// Fill value bits all the way to left, then try adding one mask bit at a time
			reps = (unksToLeft + numBitsKnown - 1) / numBitsKnown;
			for (int i = 0; i < reps; i++) {
				repVal = (repVal << numBitsKnown) | repVal;
			}
			for (int i = unksToLeft - 1; i >= 0; i--) {
				repMsk = -1L >>> i;
				MaskedLong repLeftGoal = MaskedLong.fromMaskAndValue(repMsk, repVal);
				sol = tracker.trySolverFunc(() -> {
					return tryRep(lexp, rval, repLeftGoal, goal, vals, res, cur,
						hintsWithRepetition, description);
				});
				if (sol != null) {
					return sol;
				}
			}
		}
		return tracker.returnBest(rval, goal);
	}

	@Override
	protected AssemblyResolution solveRightSide(PatternExpression rexp, MaskedLong lval,
			MaskedLong goal, Map<String, Long> vals, Map<Integer, Object> res,
			AssemblyResolvedConstructor cur, Set<SolverHint> hints, String description)
			throws NeedsBackfillException, SolverException {
		return solveLeftSide(rexp, lval, goal, vals, res, cur, hints, description);
	}

	@Override
	public MaskedLong computeLeft(MaskedLong rval, MaskedLong goal) throws SolverException {
		MaskedLong lval = goal.invMultiplyUnsigned(rval);
		if (lval.multiply(rval).agrees(goal)) {
			return lval;
		}
		throw new SolverException(
			"Encountered unsolvable multiplication: " + rval + "*x = " + goal);
	}

	@Override
	public MaskedLong compute(MaskedLong lval, MaskedLong rval) {
		return lval.multiply(rval);
	}
}
