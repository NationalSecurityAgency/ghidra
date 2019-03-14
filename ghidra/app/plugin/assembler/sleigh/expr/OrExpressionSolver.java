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

import java.util.*;

import ghidra.app.plugin.assembler.sleigh.sem.*;
import ghidra.app.plugin.assembler.sleigh.util.DbgTimer.DbgCtx;
import ghidra.app.plugin.processors.sleigh.ParserWalker;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.expression.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.xml.XmlPullParser;

/**
 * Solves expressions of the form A | B
 */
public class OrExpressionSolver extends AbstractBinaryExpressionSolver<OrExpression> {
	static final PatternExpression DUMMY = new PatternExpression() {
		@Override
		public long getValue(ParserWalker walker) throws MemoryAccessException {
			return 0;
		}

		@Override
		public void restoreXml(XmlPullParser parser, SleighLanguage lang) {
			// Dummy intentionally left empty
		}

		@Override
		public String toString() {
			return null;
		}
	};

	public OrExpressionSolver() {
		super(OrExpression.class);
	}

	@Override
	public MaskedLong compute(MaskedLong lval, MaskedLong rval) {
		return lval.or(rval);
	}

	@Override
	public MaskedLong computeLeft(MaskedLong rval, MaskedLong goal) throws SolverException {
		return goal.invOr(rval);
	}

	protected AssemblyResolution tryCatenationExpression(OrExpression exp, MaskedLong goal,
			Map<String, Long> vals, Map<Integer, Object> res, AssemblyResolvedConstructor cur,
			Set<SolverHint> hints, String description) throws SolverException {
		/*
		 * If OR is being used to concatenate fields, then we can solve with some symbolic
		 * manipulation. We'll descend to see if this is a tree of ORs with SHIFTs or fields at the
		 * leaves. If it is, we can derive the layout of the composite field and solve each
		 * component independently.
		 */
		Map<Long, PatternExpression> fields = new TreeMap<>();
		fields.put(0L, new ConstantValue(0));
		collectComponentsOr(exp, 0, fields, vals, res, cur);
		fields.put(64L, new ConstantValue(0));
		long lo = 0;
		PatternExpression fieldExp = null;
		AssemblyResolvedConstructor result = AssemblyResolution.nop(description, null);
		try (DbgCtx dc = dbg.start("Trying solution of field catenation")) {
			dbg.println("Original: " + goal + ":= " + exp);
			for (Map.Entry<Long, PatternExpression> ent : fields.entrySet()) {
				long hi = ent.getKey();
				if (hi == 0) {
					fieldExp = ent.getValue();
					continue;
				}

				dbg.println("Part(" + hi + ":" + lo + "]:= " + fieldExp);
				MaskedLong part = goal.shiftLeft(64 - hi).shiftRightPositional(64 - hi + lo);
				dbg.println("Solving: " + part + ":= " + fieldExp);
				AssemblyResolution sol = solver.solve(fieldExp, part, vals, res, cur, hints,
					description + " with shift " + lo);
				if (sol.isError()) {
					return sol;
				}
				result = result.combine((AssemblyResolvedConstructor) sol);
				if (result == null) {
					throw new SolverException("Solutions to individual fields produced conflict");
				}

				lo = hi;
				fieldExp = ent.getValue();
			}
		}
		return result;
	}

	protected AssemblyResolution tryCircularShiftExpression(OrExpression exp, MaskedLong goal,
			Map<String, Long> vals, Map<Integer, Object> res, AssemblyResolvedConstructor cur,
			Set<SolverHint> hints, String description) throws SolverException {
		// If OR is being used to accomplish a circular shift, then we can apply a clever solver.
		// We'll match against the patterns: (f << (C - g)) | (f >> g)
		//                                   (f >> (C - g)) | (f << g)
		int leftdir; // 0 is left, 1 is right
		// "left" and "right" are about to get really overloaded....
		if ((exp.getLeft() instanceof LeftShiftExpression &&
			exp.getRight() instanceof RightShiftExpression)) {
			leftdir = 0;
		}
		else if (exp.getLeft() instanceof RightShiftExpression &&
			exp.getRight() instanceof LeftShiftExpression) {
			leftdir = 1;
		}
		else {
			throw new SolverException("Not a circular shift");
		}

		BinaryExpression left = (BinaryExpression) exp.getLeft();
		BinaryExpression right = (BinaryExpression) exp.getRight();
		PatternExpression expValu1 = left.getLeft();
		PatternExpression expValu2 = right.getLeft();
		if (!expValu1.equals(expValu2)) {
			throw new SolverException("Not a circular shift");
		}

		PatternExpression expShift = null;
		int size = -1, dir = -1;

		PatternExpression s1 = left.getRight();
		PatternExpression s2 = right.getRight();
		if (s1 instanceof SubExpression) {
			SubExpression sub = (SubExpression) s1;
			expShift = sub.getRight();
			if (expShift.equals(s2)) {
				PatternExpression c = sub.getLeft();
				MaskedLong cc = solver.getValue(c, vals, res, cur);
				if (cc.isFullyDefined()) {
					// the left side has the subtraction, so the overall shift is the opposite
					// of the direction of the shift on the left
					dir = 1 - leftdir;
					size = (int) cc.longValue();
				}
			}
		}
		if (dir == -1 && s2 instanceof SubExpression) {
			SubExpression sub = (SubExpression) s2;
			expShift = sub.getRight();
			if (expShift.equals(s1)) {
				PatternExpression c = sub.getLeft();
				MaskedLong cc = solver.getValue(c, vals, res, cur);
				if (cc.isFullyDefined()) {
					// the right side has the subtraction, so the overall shift is the same
					// as the direction of the shift on the left
					dir = leftdir;
					size = (int) cc.longValue();
				}
			}
		}
		if (dir == -1) {
			throw new SolverException("Not a circular shift (or of known size)");
		}

		// At this point, I know it's a circular shift
		dbg.println("Identified circular shift: value:= " + expValu1 + ", shift:= " + expShift +
			", size:= " + size + ", dir:= " + (dir == 1 ? "right" : "left"));
		return solveLeftCircularShift(expValu1, expShift, size, dir, goal, vals, res, cur, hints,
			description);
	}

	protected AssemblyResolution solveLeftCircularShift(PatternExpression expValue,
			PatternExpression expShift, int size, int dir, MaskedLong goal, Map<String, Long> vals,
			Map<Integer, Object> res, AssemblyResolvedConstructor cur, Set<SolverHint> hints,
			String description) throws NeedsBackfillException, SolverException {
		MaskedLong valValue = solver.getValue(expValue, vals, res, cur);
		MaskedLong valShift = solver.getValue(expShift, vals, res, cur);

		if (valValue != null && !valValue.isFullyDefined()) {
			if (!valValue.isFullyUndefined()) {
				dbg.println("Partially-defined f for left circular shift solver: " + valValue);
			}
			valValue = null;
		}
		if (valShift != null && valShift.isFullyDefined()) {
			if (!valShift.isFullyUndefined()) {
				dbg.println("Partially-defined g for left circular shift solver: " + valShift);
			}
			valShift = null;
		}

		if (valValue != null && valShift != null) {
			throw new AssertionError("Should not have constants when solving special forms");
		}
		else if (valValue != null) {
			return solver.solve(expShift, computeCircShiftG(valValue, size, dir, goal), vals, res,
				cur, hints, description);
		}
		else if (valShift != null) {
			return solver.solve(expValue, computeCircShiftF(valShift, size, dir, goal), vals, res,
				cur, hints, description);
		}

		// Oiy. Try guessing the shift amount, starting at 0
		if (hints.contains(DefaultSolverHint.GUESSING_CIRCULAR_SHIFT_AMOUNT)) {
			throw new SolverException("Already guessing circular shift amount. " +
				"Try to express a double-shift as a shift by sum.");
		}
		Set<SolverHint> hintsWithCircularShift =
			SolverHint.with(hints, DefaultSolverHint.GUESSING_CIRCULAR_SHIFT_AMOUNT);
		for (int shift = 0; shift < size; shift++) {
			try {
				MaskedLong reqShift = MaskedLong.fromLong(shift);
				MaskedLong reqValue = computeCircShiftF(reqShift, size, dir, goal);
				AssemblyResolution resValue = solver.solve(expValue, reqValue, vals, res, cur,
					hintsWithCircularShift, description);
				if (resValue.isError()) {
					AssemblyResolvedError err = (AssemblyResolvedError) resValue;
					throw new SolverException("Solving f failed: " + err.getError());
				}
				AssemblyResolution resShift =
					solver.solve(expShift, reqShift, vals, res, cur, hints, description);
				if (resShift.isError()) {
					AssemblyResolvedError err = (AssemblyResolvedError) resShift;
					throw new SolverException("Solving g failed: " + err.getError());
				}
				AssemblyResolvedConstructor solValue = (AssemblyResolvedConstructor) resValue;
				AssemblyResolvedConstructor solShift = (AssemblyResolvedConstructor) resShift;
				AssemblyResolvedConstructor sol = solValue.combine(solShift);
				if (sol == null) {
					throw new SolverException(
						"value and shift solutions conflict for shift=" + shift);
				}
				return sol;
			}
			catch (SolverException | UnsupportedOperationException e) {
				Msg.trace(this, "Shift of " + shift + " resulted in " + e);
				// try the next
			}
		}

		throw new SolverException(
			"Could not solve circular shift with variable bits and shift amount");
	}

	protected MaskedLong computeCircShiftG(MaskedLong fval, int size, int dir, MaskedLong goal)
			throws SolverException {
		long acc = 0;
		//long bit = 1;
		for (int i = 0; i < size; i++) {
			if (fval.shiftCircular(i, size, dir).agrees(goal)) {
				return MaskedLong.fromLong(i);
				//acc |= bit;
			}
			//bit <<= 1;
		}
		if (Long.bitCount(acc) == 1) {
			return MaskedLong.fromLong(Long.numberOfTrailingZeros(acc));
		}
		throw new SolverException("Cannot solve for the circular shift amount");
	}

	protected MaskedLong computeCircShiftF(MaskedLong gval, int size, int dir, MaskedLong goal) {
		// Should just be the plain ol' opposite
		return goal.shiftCircular(gval, size, 1 - dir);
	}

	@Override
	protected AssemblyResolution solveTwoSided(OrExpression exp, MaskedLong goal,
			Map<String, Long> vals, Map<Integer, Object> res, AssemblyResolvedConstructor cur,
			Set<SolverHint> hints, String description)
			throws NeedsBackfillException, SolverException {
		try {
			return tryCatenationExpression(exp, goal, vals, res, cur, hints, description);
		}
		catch (Exception e) {
			dbg.println("while solving: " + goal + "=:" + exp);
			dbg.println(e.getMessage());
		}

		try {
			return tryCircularShiftExpression(exp, goal, vals, res, cur, hints, description);
		}
		catch (Exception e) {
			dbg.println("while solving: " + goal + "=:" + exp);
			dbg.println(e.getMessage());
		}
		throw new SolverException("Could not solve two-sided OR");
	}

	void collectComponents(PatternExpression exp, long shift,
			Map<Long, PatternExpression> components, Map<String, Long> vals,
			Map<Integer, Object> res, AssemblyResolvedConstructor cur) throws SolverException {
		if (exp instanceof OrExpression) {
			collectComponentsOr((OrExpression) exp, shift, components, vals, res, cur);
		}
		else if (exp instanceof LeftShiftExpression) {
			collectComponentsLeft((LeftShiftExpression) exp, shift, components, vals, res, cur);
		}
		else if (exp instanceof RightShiftExpression) {
			collectComponentsRight((RightShiftExpression) exp, shift, components, vals, res, cur);
		}
		else {
			assert shift < 64;
			components.put(shift, exp);
		}
	}

	void collectComponentsOr(OrExpression exp, long shift, Map<Long, PatternExpression> components,
			Map<String, Long> vals, Map<Integer, Object> res, AssemblyResolvedConstructor cur)
			throws SolverException {
		collectComponents(exp.getLeft(), shift, components, vals, res, cur);
		collectComponents(exp.getRight(), shift, components, vals, res, cur);
	}

	void collectComponentsLeft(LeftShiftExpression exp, long shift,
			Map<Long, PatternExpression> components, Map<String, Long> vals,
			Map<Integer, Object> res, AssemblyResolvedConstructor cur) throws SolverException {
		MaskedLong adj;
		try {
			adj = solver.getValue(exp.getRight(), vals, res, cur);
		}
		catch (NeedsBackfillException e) {
			throw new SolverException("Variable shifts break field catenation solver", e);
		}
		if (adj == null || !adj.isFullyDefined()) {
			throw new SolverException("Variable shifts break field catenation solver");
		}
		collectComponents(exp.getLeft(), shift + adj.val, components, vals, res, cur);
	}

	void collectComponentsRight(RightShiftExpression exp, long shift,
			Map<Long, PatternExpression> components, Map<String, Long> vals,
			Map<Integer, Object> res, AssemblyResolvedConstructor cur) throws SolverException {
		MaskedLong adj;
		try {
			adj = solver.getValue(exp.getRight(), vals, res, cur);
		}
		catch (NeedsBackfillException e) {
			throw new SolverException("Variable shifts break field catenation solver", e);
		}
		if (adj == null || !adj.isFullyDefined()) {
			throw new SolverException("Variable shifts break field catenation solver");
		}
		collectComponents(exp.getLeft(), shift - adj.val, components, vals, res, cur);
	}
}
