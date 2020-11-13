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
package ghidra.app.plugin.assembler.sleigh.sem;

import java.util.Map;

import ghidra.app.plugin.assembler.sleigh.expr.*;
import ghidra.app.plugin.processors.sleigh.expression.PatternExpression;

/**
 * A {@link AssemblyResolution} indicating the need to solve an expression in the future
 * 
 * Such records are collected within a {@link AssemblyResolvedConstructor} and then solved just
 * before the final result(s) are assembled. This is typically required by instructions that refer
 * to the {@code inst_next} symbol.
 * 
 * NOTE: These are used internally. The user ought never to see these from the assembly API.
 */
public class AssemblyResolvedBackfill extends AssemblyResolution {
	protected final PatternExpression exp;
	protected final MaskedLong goal;
	protected final Map<Integer, Object> res;
	protected final int inslen;
	protected final int offset;

	@Override
	protected int computeHash() {
		int result = 0;
		result += exp.hashCode();
		result *= 31;
		result += goal.hashCode();
		result *= 31;
		result += inslen;
		result *= 31;
		result += offset;
		return result;
	}

	/**
	 * @see {@link AssemblyResolution#backfill(PatternExpression, MaskedLong, Map, int, String)}
	 */
	AssemblyResolvedBackfill(String description, PatternExpression exp, MaskedLong goal,
			Map<Integer, Object> res, int inslen, int offset) {
		super(description, null);
		this.exp = exp;
		this.goal = goal;
		this.res = res;
		this.inslen = inslen;
		this.offset = offset;
	}

	/**
	 * Duplicate this record
	 * @return the duplicate
	 */
	AssemblyResolvedBackfill copy() {
		AssemblyResolvedBackfill cp =
			new AssemblyResolvedBackfill(description, exp, goal, res, inslen, offset);
		return cp;
	}

	/**
	 * Get the expected length of the instruction portion of the future encoding
	 * 
	 * This is used to make sure that operands following a to-be-determined encoding are placed
	 * properly. Even though the actual encoding cannot yet be determined, its length can.
	 * @return the total expected length (including the offset)
	 */
	public int getInstructionLength() {
		return offset + inslen;
	}

	@Override
	public boolean isError() {
		return false;
	}

	@Override
	public boolean isBackfill() {
		return true;
	}

	@Override
	protected String lineToString() {
		return "Backfill (len:" + inslen + ",off:" + offset + ") " + goal + " := " + exp + " (" +
			description + ")";
	}

	/**
	 * Shift the back-fill record's "instruction" pattern to the right.
	 * @param amt the number of bytes to shift the result when solved.
	 * @return the result
	 */
	public AssemblyResolvedBackfill shift(int amt) {
		return new AssemblyResolvedBackfill(description, exp, goal, res, inslen, offset + amt);
	}

	/**
	 * Attempt (again) to solve the expression that generated this backfill record
	 * 
	 * This will attempt to solve the same expression and goal again, using the same parameters as
	 * were given to the original attempt, except with additional defined symbols. Typically, the
	 * symbol that required backfill is {@code inst_next}. This method will not throw
	 * {@link NeedsBackfillException}, since that would imply the missing symbol(s) from the
	 * original attempt are still missing. Instead, the method returns an instance of
	 * {@link AssemblyResolvedError}.
	 * @param solver a solver, usually the same as the one from the original attempt.
	 * @param vals the defined symbols, usually the same, but with the missing symbol(s).
	 * @return the solution result
	 */
	public AssemblyResolution solve(RecursiveDescentSolver solver, Map<String, Long> vals,
			AssemblyResolvedConstructor cur) {
		try {
			AssemblyResolution ar =
				solver.solve(exp, goal, vals, res, cur.truncate(offset), description);
			if (ar.isError()) {
				return ar;
			}
			AssemblyResolvedConstructor rc = (AssemblyResolvedConstructor) ar;
			return rc.shift(offset);
		}
		catch (NeedsBackfillException e) {
			return AssemblyResolution.error("Solution still requires backfill", description, null);
		}
		catch (UnsupportedOperationException e) {
			return AssemblyResolution.error("Unsupported: " + e.getMessage(), description, null);
		}
	}
}
