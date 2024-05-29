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
import java.util.Objects;

import ghidra.app.plugin.assembler.sleigh.expr.*;
import ghidra.app.plugin.assembler.sleigh.sem.AbstractAssemblyResolutionFactory.AbstractAssemblyResolvedBackfillBuilder;
import ghidra.app.plugin.processors.sleigh.expression.PatternExpression;

/**
 * A {@link AssemblyResolution} indicating the need to solve an expression in the future
 * 
 * <p>
 * Such records are collected within a {@link AssemblyResolvedPatterns} and then solved just before
 * the final result(s) are assembled. This is typically required by instructions that refer to the
 * {@code inst_next} symbol.
 * 
 * <p>
 * <b>NOTE:</b> These are used internally. The user ought never to see these from the assembly API.
 */
public class DefaultAssemblyResolvedBackfill extends AbstractAssemblyResolution
		implements AssemblyResolvedBackfill {
	protected final PatternExpression exp;
	protected final MaskedLong goal;
	protected final int inslen;
	protected final int offset;

	/**
	 * @see {@link AssemblyResolution#backfill(PatternExpression, MaskedLong, Map, int, String)}
	 */
	protected DefaultAssemblyResolvedBackfill(AbstractAssemblyResolutionFactory<?, ?> factory,
			String description, PatternExpression exp, MaskedLong goal, int inslen, int offset) {
		super(factory, description, null, null);
		this.exp = Objects.requireNonNull(exp);
		this.goal = Objects.requireNonNull(goal);
		this.inslen = inslen;
		this.offset = offset;
	}

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

	protected AbstractAssemblyResolvedBackfillBuilder<?> copyBuilder() {
		var builder = factory.newBackfillBuilder();
		builder.description = description;
		builder.exp = exp;
		builder.goal = goal;
		builder.inslen = inslen;
		builder.offset = offset;
		return builder;
	}

	/**
	 * Duplicate this record
	 * 
	 * @return the duplicate
	 */
	protected AssemblyResolvedBackfill copy() {
		return copyBuilder().build();
	}

	@Override
	public AssemblyResolvedBackfill withRight(AssemblyResolution right) {
		throw new AssertionError();
	}

	@Override
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
	public String lineToString() {
		return "Backfill (len:" + inslen + ",off:" + offset + ") " + goal + " := " + exp + " (" +
			description + ")";
	}

	protected AbstractAssemblyResolvedBackfillBuilder<?> shiftBuilder(int amt) {
		var builder = factory.newBackfillBuilder();
		builder.description = description;
		builder.exp = exp;
		builder.goal = goal;
		builder.inslen = inslen;
		builder.offset = offset + amt;
		return builder;
	}

	@Override
	public AssemblyResolvedBackfill shift(int amt) {
		return shiftBuilder(amt).build();
	}

	@Override
	public AssemblyResolution parent(String description, int opCount) {
		throw new AssertionError();
	}

	@Override
	public AssemblyResolution solve(RecursiveDescentSolver solver, Map<String, Long> vals,
			AssemblyResolvedPatterns cur) {
		try {
			AssemblyResolution ar =
				solver.solve(factory, exp, goal, vals, cur.truncate(offset), description);
			if (ar.isError()) {
				return ar;
			}
			AssemblyResolvedPatterns rc = (AssemblyResolvedPatterns) ar;
			return rc.shift(offset);
		}
		catch (NeedsBackfillException e) {
			return factory.newErrorBuilder()
					.error("Solution still requires backfill")
					.description(description)
					.build();
		}
		catch (UnsupportedOperationException e) {
			return factory.newErrorBuilder()
					.error("Unsupported: " + e.getMessage())
					.description(description)
					.build();
		}
	}
}
