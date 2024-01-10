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

import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

import ghidra.app.plugin.assembler.sleigh.expr.*;
import ghidra.app.plugin.assembler.sleigh.sem.AbstractAssemblyResolutionFactory.AbstractAssemblyResolvedBackfillBuilder;
import ghidra.app.plugin.assembler.sleigh.sem.AbstractAssemblyResolutionFactory.AbstractAssemblyResolvedPatternsBuilder;
import ghidra.app.plugin.processors.sleigh.Constructor;
import ghidra.app.plugin.processors.sleigh.expression.PatternExpression;
import ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern;

public abstract class AbstractAssemblyResolutionFactory< //
		RP extends AssemblyResolvedPatterns, //
		BF extends AssemblyResolvedBackfill> {
	protected static final RecursiveDescentSolver SOLVER = RecursiveDescentSolver.getSolver();
	protected static final String INS = "ins:";
	protected static final String CTX = "ctx:";
	protected static final String SEP = ",";

	public abstract static class AbstractAssemblyResolutionBuilder< //
			B extends AbstractAssemblyResolutionBuilder<B, T>, //
			T extends AssemblyResolution> {
		protected String description;
		protected List<AssemblyResolution> children;
		protected AssemblyResolution right;

		public void copyFromDefault(AbstractAssemblyResolution ar) {
			this.description = ar.description;
			this.children = ar.children;
			this.right = ar.right;
		}

		@SuppressWarnings("unchecked")
		protected B self() {
			return (B) this;
		}

		public B description(String description) {
			this.description = description;
			return self();
		}

		public B children(List<AssemblyResolution> children) {
			this.children = children;
			return self();
		}

		public B right(AssemblyResolution right) {
			this.right = right;
			return self();
		}

		protected abstract T build();
	}

	public abstract static class AbstractAssemblyResolvedPatternsBuilder< //
			RP extends AssemblyResolvedPatterns> extends
			AbstractAssemblyResolutionBuilder<AbstractAssemblyResolvedPatternsBuilder<RP>, RP> {
		protected Constructor cons;
		protected AssemblyPatternBlock ins;
		protected AssemblyPatternBlock ctx;
		protected Set<AssemblyResolvedBackfill> backfills;
		protected Set<AssemblyResolvedPatterns> forbids;

		public void copyFromDefault(DefaultAssemblyResolvedPatterns rp) {
			super.copyFromDefault(rp);
			this.cons = rp.cons;
			this.ins = rp.ins;
			this.ctx = rp.ctx;
			this.backfills = rp.backfills;
			this.forbids = rp.forbids;
		}
	}

	public abstract static class AbstractAssemblyResolvedBackfillBuilder< //
			BF extends AssemblyResolvedBackfill> extends
			AbstractAssemblyResolutionBuilder<AbstractAssemblyResolvedBackfillBuilder<BF>, BF> {
		protected PatternExpression exp;
		protected MaskedLong goal;
		protected int inslen;
		protected int offset;
	}

	public class DefaultAssemblyResolvedPatternBuilder
			extends AbstractAssemblyResolvedPatternsBuilder<AssemblyResolvedPatterns> {
		@Override
		protected AssemblyResolvedPatterns build() {
			return new DefaultAssemblyResolvedPatterns(AbstractAssemblyResolutionFactory.this,
				description, cons, children, right, ins, ctx, backfills, forbids);
		}
	}

	public class DefaultAssemblyResolvedBackfillBuilder
			extends AbstractAssemblyResolvedBackfillBuilder<AssemblyResolvedBackfill> {
		@Override
		protected AssemblyResolvedBackfill build() {
			return new DefaultAssemblyResolvedBackfill(AbstractAssemblyResolutionFactory.this,
				description, exp, goal, inslen, offset);
		}
	}

	public class AssemblyResolvedErrorBuilder extends
			AbstractAssemblyResolutionBuilder<AssemblyResolvedErrorBuilder, AssemblyResolvedError> {
		protected String error;

		public AssemblyResolvedErrorBuilder error(String error) {
			this.error = error;
			return self();
		}

		@Override
		public AssemblyResolvedError build() {
			return new DefaultAssemblyResolvedError(AbstractAssemblyResolutionFactory.this,
				description, children, right, error);
		}
	}

	public abstract AbstractAssemblyResolvedPatternsBuilder<RP> newPatternsBuilder();

	public abstract AbstractAssemblyResolvedBackfillBuilder<BF> newBackfillBuilder();

	public AssemblyResolvedErrorBuilder newErrorBuilder() {
		return new AssemblyResolvedErrorBuilder();
	}

	/**
	 * Construct an immutable single-entry result set consisting of the one given resolution
	 * 
	 * @param rp the single resolution entry
	 * @return the new resolution set
	 */
	protected AssemblyResolutionResults singleton(AssemblyResolution one) {
		return results(Set.of(one));
	}

	public AssemblyResolutionResults newAssemblyResolutionResults() {
		return new AssemblyResolutionResults();
	}

	protected AssemblyResolutionResults results(Set<AssemblyResolution> col) {
		return new AssemblyResolutionResults(col);
	}

	/**
	 * Attempt to solve an expression
	 * 
	 * @param exp the expression to solve
	 * @param goal the desired value of the expression
	 * @param cur the resolved constructor so far
	 * @param description a description of the result
	 * @return the encoded solution, or a backfill record
	 */
	protected AssemblyResolution solveOrBackfill(PatternExpression exp, MaskedLong goal,
			Map<String, Long> vals, AssemblyResolvedPatterns cur, String description) {
		try {
			return SOLVER.solve(this, exp, goal, vals, cur, description);
		}
		catch (NeedsBackfillException bf) {
			int fieldLength = SOLVER.getInstructionLength(exp);
			return backfill(exp, goal, fieldLength, description);
		}
	}

	/**
	 * Attempt to solve an expression
	 * 
	 * <p>
	 * Converts the given goal and bits count to a {@link MaskedLong} and then solves as before. As
	 * a special case, if {@code bits == 0}, the goal is considered fully-defined (as if
	 * {@code bits == 64}).
	 * 
	 * @see #solveOrBackfill(PatternExpression, MaskedLong, AssemblyResolvedPatterns, String)
	 */
	protected AssemblyResolution solveOrBackfill(PatternExpression exp, long goal, int bits,
			Map<String, Long> vals, AssemblyResolvedPatterns cur, String description) {
		long msk;
		if (bits == 0 || bits >= 64) {
			msk = -1L;
		}
		else {
			msk = ~(-1L << bits);
		}
		return solveOrBackfill(exp, MaskedLong.fromMaskAndValue(msk, goal), vals, cur, description);
	}

	/**
	 * Attempt to solve an expression
	 * 
	 * <p>
	 * Converts the given goal to a fully-defined {@link MaskedLong} and then solves.
	 * 
	 * @see #solveOrBackfill(PatternExpression, MaskedLong, Map, AssemblyResolvedPatterns, String)
	 */
	protected AssemblyResolution solveOrBackfill(PatternExpression exp, long goal,
			Map<String, Long> vals, AssemblyResolvedPatterns cur, String description) {
		return solveOrBackfill(exp, MaskedLong.fromLong(goal), vals, cur, description);
	}

	public AssemblyResolvedErrorBuilder errorBuilder(String error, AssemblyResolution res) {
		var builder = newErrorBuilder();
		builder.error = error;
		builder.description = res.getDescription();
		builder.children = res.getChildren();
		builder.right = res.getRight();
		return builder;
	}

	/**
	 * Build an error resolution record, based on an intermediate SLEIGH constructor record
	 * 
	 * @param error a description of the error
	 * @param res the constructor record that was being populated when the error occurred
	 * @return the new error resolution
	 */
	public AssemblyResolution error(String error, AssemblyResolution res) {
		return errorBuilder(error, res).build();
	}

	protected AbstractAssemblyResolvedPatternsBuilder<RP> nopBuilder(String description) {
		var builder = newPatternsBuilder();
		builder.ins = AssemblyPatternBlock.nop();
		builder.ctx = AssemblyPatternBlock.nop();
		builder.description = description;
		return builder;
	}

	/**
	 * Obtain a new "blank" resolved SLEIGH constructor record
	 * 
	 * @param description a description of the resolution
	 * @return the new resolution
	 */
	public RP nop(String description) {
		return nopBuilder(description).build();
	}

	protected AbstractAssemblyResolvedPatternsBuilder<RP> nopBuilder(String description,
			List<AssemblyResolution> children, AssemblyResolution right) {
		var builder = newPatternsBuilder();
		builder.ins = AssemblyPatternBlock.nop();
		builder.ctx = AssemblyPatternBlock.nop();
		builder.description = description;
		builder.children = children;
		builder.right = right;
		return builder;
	}

	/**
	 * Obtain a new "blank" resolved SLEIGH constructor record
	 * 
	 * @param description a description of the resolution
	 * @param children any children that will be involved in populating this record
	 * @return the new resolution
	 */
	public RP nop(String description, List<AssemblyResolution> children, AssemblyResolution right) {
		return nopBuilder(description, children, right).build();
	}

	public AbstractAssemblyResolvedBackfillBuilder<BF> backfillBuilder(PatternExpression exp,
			MaskedLong goal, int inslen, String description) {
		var builder = newBackfillBuilder();
		builder.exp = exp;
		builder.goal = goal;
		builder.inslen = inslen;
		builder.description = description;
		return builder;
	}

	/**
	 * Build a backfill record to attach to a successful resolution result
	 * 
	 * @param exp the expression depending on a missing symbol
	 * @param goal the desired value of the expression
	 * @param inslen the length of instruction portion expected in the future solution
	 * @param description a description of the backfill record
	 * @return the new record
	 */
	public AssemblyResolution backfill(PatternExpression exp, MaskedLong goal, int inslen,
			String description) {
		return backfillBuilder(exp, goal, inslen, description).build();
	}

	protected AbstractAssemblyResolvedPatternsBuilder<RP> resolvedBuilder(AssemblyPatternBlock ins,
			AssemblyPatternBlock ctx, String description, Constructor cons,
			List<AssemblyResolution> children, AssemblyResolution right) {
		var builder = newPatternsBuilder();
		builder.ins = ins;
		builder.ctx = ctx;
		builder.description = description;
		builder.cons = cons;
		builder.children = children;
		builder.right = right;
		return builder;
	}

	/**
	 * Build the result of successfully resolving a SLEIGH constructor
	 * 
	 * <p>
	 * <b>NOTE:</b> This is not used strictly for resolved SLEIGH constructors. It may also be used
	 * to store intermediates, e.g., encoded operands, during constructor resolution.
	 * 
	 * @param ins the instruction pattern block
	 * @param ctx the context pattern block
	 * @param description a description of the resolution
	 * @param cons the constructor, or null
	 * @param children the children of this constructor, or null
	 * @return the new resolution
	 */
	public RP resolved(AssemblyPatternBlock ins, AssemblyPatternBlock ctx, String description,
			Constructor cons, List<AssemblyResolution> children, AssemblyResolution right) {
		return resolvedBuilder(ins, ctx, description, cons, children, right).build();
	}

	protected AbstractAssemblyResolvedPatternsBuilder<RP> instrOnlyBuilder(AssemblyPatternBlock ins,
			String description) {
		var builder = newPatternsBuilder();
		builder.ins = ins;
		builder.ctx = AssemblyPatternBlock.nop();
		builder.description = description;
		return builder;
	}

	/**
	 * Build an instruction-only successful resolution result
	 * 
	 * @param ins the instruction pattern block
	 * @param description a description of the resolution
	 * @return the new resolution
	 * @see #resolved(AssemblyPatternBlock, AssemblyPatternBlock, String, Constructor, List,
	 *      AssemblyResolution)
	 */
	public RP instrOnly(AssemblyPatternBlock ins, String description) {
		return instrOnlyBuilder(ins, description).build();
	}

	protected AbstractAssemblyResolvedPatternsBuilder<RP> contextOnlyBuilder(
			AssemblyPatternBlock ctx, String description) {
		var builder = newPatternsBuilder();
		builder.ins = AssemblyPatternBlock.nop();
		builder.ctx = ctx;
		builder.description = description;
		return builder;
	}

	/**
	 * Build a context-only successful resolution result
	 * 
	 * @param ctx the context pattern block
	 * @param description a description of the resolution
	 * @return the new resolution
	 * @see #resolved(AssemblyPatternBlock, AssemblyPatternBlock, String, Constructor, List,
	 *      AssemblyResolution)
	 */
	public RP contextOnly(AssemblyPatternBlock ctx, String description) {
		return contextOnlyBuilder(ctx, description).build();
	}

	protected AbstractAssemblyResolvedPatternsBuilder<RP> fromPatternBuilder(DisjointPattern pat,
			int minLen, String description, Constructor cons) {
		var builder = newPatternsBuilder();
		builder.ins = AssemblyPatternBlock.fromPattern(pat, minLen, false);
		builder.ctx = AssemblyPatternBlock.fromPattern(pat, 0, true);
		builder.description = description;
		builder.cons = cons;
		return builder;
	}

	/**
	 * Build a successful resolution result from a SLEIGH constructor's patterns
	 * 
	 * @param pat the constructor's pattern
	 * @param description a description of the resolution
	 * @return the new resolution
	 */
	public RP fromPattern(DisjointPattern pat, int minLen,
			String description, Constructor cons) {
		return fromPatternBuilder(pat, minLen, description, cons).build();
	}

	protected AbstractAssemblyResolvedPatternsBuilder<RP> fromStringBuilder(String str,
			String description, List<AssemblyResolution> children) {
		var builder = newPatternsBuilder();
		builder.description = description;
		builder.children = children;
		if (str.startsWith(INS)) {
			int end = str.indexOf(SEP);
			if (end == -1) {
				end = str.length();
			}
			builder.ins = AssemblyPatternBlock.fromString(str.substring(INS.length(), end));
			str = str.substring(end);
			if (str.startsWith(SEP)) {
				str = str.substring(1);
			}
		}
		if (str.startsWith(CTX)) {
			int end = str.length();
			builder.ctx = AssemblyPatternBlock.fromString(str.substring(CTX.length(), end));
			str = str.substring(end);
		}
		if (str.length() != 0) {
			throw new IllegalArgumentException(str);
		}
		return builder;
	}

	/**
	 * Build a new successful SLEIGH constructor resolution from a string representation
	 * 
	 * <p>
	 * This was used primarily in testing, to specify expected results.
	 * 
	 * @param str the string representation: "{@code ins:[pattern],ctx:[pattern]}"
	 * @see ghidra.util.NumericUtilities#convertHexStringToMaskedValue(AtomicLong, AtomicLong,
	 *      String, int, int, String) NumericUtilities.convertHexStringToMaskedValue(AtomicLong,
	 *      AtomicLong, String, int, int, String)
	 * @param description a description of the resolution
	 * @param children any children involved in the resolution
	 * @return the decoded resolution
	 */
	public AssemblyResolvedPatterns fromString(String str, String description,
			List<AssemblyResolution> children) {
		return fromStringBuilder(str, description, children).build();
	}
}
