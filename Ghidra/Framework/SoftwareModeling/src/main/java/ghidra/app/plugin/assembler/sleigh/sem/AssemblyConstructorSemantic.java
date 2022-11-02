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
import java.util.stream.Stream;

import ghidra.app.plugin.assembler.sleigh.expr.MaskedLong;
import ghidra.app.plugin.assembler.sleigh.expr.RecursiveDescentSolver;
import ghidra.app.plugin.assembler.sleigh.util.DbgTimer;
import ghidra.app.plugin.languages.sleigh.SleighLanguages;
import ghidra.app.plugin.languages.sleigh.SubtableEntryVisitor;
import ghidra.app.plugin.processors.sleigh.*;
import ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern;
import ghidra.app.plugin.processors.sleigh.symbol.SubtableSymbol;

/**
 * Describes a SLEIGH constructor semantic
 * 
 * <p>
 * These are collected and associated with productions in the grammar based on the given
 * constructor's print pieces.
 */
public class AssemblyConstructorSemantic implements Comparable<AssemblyConstructorSemantic> {
	protected static final RecursiveDescentSolver SOLVER = RecursiveDescentSolver.getSolver();
	protected static final DbgTimer DBG = AssemblyTreeResolver.DBG;

	protected final Set<AssemblyResolvedPatterns> patterns = new HashSet<>();
	protected final Constructor cons;
	protected final List<Integer> indices;
	protected final List<ContextChange> contextChanges;
	protected final List<ContextChange> reversedChanges;

	// A set initialized on first access with forbidden patterns added
	protected Set<AssemblyResolvedPatterns> upatterns;

	/**
	 * Build a new SLEIGH constructor semantic
	 * 
	 * @param cons the SLEIGH constructor
	 * @param indices the indices of RHS non-terminals in the associated production that represent
	 *            an operand in the SLEIGH constructor
	 */
	public AssemblyConstructorSemantic(Constructor cons, List<Integer> indices) {
		this.cons = cons;
		this.indices = Collections.unmodifiableList(indices);
		List<ContextChange> changes = new ArrayList<>(cons.getContextChanges());
		this.contextChanges = List.copyOf(changes);
		Collections.reverse(changes);
		this.reversedChanges = List.copyOf(changes);
	}

	/**
	 * Record a pattern that would select the constructor
	 * 
	 * @param pat the pattern
	 */
	public void addPattern(DisjointPattern pat) {
		addPattern(AssemblyResolution.fromPattern(pat, cons.getMinimumLength(),
			"Generated constructor pattern " + getLocation(), cons));
	}

	/**
	 * Record a pattern that would select the constructor
	 * 
	 * @param pat the pattern
	 */
	public void addPattern(AssemblyResolvedPatterns pat) {
		if (upatterns != null) {
			throw new IllegalStateException("Cannot add patterns after a call to getPatterns()");
		}
		this.patterns.add(pat);
	}

	@Override
	public String toString() {
		return getLocation();
	}

	/**
	 * Render the constructor's source location for diagnostics
	 * 
	 * @param cons the constructor
	 * @return the location as {@code file:lineno}
	 */
	public static String getLocation(Constructor cons) {
		return cons.getSourceFile() + ":" + cons.getLineno();
	}

	/**
	 * Render this constructor's source location for diagnostics
	 * 
	 * @return the location
	 */
	public String getLocation() {
		return getLocation(cons);
	}

	/**
	 * Get the SLEIGH constructor
	 * 
	 * @return the constructor
	 */
	public Constructor getConstructor() {
		return cons;
	}

	/**
	 * Get the associated encoding patterns for the constructor
	 * 
	 * @return the patterns
	 */
	public Collection<AssemblyResolvedPatterns> getPatterns() {
		if (upatterns == null) {
			computeAllForbids();
		}
		return upatterns;
	}

	/**
	 * Convert the index of a print piece to its associated operand index
	 * 
	 * @param printpos position excluding whitespace and string tokens.
	 * @return the operand index
	 */
	public int getOperandIndex(int printpos) {
		return indices.get(printpos);
	}

	/**
	 * Get the list of operand indices in print piece order
	 * 
	 * @return the list
	 */
	public List<Integer> getOperandIndices() {
		return indices;
	}

	/**
	 * Get an iterator over the operand indices
	 * 
	 * <p>
	 * If this iterator is advanced for each non-terminal, while simultaneously iterating over the
	 * RHS of the associated production, then this will identify the corresponding operand index for
	 * each non-terminal
	 * 
	 * @return the iterator
	 */
	public Iterator<Integer> getOperandIndexIterator() {
		return Collections.unmodifiableList(indices).iterator();
	}

	/**
	 * Initialize upatterns with an unmodifiable copy of patterns, with forbidden patterns added
	 */
	protected void computeAllForbids() {
		if (upatterns != null) {
			throw new IllegalStateException(
				"Already computed all forbidden patterns for this constructor");
		}
		Set<AssemblyResolvedPatterns> result = new HashSet<>();
		for (AssemblyResolvedPatterns pat : patterns) {
			AssemblyResolvedPatterns fpat = withComputedForbids(pat);
			result.add(fpat);
		}
		upatterns = Collections.unmodifiableSet(result);
	}

	/**
	 * Add the list of forbidden patterns to one of the constructor's patterns
	 * 
	 * <p>
	 * SLEIGH disambiguates multiple matching pattern by two rules. First, if one is more specific
	 * than ("specializes") another, i.e., it matches on more bits than another pattern, the more
	 * specific pattern is chosen. Second, if the two are equally special, then the one that occurs
	 * first in the SLEIGH specification is taken. So, during resolution, if a less-special or
	 * later-occurring constructor is chosen, we must prevent continued resolution from matching the
	 * more-special or earlier-occurring pattern(s).
	 * 
	 * <p>
	 * Essentially, this states, "you may choose any value matching my pattern, except those that
	 * match these forbidden patterns."
	 * 
	 * <p>
	 * This takes a given pattern, and searches the rest of the language for any patterns that would
	 * take precedence, and combines them as forbidden patterns with the given pattern.
	 * 
	 * @param pat the given pattern
	 * @return the same pattern with forbidden records added
	 */
	protected AssemblyResolvedPatterns withComputedForbids(AssemblyResolvedPatterns pat) {
		// Forbid anything more specific (or otherwise takes precedence) over me.
		Set<AssemblyResolvedPatterns> forbids = new HashSet<>();
		SubtableSymbol parent = cons.getParent();

		SleighLanguages.traverseConstructors(parent, new SubtableEntryVisitor() {
			@Override
			public int visit(DisjointPattern sibDP, Constructor sibcons) {
				// Do not forbid myself.
				if (sibcons == cons) {
					return CONTINUE;
				}

				/**
				 * I had misunderstood the precedence rules originally.
				 * 
				 * 1. If one pattern defines a subset of the other pattern, then the more-specific
				 * one is preferred.
				 * 
				 * 2. Otherwise, preference is by line number
				 * 
				 * Thus, I need to check if there is any overlap at all. If not, then I don't need
				 * to worry about forbidding anything. Then, I'll check if it defines a strict
				 * subset, and forbid it if so. Then, I'll check if it defines a strict overset, and
				 * skip the line check if so. Then, I'll check if its line number *precedes* mine,
				 * and forbid it if so.
				 * 
				 * (I originally though the pattern with the most bits won, no matter whether or not
				 * those bits overlapped.)
				 * 
				 * There's an additional nuance. Because context is an *input* to the assembler, it
				 * may still cause the selection of a later constructor, despite line number. Thus,
				 * we can't apply the line number rule unless the earlier one also has an overset in
				 * terms of context.
				 */

				// If the two patterns cannot be combined, then they are disjoint.
				AssemblyResolvedPatterns sibpat = AssemblyResolution.fromPattern(sibDP,
					sibcons.getMinimumLength(), "For specialization check", sibcons);
				AssemblyResolvedPatterns comb = pat.combine(sibpat);
				if (null == comb) {
					return CONTINUE;
				}

				// OK, they overlap. Let's see if its a strict subset
				if (comb.bitsEqual(sibpat)) {
					// My sibling is a strict subset, so it will win the overlap
					forbids.add(sibpat.withDescription(getLocation(sibcons) + " forbids " +
						getLocation(cons) + " by pattern specificity"));
					return CONTINUE;
				}
				else if (comb.bitsEqual(pat)) {
					// I'm a strict subset, so I will win the overlap
					return CONTINUE;
				}

				// We can't apply the line number rule unless the sibling's context is an overset
				if (!comb.ctx.equals(pat.ctx)) {
					return CONTINUE;
				}

				// Finally, check the line number
				if (sibcons.getId() < cons.getId()) {
					forbids.add(sibpat.withDescription(getLocation(sibcons) + " forbids " +
						getLocation(cons) + " by rule position"));
					return CONTINUE;
				}

				// I guess, I have the more-specific pattern, or I appear higher... 
				return CONTINUE;
			}
		});

		return pat.withForbids(forbids);
	}

	/**
	 * Solve this constructor's context changes
	 * 
	 * <p>
	 * Each value in {@code opvals} must either be a numeric value, e.g., an index from a varnode
	 * list, or another {@link AssemblyResolvedPatterns} for a subconstructor operand.
	 * 
	 * <p>
	 * It's helpful to think of the SLEIGH disassembly process here. Normally, once the appropriate
	 * constructor has been identified (by matching patterns), its context changes are applied, and
	 * then its operands parsed (possibly parsing subconstructor operands). Thus, {@code res} can be
	 * thought of as the intermediate result between applying context changes and parsing operands,
	 * except in reverse. The output of this method corresponds to the state before context changes
	 * were applied, i.e., immediately after selecting the constructor. Thus, in reverse, the
	 * context is solved immediately before applying the selected constructor patterns.
	 * 
	 * @param res the combined resolution requirements derived from the subconstructors
	 * @param vals any defined symbols (usually {@code inst_start}, and {@code inst_next})
	 * @return the resolution with context changes applied in reverse, or an error 
	 */
	public AssemblyResolution solveContextChanges(AssemblyResolvedPatterns res,
			Map<String, Long> vals) {
		for (ContextChange chg : reversedChanges) {
			if (chg instanceof ContextOp) {
				DBG.println("Current: " + res.lineToString());
				// This seems backwards. That's because we're going backwards.
				// This is the "write" location for disassembly.
				ContextOp cop = (ContextOp) chg;
				DBG.println("Handling context change: " + cop);

				// TODO: Is this res or subres?
				MaskedLong reqval = res.readContextOp(cop);
				if (reqval.equals(MaskedLong.UNKS)) {
					DBG.println("Doesn't affect a current requirement");
					continue; // this context change does not satisfy any requirement
				}
				DBG.println("'read' " + reqval);

				// Remove the requirement that we just read before trying to solve
				res = res.maskOut(cop);
				DBG.println("Masked out: " + res.lineToString());

				// Now, solve
				AssemblyResolution sol = AssemblyTreeResolver.solveOrBackfill(
					cop.getPatternExpression(), reqval, vals, res, "Solution to " + cop);
				DBG.println("Solution: " + sol.lineToString());
				if (sol.isError()) {
					AssemblyResolvedError err = (AssemblyResolvedError) sol;
					return AssemblyResolution.error(err.getError(), res);
				}

				// Now, forward the new requirements to my parents.
				if (sol instanceof AssemblyResolvedPatterns) {
					AssemblyResolvedPatterns solcon = (AssemblyResolvedPatterns) sol;
					AssemblyResolvedPatterns check = res.combine(solcon);
					if (null == check) {
						return AssemblyResolution.error(
							"A context change caused a conflict: " + sol, res);
					}
					res = check;
				}
				else {
					AssemblyResolvedBackfill solbf = (AssemblyResolvedBackfill) sol;
					res = res.combine(solbf);
				}
				DBG.println("Combined: " + res.lineToString());
			}
		}
		return res;
	}

	/**
	 * Apply just context transformations in the forward (disassembly) direction
	 * 
	 * <p>
	 * Unlike the usual disassembly process, this method does not take into account any information
	 * from the instruction encoding. Any context bits that depend on it are set to unknown
	 * ({@code x}) in the output. This method is used to pre-compute a context transition graph in
	 * order to quickly resolve purely-recursive semantics on the root constructor table.
	 * 
	 * @param fromLeft the state before context changes
	 * @return the state after context changes
	 */
	public AssemblyResolvedPatterns applyContextChangesForward(Map<String, Long> vals,
			AssemblyResolvedPatterns fromLeft) {
		AssemblyResolvedPatterns res = fromLeft;
		// TODO: Figure out semantics of ContextCommit. Not sure it matters here.
		for (ContextChange chg : contextChanges) {
			if (chg instanceof ContextOp) {
				ContextOp cop = (ContextOp) chg;
				MaskedLong val = SOLVER.valueForResolution(cop.getPatternExpression(), vals, res);
				res = res.writeContextOp(cop, val);
			}
		}
		return res;
	}

	/**
	 * Apply just the instruction patterns in the forward (disassembly) direction
	 * 
	 * @param shift the (right) shift in bytes to apply to the patterns before combining
	 * @param fromLeft the accumulated patterns from the left sibling or parent
	 * @return
	 */
	public Stream<AssemblyResolvedPatterns> applyPatternsForward(int shift,
			AssemblyResolvedPatterns fromLeft) {
		if (patterns.isEmpty()) {
			DBG.println("No patterns for " + getLocation() + "?" + "(hash=" +
				System.identityHashCode(this) + ")");
		}
		return patterns.stream().map(pat -> fromLeft.combine(pat.shift(shift)));
	}

	@Override
	public int compareTo(AssemblyConstructorSemantic that) {
		// TODO: This could be better
		return this.toString().compareTo(that.toString());
	}
}
