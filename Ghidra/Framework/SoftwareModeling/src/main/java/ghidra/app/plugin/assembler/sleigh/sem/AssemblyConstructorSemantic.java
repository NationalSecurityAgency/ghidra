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

import ghidra.app.plugin.assembler.sleigh.expr.MaskedLong;
import ghidra.app.plugin.assembler.sleigh.expr.RecursiveDescentSolver;
import ghidra.app.plugin.assembler.sleigh.grammars.AssemblyProduction;
import ghidra.app.plugin.assembler.sleigh.util.DbgTimer;
import ghidra.app.plugin.languages.sleigh.SleighLanguages;
import ghidra.app.plugin.languages.sleigh.SubtableEntryVisitor;
import ghidra.app.plugin.processors.sleigh.*;
import ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern;
import ghidra.app.plugin.processors.sleigh.symbol.SubtableSymbol;

/**
 * Describes a SLEIGH constructor semantic
 * 
 * These are collected and associated with productions in the grammar based on the given
 * constructor's print pieces.
 */
public class AssemblyConstructorSemantic implements Comparable<AssemblyConstructorSemantic> {
	protected static final RecursiveDescentSolver solver = RecursiveDescentSolver.getSolver();
	protected static final DbgTimer dbg = AssemblyTreeResolver.dbg;

	protected final Set<AssemblyResolvedConstructor> patterns = new HashSet<>();
	protected final Constructor cons;
	protected final List<Integer> indices;

	// A set initialized on first access with forbidden patterns added
	protected Set<AssemblyResolvedConstructor> upatterns;

	/**
	 * Build a new SLEIGH constructor semantic
	 * @param cons the SLEIGH constructor
	 * @param indices the indices of RHS non-terminals in the associated production that represent an
	 *                operand in the SLEIGH constructor
	 */
	public AssemblyConstructorSemantic(Constructor cons, List<Integer> indices) {
		this.cons = cons;
		this.indices = Collections.unmodifiableList(indices);
	}

	public void addPattern(DisjointPattern pat) {
		addPattern(AssemblyResolution.fromPattern(pat, cons.getMinimumLength(), cons.toString()));
	}

	public void addPattern(AssemblyResolvedConstructor pat) {
		if (upatterns != null) {
			throw new IllegalStateException("Cannot add patterns after a call to getPatterns()");
		}
		this.patterns.add(pat);
	}

	@Override
	public String toString() {
		return cons.toString() + ":" + patterns.toString();
	}

	/**
	 * Get the SLEIGH constructor
	 * @return the constructor
	 */
	public Constructor getConstructor() {
		return cons;
	}

	/**
	 * Get the associated encoding patterns for the constructor
	 * @return the patterns
	 */
	public Collection<AssemblyResolvedConstructor> getPatterns() {
		if (upatterns == null) {
			computeAllForbids();
		}
		return upatterns;
	}

	/**
	 * Convert the index of a print piece to its associated operand index
	 * @param printpos position excluding whitespace and string tokens.
	 * @return the operand index
	 */
	public int getOperandIndex(int printpos) {
		return indices.get(printpos);
	}

	/**
	 * Get the list of operand indices in print piece order
	 * @return the list
	 */
	public List<Integer> getOperandIndices() {
		return indices;
	}

	/**
	 * Get an iterator over the operand indices
	 * 
	 * If this iterator is advanced for each non-terminal, while simultaneously iterating over the
	 * RHS of the associated production, then this will identify the corresponding operand index
	 * for each non-terminal
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
		Set<AssemblyResolvedConstructor> result = new HashSet<>();
		for (AssemblyResolvedConstructor pat : patterns) {
			AssemblyResolvedConstructor fpat = withComputedForbids(pat);
			result.add(fpat);
		}
		upatterns = Collections.unmodifiableSet(result);
	}

	/**
	 * Add the list of forbidden patterns to one of the constructor's patterns
	 * 
	 * SLEIGH disambiguates multiple matching pattern by two rules. First, if one is more specific
	 * than ("specializes") another, i.e., it matches on more bits than another pattern, the more
	 * specific pattern is chosen. Second, if the two are equally special, then the one that occurs
	 * first in the SLEIGH specification is taken. So, during resolution, if a less-special or
	 * later-occurring constructor is chosen, we must prevent continued resolution from matching
	 * the more-special  or earlier-occurring pattern(s).
	 * 
	 * Essentially, this states, "you may choose any value matching my pattern, except those that
	 * match these forbidden patterns."
	 * 
	 * This takes a given pattern, and searches the rest of the language for any patterns that
	 * would take precedence, and combines them as forbidden patterns with the given pattern.
	 * 
	 * @param pat the given pattern
	 * @return the same pattern with forbidden records added 
	 */
	protected AssemblyResolvedConstructor withComputedForbids(AssemblyResolvedConstructor pat) {
		// Forbid anything more specific (or otherwise takes precedence) over me.
		Set<AssemblyResolvedConstructor> forbids = new HashSet<>();
		SubtableSymbol parent = cons.getParent();

		SleighLanguages.traverseConstructors(parent, new SubtableEntryVisitor() {
			@Override
			public int visit(DisjointPattern sibDP, Constructor sibcons) {
				// Do not forbid myself.
				if (sibcons == cons) {
					return CONTINUE;
				}

				/*
				 * I had misunderstood the precedence rules originally.
				 * 1. If one pattern defines a subset of the other pattern, then the more-specific
				 *    one is preferred.
				 * 2. Otherwise, preference is by line number
				 * 
				 * Thus, I need to check if there is any overlap at all. If not, then I don't
				 * need to worry about forbidding anything.
				 * Then, I'll check if it defines a strict subset, and forbid it if so.
				 * Then, I'll check if it defines a strict overset, and skip the line check if so.
				 * Then, I'll check if its line number *precedes* mine, and forbid it if so.
				 * 
				 * (I originally though the pattern with the most bits won, no matter whether or
				 * not those bits overlapped.)
				 */

				// If the two patterns cannot be combined, then they are disjoint.
				AssemblyResolvedConstructor sibpat = AssemblyResolution.fromPattern(sibDP,
					sibcons.getMinimumLength(), "For specialization check");
				AssemblyResolvedConstructor comb = pat.combine(sibpat);
				if (null == comb) {
					return CONTINUE;
				}

				// OK, they overlap. Let's see if its a strict subset
				if (comb.bitsEqual(sibpat)) {
					forbids.add(sibpat.withDescription(
						cons + " forbids " + sibcons + " by pattern specificity"));
					return CONTINUE;
				}
				else if (comb.bitsEqual(pat)) {
					// I'm a strict subset, so I will no matter the line number
					return CONTINUE;
				}

				// Finally, check the line number
				if (sibcons.getId() < cons.getId()) {
					forbids.add(
						sibpat.withDescription(cons + " forbids " + sibcons + " by rule position"));
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
	 * @param res the combined resolution requirements derived from the subconstructors
	 * @param vals any defined symbols (usually {@code inst_start}, and {@code inst_next})
	 * @param opvals a map from operand index to operand value
	 * @return the resolution with context changes applied in reverse, or an error
	 * 
	 * Each value in {@code opvals} must either be a numeric value, e.g., an index from a varnode
	 * list, or another {@link AssemblyResolvedConstructor} for a subconstructor operand.
	 * 
	 * It's helpful to think of the SLEIGH disassembly process here. Normally, once the appropriate
	 * constructor has been identified (by matching patterns), its context changes are applied, and
	 * then its operands parsed (possibly parsing subconstructor operands). Thus, {@code res} can
	 * be thought of as the intermediate result between applying context changes and parsing
	 * operands, except in reverse. The output of this method corresponds to the state before
	 * context changes were applied, i.e., immediately after selecting the constructor. Thus, in
	 * reverse, the context is solved immediately before applying the selected constructor
	 * patterns.
	 * 
	 * @see AssemblyTreeResolver#resolveSelectedChildren(AssemblyProduction, List, List, Collection)
	 */
	public AssemblyResolution solveContextChanges(AssemblyResolvedConstructor res,
			Map<String, Long> vals, Map<Integer, Object> opvals) {
		List<ContextChange> contextChanges = cons.getContextChanges();
		List<ContextChange> reversed = new LinkedList<>();
		for (ContextChange chg : contextChanges) {
			reversed.add(0, chg);
		}
		for (ContextChange chg : reversed) {
			if (chg instanceof ContextOp) {
				dbg.println("Current: " + res.lineToString());
				// This seems backwards. That's because we're going backwards.
				// This is the "write" location for disassembly.
				ContextOp cop = (ContextOp) chg;
				dbg.println("Handling context change: " + cop);

				// TODO: Is this res or subres?
				MaskedLong reqval = res.readContextOp(cop);
				if (reqval.equals(MaskedLong.UNKS)) {
					dbg.println("Doesn't affect a current requirement");
					continue; // this context change does not satisfy any requirement
				}
				dbg.println("'read' " + reqval);

				// Remove the requirement that we just read before trying to solve
				res = res.maskOut(cop);
				dbg.println("Masked out: " + res.lineToString());

				// Now, solve
				AssemblyResolution sol = AssemblyTreeResolver.solveOrBackfill(
					cop.getPatternExpression(), reqval, vals, opvals, res, "Solution to " + cop);
				dbg.println("Solution: " + sol.lineToString());
				if (sol.isError()) {
					AssemblyResolvedError err = (AssemblyResolvedError) sol;
					return AssemblyResolution.error(err.getError(), res);
				}

				// Now, forward the new requirements to my parents.
				if (sol instanceof AssemblyResolvedConstructor) {
					AssemblyResolvedConstructor solcon = (AssemblyResolvedConstructor) sol;
					AssemblyResolvedConstructor check = res.combine(solcon);
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
				dbg.println("Combined: " + res.lineToString());
			}
		}
		return res;
	}

	/**
	 * Apply just context transformations in the forward (disassembly) direction
	 * 
	 * @param outer the state before context changes
	 * @return the state after context changes
	 * 
	 * Unlike the usual disassembly process, this method does not take into account any information
	 * from the instruction encoding. Any context bits that depend on it are set to unknown
	 * ({@code x}) in the output. This method is used to pre-compute a context transition graph in
	 * order to quickly resolve purely-recursive semantics on the root constructor table.
	 */
	public AssemblyResolvedConstructor applyForward(AssemblyResolvedConstructor outer) {
		AssemblyResolvedConstructor res = outer;
		// TODO: Figure out semantics of ContextCommit. Not sure it matters here.
		for (ContextChange chg : cons.getContextChanges()) {
			if (chg instanceof ContextOp) {
				ContextOp cop = (ContextOp) chg;
				MaskedLong val = solver.valueForResolution(cop.getPatternExpression(), res);
				res = res.writeContextOp(cop, val);
			}
		}
		return res;
	}

	@Override
	public int compareTo(AssemblyConstructorSemantic that) {
		// TODO: This could be better
		return this.toString().compareTo(that.toString());
	}
}
