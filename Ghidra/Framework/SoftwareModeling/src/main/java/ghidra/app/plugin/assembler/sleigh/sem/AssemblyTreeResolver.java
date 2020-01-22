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

import org.apache.commons.collections4.IteratorUtils;

import com.google.common.collect.Sets;

import ghidra.app.plugin.assembler.sleigh.SleighAssemblerBuilder;
import ghidra.app.plugin.assembler.sleigh.expr.*;
import ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar;
import ghidra.app.plugin.assembler.sleigh.grammars.AssemblyProduction;
import ghidra.app.plugin.assembler.sleigh.symbol.*;
import ghidra.app.plugin.assembler.sleigh.tree.*;
import ghidra.app.plugin.assembler.sleigh.util.DbgTimer;
import ghidra.app.plugin.assembler.sleigh.util.DbgTimer.DbgCtx;
import ghidra.app.plugin.processors.sleigh.Constructor;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.expression.PatternExpression;
import ghidra.app.plugin.processors.sleigh.symbol.OperandSymbol;

/**
 * The workhorse of semantic resolution for the assembler
 * 
 * This class takes a parse tree and some additional information (start address, context, etc.) and
 * attempts to determine possible encodings using the semantics associated with each branch of the
 * given parse tree. Details of this process are described in {@link SleighAssemblerBuilder}.
 * 
 * @see SleighAssemblerBuilder
 */
public class AssemblyTreeResolver {
	protected static final RecursiveDescentSolver solver = RecursiveDescentSolver.getSolver();
	protected static final DbgTimer dbg = DbgTimer.INACTIVE;

	protected final SleighLanguage lang;
	protected final long instStart;
	protected final Map<String, Long> vals = new HashMap<>();
	protected final AssemblyParseBranch tree;
	protected final AssemblyGrammar grammar;
	protected final AssemblyPatternBlock context;
	protected final AssemblyContextGraph ctxGraph;

	public static final String INST_START = "inst_start";
	public static final String INST_NEXT = "inst_next";

	/**
	 * Construct a resolver for the given parse tree
	 * 
	 * @param lang
	 * @param instStart the byte offset where the instruction will start
	 * @param tree the parse tree
	 * @param context the context expected at {@code instStart}
	 * @param ctxGraph the context transition graph used to resolve purely-recursive productions
	 */
	public AssemblyTreeResolver(SleighLanguage lang, long instStart, AssemblyParseBranch tree,
			AssemblyPatternBlock context, AssemblyContextGraph ctxGraph) {
		this.lang = lang;
		this.instStart = instStart;
		this.vals.put(INST_START, lang.getDefaultSpace().getAddressableWordOffset(instStart));
		this.tree = tree;
		this.grammar = tree.getGrammar();
		this.context = context.fillMask();
		this.ctxGraph = ctxGraph;
	}

	/**
	 * Resolve the tree for the given parameters
	 * 
	 * @return a set of resolutions (encodings and errors)
	 */
	public AssemblyResolutionResults resolve() {
		AssemblyResolutionResults results = resolveBranch(tree);
		AssemblyResolutionResults ret = new AssemblyResolutionResults();
		for (AssemblyResolution ar : results) {
			assert !(ar instanceof AssemblyResolvedBackfill);
			if (ar.isError()) {
				ret.add(ar);
				continue;
			}
			AssemblyResolvedConstructor rc = (AssemblyResolvedConstructor) ar;
			vals.put(INST_NEXT, lang.getDefaultSpace().getAddressableWordOffset(
				instStart + rc.getInstructionLength()));
			if (rc.hasBackfills()) {
				dbg.println("Backfilling: " + rc);
			}
			ar = rc.backfill(solver, vals);
			dbg.println("Backfilled final: " + ar);
			if (ar.isError()) {
				ret.add(ar);
				continue;
			}
			rc = (AssemblyResolvedConstructor) ar;

			if (rc.hasBackfills()) {
				ret.add(AssemblyResolution.error("Solution is incomplete", "failed backfill",
					List.of(rc)));
				continue;
			}
			AssemblyResolvedConstructor ctx =
				AssemblyResolution.contextOnly(context, "Selecting context", null);
			AssemblyResolvedConstructor check = rc.combine(ctx);
			if (null == check) {
				ret.add(AssemblyResolution.error("Incompatible context", "resolving",
					List.of(rc)));
				continue;
			}
			rc = check;

			AssemblyResolution fcheck = rc.checkNotForbidden();
			if (fcheck.isError()) {
				ret.add(fcheck);
				continue;
			}
			rc = (AssemblyResolvedConstructor) fcheck;

			ret.add(rc);
		}
		return ret;
	}

	/**
	 * Resolve a branch of the parse tree
	 * 
	 * @param branch the branch
	 * @return the intermediate results
	 */
	protected AssemblyResolutionResults resolveBranch(AssemblyParseBranch branch) {
		AssemblyProduction prod = branch.getProduction();
		AssemblyNonTerminal lhs = prod.getLHS();
		AssemblyProduction rec = grammar.getPureRecursion(lhs);
		// Currently, the assembler only allows recursion at the root.
		// Otherwise, the input context cannot be known.
		if (rec != null && branch.getParent() == null) {
			return resolveBranchRecursive(branch, rec);
		}
		return resolveBranchNonRecursive(branch);
	}

	/**
	 * Apply constructors as indicated by a path returned by the context resolution graph
	 * 
	 * Please note: The path given will be emptied during processing.
	 * 
	 * @param path the path to apply
	 * @param branch the branch corresponding to the production whose LHS has a purely-recursive
	 *            definition.
	 * @param rec the purely-recursive production
	 * @param child the intermediate result to apply the constructors to
	 * @return the results
	 */
	protected AssemblyResolutionResults applyRecursionPath(Deque<AssemblyConstructorSemantic> path,
			AssemblyParseBranch branch, AssemblyProduction rec, AssemblyResolvedConstructor child) {
		/*
		 * A constructor may have multiple patterns, so I cannot assume I will get at most one
		 * output at each constructor in the path. Start (1) collecting all the results, then (2)
		 * filter out and report the errors, then (3) feed successful resolutions into the next
		 * constructor in the path (or finish).
		 */
		AssemblyResolutionResults result = new AssemblyResolutionResults();
		AssemblyResolutionResults collected = new AssemblyResolutionResults();
		Set<AssemblyResolvedConstructor> intoNext = new LinkedHashSet<>();
		intoNext.add(child);
		while (!path.isEmpty()) {
			AssemblyConstructorSemantic sem = path.pollLast();
			List<AssemblyParseTreeNode> substs = List.of((AssemblyParseTreeNode) branch);
			// 1
			for (final AssemblyResolvedConstructor res : intoNext) {
				List<AssemblyResolvedConstructor> sel = List.of(res);
				collected.absorb(resolveSelectedChildren(rec, substs, sel, List.of(sem)));
			}
			intoNext.clear();
			// 2
			for (AssemblyResolution res : collected) {
				if (res.isError()) {
					result.add(res);
				}
				else { // 3
					intoNext.add((AssemblyResolvedConstructor) res);
				}
			}
		}
		result.addAll(intoNext);
		return result;
	}

	/**
	 * Resolve a branch where the production's LHS has a purely-recursive definition
	 * 
	 * @param branch the branch
	 * @param rec the purely-recursive definition
	 * @return the results
	 */
	protected AssemblyResolutionResults resolveBranchRecursive(AssemblyParseBranch branch,
			AssemblyProduction rec) {
		// TODO: There's probably a clever trick regarding since-constructor productions
		// And short-circuiting once a compatible recursive rule is found.
		try (DbgCtx dc = dbg.start("Resolving (recursive) branch: " + branch.getProduction())) {
			AssemblyResolutionResults result = new AssemblyResolutionResults();

			for (AssemblyResolution ar : resolveBranchNonRecursive(branch)) {
				if (ar.isError()) {
					result.add(ar);
					continue;
				}
				AssemblyResolvedConstructor rc = (AssemblyResolvedConstructor) ar;
				AssemblyPatternBlock dst = rc.getContext();
				// TODO: The desired context may need to be passed in. For now, just take start.
				AssemblyPatternBlock src = context; // TODO: This is only correct for "instruction"
				String table = branch.getProduction().getName();

				dbg.println("Finding paths from " + context + " to " + ar.lineToString());
				Collection<Deque<AssemblyConstructorSemantic>> paths =
					ctxGraph.computeOptimalApplications(src, table, dst, table);
				dbg.println("Found " + paths.size());
				for (Deque<AssemblyConstructorSemantic> path : paths) {
					dbg.println("  " + path);
					result.absorb(applyRecursionPath(path, branch, rec, rc));
				}
			}

			return result;
		}
	}

	/**
	 * Resolve the given branch, having selected a particular combination of subconstructor results
	 * 
	 * @param prod the production
	 * @param substs the braches and tokens corrresponding to the symbols of the production's RHS
	 * @param sel the selected subconstructor results
	 * @param semantics the collection of possible constructors for this production
	 * @return the results
	 */
	protected AssemblyResolutionResults resolveSelectedChildren(AssemblyProduction prod,
			List<AssemblyParseTreeNode> substs, List<AssemblyResolvedConstructor> sel,
			Collection<AssemblyConstructorSemantic> semantics) {

		try (DbgCtx dc = dbg.start("Selecting: " + IteratorUtils.toString(sel.iterator(),
			(AssemblyResolvedConstructor rc) -> rc.lineToString()))) {
			AssemblyResolutionResults results = new AssemblyResolutionResults();

			// Pre-check the combined contexts
			AssemblyPatternBlock combCtx = AssemblyPatternBlock.nop();
			for (AssemblyResolvedConstructor child : sel) {
				AssemblyPatternBlock check = combCtx.combine(child.getContext());
				if (null == check) {
					results.add(AssemblyResolution.error(
						"Incompatible context requirements among selected children",
						"Resolving " + prod, sel));
					return results;
				}
				combCtx = check;
			}
			dbg.println("Combined context: " + combCtx);

			AssemblyResolvedConstructor res = AssemblyResolution.nop("Resolving " + prod, sel);

			// OK, now that we have a requirement, seek constructors that are compatible.
			nextSem: for (AssemblyConstructorSemantic sem : semantics) {
				try (DbgCtx dc2 = dbg.start("Trying: " + sem)) {
					Constructor cons = sem.getConstructor();

					// Gather the operand values (from non-constructor semantics)
					AssemblyResolvedConstructor subres =
						res.copyAppendDescription("Applying constructor: " + sem);

					Map<Integer, Object> opvals = new HashMap<>();
					Iterator<Integer> opidxit = sem.getOperandIndexIterator();
					Iterator<AssemblyResolvedConstructor> selit = sel.iterator();
					for (int i = 0; i < prod.size(); i++) {
						AssemblyParseTreeNode child = substs.get(i);
						AssemblySymbol sym = prod.get(i);
						if (sym.takesOperandIndex()) {
							int opidx = opidxit.next();
							if (child.isNumeric()) {
								AssemblyParseNumericToken num = (AssemblyParseNumericToken) child;
								opvals.put(opidx, num.getNumericValue());
							}
							else if (child.isConstructor()) {
								opvals.put(opidx, selit.next());
							}
						}
					}

					// Now, work out how to write the operand values in
					opidxit = sem.getOperandIndexIterator();
					Iterator<AssemblyResolvedConstructor> subit = sel.iterator();
					for (int i = 0; i < prod.size(); i++) {
						AssemblyParseTreeNode child = substs.get(i);
						AssemblySymbol sym = prod.get(i);
						if (!sym.takesOperandIndex()) {
							continue;
						}
						dbg.println("Current: " + subres.lineToString());
						int opidx = opidxit.next();
						OperandSymbol subsym = cons.getOperand(opidx);
						int shift = computeOffset(subsym, cons, opvals);
						String symname = subsym.getName();
						dbg.println("Processing symbol: " + symname);
						if (child.isNumeric()) {
							int bitsize = 0;
							if (sym instanceof AssemblyNumericTerminal) {
								AssemblyNumericTerminal numeric = (AssemblyNumericTerminal) sym;
								bitsize = numeric.getBitSize();
							}
							Long opval = (Long) opvals.get(opidx); // delay unboxing until solving
							PatternExpression symexp = subsym.getDefiningExpression();
							if (symexp == null) {
								symexp = subsym.getDefiningSymbol().getPatternExpression();
							}
							String desc =
								"Solution to " + sym + " := " + Long.toHexString(opval) + " = " +
									symexp + " (immediate op:" + opidx + ",shift:" + shift + ")";
							dbg.println("Writing: " + desc);
							AssemblyResolution sol =
								solveOrBackfill(symexp, opval, bitsize, vals, opvals, null, desc);
							dbg.println("Solution: " + sol);
							if (null == sol) {
								throw new AssertionError("Who returned a null solution!? " +
									"Throw an exception or return an error result, please!");
							}
							if (sol.isError()) {
								AssemblyResolvedError err = (AssemblyResolvedError) sol;
								results.add(AssemblyResolution.error(err.getError(), subres));
								continue nextSem;
							}
							if (sol instanceof AssemblyResolvedConstructor) {
								AssemblyResolvedConstructor solcon =
									(AssemblyResolvedConstructor) sol;
								AssemblyResolvedConstructor check =
									subres.combine(solcon.shift(shift));
								if (null == check) {
									results.add(AssemblyResolution.error(
										"Conflict: Immediate operand (token " + i + ") " + sol,
										subres));
									continue nextSem;
								}
								subres = check;
							}
							else {
								AssemblyResolvedBackfill solbf = (AssemblyResolvedBackfill) sol;
								subres = subres.combine(solbf.shift(shift));
							}
						}
						else if (child.isConstructor()) {
							// Write the instruction pattern in, shifted
							AssemblyResolvedConstructor childrc = subit.next();
							dbg.println("Writing subtable(opidx:" + opidx + "): " + symname + ": " +
								childrc.lineToString() + " (shift:" + shift + ")");
							// I've already combined the contexts
							AssemblyResolvedConstructor check =
								subres.combine(childrc.shift(shift));
							if (null == check) {
								results.add(AssemblyResolution.error(
									"Conflict: Subtable operand (token " + i + ")", subres));
								continue nextSem;
							}
							subres = check;
						}
						else {
							dbg.println("Probably encountered a varnode production: " + child);
						}
					}

					// Now, write out the proper requirements based on context mutations
					AssemblyResolution backctx = sem.solveContextChanges(subres, vals, opvals);
					if (!(backctx instanceof AssemblyResolvedConstructor)) {
						results.add(backctx);
						continue;
					}
					subres = (AssemblyResolvedConstructor) backctx;
					subres = subres.solveContextChangesForForbids(sem, vals, opvals);

					// Now, write the actual instruction and context requirements from the constructor
					// patterns
					dbg.println("Writing patterns:");
					for (AssemblyResolvedConstructor pat : sem.getPatterns()) { // use the accessor
						AssemblyResolvedConstructor temp = subres;
						dbg.println("  Pattern: " + pat.lineToString());
						dbg.println("    Current: " + temp.lineToString());
						AssemblyResolvedConstructor check = temp.combine(pat);
						if (null == check) {
							results.add(
								AssemblyResolution.error("The patterns conflict " + subres, temp));
							continue;
						}
						temp = check;

						dbg.println("    Final: " + temp.lineToString());

						AssemblyResolution fcheck = temp.checkNotForbidden();
						if (fcheck.isError()) {
							results.add(fcheck);
							continue;
						}
						temp = (AssemblyResolvedConstructor) fcheck;

						results.add(temp);
					}
				}
				catch (Exception e) {
					dbg.println("While processing: " + sem);
					throw e;
				}
			}
			results = tryResolveBackfills(results);
			return results;
		}
	}

	protected AssemblyResolutionResults tryResolveBackfills(AssemblyResolutionResults results) {
		AssemblyResolutionResults res = new AssemblyResolutionResults();
		next_ar: for (AssemblyResolution ar : results) {
			if (ar.isError()) {
				res.add(ar);
				continue;
			}
			while (true) {
				AssemblyResolvedConstructor rc = (AssemblyResolvedConstructor) ar;
				if (!rc.hasBackfills()) {
					// finish: The complete solution is known
					res.add(rc);
					continue next_ar;
				}
				ar = rc.backfill(solver, vals);
				if (ar.isError() || ar.isBackfill()) {
					// fail: It is now known that the solution doesn't exist
					res.add(ar);
					continue next_ar;
				}
				if (ar.equals(rc)) {
					// fail: The solution is /still/ not known, and we made no progress
					res.add(ar);
					continue next_ar;
				}
				// Some progress was made, continue trying until we finish or fail
			}
		}
		return res;
	}

	/**
	 * Resolve a branch without considering any purely-recursive productions
	 * 
	 * This method is used either when the LHS has no purely-recursive definition, or before
	 * considering the purely-recursive definition when it is present.
	 * 
	 * @param branch the branch
	 * @return the results
	 */
	protected AssemblyResolutionResults resolveBranchNonRecursive(AssemblyParseBranch branch) {
		try (DbgCtx dc = dbg.start("Resolving (non-recursive) branch: " + branch.getProduction())) {
			// Resolve children first
			AssemblyResolutionResults results = new AssemblyResolutionResults();
			AssemblyProduction prod = branch.getProduction();
			List<AssemblyParseTreeNode> substs = branch.getSubstitutions();
			assert prod.size() == substs.size();

			// Sort the wheat and chaff
			// The resolved ones need to stay in order for the cross product
			List<HashSet<AssemblyResolvedConstructor>> childRes = new ArrayList<>();
			List<AssemblyResolvedError> childErr = new ArrayList<>();
			for (int i = 0; i < prod.size(); i++) {
				AssemblySymbol sym = prod.get(i);
				if (!sym.takesOperandIndex()) {
					continue;
				}
				AssemblyParseTreeNode child = substs.get(i);
				if (child.isConstructor()) {
					AssemblyResolutionResults rr = resolveBranch((AssemblyParseBranch) child);
					HashSet<AssemblyResolvedConstructor> childResElem = new HashSet<>();
					for (AssemblyResolution ar : rr) {
						if (ar.isError()) {
							childErr.add((AssemblyResolvedError) ar);
						}
						else {
							childResElem.add((AssemblyResolvedConstructor) ar);
						}
					}
					childRes.add(childResElem);
				}
			}

			// Now, search for constructors that are compatible, and resolve them wrt. the
			// selected resolved children:
			// This is also where the shifting will happen.
			Collection<AssemblyConstructorSemantic> semantics = grammar.getSemantics(prod);
			for (List<AssemblyResolvedConstructor> sel : Sets.cartesianProduct(childRes)) {
				results.absorb(resolveSelectedChildren(prod, substs,
					Collections.unmodifiableList(sel), semantics));
			}
			if (!childErr.isEmpty()) {
				results.add(AssemblyResolution.error("Child errors", "Resolving " + prod,
					Collections.unmodifiableList(childErr)));
			}
			return results;
		}
	}

	/**
	 * Compute the offset of an operand encoded in the instruction block
	 * 
	 * @param opsym the operand symbol
	 * @param cons the constructor containing the operand
	 * @param res the selected subconstructor encodings
	 * @return the offset (right shift) to apply to the encoded operand
	 */
	public static int computeOffset(OperandSymbol opsym, Constructor cons,
			Map<Integer, Object> res) {
		int offset = opsym.getRelativeOffset();
		int baseidx = opsym.getOffsetBase();
		if (baseidx != -1) {
			OperandSymbol baseop = cons.getOperand(baseidx);
			Object r = res.get(baseidx);
			if (r instanceof AssemblyResolvedConstructor) {
				AssemblyResolvedConstructor rc = (AssemblyResolvedConstructor) r;
				offset += rc.getInstructionLength();
			}
			else {
				offset += baseop.getMinimumLength();
			}
			offset += computeOffset(baseop, cons, res);
		}
		return offset;
	}

	/**
	 * Attempt to solve an expression
	 * 
	 * @param exp the expression to solve
	 * @param goal the desired value of the expression
	 * @param vals any defined symbols
	 * @param res the selected subconstructor encodings
	 * @param cur the resolved constructor so far
	 * @param description a description of the result
	 * @return the encoded solution, or a backfill record
	 */
	protected static AssemblyResolution solveOrBackfill(PatternExpression exp, MaskedLong goal,
			Map<String, Long> vals, Map<Integer, Object> res, AssemblyResolvedConstructor cur,
			String description) {
		try {
			return solver.solve(exp, goal, vals, res, cur, description);
		}
		catch (NeedsBackfillException bf) {
			int fieldLength = solver.getInstructionLength(exp, res);
			return AssemblyResolution.backfill(exp, goal, res, fieldLength, description);
		}
	}

	/**
	 * Attempt to solve an expression
	 * 
	 * Converts the given goal to a fully-defined {@link MaskedLong} and then solves as before.
	 * 
	 * @see #solveOrBackfill(PatternExpression, MaskedLong, Map, Map, AssemblyResolvedConstructor,
	 *      String)
	 */
	protected static AssemblyResolution solveOrBackfill(PatternExpression exp, long goal,
			Map<String, Long> vals, Map<Integer, Object> res, AssemblyResolvedConstructor cur,
			String description) {
		return solveOrBackfill(exp, MaskedLong.fromLong(goal), vals, res, cur, description);
	}

	/**
	 * Attempt to solve an expression
	 * 
	 * Converts the given goal and bits count to a {@link MaskedLong} and then solves as before. As
	 * a special case, if {@code bits == 0}, the goal is considered fully-defined (as if
	 * {@code bits == 64}).
	 * 
	 * @see #solveOrBackfill(PatternExpression, MaskedLong, Map, Map, AssemblyResolvedConstructor,
	 *      String)
	 * 
	 */
	protected static AssemblyResolution solveOrBackfill(PatternExpression exp, long goal, int bits,
			Map<String, Long> vals, Map<Integer, Object> res, AssemblyResolvedConstructor cur,
			String description) {
		long msk;
		if (bits == 0 || bits >= 64) {
			msk = -1L;
		}
		else {
			msk = ~(-1L << bits);
		}
		return solveOrBackfill(exp, MaskedLong.fromMaskAndValue(msk, goal), vals, res, cur,
			description);
	}
}
