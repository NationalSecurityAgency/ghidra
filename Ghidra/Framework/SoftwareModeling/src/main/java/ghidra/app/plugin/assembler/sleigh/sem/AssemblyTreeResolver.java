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
import java.util.stream.Collectors;
import java.util.stream.Stream;

import ghidra.app.plugin.assembler.sleigh.SleighAssemblerBuilder;
import ghidra.app.plugin.assembler.sleigh.expr.*;
import ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar;
import ghidra.app.plugin.assembler.sleigh.grammars.AssemblyProduction;
import ghidra.app.plugin.assembler.sleigh.sem.AbstractAssemblyStateGenerator.GeneratorContext;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolutionResults.Applicator;
import ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNonTerminal;
import ghidra.app.plugin.assembler.sleigh.tree.*;
import ghidra.app.plugin.assembler.sleigh.util.DbgTimer;
import ghidra.app.plugin.assembler.sleigh.util.DbgTimer.DbgCtx;
import ghidra.app.plugin.processors.sleigh.*;
import ghidra.app.plugin.processors.sleigh.expression.PatternExpression;
import ghidra.app.plugin.processors.sleigh.symbol.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InsufficientBytesException;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;

/**
 * The workhorse of semantic resolution for the assembler
 * 
 * <p>
 * This class takes a parse tree and some additional information (start address, context, etc.) and
 * attempts to determine possible encodings using the semantics associated with each branch of the
 * given parse tree. Details of this process are described in {@link SleighAssemblerBuilder}.
 * 
 * @see SleighAssemblerBuilder
 */
public class AssemblyTreeResolver {
	protected static final RecursiveDescentSolver SOLVER = RecursiveDescentSolver.getSolver();
	protected static final DbgTimer DBG = DbgTimer.INACTIVE;

	public static final String INST_START = "inst_start";
	public static final String INST_NEXT = "inst_next";
	public static final String INST_NEXT2 = "inst_next2";

	protected final SleighLanguage lang;
	protected final Address at;
	protected final Map<String, Long> vals = new HashMap<>();
	protected final AssemblyParseBranch tree;
	protected final AssemblyGrammar grammar;
	protected final AssemblyPatternBlock context;
	protected final AssemblyContextGraph ctxGraph;

	/**
	 * Construct a resolver for the given parse tree
	 * 
	 * @param lang
	 * @param at the address where the instruction will start
	 * @param tree the parse tree
	 * @param context the context expected at {@code instStart}
	 * @param ctxGraph the context transition graph used to resolve purely-recursive productions
	 */
	public AssemblyTreeResolver(SleighLanguage lang, Address at, AssemblyParseBranch tree,
			AssemblyPatternBlock context, AssemblyContextGraph ctxGraph) {
		this.lang = lang;
		this.at = at;
		this.vals.put(INST_START, at.getAddressableWordOffset());
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
		AssemblyResolvedPatterns empty = AssemblyResolution.nop("Empty");
		AssemblyConstructStateGenerator rootGen =
			new AssemblyConstructStateGenerator(this, tree, empty);

		Collection<AssemblyResolvedError> errors = new ArrayList<>();
		Stream<AssemblyGeneratedPrototype> protStream =
			rootGen.generate(new GeneratorContext(List.of(), 0));

		if (DBG == DbgTimer.ACTIVE) {
			try (DbgCtx dc = DBG.start("Prototypes:")) {
				protStream = protStream.map(prot -> {
					DBG.println(prot);
					return prot;
				}).collect(Collectors.toList()).stream();
			}
		}

		Stream<AssemblyResolvedPatterns> patStream =
			protStream.map(p -> p.state).distinct().flatMap(s -> s.resolve(empty, errors));

		AssemblyResolutionResults results = new AssemblyResolutionResults();
		patStream.forEach(results::add);

		results = resolveRootRecursion(results);
		results = resolvePendingBackfills(results);
		results = selectContext(results);
		// TODO: Remove this? It's subsumed by filterByDisassembly, and more accurately....
		results = filterForbidden(results);
		results = filterByDisassembly(results);
		results.addAll(errors);
		return results;
	}

	/**
	 * If applicable, get the {@code I => I} production of the grammar
	 * 
	 * @return the production
	 */
	protected AssemblyProduction getRootRecursion() {
		assert tree.getParent() == null;
		AssemblyProduction rootProd = tree.getProduction();
		AssemblyNonTerminal start = rootProd.getLHS();
		AssemblyProduction rec = grammar.getPureRecursion(start);
		return rec;
	}

	/**
	 * If necessary, resolve recursive constructors at the root, usually for prefixes
	 * 
	 * <p>
	 * If there are no pure recursive constructors at the root, then this simply returns
	 * {@code temp} unmodified.
	 * 
	 * @param temp the resolved root results
	 * @return the results with pure recursive constructors applied to obtain a compatible context
	 */
	// Ugh, public so I can refer to it in javadocs...
	public AssemblyResolutionResults resolveRootRecursion(AssemblyResolutionResults temp) {
		AssemblyProduction rootRec = getRootRecursion();
		if (rootRec == null) {
			return temp;
		}
		try (DbgCtx dc = DBG.start("Resolving root recursion:")) {
			AssemblyResolutionResults result = new AssemblyResolutionResults();

			for (AssemblyResolution ar : temp) {
				if (ar.isError()) {
					result.add(ar);
					continue;
				}
				AssemblyResolvedPatterns rc = (AssemblyResolvedPatterns) ar;
				AssemblyPatternBlock dst = rc.getContext();
				// TODO: The desired context may need to be passed in. For now, just take start.
				AssemblyPatternBlock src = context; // NOTE: This is only correct for "instruction"
				String table = "instruction";

				DBG.println("Finding paths from " + src + " to " + ar.lineToString());
				Collection<Deque<AssemblyConstructorSemantic>> paths =
					ctxGraph.computeOptimalApplications(src, table, dst, table);
				DBG.println("Found " + paths.size());
				for (Deque<AssemblyConstructorSemantic> path : paths) {
					DBG.println("  " + path);
					result.absorb(applyRecursionPath(path, tree, rootRec, rc));
				}
			}

			return result;
		}
	}

	/**
	 * Attempt a second time to solve operands and context changes
	 * 
	 * <p>
	 * Backfills that depended on {@code inst_next} should now easily be solved, since the
	 * instruction length is now known.
	 * 
	 * @param temp the resolved results, with backfill pending
	 * @return the results without backfill, possible with new errors
	 */
	protected AssemblyResolutionResults resolvePendingBackfills(AssemblyResolutionResults temp) {
		return temp.apply(rc -> {
			if (!rc.hasBackfills()) {
				return rc;
			}
			vals.put(INST_NEXT, at.add(rc.getInstructionLength()).getAddressableWordOffset());
			// inst_next2 use not really supported
			vals.put(INST_NEXT2, at.add(rc.getInstructionLength()).getAddressableWordOffset());
			DBG.println("Backfilling: " + rc);
			AssemblyResolution ar = rc.backfill(SOLVER, vals);
			DBG.println("Backfilled final: " + ar);
			return ar;
		}).apply(rc -> {
			if (rc.hasBackfills()) {
				return AssemblyResolution.error("Solution is incomplete", "failed backfill",
					List.of(rc), null);
			}
			return rc;
		});
	}

	/**
	 * Filter out results whose context do not match that requested
	 * 
	 * @param temp the results whose contexts have not yet been checked
	 * @return the results that pass. Those that do not are replaced with errors.
	 */
	protected AssemblyResolutionResults selectContext(AssemblyResolutionResults temp) {
		AssemblyResolvedPatterns ctx =
			AssemblyResolution.contextOnly(context, "Selecting context");
		return temp.apply(rc -> {
			AssemblyResolvedPatterns check = rc.combine(ctx);
			if (null == check) {
				return AssemblyResolution.error("Incompatible context", "resolving", List.of(rc),
					null);
			}
			return check;
		});
	}

	/**
	 * Filter out results that would certainly be disassembled differently than assembled
	 * 
	 * <p>
	 * Because of constructor precedence rules, it is possible to assemble a pattern from a
	 * prototype that would not result in equivalent disassembly. This can be detected in some cases
	 * via the "forbids" mechanism, where more specific constructors are recorded with the result.
	 * If the generated pattern matches on of those more-specific constructors, it is forbidden.
	 * 
	 * @param temp the results whose forbids have not yet been checked
	 * @return the results that pass. Those that do not are replaced with errors.
	 */
	protected AssemblyResolutionResults filterForbidden(AssemblyResolutionResults temp) {
		return temp.apply(rc -> rc.checkNotForbidden());
	}

	/**
	 * Filter out results that get disassembled differently than assembled
	 * 
	 * <p>
	 * The forbids mechanism is not perfect, so as a final fail safe, we disassemble the result and
	 * compare the prototypes.
	 * 
	 * @param temp the results whose disassemblies have not yet been checked
	 * @return the results that pass. Those that do not are replaced with errors.
	 */
	protected AssemblyResolutionResults filterByDisassembly(AssemblyResolutionResults temp) {
		AssemblyDefaultContext asmCtx = new AssemblyDefaultContext(lang);
		asmCtx.setContextRegister(context);
		return temp.apply(rc -> {
			MemBuffer buf =
				new ByteMemBufferImpl(at, rc.getInstruction().getVals(), lang.isBigEndian());
			try {
				SleighInstructionPrototype ip =
					(SleighInstructionPrototype) lang.parse(buf, asmCtx, false);
				if (!rc.equivalentConstructState(ip.getRootState())) {
					return AssemblyResolution.error("Disassembly prototype mismatch", rc);
				}
				return rc;
			}
			catch (InsufficientBytesException | UnknownInstructionException e) {
				return AssemblyResolution.error("Disassembly failed: " + e.getMessage(), rc);
			}
		});
	}

	/**
	 * Get the state generator for a given operand and parse tree node
	 * 
	 * @param opSym the operand symbol
	 * @param node the corresponding parse tree node, possibly null indicating a hidden operand
	 * @param fromLeft the accumulated patterns from the left sibling or parent
	 * @return the generator
	 */
	protected AbstractAssemblyStateGenerator<?> getStateGenerator(OperandSymbol opSym,
			AssemblyParseTreeNode node, AssemblyResolvedPatterns fromLeft) {
		if (node == null) {
			return getHiddenStateGenerator(opSym, fromLeft);
		}
		if (node.isNumeric()) {
			return new AssemblyOperandStateGenerator(this, (AssemblyParseNumericToken) node, opSym,
				fromLeft);
		}
		if (node.isConstructor()) {
			return new AssemblyConstructStateGenerator(this, (AssemblyParseBranch) node, fromLeft);
		}
		throw new AssertionError();
	}

	/**
	 * Get the state generator for a hidden operand
	 * 
	 * @param opSym the operand symbol
	 * @param fromLeft the accumulated patterns from the left sibling or parent
	 * @return the generator
	 */
	protected AbstractAssemblyStateGenerator<?> getHiddenStateGenerator(OperandSymbol opSym,
			AssemblyResolvedPatterns fromLeft) {
		TripleSymbol defSym = opSym.getDefiningSymbol();
		if (defSym instanceof SubtableSymbol) {
			return new AssemblyHiddenConstructStateGenerator(this, (SubtableSymbol) defSym,
				fromLeft);
		}
		return new AssemblyNopStateGenerator(this, opSym, fromLeft);
	}

	/**
	 * Apply a constructor pattern
	 * 
	 * <p>
	 * TODO: This is currently used only for resolving recursion. Could this be factored with
	 * {@link AssemblyConstructState#resolve(AssemblyResolvedPatterns, Collection)}?
	 * 
	 * @param sem the SLEIGH constructor
	 * @param shift the shift
	 * @param fromChildren the results from the single resolved child
	 * @return the results
	 */
	protected AssemblyResolutionResults resolvePatterns(AssemblyConstructorSemantic sem, int shift,
			AssemblyResolutionResults fromChildren) {
		AssemblyResolutionResults results = fromChildren;
		results = applyMutations(sem, results);
		results = applyPatterns(sem, shift, results);
		results = tryResolveBackfills(results);
		return results;
	}

	/**
	 * TODO: Can this be factored?
	 */
	protected AssemblyResolutionResults parent(String description, AssemblyResolutionResults temp,
			int opCount) {
		return temp.stream()
				.map(r -> r.parent(description, opCount))
				.collect(Collectors.toCollection(AssemblyResolutionResults::new));
	}

	/**
	 * TODO: This is currently used only for resolving recursion. Could this be factored with
	 * {@link AssemblyConstructState#resolveMutations(AssemblyResolvedPatterns, Collection)}?
	 */
	protected AssemblyResolutionResults applyMutations(AssemblyConstructorSemantic sem,
			AssemblyResolutionResults temp) {
		DBG.println("Applying context mutations:");
		return temp.apply(rc -> {
			DBG.println("Current: " + rc.lineToString());
			AssemblyResolution backctx = sem.solveContextChanges(rc, vals);
			DBG.println("Mutated: " + backctx.lineToString());
			return backctx;
		}).apply(rc -> {
			return rc.solveContextChangesForForbids(sem, vals);
		});
	}

	/**
	 * TODO: This is currently used only for resolving recursion. Could this be factored with
	 * {@link AssemblyConstructState#resolvePatterns(AssemblyResolvedPatterns, Collection)}?
	 */
	protected AssemblyResolutionResults applyPatterns(AssemblyConstructorSemantic sem, int shift,
			AssemblyResolutionResults temp) {
		DBG.println("Applying patterns:");
		Collection<AssemblyResolvedPatterns> patterns =
			sem.getPatterns().stream().map(p -> p.shift(shift)).collect(Collectors.toList());
		return temp.apply(new Applicator() {
			@Override
			public Iterable<? extends AssemblyResolution> getPatterns(
					AssemblyResolvedPatterns cur) {
				return patterns;
			}

			@Override
			public AssemblyResolvedPatterns setRight(AssemblyResolvedPatterns res,
					AssemblyResolvedPatterns cur) {
				// This is typically applied by parent, so don't insert sibling
				return res;
			}

			@Override
			public String describeError(AssemblyResolvedPatterns rc, AssemblyResolution pat) {
				return "The patterns conflict " + pat.lineToString();
			}

			@Override
			public AssemblyResolvedPatterns combineBackfill(AssemblyResolvedPatterns cur,
					AssemblyResolvedBackfill bf) {
				throw new AssertionError();
			}

			@Override
			public AssemblyResolution finish(AssemblyResolvedPatterns resolved) {
				return resolved.checkNotForbidden();
			}
		});
	}

	/**
	 * Apply constructors as indicated by a path returned by the context resolution graph
	 * 
	 * <p>
	 * <b>NOTE:</b> The given path will be emptied during processing.
	 * 
	 * @param path the path to apply
	 * @param branch the branch corresponding to the production whose LHS has a purely-recursive
	 *            definition.
	 * @param rec the purely-recursive production
	 * @param child the intermediate result to apply the constructors to
	 * @return the results
	 */
	protected AssemblyResolutionResults applyRecursionPath(Deque<AssemblyConstructorSemantic> path,
			AssemblyParseBranch branch, AssemblyProduction rec, AssemblyResolvedPatterns child) {
		/*
		 * A constructor may have multiple patterns, so I cannot assume I will get at most one
		 * output at each constructor in the path. Start (1) collecting all the results, then (2)
		 * filter out and report the errors, then (3) feed successful resolutions into the next
		 * constructor in the path (or finish).
		 */
		AssemblyResolutionResults results = new AssemblyResolutionResults();
		results.add(child);
		while (!path.isEmpty()) {
			AssemblyConstructorSemantic sem = path.pollLast();

			int opIdx = sem.getOperandIndex(0);
			Constructor cons = sem.getConstructor();
			OperandSymbol opSym = cons.getOperand(opIdx);
			if (-1 != opSym.getOffsetBase()) {
				throw new AssertionError("TODO");
			}
			int offset = opSym.getRelativeOffset();
			results = parent("Resolving recursive constructor: " + cons.getSourceFile() + ":" +
				cons.getLineno(), results, 1);
			results = results.apply(rc -> rc.shift(offset));
			results = resolvePatterns(sem, 0, results).apply(rc -> rc.withConstructor(cons));
		}
		return results;
	}

	/**
	 * TODO: This is currently used only for resolving recursion. It seems its missing from the
	 * refactor?
	 */
	protected AssemblyResolutionResults tryResolveBackfills(AssemblyResolutionResults results) {
		AssemblyResolutionResults res = new AssemblyResolutionResults();
		next_ar: for (AssemblyResolution ar : results) {
			if (ar.isError()) {
				res.add(ar);
				continue;
			}
			while (true) {
				AssemblyResolvedPatterns rc = (AssemblyResolvedPatterns) ar;
				if (!rc.hasBackfills()) {
					// finish: The complete solution is known
					res.add(rc);
					continue next_ar;
				}
				ar = rc.backfill(SOLVER, vals);
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
	 * Compute the offset of an operand encoded in the instruction block
	 * 
	 * <p>
	 * TODO: Currently, there are duplicate mechanisms for resolving a constructor: 1) The newer
	 * mechanism implemented in {@link AssemblyConstructState}, and 2) the older one implemented in
	 * {@link #applyPatterns(AssemblyConstructorSemantic, int, AssemblyResolutionResults)}. The
	 * latter seems to require this method, since it does not have pre-computed shifts as in the
	 * former. We should probably remove the latter in favor of the former....
	 * 
	 * @param opsym the operand symbol
	 * @param cons the constructor containing the operand
	 * @return the offset (right shift) to apply to the encoded operand
	 */
	public static int computeOffset(OperandSymbol opsym, Constructor cons) {
		int offset = opsym.getRelativeOffset();
		int baseidx = opsym.getOffsetBase();
		if (baseidx != -1) {
			OperandSymbol baseop = cons.getOperand(baseidx);
			offset += baseop.getMinimumLength();
			offset += computeOffset(baseop, cons);
		}
		return offset;
	}

	/**
	 * Attempt to solve an expression
	 * 
	 * @param exp the expression to solve
	 * @param goal the desired value of the expression
	 * @param vals any defined symbols
	 * @param cur the resolved constructor so far
	 * @param description a description of the result
	 * @return the encoded solution, or a backfill record
	 */
	protected static AssemblyResolution solveOrBackfill(PatternExpression exp, MaskedLong goal,
			Map<String, Long> vals, AssemblyResolvedPatterns cur, String description) {
		try {
			return SOLVER.solve(exp, goal, vals, cur, description);
		}
		catch (NeedsBackfillException bf) {
			int fieldLength = SOLVER.getInstructionLength(exp);
			return AssemblyResolution.backfill(exp, goal, fieldLength, description);
		}
	}

	/**
	 * Attempt to solve an expression
	 * 
	 * <p>
	 * Converts the given goal to a fully-defined {@link MaskedLong} and then solves as before.
	 * 
	 * @see #solveOrBackfill(PatternExpression, MaskedLong, Map, AssemblyResolvedPatterns, String)
	 */
	protected static AssemblyResolution solveOrBackfill(PatternExpression exp, long goal,
			Map<String, Long> vals, AssemblyResolvedPatterns cur, String description) {
		return solveOrBackfill(exp, MaskedLong.fromLong(goal), vals, cur, description);
	}

	/**
	 * Attempt to solve an expression
	 * 
	 * <p>
	 * Converts the given goal and bits count to a {@link MaskedLong} and then solves as before. As
	 * a special case, if {@code bits == 0}, the goal is considered fully-defined (as if
	 * {@code bits == 64}).
	 * 
	 * @see #solveOrBackfill(PatternExpression, MaskedLong, Map, AssemblyResolvedPatterns, String)
	 */
	protected static AssemblyResolution solveOrBackfill(PatternExpression exp, long goal, int bits,
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
}
