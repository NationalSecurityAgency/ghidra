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
import ghidra.app.plugin.assembler.sleigh.expr.RecursiveDescentSolver;
import ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar;
import ghidra.app.plugin.assembler.sleigh.grammars.AssemblyProduction;
import ghidra.app.plugin.assembler.sleigh.sem.AbstractAssemblyStateGenerator.GeneratorContext;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolutionResults.Applicator;
import ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNonTerminal;
import ghidra.app.plugin.assembler.sleigh.tree.*;
import ghidra.app.plugin.assembler.sleigh.util.DbgTimer;
import ghidra.app.plugin.assembler.sleigh.util.DbgTimer.DbgCtx;
import ghidra.app.plugin.processors.sleigh.*;
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
public abstract class AbstractAssemblyTreeResolver<RP extends AssemblyResolvedPatterns> {
	protected static final RecursiveDescentSolver SOLVER = RecursiveDescentSolver.getSolver();
	protected static final DbgTimer DBG = DbgTimer.INACTIVE;

	public static final String INST_START = "inst_start";
	public static final String INST_NEXT = "inst_next";
	public static final String INST_NEXT2 = "inst_next2";

	protected final AbstractAssemblyResolutionFactory<RP, ?> factory;
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
	public AbstractAssemblyTreeResolver(AbstractAssemblyResolutionFactory<RP, ?> factory,
			SleighLanguage lang, Address at, AssemblyParseBranch tree, AssemblyPatternBlock context,
			AssemblyContextGraph ctxGraph) {
		this.factory = factory;
		this.lang = lang;
		this.at = at;
		this.vals.put(INST_START, at.getAddressableWordOffset());
		this.tree = tree;
		this.grammar = tree.getGrammar();
		this.context = context.fillMask();
		this.ctxGraph = ctxGraph;
	}

	public AbstractAssemblyResolutionFactory<RP, ?> getFactory() {
		return factory;
	}

	/**
	 * Resolve the tree for the given parameters
	 * 
	 * @return a set of resolutions (encodings and errors)
	 */
	public AssemblyResolutionResults resolve() {
		RP empty = factory.nop("Empty");
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

		AssemblyResolutionResults results =
			patStream.collect(Collectors.toCollection(factory::newAssemblyResolutionResults));
		results = resolveRootRecursion(results);
		results = selectContext(results);
		results = resolvePendingBackfills(results);
		// TODO: Remove this? It's subsumed by filterByDisassembly, and more accurately....
		results = filterForbidden(results);
		results = filterByDisassembly(results);
		for (AssemblyResolvedError err : errors) {
			results.add(err);
		}
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
			AssemblyResolutionResults result = factory.newAssemblyResolutionResults();

			for (AssemblyResolution ar : temp) {
				if (ar.isError()) {
					result.add(ar);
					continue;
				}
				@SuppressWarnings("unchecked")
				RP rp = (RP) ar;
				AssemblyPatternBlock dst = rp.getContext();
				// TODO: The desired context may need to be passed in. For now, just take start.
				AssemblyPatternBlock src = context; // NOTE: This is only correct for "instruction"
				String table = "instruction";

				DBG.println("Finding paths from " + src + " to " + ar.lineToString());
				Collection<Deque<AssemblyConstructorSemantic>> paths =
					ctxGraph.computeOptimalApplications(src, table, dst, table);
				DBG.println("Found " + paths.size());
				for (Deque<AssemblyConstructorSemantic> path : paths) {
					DBG.println("  " + path);
					result.absorb(applyRecursionPath(path, tree, rootRec, ar));
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
		return temp.apply(factory, rp -> {
			if (!rp.hasBackfills()) {
				return rp;
			}
			vals.put(INST_NEXT, at.add(rp.getInstructionLength()).getAddressableWordOffset());
			// inst_next2 use not really supported
			vals.put(INST_NEXT2, at.add(rp.getInstructionLength()).getAddressableWordOffset());
			DBG.println("Backfilling: " + rp);
			AssemblyResolution ar = rp.backfill(SOLVER, vals);
			DBG.println("Backfilled final: " + ar);
			return ar;
		}).apply(factory, rp -> {
			if (rp.hasBackfills()) {
				return factory.newErrorBuilder()
						.error("Solution is incomplete")
						.description("failed backfill")
						.children(List.of(rp))
						.build();
			}
			return rp;
		});
	}

	/**
	 * Filter out results whose context do not match that requested
	 * 
	 * @param temp the results whose contexts have not yet been checked
	 * @return the results that pass. Those that do not are replaced with errors.
	 */
	protected AssemblyResolutionResults selectContext(AssemblyResolutionResults temp) {
		RP ctx = factory.contextOnly(context, "Selecting context");
		return temp.apply(factory, rp -> {
			AssemblyResolution check = rp.combine(ctx);
			if (null == check) {
				return factory.newErrorBuilder()
						.error("Incompatible context")
						.description("resolving")
						.children(List.of(rp))
						.build();
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
		return temp.apply(factory, rp -> rp.checkNotForbidden());
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
		return temp.apply(factory, rp -> {
			MemBuffer buf =
				new ByteMemBufferImpl(at, rp.getInstruction().getVals(), lang.isBigEndian());
			try {
				SleighInstructionPrototype ip =
					(SleighInstructionPrototype) lang.parse(buf, asmCtx, false);
				if (!rp.equivalentConstructState(ip.getRootState())) {
					return factory.error("Disassembly prototype mismatch", rp);
				}
				return rp;
			}
			catch (InsufficientBytesException | UnknownInstructionException e) {
				return factory.error("Disassembly failed: " + e.getMessage(), rp);
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
		if (node instanceof AssemblyParseHiddenNode) {
			return getHiddenStateGenerator(opSym, fromLeft);
		}
		if (node instanceof AssemblyParseNumericToken token) {
			return new AssemblyOperandStateGenerator(this, token, opSym, fromLeft);
		}
		if (node instanceof AssemblyParseBranch branch) {
			return new AssemblyConstructStateGenerator(this, branch, fromLeft);
		}
		if (node instanceof AssemblyParseToken token && node.getSym().takesOperandIndex()) {
			return new AssemblyStringStateGenerator(this, token, opSym, fromLeft);
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
		if (defSym instanceof SubtableSymbol subtable) {
			return new AssemblyHiddenConstructStateGenerator(this, subtable, fromLeft);
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

	protected AssemblyResolutionResults parent(String description, AssemblyResolutionResults temp,
			int opCount) {
		return temp.stream()
				.map(r -> r.parent(description, opCount))
				.collect(Collectors.toCollection(factory::newAssemblyResolutionResults));
	}

	/**
	 * TODO: This is currently used only for resolving recursion. Could this be factored with
	 * {@link AssemblyConstructState#resolveMutations(AssemblyResolvedPatterns, Collection)}?
	 */
	protected AssemblyResolutionResults applyMutations(AssemblyConstructorSemantic sem,
			AssemblyResolutionResults temp) {
		DBG.println("Applying context mutations:");
		return temp.apply(factory, rp -> {
			DBG.println("Current: " + rp.lineToString());
			AssemblyResolution backctx = sem.solveContextChanges(rp, vals);
			DBG.println("Mutated: " + backctx.lineToString());
			return backctx;
		}).apply(factory, rp -> {
			return rp.solveContextChangesForForbids(sem, vals);
		});
	}

	/**
	 * TODO: This is currently used only for resolving recursion. Could this be factored with
	 * {@link AssemblyConstructState#resolvePatterns(AssemblyResolvedPatterns, Collection)}?
	 */
	protected AssemblyResolutionResults applyPatterns(AssemblyConstructorSemantic sem, int shift,
			AssemblyResolutionResults temp) {
		DBG.println("Applying patterns:");
		Collection<AssemblyResolution> patterns =
			sem.getPatterns()
					.stream()
					.map(p -> p.shift(shift))
					.collect(Collectors.toList());
		return temp.apply(factory, new Applicator() {
			@Override
			public Iterable<AssemblyResolution> getPatterns(
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
			public String describeError(AssemblyResolvedPatterns rp, AssemblyResolution pat) {
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
			AssemblyParseBranch branch, AssemblyProduction rec, AssemblyResolution child) {
		/*
		 * A constructor may have multiple patterns, so I cannot assume I will get at most one
		 * output at each constructor in the path. Start (1) collecting all the results, then (2)
		 * filter out and report the errors, then (3) feed successful resolutions into the next
		 * constructor in the path (or finish).
		 */
		AssemblyResolutionResults results = factory.newAssemblyResolutionResults();
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
			results = results.apply(factory, rp -> rp.shift(offset));
			results =
				resolvePatterns(sem, 0, results).apply(factory, rp -> rp.withConstructor(cons));
		}
		return results;
	}

	/**
	 * TODO: This is currently used only for resolving recursion. It seems it's missing from the
	 * refactor?
	 */
	protected AssemblyResolutionResults tryResolveBackfills(AssemblyResolutionResults results) {
		AssemblyResolutionResults res = factory.newAssemblyResolutionResults();
		next_ar: for (AssemblyResolution ar : results) {
			if (ar.isError()) {
				res.add(ar);
				continue;
			}
			while (true) {
				AssemblyResolvedPatterns rp = (AssemblyResolvedPatterns) ar;
				if (!rp.hasBackfills()) {
					// finish: The complete solution is known
					res.add(ar);
					continue next_ar;
				}
				ar = rp.backfill(SOLVER, vals);
				if (ar.isError() || ar.isBackfill()) {
					// fail: It is now known that the solution doesn't exist
					res.add(ar);
					continue next_ar;
				}
				if (ar.equals(rp)) {
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

	public AssemblyGrammar getGrammar() {
		return grammar;
	}
}
