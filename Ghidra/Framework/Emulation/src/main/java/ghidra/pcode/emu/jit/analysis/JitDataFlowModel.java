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
package ghidra.pcode.emu.jit.analysis;

import java.io.*;
import java.util.*;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.lifecycle.Internal;
import ghidra.pcode.emu.jit.JitCompiler;
import ghidra.pcode.emu.jit.JitCompiler.Diag;
import ghidra.pcode.emu.jit.JitPassage;
import ghidra.pcode.emu.jit.JitPassage.DecodedPcodeOp;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.op.*;
import ghidra.pcode.emu.jit.var.*;
import ghidra.pcode.emu.jit.var.JitVal.ValUse;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.exec.PcodeProgram;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/**
 * The data flow analysis for JIT-accelerated emulation.
 * 
 * <p>
 * This implements the Data Flow Analysis phase of the {@link JitCompiler}. The result is a use-def
 * graph. The graph follows Static Single Assignment (SSA) form, in that each definition of a
 * variable, even if it's at the same address as a previous definition, is given a unique
 * identifier. The graph is bipartite with {@link JitOp ops} on one side and {@link JitVal values}
 * on the other. Please node the distinction between a <em>varnode</em> and a <em>variable</em> in
 * this context. A <em>varnode</em> refers to the address and size in the machine's state. For
 * better or for worse, this is often referred to as a "variable" in other contexts. A
 * <em>variable</em> in the SSA sense is a unique "instance" of a varnode with precisely one
 * <em>definition</em>. Consider the following x86 assembly:
 * 
 * <pre>
 * MOV RAX, qword ptr [...]
 * ADD RAX, RDX
 * MOV qword ptr [...], RAX
 * </pre>
 * 
 * <p>
 * Ignoring RAM, there are two varnodes at play, named for the registers they represent: {@code RAX}
 * and {@code RDX}. However, there are three variables. The first is an instance of {@code RAX},
 * defined by the first {@code MOV} instruction. The second is an instance of {@code RDX}, which is
 * implicitly defined as an input to the passage. The third is another instance of of {@code RAX},
 * defined by the {@code ADD} instruction. These could be given unique names
 * {@code RAX}<sub>1</sub>, {@code RDX}<sub>in</sub>, and {@code RAX}<sub>2</sub>, respectively.
 * Thus, the {@code ADD} instruction uses {@code RAX}<sub>1</sub> and {@code RDX}<sub>in</sub>, to
 * define {@code RAX}<sub>2</sub>. The last {@code MOV} instruction uses {@code RAX}<sub>2</sub>. If
 * we plot each instruction and variable in a graph, drawing edges for each use and definition, we
 * get a use-def graph.
 * 
 * <p>
 * Our analysis produces a use-def graph for the passage's p-code (not instructions) in two steps:
 * First, we analyze each basic block independently. There are a lot of nuts and bolts in the
 * implementation, but the analysis is achieved by straightforward interpretation of each block's
 * p-code ops. Second, we connect the blocks' use-def graphs together using phi nodes where
 * appropriate, according to the control flow.
 * 
 * <h2>Intra-block analysis</h2>
 * <p>
 * For each block, we create a p-code interpreter consisting of a {@link JitDataFlowState} and
 * {@link JitDataFlowExecutor}. Both are given this model's {@link JitDataFlowArithmetic}, which
 * populates the use-def graph. We then feed the block's p-code into the executor. The block gets a
 * fresh {@link JitDataFlowState}, so that its result has no dependency on the interpretation of any
 * other block, except in the numbering of variable identifiers; those must be unique across the
 * model.
 * 
 * <p>
 * During interpretation, varnode accesses generate value nodes. When a constant varnode is
 * accessed, it simply creates a {@link JitConstVal}. When an op produces an output, it generates a
 * {@link JitOutVar} and places it into the interpreter's {@link JitDataFlowState state} for its
 * varnode. When a varnode is read, the interpreter examines its state for the last definition. If
 * one is found, the variable is returned, its use noted, and nothing new is generated. Otherwise, a
 * {@link JitMissingVar} is generated. Note that the interpreter does not track memory variables in
 * its state, because the JIT translator does not seek to optimize these. At run time, such accesses
 * will affect the emulator's state immediately. Registers and Sleigh uniques, on the other hand,
 * are allocated as JVM locals, so we must know how they are used and defined. Direct memory
 * accesses generate {@link JitDirectMemoryVar} and {@link JitMemoryOutVar}. Indirect memory
 * accesses are denoted by the {@link JitLoadOp load} and {@link JitStoreOp store} op nodes, not as
 * variables. There is a dummy {@link JitIndirectMemoryVar} singleton, so that the state can return
 * something when the memory address is not fixed.
 * 
 * <h2>Inter-block analysis</h2>
 * <p>
 * Up to this point, each block's use-def sub-graph is disconnected from the others'. We define each
 * {@link JitMissingVar missing} variable generated during block interpretation as a {@link JitPhiOp
 * phi} op. A phi op is said to belong to the block that generated the missing variable. We seek
 * options for the phi op by examining the block's inward flows. For each source block, we check the
 * most recent definition of the sought varnode. If one is present, the option is added to the phi
 * op. Otherwise, we create an option by generating another phi op and taking its output. The new
 * phi op belongs to the source block, and we recurse to seek its options. If a cycle is
 * encountered, or we encounter a block with no inward flows, we do not recurse. An
 * {@link JitInputVar input} variable is generated whenever we encounter a passage entry, indicating
 * the variable could be defined outside the passage.
 *
 * <p>
 * Note that the resulting phi ops may not adhere precisely to the formal definition of <em>phi
 * node</em>. A phi op may have only one option. The recursive part of the option seeking algorithm
 * generates chains of phi ops such that an option must come from an immediately upstream block,
 * even if that block does not offer a direct definition. This may produce long chains when a
 * varnode use is several block flows removed from a possible definition. We had considered
 * simplifying/removing single-option phi ops afterward, but we found it too onerous, and the output
 * bytecode is not improved. We do not generate bytecode for phi ops; they are synthetic and only
 * used for analysis.
 */
public class JitDataFlowModel {

	/**
	 * Create a list of {@link JitTypeBehavior#ANY ANY}s having the same size as the list of values.
	 * 
	 * @param inVals the values, e.g., of each parameter to a userop
	 * @return the list
	 */
	static List<JitTypeBehavior> allAny(List<JitVal> inVals) {
		return inVals.stream().map(v -> JitTypeBehavior.ANY).toList();
	}

	private final JitAnalysisContext context;
	private final JitControlFlowModel cfm;

	private final JitPassage passage;
	private final SleighLanguage language;

	private final JitDataFlowArithmetic arithmetic;
	private final JitDataFlowUseropLibrary library;

	private int nextVarId = 1;
	private final List<JitPhiOp> phiNodes = new ArrayList<>();
	private final List<JitSyntheticOp> synthNodes = new ArrayList<>();
	private final Map<PcodeOp, JitOp> ops = new HashMap<>();

	private final Map<JitBlock, JitDataFlowBlockAnalyzer> analyzers = new HashMap<>();
	final SequencedSet<JitPhiOp> phiQueue = new LinkedHashSet<>();

	/**
	 * Construct the data flow model.
	 * 
	 * <p>
	 * Analysis is performed as part of constructing the model.
	 * 
	 * @param context the analysis context
	 * @param cfm the control flow model
	 */
	public JitDataFlowModel(JitAnalysisContext context, JitControlFlowModel cfm) {
		this.context = context;
		this.cfm = cfm;

		this.passage = context.getPassage();
		this.language = context.getLanguage();

		this.arithmetic = new JitDataFlowArithmetic(context, this);
		this.library = new JitDataFlowUseropLibrary(context, this);

		analyze();
	}

	/**
	 * Get the model's arithmetic that places p-code ops into the use-def graph
	 * 
	 * @return the arithmetic
	 */
	public JitDataFlowArithmetic getArithmetic() {
		return arithmetic;
	}

	/**
	 * Get a wrapper library that places userop calls into the use-def graph
	 * 
	 * @return the library
	 */
	public JitDataFlowUseropLibrary getLibrary() {
		return library;
	}

	/**
	 * Get all the phi nodes in the use-def graph.
	 * 
	 * @return the list of phi nodes
	 */
	public List<JitPhiOp> phiNodes() {
		return phiNodes;
	}

	/**
	 * Get all the synthetic op nodes in the use-def graph.
	 * 
	 * @return the list of synthetic op nodes
	 */
	public List<JitSyntheticOp> synthNodes() {
		return synthNodes;
	}

	/**
	 * Generate a unique variable identifier
	 * 
	 * @return the generated identifier
	 */
	private int nextVarId() {
		return nextVarId++;
	}

	/**
	 * Generate a new op output variable for eventual placement in the use-def graph
	 * 
	 * @param out the varnode describing the corresponding {@link PcodeOp}'s
	 *            {@link PcodeOp#getOutput() output}.
	 * @return the generated variable
	 * @see JitDataFlowModel
	 */
	public JitOutVar generateOutVar(Varnode out) {
		if (out.isRegister() || out.isUnique()) {
			return new JitLocalOutVar(nextVarId(), out);
		}
		return new JitMemoryOutVar(nextVarId(), out);
	}

	/**
	 * Generate a variable representing a direct memory access
	 * 
	 * @param vn the varnode, which ought to be neither register nor unique
	 * @return the variable
	 */
	public JitDirectMemoryVar generateDirectMemoryVar(Varnode vn) {
		return new JitDirectMemoryVar(nextVarId(), vn);
	}

	/**
	 * Generate a variable representing an indirect memory access
	 * 
	 * @param space the address space containing the variable, which out to be neither register nor
	 *            unique
	 * @param offset another variable describing the (dynamic) offset of the variable in the given
	 *            space
	 * @param size the number of bytes in the variable
	 * @param quantize true if the offset should be quantized (as in
	 *            {@link PcodeExecutorState#getVar(AddressSpace, Object, int, boolean, Reason)
	 *            getVar}).
	 * @return the variable
	 * @see JitIndirectMemoryVar
	 * @see JitLoadOp
	 * @see JitStoreOp
	 * @implNote because the load and store ops already encode these details (except maybe
	 *           {@code quantize}), this just returns a dummy instance.
	 */
	public JitIndirectMemoryVar generateIndirectMemoryVar(AddressSpace space, JitVal offset,
			int size, boolean quantize) {
		return JitIndirectMemoryVar.INSTANCE;
	}

	/**
	 * Add the given {@link JitOp} to the use-def graph
	 * 
	 * @param <T> the type of the node
	 * @param op the op
	 * @return the same op
	 * @see JitDataFlowModel
	 */
	public <T extends JitOp> T notifyOp(T op) {
		op.link();
		if (op instanceof JitPhiOp phi) {
			phiNodes.add(phi);
			synthNodes.add(phi);
		}
		else if (op instanceof JitSyntheticOp synth) {
			// Prevent call of .op()
			synthNodes.add(synth);
		}
		else {
			ops.put(Objects.requireNonNull(op.op()), op);
		}
		return op;
	}

	/**
	 * Get the use-def op node for the given p-code op
	 * 
	 * <p>
	 * NOTE: When used in testing, if the passage is manufactured from a {@link PcodeProgram}, the
	 * decoder will re-write the p-code ops as {@link DecodedPcodeOp}s. Be sure to pass an op to
	 * this method that comes from the resulting {@link JitPassage}, not the original program, or
	 * else this method will certainly return {@code null}.
	 * 
	 * @param op the p-code op from the source passage
	 * @return the node from the use-def graph, if present, or {@code null}
	 */
	public JitOp getJitOp(PcodeOp op) {
		return ops.get(op);
	}

	/**
	 * Get all the op nodes, whether from a p-code op or synthesized.
	 * 
	 * @return the ops.
	 * @see JitDataFlowModel
	 */
	Collection<JitOp> allOps() {
		Set<JitOp> all = new LinkedHashSet<>();
		all.addAll(ops.values());
		all.addAll(synthNodes);
		return all;
	}

	/**
	 * An upward graph traversal for collecting all values in the use-def graph.
	 * 
	 * @see #allValues()
	 * @see #allValuesSorted()
	 */
	protected class ValCollector extends HashSet<JitVal> implements JitOpUpwardVisitor {
		public ValCollector() {
			for (PcodeOp op : passage.getCode()) {
				JitOp jitOp = getJitOp(op);
				visitOp(jitOp);
				if (jitOp instanceof JitDefOp defOp) {
					visitVal(defOp.out());
				}
			}
		}

		@Override
		public void visitVal(JitVal v) {
			if (!add(v)) {
				return;
			}
			JitOpUpwardVisitor.super.visitVal(v);
		}
	}

	/**
	 * Get all values (and variables) in the use-def graph
	 * 
	 * @return the set of values
	 */
	public Set<JitVal> allValues() {
		return new ValCollector();
	}

	/**
	 * Get the sort key of a given value. Variables get their ID, constants get -2.
	 * 
	 * @param v the value
	 * @return the sort key
	 */
	int idOfVal(JitVal v) {
		return v instanceof JitVar vv ? vv.id() : -2;
	}

	/**
	 * Same as {@link #allValues()}, but sorted by ID with constants at the top
	 * 
	 * @return the list of values
	 */
	public List<JitVal> allValuesSorted() {
		return allValues().stream().sorted(Comparator.comparing(this::idOfVal)).toList();
	}

	protected JitDataFlowBlockAnalyzer getOrCreateAnalyzer(JitBlock block) {
		return analyzers.computeIfAbsent(block,
			b -> new JitDataFlowBlockAnalyzer(context, this, b));
	}

	/**
	 * Get the per-block data flow analyzer for the given basic block
	 * 
	 * @param block the block
	 * @return the analyzer
	 */
	public JitDataFlowBlockAnalyzer getAnalyzer(JitBlock block) {
		return analyzers.get(block);
	}

	/**
	 * Construct the use-def graph
	 */
	protected void analyze() {
		/**
		 * Just visit the blocks in any order. Use input placeholders and glue them together
		 * afterward.
		 * 
		 * I considered unrolling each loop at least once to avoid certain multi-equals stuff. I
		 * don't think that'll be necessary. If we pre-load the registers into local variables, then
		 * we'll always be reading and writing to those locals, so no worries about multi-equals.
		 */
		for (JitBlock block : cfm.getBlocks()) {
			getOrCreateAnalyzer(block).doIntrablock();
		}

		/**
		 * Now, work out the inter-block flows.
		 */
		analyzeInterblock(phiNodes);
	}

	/**
	 * Perform the inter-block analysis.
	 * 
	 * <p>
	 * This is called by {@link #analyze()} after intra-block analysis.
	 * 
	 * @implNote This may be called a second time by the {@link JitOpUseModel}, since a variable's
	 *           definition may be several block flows removed from its retirement, which counts as
	 *           a use.
	 * 
	 * @see JitVarScopeModel
	 * @see JitOpUseModel
	 */
	void analyzeInterblock(Collection<JitPhiOp> phis) {
		phiQueue.addAll(phis);
		while (!phiQueue.isEmpty()) {
			JitPhiOp phi = phiQueue.removeFirst();
			JitDataFlowBlockAnalyzer analyzer = getOrCreateAnalyzer(phi.block());
			analyzer.fillPhiFromDeps(phi);
		}
	}

	/**
	 * For testing: Get the value(s) in (or intersecting) the given register defined by the given
	 * block
	 * 
	 * @param block the block whose p-code to consider
	 * @param register the register to examine
	 * @return the list of values (usually variables)
	 */
	@Internal
	List<JitVal> getOutput(JitBlock block, Register register) {
		return getAnalyzer(block).getOutput(register);
	}

	/**
	 * For diagnostics: Dump the analysis result to stderr
	 * 
	 * @see Diag#PRINT_DFM
	 */
	public void dumpResult() {
		System.err.println("STAGE: DataFlow");
		for (JitBlock block : cfm.getBlocks()) {
			System.err.println("  Block: " + block);
			for (PcodeOp op : block.getCode()) {
				System.err.println("    %s: %s".formatted(op.getSeqnum(), getJitOp(op)));
			}
		}
	}

	/**
	 * For diagnostics: Dump the synthetic ops to stderr
	 * 
	 * @see Diag#PRINT_SYNTH
	 */
	public void dumpSynth() {
		System.err.println("SYNTHETIC OPS");
		for (JitSyntheticOp synthOp : synthNodes) {
			System.err.println("  " + synthOp);
		}
	}

	/**
	 * A diagnostic tool for visualizing the use-def graph.
	 * 
	 * <p>
	 * NOTE: This is only as complete as it needed to be for me to diagnose whatever issue I was
	 * having at the time.
	 * 
	 * @see #exportGraphviz(File)
	 */
	protected class GraphvizExporter implements JitOpUpwardVisitor {
		final PrintWriter out;
		final Set<JitVar> vars = new HashSet<>();
		final Set<JitOp> ops = new HashSet<>();

		public GraphvizExporter(File outFile) {
			try (FileOutputStream outStream = new FileOutputStream(outFile);
					PrintWriter out = new PrintWriter(outStream)) {
				this.out = out;
				out.println("digraph DataFlow {");
				for (PcodeOp op : passage.getCode()) {
					JitOp jitOp = getJitOp(op);
					if (jitOp instanceof JitDefOp defOp) {
						// Because of direction of visit
						visitVal(defOp.out());
					}
					else {
						visitOp(jitOp);
					}
				}
				out.println("}");
			}
			catch (IOException e) {
				throw new RuntimeException(e);
			}
		}

		String opLabel(JitOp op) {
			return switch (op) {
				case null -> "null";
				//case JitSyntheticOp synth -> synth.getClass().getSimpleName();
				//default -> op.op().toString();
				default -> "%s\n%x".formatted(op.getClass().getSimpleName(),
					System.identityHashCode(op));
			};
		}

		@Override
		public void visitOp(JitOp op) {
			if (!ops.add(op)) {
				return;
			}
			out.println("""
					  "op%x" [
					    label = "%s"
					    shape = "ellipse"
					  ];
					""".formatted(
				System.identityHashCode(op),
				opLabel(op)));

			if (op == null) {
				return;
			}

			int i = 0;
			for (JitVal input : op.inputs()) {
				i++;
				if (input instanceof JitVar iv) {
					out.println("""
							  "var%d" -> "op%x" [
							    headlabel = "[%d]"
							  ];
							""".formatted(
						iv.id(),
						System.identityHashCode(op),
						i));
				}
				else {
					out.println("""
							  "val%x" -> "op%x" [
							    headlabel = "[%d]"
							  ];
							""".formatted(
						System.identityHashCode(input),
						System.identityHashCode(op),
						i));
				}
			}

			if (op instanceof JitDefOp defOp) {
				out.println("""
						  "op%x" -> "var%d" [
						    taillabel = "out"
						  ];
						""".formatted(
					System.identityHashCode(op),
					defOp.out().id()));
			}

			JitOpUpwardVisitor.super.visitOp(op);
		}

		String varLabel(JitVar v) {
			return switch (v) {
				case JitVarnodeVar vv -> "%s\n%d".formatted(vv.varnode().toString(language),
					v.id());
				default -> throw new AssertionError();
			};
		}

		@Override
		public void visitVal(JitVal v) {
			final String name;
			final String label;
			if (v instanceof JitVar vv) {
				if (!vars.add(vv)) {
					return;
				}
				name = "var%d".formatted(vv.id());
				label = varLabel(vv);
			}
			else if (v instanceof JitConstVal cv) {
				name = "val%x".formatted(System.identityHashCode(cv));
				label = cv.value().toString();
			}
			else {
				throw new AssertionError();
			}

			out.println("""
					  "%s" [
					    label = "%s"
					    shape = "box"
					  ];
					""".formatted(name, label));
			for (ValUse use : v.uses()) {
				out.println("""
						  "%s" -> "op%x" [
						    dir = "back"
						    arrowhead = "none"
						    arrowtail = "crow"
						    taillabel = "use"
						  ];
						""".formatted(name, System.identityHashCode(use.op())));
			}
			if (v instanceof JitOutVar ov) {
				out.println("""
						  "op%x" -> "%s" [
						    dir = "back"
						    arrowhead = "none"
						    arrowtail = "crow"
						    taillabel = "def"
						  ];
						""".formatted(System.identityHashCode(ov.definition()), name));
			}

			JitOpUpwardVisitor.super.visitVal(v);
		}
	}

	/**
	 * Generate a graphviz .dot file to visualize the use-def graph.
	 * 
	 * <p>
	 * <b>WARNING:</b> This is an internal diagnostic that is only as complete as it needed to be.
	 * 
	 * @param file the output file
	 */
	@Internal // for diagnostics
	public void exportGraphviz(File file) {
		new GraphvizExporter(file);
	}
}
