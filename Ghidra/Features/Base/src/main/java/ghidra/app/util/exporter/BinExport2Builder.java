/* ###
 * IP: GHIDRA
 *
 * Copyright 2011-2024 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package ghidra.app.util.exporter;

import com.google.protobuf.ByteString;
import com.google.security.zynamics.BinExport.BinExport2;
import com.google.security.zynamics.BinExport.BinExport2.Builder;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.CodeUnitFormat;
import ghidra.program.model.listing.CodeUnitFormatOptions;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import java.io.File;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;
import java.util.function.ToIntFunction;

/**
 * Java implementation of the BinExport2 writer class for Ghidra using a builder pattern.
 * 
 * @see <a href=
 *      "https://github.com/google/binexport/blob/5591588fd6b30f9f751914cb8766aa258bd6f6f5/binexport2_writer.h#L24">C++
 *      implementation</a>
 */
public class BinExport2Builder {
	private final Builder builder = BinExport2.newBuilder();

	private TaskMonitor monitor;

	private final Program program;
	private final Listing listing;
	private final BasicBlockModel bbModel;

	private BinExportExporter.MnemonicMapper mnemonicMapper =
		new BinExportExporter.IdentityMnemonicMapper();
	private long addressOffset = 0;
	private boolean prependNamespace = false;

	public BinExport2Builder(Program ghidraProgram) {
		program = ghidraProgram;
		listing = program.getListing();
		bbModel = new BasicBlockModel(program, true);
	}

	public BinExport2Builder setMnemonicMapper(BinExportExporter.MnemonicMapper mapper) {
		mnemonicMapper = mapper;
		return this;
	}

	public BinExport2Builder setAddressOffset(long offset) {
		addressOffset = offset;
		return this;
	}

	public BinExport2Builder setPrependNamespace(boolean isPrepended) {
		prependNamespace = isPrepended;
		return this;
	}

	private long getMappedAddress(Address address) {
		return address.getOffset() - addressOffset;
	}

	private long getMappedAddress(Instruction instr) {
		return getMappedAddress(instr.getAddress());
	}

	private void buildMetaInformation() {
		monitor.setIndeterminate(true);
		monitor.setMessage("Exporting meta data");

		// Ghidra uses a quad format like x86:LE:32:default, BinExport just keeps
		// the processor and address size.
		String[] quad = program.getLanguageID().toString().split(":", 4);
		// TODO(cblichmann): Canonicalize architecture names
		String arch = quad[0] + "-" + quad[2];

		builder.getMetaInformationBuilder()
				.setExecutableName(new File(program.getExecutablePath()).getName())
				.setExecutableId(program.getExecutableSHA256())
				.setArchitectureName(arch)
				.setTimestamp(System.currentTimeMillis() / 1000);
	}

	private void buildExpressions(Map<String, Integer> expressionIndices) {
		CodeUnitFormat cuf = new CodeUnitFormat(new CodeUnitFormatOptions());
		int id = 0;
		for (Instruction instr : listing.getInstructions(true)) {
			for (int i = 0; i < instr.getNumOperands(); i++) {
				String opRep = cuf.getOperandRepresentationString(instr, i);
				if (expressionIndices.putIfAbsent(opRep, id) != null) {
					continue;
				}
				id++;
				builder.addExpressionBuilder()
						.setType(BinExport2.Expression.Type.SYMBOL)
						.setSymbol(opRep);
			}
		}
	}

	private void buildOperands(Map<String, Integer> expressionIndices) {
		ArrayList<Entry<String, Integer>> entries = new ArrayList<>(expressionIndices.entrySet());
		entries.sort(Entry.comparingByValue());
		for (Entry<String, Integer> entry : entries) {
			builder.addOperandBuilder().addExpressionIndex(entry.getValue());
		}
	}

	private void buildMnemonics(Map<String, Integer> mnemonicIndices) {
		monitor.setIndeterminate(true);
		monitor.setMessage("Computing mnemonic histogram");
		HashMap<String, Integer> mnemonicHist = new HashMap<>();
		for (Instruction instr : listing.getInstructions(true)) {
			mnemonicHist.merge(mnemonicMapper.getInstructionMnemonic(instr), 1,
				Integer::sum);
		}
		ArrayList<Entry<String, Integer>> mnemonicList = new ArrayList<>(mnemonicHist.entrySet());
		mnemonicList.sort(Comparator
				.comparingInt((ToIntFunction<Entry<String, Integer>>) Entry::getValue)
				.reversed()
				.thenComparing(Entry::getKey));
		int id = 0;
		for (Entry<String, Integer> entry : mnemonicList) {
			builder.addMnemonicBuilder().setName(entry.getKey());
			mnemonicIndices.put(entry.getKey(), id++);
		}
	}

	private void buildInstructions(Map<String, Integer> mnemonics,
			Map<String, Integer> expressionIndices,
			Map<Long, Integer> instructionIndices) {
		monitor.setIndeterminate(false);
		monitor.setMessage("Exporting instructions");
		monitor.setMaximum(listing.getNumInstructions());
		int progress = 0;
		Instruction prevInstr = null;
		long prevAddress = 0;
		int prevSize = 0;
		int id = 0;
		CodeUnitFormat cuf = new CodeUnitFormat(new CodeUnitFormatOptions());
		for (Instruction instr : listing.getInstructions(true)) {
			long address = getMappedAddress(instr);

			BinExport2.Instruction.Builder instrBuilder = builder.addInstructionBuilder();
			// Write the full instruction address iff:
			// - there is no previous instruction
			// - the previous instruction doesn't have code flow into the current one
			// - the previous instruction overlaps the current one
			// - the current instruction is a function entry point
			if (prevInstr == null || !prevInstr.hasFallthrough() ||
				prevAddress + prevSize != address ||
				listing.getFunctionAt(instr.getAddress()) != null) {
				instrBuilder.setAddress(address);
			}
			try {
				byte[] bytes = instr.getBytes();
				instrBuilder.setRawBytes(ByteString.copyFrom(bytes));
				prevSize = bytes.length;
			}
			catch (MemoryAccessException e) {
				// Leave raw bytes empty
			}
			int mnemonicIndex =
				mnemonics.get(mnemonicMapper.getInstructionMnemonic(instr));
			if (mnemonicIndex != 0) {
				// Only store if different from default value
				instrBuilder.setMnemonicIndex(mnemonicIndex);
			}
			instructionIndices.put(address, id++);

			// TODO(cblichmann): One expression per operand for now
			for (int i = 0; i < instr.getNumOperands(); i++) {
				Integer lookup =
					expressionIndices.get(cuf.getOperandRepresentationString(instr, i));
				if (lookup == null) {
					continue;
				}
				instrBuilder.addOperandIndex(lookup);
			}

			// Export call targets.
			for (Reference ref : instr.getReferenceIteratorTo()) {
				RefType refType = ref.getReferenceType();
				if (!refType.isCall()) {
					continue;
				}
				instrBuilder.addCallTarget(getMappedAddress(ref.getToAddress()));
			}

			prevInstr = instr;
			prevAddress = address;
			monitor.setProgress(progress++);
		}
	}

	private void buildBasicBlocks(Map<Long, Integer> instructionIndices,
			Map<Long, Integer> basicBlockIndices) throws CancelledException {
		int id = 0;
		for (CodeBlockIterator bbIter = bbModel.getCodeBlocks(monitor); bbIter.hasNext();) {
			CodeBlock bb = bbIter.next();

			BinExport2.BasicBlock.Builder protoBb = builder.addBasicBlockBuilder();

			int instructionIndex;
			int beginIndex = -1;
			int endIndex = -1;
			for (Instruction instr : listing.getInstructions(bb, true)) {
				instructionIndex = instructionIndices.get(getMappedAddress(instr));
				if (beginIndex < 0) {
					beginIndex = instructionIndex;
					endIndex = beginIndex + 1;
				}
				else if (instructionIndex != endIndex) {
					// Sequence is broken, store an interval
					BinExport2.BasicBlock.IndexRange.Builder indexRange =
						protoBb.addInstructionIndexBuilder().setBeginIndex(beginIndex);
					if (endIndex != beginIndex + 1) {
						// Omit end index in the single instruction interval case
						indexRange.setEndIndex(endIndex);
					}
					beginIndex = instructionIndex;
					endIndex = beginIndex + 1;
				}
				else {
					// Sequence is unbroken, remember endIndex
					endIndex = instructionIndex + 1;
				}
			}
			BinExport2.BasicBlock.IndexRange.Builder indexRange =
				protoBb.addInstructionIndexBuilder().setBeginIndex(beginIndex);
			if (endIndex != beginIndex + 1) {
				// Like above, omit end index in the single instruction interval case
				indexRange.setEndIndex(endIndex);
			}
			basicBlockIndices.put(getMappedAddress(bb.getFirstStartAddress()), id++);
		}
	}

	private void buildFlowGraphs(Map<Long, Integer> basicBlockIndices)
			throws CancelledException {
		FunctionManager funcManager = program.getFunctionManager();
		monitor.setIndeterminate(false);
		monitor.setMaximum(funcManager.getFunctionCount());
		int i = 0;

		for (Function func : funcManager.getFunctions(true)) {
			monitor.setProgress(i++);
			if (func.getEntryPoint().isNonLoadedMemoryAddress()) {
				continue;
			}

			CodeBlockIterator bbIter = bbModel.getCodeBlocksContaining(func.getBody(), monitor);
			if (!bbIter.hasNext()) {
				continue; // Skip empty flow graphs, they only exist as call graph nodes
			}
			var flowGraph = builder.addFlowGraphBuilder();
			while (bbIter.hasNext()) {
				CodeBlock bb = bbIter.next();
				long bbAddress = getMappedAddress(bb.getFirstStartAddress());
				int id = basicBlockIndices.get(bbAddress);
				if (bbAddress == getMappedAddress(func.getEntryPoint())) {
					flowGraph.setEntryBasicBlockIndex(id);
				}
				flowGraph.addBasicBlockIndex(id);

				long bbLastInstrAddress =
					getMappedAddress(listing.getInstructionBefore(bb.getMaxAddress()));
				ArrayList<BinExport2.FlowGraph.Edge> edges = new ArrayList<>();
				FlowType lastFlow = RefType.INVALID;
				for (CodeBlockReferenceIterator bbDestIter = bb.getDestinations(monitor); bbDestIter
						.hasNext();) {
					CodeBlockReference bbRef = bbDestIter.next();
					// BinExport2 only stores flow from the very last instruction of a
					// basic block.
					if (getMappedAddress(bbRef.getReferent()) != bbLastInstrAddress) {
						continue;
					}

					BinExport2.FlowGraph.Edge.Builder edge = BinExport2.FlowGraph.Edge.newBuilder();
					Integer targetId = basicBlockIndices
							.get(getMappedAddress(bbRef.getDestinationAddress()));
					FlowType flow = bbRef.getFlowType();
					if (flow.isConditional() || lastFlow.isConditional()) {
						edge.setType(flow.isConditional()
								? BinExport2.FlowGraph.Edge.Type.CONDITION_TRUE
								: BinExport2.FlowGraph.Edge.Type.CONDITION_FALSE);
						edge.setSourceBasicBlockIndex(id);
						if (targetId != null) {
							edge.setTargetBasicBlockIndex(targetId);
						}
						edges.add(edge.build());
					}
					else if (flow.isUnConditional() && !flow.isComputed()) {
						edge.setSourceBasicBlockIndex(id);
						if (targetId != null) {
							edge.setTargetBasicBlockIndex(targetId);
						}
						edges.add(edge.build());
					}
					else if (flow.isJump() && flow.isComputed()) {
						edge.setSourceBasicBlockIndex(id);
						if (targetId != null) {
							edge.setTargetBasicBlockIndex(targetId);
							edge.setType(BinExport2.FlowGraph.Edge.Type.SWITCH);
						}
						edges.add(edge.build());
					}
					lastFlow = flow;
				}
				flowGraph.addAllEdge(edges);
			}
			assert flowGraph.getEntryBasicBlockIndex() > 0;
		}
	}

	private void buildCallGraph() throws CancelledException {
		BinExport2.CallGraph.Builder callGraph = builder.getCallGraphBuilder();
		FunctionManager funcManager = program.getFunctionManager();
		monitor.setIndeterminate(false);
		monitor.setMaximum(funcManager.getFunctionCount() * 2L);
		int i = 0;
		int id = 0;
		Map<Long, Integer> vertexIndices = new HashMap<>();

		// First round, gather vertex indices for all functions.
		// TODO(cblichmann): Handle imports using getExternalFunctions()
		for (Function func : funcManager.getFunctions(true)) {
			monitor.setProgress(i++);
			Address entryPoint = func.getEntryPoint();
			if (entryPoint.isNonLoadedMemoryAddress()) {
				continue;
			}
			long mappedEntryPoint = getMappedAddress(entryPoint);

			BinExport2.CallGraph.Vertex.Builder vertex =
				callGraph.addVertexBuilder().setAddress(mappedEntryPoint);
			if (func.isThunk()) {
				// Only store type if different from default value (NORMAL)
				vertex.setType(BinExport2.CallGraph.Vertex.Type.THUNK);
			}

			if (!func.getName()
					.equals(SymbolUtilities.getDefaultFunctionName(entryPoint))) {
				// Ghidra does not seem to provide both mangled and demangled names
				// (like IDA). Once the Demangle analyzer or DemangleAllScript has run,
				// function names will always appear demangled. Short of running the
				// demangler ourselves and comparing before/after names, there is no way
				// to distinguish mangled from demangled names.
				// Hence, the BinExport will have the names in the mangle_name field.

				// Mangled name is the default, optionally prefixed with namespace.
				vertex.setMangledName(getFunctionName(func));
			}
			vertexIndices.put(mappedEntryPoint, id++);
		}

		// Second round, insert all call graph edges.
		for (Function func : funcManager.getFunctions(true)) {
			monitor.setProgress(i++);
			Address entryPoint = func.getEntryPoint();
			if (entryPoint.isNonLoadedMemoryAddress()) {
				continue;
			}

			CodeBlockIterator bbIter = bbModel.getCodeBlocksContaining(func.getBody(), monitor);
			if (!bbIter.hasNext()) {
				continue; // Skip empty flow graphs, they only exist as call graph nodes
			}
			id = vertexIndices.get(getMappedAddress(func.getEntryPoint()));

			while (bbIter.hasNext()) {
				CodeBlock bb = bbIter.next();

				for (CodeBlockReferenceIterator bbDestIter = bb.getDestinations(monitor); bbDestIter
						.hasNext();) {
					CodeBlockReference bbRef = bbDestIter.next();
					FlowType flow = bbRef.getFlowType();
					if (!flow.isCall()) {
						continue;
					}

					Integer targetId = vertexIndices
							.get(getMappedAddress(bbRef.getDestinationAddress()));
					if (targetId != null) {
						callGraph.addEdgeBuilder()
								.setSourceVertexIndex(id)
								.setTargetVertexIndex(targetId);
					}
				}
			}
		}
	}

	private void buildSections() {
		monitor.setMessage("Exporting sections");
		monitor.setIndeterminate(false);
		MemoryBlock[] blocks = program.getMemory().getBlocks();
		monitor.setMaximum(blocks.length);
		for (int i = 0; i < blocks.length; i++) {
			MemoryBlock block = blocks[i];
			builder.addSectionBuilder()
					.setAddress(block.getStart().getOffset())
					.setSize(block.getSize())
					.setFlagR(block.isRead())
					.setFlagW(block.isWrite())
					.setFlagX(block.isExecute());
			monitor.setProgress(i);
		}
	}

	private String getFunctionName(Function function) {
		if (!prependNamespace) {
			return function.getName();
		}
		// Push all parent namespace names on top of the Vector.
		ArrayList<String> functionNameComponents = new ArrayList<>();
		Namespace parentNamespace = function.getParentNamespace();
		while (parentNamespace != null && !"Global".equals(parentNamespace.getName())) {
			functionNameComponents.add(0, parentNamespace.getName());
			parentNamespace = parentNamespace.getParentNamespace();
		}
		// Add the name of the function as the last component.
		functionNameComponents.add(function.getName());
		return String.join("::", functionNameComponents);
	}

	public BinExport2 build(TaskMonitor taskMonitor) throws CancelledException {
		monitor = taskMonitor != null ? taskMonitor : TaskMonitor.DUMMY;

		buildMetaInformation();

		// TODO(cblichmann): Implement full expression trees. For now, each
		// expression corresponds to exactly one operand. Those
		// consist of Ghidra's string representation and are of
		// type SYMBOL.
		HashMap<String, Integer> expressionIndices = new HashMap<>();
		buildExpressions(expressionIndices);
		buildOperands(expressionIndices);

		TreeMap<String, Integer> mnemonics = new TreeMap<>();
		buildMnemonics(mnemonics);
		TreeMap<Long, Integer> instructionIndices = new TreeMap<>();
		buildInstructions(mnemonics, expressionIndices, instructionIndices);
		monitor.setMessage("Exporting basic block structure");
		HashMap<Long, Integer> basicBlockIndices = new HashMap<>();
		buildBasicBlocks(instructionIndices, basicBlockIndices);
		// TODO(cblichmann): Implement these:
		// buildComments()
		// buildStrings();
		// buildDataReferences()
		monitor.setMessage("Exporting flow graphs");
		buildFlowGraphs(basicBlockIndices);
		monitor.setMessage("Exporting call graph");
		buildCallGraph();
		buildSections();

		return builder.build();
	}

	public BinExport2 build() {
		try {
			return build(TaskMonitor.DUMMY);
		}
		catch (final CancelledException e) {
			assert false : "TaskMonitor.DUMMY should not throw";
			throw new RuntimeException(e);
		}
	}
}
