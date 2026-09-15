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
package ghidra.features.bsim.gui.structs;

import java.util.*;
import java.util.Map.Entry;

import db.Transaction;
import ghidra.app.decompiler.*;
import ghidra.app.services.ConsoleService;
import ghidra.features.codecompare.graphanalysis.DataVertex;
import ghidra.features.codecompare.graphanalysis.Pinning;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class ComparePinningsTask extends Task {

	private StructureRecoveryPlugin plugin;
	private ConsoleService console;

	private static int DECOMPILER_TIMEOUT = 60;

	private final Program currentProgram;
	private final Program targetProgram;
	private DecompInterface currentInterface;
	private DecompInterface targetInterface;

	private Map<Program, Map<Function, DecompileResults>> decompilerResults =
		new HashMap<>();
	private Map<Long, Map<Long, Float>> results = new HashMap<>();

	private Map<String, Long> offsets;
	private Map<String, AddressSet> addressesByField;
	private Map<Function, Set<Function>> functionMap;
	private long maxOffset = 0x100000;

	private record PinningMatch(float weight, int sourceOffset, int targetOffset) {
		@Override
		public String toString() {
			return Integer.toHexString(sourceOffset) + ":" + Integer.toHexString(targetOffset) +
				" (" + weight + ")";
		}
	}

	public ComparePinningsTask(StructureRecoveryPlugin plugin) {
		super("Compare Pinnings", true, false, false);
		this.plugin = plugin;
		this.console = plugin.getConsole();
		this.currentProgram = plugin.getCurrentProgram();
		this.targetProgram = plugin.getTargetProgram();
		this.offsets = plugin.getOffsets();
		this.addressesByField = plugin.getAddressesByField();
		this.functionMap = plugin.getFunctionMap();
		this.maxOffset = plugin.getMaxOffset();
	}

	@Override
	public void run(TaskMonitor monitor) {
		String taskName = getTaskTitle();
		try {
			Thread.currentThread().setName(taskName);
			console.addMessage(taskName, "Running...");
			initDecompiler();
			comparePinnings(monitor);
			console.addMessage(taskName, "Finished!");
		}
		catch (Exception e) {
			if (!monitor.isCancelled()) {
				Msg.showError(this, null, getTaskTitle(), "Error running task: " + taskName +
					"\n" + e.getClass().getName() + ": " + e.getMessage(), e);
				console.addErrorMessage("", "Error running task: " + taskName);
				console.addException(taskName, e);
			}
		}
		finally {
			cleanupDecompiler();
		}
	}

	protected void comparePinnings(TaskMonitor monitor) throws CancelledException {
		monitor.setMessage("Comparing pinnings...");
		monitor.setIndeterminate(false);
		monitor.initialize(functionMap.size());

		for (Function left : functionMap.keySet()) {
			monitor.checkCancelled();

			Set<Function> tgtSet = functionMap.get(left);
			for (Function right : tgtSet) {
				monitor.checkCancelled();

				DecompileResults currentResults =
					getDecompilerResults(currentInterface, left, monitor);
				HighFunction currentHFunc = currentResults.getHighFunction();
				if (currentHFunc == null) {
					continue;
				}

				DecompileResults targetResults =
					getDecompilerResults(targetInterface, right, monitor);
				HighFunction targetHFunc = targetResults.getHighFunction();
				if (targetHFunc == null) {
					continue;
				}

				Pinning pin =
					Pinning.makePinning(currentHFunc, targetHFunc, false, false, true,
						TaskMonitor.DUMMY);

				for (String fieldName : offsets.keySet()) {
					Long offset = offsets.get(fieldName);
					AddressSet addresses = addressesByField.get(fieldName);
					results.putIfAbsent(offset, new HashMap<>());
					analyzePinning(pin, offset, addresses);
				}
			}
			monitor.increment();
		}
		//printResults();
		buildStructure();

	}

	private void initDecompiler() {
		DecompileOptions options = new DecompileOptions();

		currentInterface = new DecompInterface();
		currentInterface.setOptions(options);
		currentInterface.openProgram(currentProgram);

		targetInterface = new DecompInterface();
		targetInterface.setOptions(options);
		targetInterface.openProgram(targetProgram);
	}

	private void cleanupDecompiler() {
		if (currentInterface != null) {
			currentInterface.dispose();
		}
		if (targetInterface != null) {
			targetInterface.dispose();
		}
		decompilerResults.clear();
	}

	public DecompileResults getDecompilerResults(DecompInterface ifc, Function func,
			TaskMonitor monitor) {
		return decompilerResults
				.computeIfAbsent(ifc.getProgram(), _ -> new HashMap<>())
				.computeIfAbsent(func, f -> ifc.decompileFunction(f, DECOMPILER_TIMEOUT, monitor));
	}

	private void analyzePinning(Pinning pin, long offset, AddressSet addresses) {
		Map<DataVertex, DataVertex> originalPinMap = pin.getPinMap();
		Map<PcodeOp, DataVertex> op2vertex = new HashMap<>();
		Map<PcodeOp, DataVertex> opToVertexMap = new HashMap<>();

		for (DataVertex lv : originalPinMap.keySet()) {
			PcodeOpAST op = lv.getOp();
			if (op != null && !opToVertexMap.containsKey(op)) {
				opToVertexMap.put(op, originalPinMap.get(lv));
				op2vertex.put(op, lv);
			}
		}

		for (PcodeOp lop : opToVertexMap.keySet()) {
			DataVertex rv = opToVertexMap.get(lop);
			DataVertex lv = op2vertex.get(lop);
			if (addresses != null && addresses.contains(lop.getSeqnum().getTarget())) {
				compareConstants(lv, rv, offset);
			}
		}
	}

	private void compareConstants(DataVertex vertL, DataVertex vertR, long offset) {
		Set<Varnode> constantsL = new LinkedHashSet<>();
		collectConstantsByOperand(vertL.getOp(), new HashSet<>(), constantsL,
			vertL.getDepthPaired());

		Set<Varnode> constantsR = new LinkedHashSet<>();
		collectConstantsByOperand(vertR.getOp(), new HashSet<>(), constantsR,
			vertR.getDepthPaired());

		Set<Long> uniqL = extractConstants(constantsL);
		Set<Long> uniqR = extractConstants(constantsR);
		Set<Long> init = new TreeSet<>();
		init.addAll(uniqL);

		uniqR.removeAll(plugin.getExcludedOffsets());

		Set<Long> common = new HashSet<>(uniqL);
		common.retainAll(uniqR);

		// Remove what's in common
		uniqL.removeAll(common);
		uniqR.removeAll(common);

		if (uniqL.isEmpty() || uniqR.isEmpty()) {
			if (init.contains(offset)) {
				upcount(offset, offset);
			}
			return;
		}

		// Use obvious matches
		if (uniqL.size() == 1 && uniqL.contains(offset) && uniqR.size() == 1) {
			upcount(offset, uniqR.iterator().next());
		}
	}

	private void upcount(Long offsetL, Long offsetR) {
		results.computeIfAbsent(offsetL, _ -> new HashMap<>())
				.merge(offsetR, 1.0f, Float::sum);
	}

	private Set<Long> extractConstants(Set<Varnode> constants) {
		Set<Long> uniq = new TreeSet<>();
		for (Varnode vn : constants) {
			PcodeOp descendent = vn.getLoneDescend();
			if (descendent != null) {
				int opcode = descendent.getOpcode();
				if (opcode == PcodeOp.INDIRECT) {
					continue;
				}
				if (opcode == PcodeOp.PTRADD) {
					Varnode input1 = descendent.getInput(1);
					Varnode input2 = descendent.getInput(2);
					if (input1.isConstant() && input2.isConstant()) {
						uniq.add(Math.abs(input1.getOffset() * input2.getOffset()));
						continue;
					}
				}
			}
			long vnOffset = vn.getOffset();
			if (vnOffset == 0 || vnOffset == 1) {
				continue;
			}
			vnOffset = Math.abs(vnOffset);
			if (vnOffset > maxOffset) {
				continue;
			}
			uniq.add(vnOffset);
		}
		return uniq;
	}

	private void collectConstantsByOperand(PcodeOp op, Set<PcodeOp> visitedOps,
			Set<Varnode> constants, int depth) {
		if (depth < 0 || !visitedOps.add(op)) {
			return;
		}

		int nextDepth = depth - 1;
		int numInputs = op.getNumInputs();
		for (int i = 0; i < numInputs; i++) {
			Varnode input = op.getInput(i);
			if (input != null) {
				collectConstantsByVarnode(input, visitedOps, constants, nextDepth);
			}
		}
	}

	private void collectConstantsByVarnode(Varnode vn, Set<PcodeOp> visitedOps,
			Set<Varnode> constants, int depth) {
		if (depth < 0) {
			return;
		}
		if (vn.isConstant()) {
			constants.add(vn);
		}
		PcodeOp def = vn.getDef();
		if (def != null) {
			collectConstantsByOperand(def, visitedOps, constants, depth);
		}
	}

	private void buildStructure() {
		Structure original = plugin.getTargetDataType();
		if (original == null) {
			console.addMessage(StructureRecoveryPlugin.REGENERATE_STRUCT,
				"Error: Target data type is missing.");
			return;
		}

		List<PinningMatch> matchHistory = new ArrayList<>();
		long max = -1L;
		for (Entry<Long, Map<Long, Float>> entry : results.entrySet()) {
			Long currentOffset = entry.getKey();
			DataTypeComponent c = original.getComponentAt(currentOffset.intValue());
			int srcOffset = entry.getKey().intValue();
			Map<Long, Float> targetMap = entry.getValue();
			for (Entry<Long, Float> targetEntry : targetMap.entrySet()) {
				Long targetOffset = targetEntry.getKey();
				if (targetOffset > max) {
					max = targetOffset + c.getLength();
				}
				Float weight = targetEntry.getValue();
				if (weight != null) {
					matchHistory.add(new PinningMatch(weight, srcOffset, targetOffset.intValue()));
				}
			}
		}

		matchHistory.sort((a, b) -> Float.compare(b.weight, a.weight));

		try (Transaction _ = targetProgram.openTransaction("Build structure")) {
			ProgramBasedDataTypeManager dtm = targetProgram.getDataTypeManager();
			Structure structure =
				new StructureDataType("RECOVERED_" + original.getName(), (int) max, dtm);

			Set<Integer> placed = new HashSet<>();
			Set<Integer> occupiedBytes = new HashSet<>();
			for (PinningMatch match : matchHistory) {
				if (placed.contains(match.sourceOffset)) {
					continue;
				}

				DataTypeComponent origComp = original.getComponentAt(match.sourceOffset);
				DataTypeComponent targetComp = structure.getComponentAt(match.targetOffset);

				DataType dataType = origComp.getDataType();
				DataType targetDataType = dtm.getDataType(dataType.getDataTypePath());

				if (targetComp != null && targetComp.isUndefined()) {
					if (targetDataType == null) {
						// Try to resolve or replicate the type context locally if path missing
						targetDataType =
							dtm.resolve(dataType, DataTypeConflictHandler.DEFAULT_HANDLER);
					}
					if (targetDataType == null) {
						targetDataType = DataType.DEFAULT;
					}

					int componentLength = targetDataType.getLength();
					if (componentLength <= 0) {
						componentLength = origComp.getLength();
					}

					// Check for overlapping byte targets (possibly overkill,, but...)
					boolean conflict = false;
					for (int i = 0; i < componentLength; i++) {
						if (occupiedBytes.contains(match.targetOffset + i)) {
							conflict = true;
							break;
						}
					}

					if (conflict) {
						console.addMessage(StructureRecoveryPlugin.REGENERATE_STRUCT,
							"Overlapping target bounds for " + match + " : " +
								origComp + " using Byte");
						targetDataType = ByteDataType.dataType;
						componentLength = targetDataType.getLength();
					}

					try {
						structure.replaceAtOffset(match.targetOffset, targetDataType,
							targetDataType.getLength(), origComp.getFieldName(),
							origComp.getComment());
						placed.add(match.sourceOffset);
						for (int i = 0; i < componentLength; i++) {
							occupiedBytes.add(match.targetOffset + i);
						}
					}
					catch (IllegalArgumentException iae) {
						console.addMessage(StructureRecoveryPlugin.REGENERATE_STRUCT,
							iae.getMessage());
					}
				}
			}

			console.addMessage(StructureRecoveryPlugin.REGENERATE_STRUCT,
				"Placed: " + placed.size() + " in " + structure.getName());
			DataTypeComponent[] definedComponents = structure.getDefinedComponents();
			DataTypeComponent last = definedComponents[definedComponents.length - 1];
			structure.setLength(last.getEndOffset() + 1);
			dtm.addDataType(structure, DataTypeConflictHandler.DEFAULT_HANDLER);
		}
	}
}
