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
package ghidra.app.plugin.core.debug.gui.slice;

import java.util.*;

import ghidra.debug.api.modules.DebuggerAddressTranslator;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.*;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.util.exception.CancelledException;
import ghidra.util.formatter.InstructionHtmlFormatter;
import ghidra.util.task.TaskMonitor;

class InstructionSliceNode extends UnitSliceNode<Instruction> {
	private static final InstructionHtmlFormatter FORMATTER = new InstructionHtmlFormatter();

	static String computeValue(Trace trace, Instruction instruction, long snap) {
		return instruction.toString();
	}

	static String computeDisplay(Trace trace, Instruction instruction, long snap) {
		return FORMATTER.formatInstruction(instruction);
	}

	public InstructionSliceNode(SliceEdgeType type, Trace trace, Instruction instruction,
			long snap, boolean displaySnap, DebuggerAddressTranslator ms) {
		ProgramLocation stPc = ms.getOpenMappedLocation(
			new DefaultTraceLocation(trace, null, Lifespan.at(snap), instruction.getAddress()));
		super(type, computeValue(trace, instruction, snap),
			computeDisplay(trace, instruction, snap),
			trace, instruction, snap, displaySnap, stPc == null ? null : stPc.getProgram(),
			stPc == null ? null : stPc.getByteAddress());
	}

	public InstructionSliceNode computeActualBranchFrom(TaskMonitor monitor,
			DebuggerAddressTranslator ms) throws CancelledException {
		UnitSnap<Instruction> branch =
			SliceAnalysis.INSTANCE.actualBranchFrom(trace, snap, monitor);
		return branch == null ? null
				: newInstructionNode(SliceEdgeType.ACTUAL_BRANCH_FROM, branch.unit(), branch.snap(),
					branch.displaySnap(), ms);
	}

	public void descendActualBranchFrom(TaskMonitor monitor, DebuggerAddressTranslator ms)
			throws CancelledException {
		addOnSwing(SliceEdgeType.ACTUAL_BRANCH_FROM, computeActualBranchFrom(monitor, ms));
	}

	public InstructionSliceNode computeActualConditionalBranchTo(TaskMonitor monitor,
			DebuggerAddressTranslator ms) throws CancelledException {
		UnitSnap<Instruction> is =
			SliceAnalysis.INSTANCE.actualConditionalBranchTo(trace, snap, monitor);
		return is == null ? null
				: newInstructionNode(SliceEdgeType.ACTUAL_CBRANCH_TO, is.unit(), is.snap(), true,
					ms);
	}

	public void descendActualConditionalBranchTo(TaskMonitor monitor, DebuggerAddressTranslator ms)
			throws CancelledException {
		addOnSwing(SliceEdgeType.ACTUAL_CBRANCH_TO, computeActualConditionalBranchTo(monitor, ms));
	}

	public List<DataSliceNode> computeStaticInputs(DebuggerAddressTranslator ms) {
		TraceMemorySpace regs = SliceAnalysis.INSTANCE.getEventThreadRegisters(trace, snap);
		if (regs == null) {
			return List.of();
		}

		Set<DataSliceNode> nodes = new LinkedHashSet<>();
		for (Varnode vn : SliceAnalysis.INSTANCE.getInputs(unit)) {
			// The instruction was disassembled from the trace, so no need to map addresses
			Address min = vn.isRegister()
					? regs.getAddressSpace().getOverlayAddress(vn.getAddress())
					: vn.getAddress();
			AddressRange range = new AddressRangeImpl(min, min.add(vn.getSize() - 1));
			Data data = SliceAnalysis.INSTANCE.getOrPseudoData(trace, snap, range);
			if (data != null) {
				nodes.add(newDataNode(SliceEdgeType.STATIC_INPUT, data, snap, displaySnap));
			}
		}
		return List.copyOf(nodes);
	}

	public void descendStaticInputs(DebuggerAddressTranslator ms) {
		addOnSwing(SliceEdgeType.STATIC_INPUT, computeStaticInputs(ms));
	}

	public List<DataSliceNode> computeStaticOutputs(DebuggerAddressTranslator ms) {
		TraceMemorySpace regs = SliceAnalysis.INSTANCE.getEventThreadRegisters(trace, snap);
		if (regs == null) {
			return List.of();
		}

		Set<DataSliceNode> nodes = new LinkedHashSet<>();
		for (Varnode vn : SliceAnalysis.INSTANCE.getOutputs(unit)) {
			Address min = vn.isRegister()
					? regs.getAddressSpace().getOverlayAddress(vn.getAddress())
					: vn.getAddress();
			AddressRange range = new AddressRangeImpl(min, min.add(vn.getSize() - 1));
			Data data = SliceAnalysis.INSTANCE.getOrPseudoData(trace, snap, range);
			if (data != null) {
				nodes.add(newDataNode(SliceEdgeType.STATIC_OUTPUT, data, snap, displaySnap));
			}
		}
		return List.copyOf(nodes);
	}

	public void descendStaticOutputs(DebuggerAddressTranslator ms) {
		addOnSwing(SliceEdgeType.STATIC_OUTPUT, computeStaticOutputs(ms));
	}

	public List<InstructionSliceNode> computeStaticConditionalBranchTo(DebuggerAddressTranslator ms,
			TaskMonitor monitor) throws CancelledException {
		Register ctxreg = trace.getBaseLanguage().getContextBaseRegister();
		Instruction stIns = image.getListing().getInstructionAt(staticPc);
		if (stIns == null) {
			return List.of();
		}
		Set<Instruction> stDeps =
			SliceAnalysis.INSTANCE.staticConditionalBranchesTo(image, stIns, monitor);

		Set<InstructionSliceNode> nodes = new LinkedHashSet<>();
		for (Instruction stDep : stDeps) {
			TraceLocation dyLoc = mapDynamic(ms, image, stDep.getAddress());
			OptionalLong mostRecent = SliceAnalysis.INSTANCE.computeMostRecentExecution(trace, snap,
				dyLoc.getAddress());
			long branchSnap = mostRecent.orElse(snap);
			Instruction dyIns = SliceAnalysis.INSTANCE.getOrDisassemble(trace, branchSnap,
				dyLoc.getAddress(), stDep.getRegisterValue(ctxreg));
			if (dyIns == null) {
				continue;
			}
			nodes.add(newInstructionNode(SliceEdgeType.STATIC_CBRANCH_TO, dyIns, branchSnap,
				mostRecent.isPresent(), ms));
		}
		return List.copyOf(nodes);
	}

	public void descendStaticConditionalBranchTo(DebuggerAddressTranslator ms, TaskMonitor monitor)
			throws CancelledException {
		addOnSwing(SliceEdgeType.STATIC_CBRANCH_TO, computeStaticConditionalBranchTo(ms, monitor));
	}

	public InstructionSliceNode computeStaticBranchFrom(DebuggerAddressTranslator ms,
			TaskMonitor monitor) throws CancelledException {
		Register ctxreg = trace.getBaseLanguage().getContextBaseRegister();
		Instruction stIns = image.getListing().getInstructionAt(staticPc);
		if (stIns == null) {
			return null;
		}
		Instruction stBranch = SliceAnalysis.INSTANCE.staticBranchFrom(image, stIns, monitor);
		if (stBranch == null) {
			return null;
		}
		TraceLocation dyLoc = mapDynamic(ms, image, stBranch.getAddress());
		if (dyLoc == null) {
			return null;
		}
		OptionalLong next =
			SliceAnalysis.INSTANCE.computeNextExecution(trace, snap, dyLoc.getAddress());
		long branchSnap = next.orElse(snap);
		Instruction dyIns = SliceAnalysis.INSTANCE.getOrDisassemble(trace, branchSnap,
			dyLoc.getAddress(), stBranch.getRegisterValue(ctxreg));
		if (dyIns == null) {
			return null;
		}
		return newInstructionNode(SliceEdgeType.STATIC_BRANCH_FROM, dyIns, branchSnap,
			next.isPresent(), ms);
	}

	public void descendStaticBranchFrom(DebuggerAddressTranslator ms, TaskMonitor monitor)
			throws CancelledException {
		addOnSwing(SliceEdgeType.STATIC_BRANCH_FROM, computeStaticBranchFrom(ms, monitor));
	}

	public List<InstructionSliceNode> computeStaticFlows(DebuggerAddressTranslator ms,
			TaskMonitor monitor) throws CancelledException {
		Register ctxreg = trace.getBaseLanguage().getContextBaseRegister();
		Instruction stIns = image.getListing().getInstructionAt(staticPc);
		if (stIns == null) {
			return List.of();
		}
		List<Address> stFlows = new ArrayList<>();
		stFlows.addAll(Arrays.asList(stIns.getFlows()));
		stFlows.add(stIns.getFallThrough());
		stFlows.removeIf(a -> a == null || a == Address.NO_ADDRESS);

		Set<InstructionSliceNode> nodes = new LinkedHashSet<>();
		for (Address stFlow : stFlows) {
			Instruction stFlowIns = image.getListing().getInstructionAt(stFlow);
			if (stFlowIns == null) {
				continue;
			}
			TraceLocation dyLoc = mapDynamic(ms, image, stFlow);
			if (dyLoc == null) {
				continue;
			}
			OptionalLong next =
				SliceAnalysis.INSTANCE.computeNextExecution(trace, snap, dyLoc.getAddress());
			long flowSnap = next.orElse(snap);
			Instruction dyFlowIns = SliceAnalysis.INSTANCE.getOrDisassemble(trace, flowSnap,
				dyLoc.getAddress(), stFlowIns.getRegisterValue(ctxreg));
			if (dyFlowIns == null) {
				continue;
			}
			nodes.add(newInstructionNode(SliceEdgeType.STATIC_FLOW_FROM, dyFlowIns, flowSnap,
				next.isPresent(), ms));
		}
		return List.copyOf(nodes);
	}

	public void descendStaticFlows(DebuggerAddressTranslator ms, TaskMonitor monitor)
			throws CancelledException {
		addOnSwing(SliceEdgeType.STATIC_FLOW_FROM, computeStaticFlows(ms, monitor));
	}
}
