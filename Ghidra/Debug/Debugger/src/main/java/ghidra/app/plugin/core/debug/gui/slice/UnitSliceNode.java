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

import java.nio.ByteBuffer;
import java.util.*;

import javax.swing.Icon;

import docking.widgets.gtreetable.GTreeTableNode;
import ghidra.debug.api.modules.DebuggerAddressTranslator;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.*;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.symbol.TraceReference;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

abstract class UnitSliceNode<U extends CodeUnit> extends AbstractSliceNode {
	static String computeLocation(Trace trace, CodeUnit unit) {
		Register register = trace.getBaseLanguage()
				.getRegister(unit.getAddress().getPhysicalAddress(), unit.getLength());
		if (register != null) {
			return register.getName();
		}
		return "%s:%d".formatted(unit.getAddress(), unit.getLength());
	}

	record Key(SliceEdgeType type, Address start, long snap, int length) {}

	private final Key key;

	private final SliceEdgeType type;
	private final String display;
	protected final U unit;
	protected final long snap;
	protected final boolean displaySnap;
	protected final Program image;
	protected final Address staticPc;
	private final String location;

	public UnitSliceNode(SliceEdgeType type, String value, String display, Trace trace, U unit,
			long snap, boolean displaySnap, Program image, Address staticPc) {
		this.key = new Key(type, unit.getAddress(), snap, unit.getLength());
		this.type = type;
		this.display = display;
		this.unit = unit;
		this.snap = snap;
		this.displaySnap = displaySnap;
		this.image = image;
		this.staticPc = staticPc;
		this.location = computeLocation(trace, unit);
		super("%s: %s".formatted(type, value), trace);
	}

	@Override
	public boolean equals(Object obj) {
		return obj instanceof UnitSliceNode<?> that && this.key.equals(that.key);
	}

	@Override
	public int hashCode() {
		return key.hashCode();
	}

	@Override
	public Icon getIcon() {
		return type.getIcon();
	}

	@Override
	public String getTreeData() {
		return display;
	}

	@Override
	public String getLocation() {
		return location;
	}

	@Override
	public Address getAddress() {
		return unit.getAddress();
	}

	@Override
	public long getSnap() {
		return snap;
	}

	public SliceEdgeType getEdgeType() {
		return type;
	}

	@Override
	public boolean displaySnap() {
		return displaySnap;
	}

	@Override
	public Program getImage() {
		return image;
	}

	@Override
	public Address getStaticPc() {
		return staticPc;
	}

	@Override
	public byte[] getBytes() {
		ByteBuffer buf = ByteBuffer.allocate(unit.getLength());
		trace.getMemoryManager().getViewBytes(snap, unit.getAddress(), buf);
		return buf.array();
	}

	protected void clearType(SliceEdgeType type) {
		for (GTreeTableNode child : getChildren().stream()
				.filter(c -> c instanceof UnitSliceNode n && n.type == type)
				.toList()) {
			remove(child);
		}
	}

	protected void addOnSwing(SliceEdgeType type, List<? extends UnitSliceNode<?>> nodes) {
		Swing.runLater(() -> {
			clearType(type);
			for (var node : nodes) {
				add(node);
			}
			setExpanded(true);
		});
	}

	protected void addOnSwing(SliceEdgeType type, UnitSliceNode<?> node) {
		Swing.runLater(() -> {
			clearType(type);
			if (node != null) {
				add(node);
			}
			setExpanded(true);
		});
	}

	public List<InstructionSliceNode> computeActualDefinitions(DebuggerAddressTranslator ms) {
		Set<InstructionSliceNode> nodes = new LinkedHashSet<>();
		AddressRangeImpl target = new AddressRangeImpl(unit.getMinAddress(), unit.getMaxAddress());
		for (TraceReference xref : SliceAnalysis.INSTANCE.actualDefinitionsOfVariable(trace, target,
			snap)) {
			TraceMemorySpace regs =
				SliceAnalysis.INSTANCE.getEventThreadRegisters(trace, xref.getStartSnap());
			if (regs == null) {
				continue;
			}
			Register ctxreg = trace.getBaseLanguage().getContextBaseRegister();
			Instruction ins = SliceAnalysis.INSTANCE.getOrDisassemble(trace, snap,
				xref.getFromAddress(), regs.getValue(snap, ctxreg));
			if (ins != null) {
				nodes.add(newInstructionNode(SliceEdgeType.ACTUAL_DEFINITION, ins,
					xref.getStartSnap(), true, ms));
			}
		}
		return List.copyOf(nodes);
	}

	public void descendActualDefinitions(DebuggerAddressTranslator ms) {
		addOnSwing(SliceEdgeType.ACTUAL_DEFINITION, computeActualDefinitions(ms));
	}

	public List<DataSliceNode> computeActualInputs() {
		Set<DataSliceNode> nodes = new LinkedHashSet<>();
		for (TraceReference ref : SliceAnalysis.INSTANCE.actualInputsToInstruction(trace,
			unit.getMinAddress(), snap)) {
			Data data = SliceAnalysis.INSTANCE.getOrPseudoData(trace, ref.getStartSnap(),
				ref.getToRange());
			if (data != null) {
				nodes.add(newDataNode(SliceEdgeType.ACTUAL_INPUT, data, ref.getStartSnap(), true));
			}
		}
		return List.copyOf(nodes);
	}

	public void descendActualInputs() {
		addOnSwing(SliceEdgeType.ACTUAL_INPUT, computeActualInputs());
	}

	public ProgramLocation getStaticLocation(DebuggerAddressTranslator ms) {
		if (unit.getAddress().isRegisterAddress()) {
			assert unit instanceof Data;
			// LATER: Figure this out through the platform/guest mappings, when needed
			return new ProgramLocation(image, unit.getAddress().getPhysicalAddress());
		}
		if (ms == null) {
			return null;
		}
		return ms.getOpenMappedLocation(
			new DefaultTraceLocation(trace, null, Lifespan.at(snap), unit.getAddress()));
	}

	public TraceLocation mapDynamic(DebuggerAddressTranslator ms, Program program,
			Address st) {
		return ms.getOpenMappedLocation(trace, new ProgramLocation(program, st), snap);
	}

	public List<InstructionSliceNode> computeActualUses(DebuggerAddressTranslator ms) {
		Set<InstructionSliceNode> nodes = new LinkedHashSet<>();
		AddressRange target = new AddressRangeImpl(unit.getMinAddress(), unit.getMaxAddress());
		for (TraceReference ref : SliceAnalysis.INSTANCE.actualUsesOfVariable(trace, target,
			snap)) {
			TraceMemorySpace regs =
				SliceAnalysis.INSTANCE.getEventThreadRegisters(trace, ref.getStartSnap());
			if (regs == null) {
				continue;
			}
			Register ctxreg = trace.getBaseLanguage().getContextBaseRegister();
			Instruction ins = SliceAnalysis.INSTANCE.getOrDisassemble(trace, ref.getStartSnap(),
				ref.getFromAddress(), regs.getValue(ref.getStartSnap(), ctxreg));
			if (ins != null) {
				nodes.add(newInstructionNode(SliceEdgeType.ACTUAL_USE, ins, ref.getStartSnap(),
					true, ms));
			}
		}
		return List.copyOf(nodes);
	}

	public void descendActualUses(DebuggerAddressTranslator ms) {
		addOnSwing(SliceEdgeType.ACTUAL_USE, computeActualUses(ms));
	}

	public List<InstructionSliceNode> computeStaticUses(DebuggerAddressTranslator ms,
			TaskMonitor monitor) throws CancelledException {
		ProgramLocation stLoc = getStaticLocation(ms);
		if (stLoc == null) {
			return List.of();
		}
		Register ctxreg = trace.getBaseLanguage().getContextBaseRegister();
		Address stMin = stLoc.getByteAddress();
		AddressRange stRange = new AddressRangeImpl(stMin, stMin.add(unit.getLength() - 1));
		Program program = stLoc.getProgram();

		Set<InstructionSliceNode> nodes = new LinkedHashSet<>();
		for (Address stUse : SliceAnalysis.INSTANCE.staticUsesOfVariable(image, staticPc, stRange,
			monitor)) {
			TraceLocation dyUse = mapDynamic(ms, program, stUse);
			if (dyUse == null) {
				continue;
			}
			OptionalLong next =
				SliceAnalysis.INSTANCE.computeNextExecution(trace, snap, dyUse.getAddress());
			long useSnap = next.orElse(snap);
			RegisterValue ctxval = program.getProgramContext().getRegisterValue(ctxreg, stUse);
			Instruction dyIns =
				SliceAnalysis.INSTANCE.getOrDisassemble(trace, useSnap, dyUse.getAddress(), ctxval);
			if (dyIns != null) {
				nodes.add(newInstructionNode(SliceEdgeType.STATIC_USE, dyIns, useSnap,
					next.isPresent(), ms));
			}
		}
		return List.copyOf(nodes);
	}

	public void descendStaticUses(DebuggerAddressTranslator ms, TaskMonitor monitor)
			throws CancelledException {
		addOnSwing(SliceEdgeType.STATIC_USE, computeStaticUses(ms, monitor));
	}

	public List<InstructionSliceNode> computeStaticDefinitions(DebuggerAddressTranslator ms,
			TaskMonitor monitor) throws CancelledException {
		ProgramLocation stLoc = getStaticLocation(ms);
		if (stLoc == null) {
			return List.of();
		}
		Register ctxreg = trace.getBaseLanguage().getContextBaseRegister();
		Address stMin = stLoc.getByteAddress();
		AddressRange stRange = new AddressRangeImpl(stMin, stMin.add(unit.getLength() - 1));
		Program program = stLoc.getProgram();

		Set<InstructionSliceNode> nodes = new LinkedHashSet<>();
		for (Address stDef : SliceAnalysis.INSTANCE.staticDefinitionsOfVariable(image, staticPc,
			stRange, monitor)) {
			TraceLocation dyDef = mapDynamic(ms, program, stDef);
			if (dyDef == null) {
				continue;
			}
			OptionalLong mostRecent = SliceAnalysis.INSTANCE.computeMostRecentExecution(trace, snap,
				dyDef.getAddress());
			long defSnap = mostRecent.orElse(snap);
			RegisterValue ctxval = program.getProgramContext().getRegisterValue(ctxreg, stDef);
			Instruction dyIns =
				SliceAnalysis.INSTANCE.getOrDisassemble(trace, defSnap, dyDef.getAddress(), ctxval);
			if (dyIns != null) {
				nodes.add(newInstructionNode(SliceEdgeType.STATIC_DEFINITION, dyIns, defSnap,
					mostRecent.isPresent(), ms));
			}
		}
		return List.copyOf(nodes);
	}

	public void descendStaticDefinitions(DebuggerAddressTranslator ms, TaskMonitor monitor)
			throws CancelledException {
		addOnSwing(SliceEdgeType.STATIC_DEFINITION, computeStaticDefinitions(ms, monitor));
	}

	public List<DataSliceNode> computeActualOutputs(DebuggerAddressTranslator ms) {
		Set<DataSliceNode> nodes = new LinkedHashSet<>();
		for (TraceReference ref : SliceAnalysis.INSTANCE.actualOutputsFromInstruction(trace,
			unit.getMinAddress(), snap)) {
			Data data = SliceAnalysis.INSTANCE.getOrPseudoData(trace, snap, ref.getToRange());
			if (data != null) {
				nodes.add(newDataNode(SliceEdgeType.ACTUAL_OUTPUT, data, snap, true));
			}
		}
		return List.copyOf(nodes);
	}

	public void descendActualOutputs(DebuggerAddressTranslator ms) {
		addOnSwing(SliceEdgeType.ACTUAL_OUTPUT, computeActualOutputs(ms));
	}
}
