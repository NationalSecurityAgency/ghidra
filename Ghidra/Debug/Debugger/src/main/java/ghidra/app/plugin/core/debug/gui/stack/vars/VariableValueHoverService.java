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
package ghidra.app.plugin.core.debug.gui.stack.vars;

import java.awt.Window;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.concurrent.CompletableFuture;

import javax.swing.*;

import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.GhidraOptions;
import ghidra.app.decompiler.ClangFieldToken;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.component.ClangTextField;
import ghidra.app.decompiler.component.hover.DataTypeDecompilerHover;
import ghidra.app.decompiler.component.hover.DecompilerHoverService;
import ghidra.app.plugin.core.codebrowser.hover.ListingHoverService;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.stack.vars.VariableValueRow.*;
import ghidra.app.plugin.core.debug.gui.stack.vars.VariableValueUtils.VariableEvaluator;
import ghidra.app.plugin.core.debug.stack.*;
import ghidra.app.plugin.core.debug.stack.StackUnwindWarning.CustomStackUnwindWarning;
import ghidra.app.plugin.core.debug.utils.BackgroundUtils.PluginToolExecutorService;
import ghidra.app.plugin.core.debug.utils.BackgroundUtils.PluginToolExecutorService.TaskOpt;
import ghidra.app.plugin.core.hover.AbstractConfigurableHover;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.async.AsyncUtils;
import ghidra.async.SwingExecutorService;
import ghidra.framework.plugintool.AutoService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.pcode.exec.DebuggerPcodeUtils;
import ghidra.pcode.exec.DebuggerPcodeUtils.WatchValue;
import ghidra.pcode.exec.DebuggerPcodeUtils.WatchValuePcodeExecutorState;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.*;
import ghidra.trace.model.Trace;
import ghidra.trace.model.listing.*;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.util.task.TaskMonitor;

public class VariableValueHoverService extends AbstractConfigurableHover
		implements ListingHoverService, DecompilerHoverService {
	private static final String NAME = "Variable Value Display";
	private static final String DESCRIPTION =
		"Show a variable's value when hovering over it and debugging";

	private static final int PRIORITY = 100;

	private static class LRUCache<K, V> extends LinkedHashMap<K, V> {
		private static final int DEFAULT_MAX_SIZE = 5;

		private int maxSize;

		public LRUCache() {
			this(DEFAULT_MAX_SIZE);
		}

		public LRUCache(int maxSize) {
			super(maxSize, 0.75f, true);
			this.maxSize = maxSize;
		}

		@Override
		protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
			if (size() > maxSize) {
				removed(eldest);
				return true;
			}
			return false;
		}

		protected void removed(Map.Entry<K, V> eldest) {
		}
	}

	// TODO: Option to always unwind from frame 0, or take the nearest frame?

	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;
	@AutoServiceConsumed
	private DebuggerStaticMappingService mappingService;
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoServiceWiring;

	private final Map<DebuggerCoordinates, VariableEvaluator> cachedEvaluators =
		new LRUCache<>() {
			protected void removed(Map.Entry<DebuggerCoordinates, VariableEvaluator> eldest) {
				eldest.getValue().dispose();
			}
		};

	public VariableValueHoverService(PluginTool tool) {
		super(tool, PRIORITY);
		autoServiceWiring = AutoService.wireServicesConsumed(tool, this);
	}

	@Override
	public void dispose() {
		super.dispose();
		for (VariableEvaluator eval : cachedEvaluators.values()) {
			eval.dispose();
		}
	}

	@Override
	protected String getName() {
		return NAME;
	}

	@Override
	protected String getDescription() {
		return DESCRIPTION;
	}

	@Override
	protected String getOptionsCategory() {
		return GhidraOptions.CATEGORY_DECOMPILER_POPUPS;
	}

	public static class TableFiller {
		private final VariableValueTable table;
		private final PluginTool tool;
		private final DebuggerCoordinates current;
		private final StackUnwindWarningSet warnings;

		private final DebuggerStaticMappingService mappingService;
		private final VariableEvaluator eval;

		public TableFiller(VariableValueTable table, PluginTool tool, DebuggerCoordinates current,
				VariableEvaluator eval, StackUnwindWarningSet warnings) {
			this.table = table;
			this.tool = tool;
			this.current = current;
			this.warnings = warnings;

			this.mappingService = tool.getService(DebuggerStaticMappingService.class);
			this.eval = eval;
		}

		protected <T> CompletableFuture<T> executeBackground(
				java.util.function.Function<TaskMonitor, T> command) {
			PluginToolExecutorService executor =
				new PluginToolExecutorService(tool, "Get Variable Value", current.getTrace(), 250,
					TaskOpt.IS_BACKGROUND, TaskOpt.CAN_CANCEL);
			return CompletableFuture.supplyAsync(() -> command.apply(executor.getLastMonitor()),
				executor);
		}

		public VariableValueTable fillUndefinedUnit(TraceData dynData, Program stProg,
				Address stAddr) {
			if (stProg == null) {
				return fillDefinedData(dynData);
			}
			CodeUnit stUnit = stProg.getListing().getCodeUnitAt(stAddr);
			if (stUnit == null) {
				return fillDefinedData(dynData);
			}
			if (stUnit instanceof Data stData) {
				DataType stType = stData.getDataType();
				if (stType == DataType.DEFAULT) {
					return fillDefinedData(dynData);
				}
				table.add(StorageRow.fromCodeUnit(stUnit));
				table.add(new TypeRow(stType));
				AddressRange dynRange = new AddressRangeImpl(dynData.getMinAddress(),
					dynData.getMinAddress().add(stData.getLength() - 1));
				table.add(LocationRow.fromRange(dynRange));
				BytesRow bytesRow =
					BytesRow.fromRange(current.getPlatform(), dynRange, current.getViewSnap());
				table.add(bytesRow);
				table.add(new IntegerRow(bytesRow));
				String repr = eval.getRepresentation(dynData.getAddress(), bytesRow.bytes().bytes(),
					stType, stData);
				if (repr != null) {
					table.add(new ValueRow(repr, bytesRow.state()));
				}
				return table;
			}
			if (stUnit instanceof Instruction stIns) {
				fillDefinedData(dynData);
				table.add(new InstructionRow(stIns));
				table.add(new WarningsRow(
					StackUnwindWarningSet.custom("Instruction taken from static listing")));
				return table;
			}
			throw new AssertionError();
		}

		public VariableValueTable fillDefinedData(TraceData data) {
			table.add(new TypeRow(data.getDataType()));
			table.add(LocationRow.fromCodeUnit(data));
			BytesRow bytesRow = BytesRow.fromCodeUnit(data, current.getViewSnap());
			table.add(bytesRow);
			table.add(new IntegerRow(bytesRow));
			String repr = data.getDefaultValueRepresentation();
			if (repr != null) {
				table.add(new ValueRow(repr, bytesRow.state()));
			}
			return table;
		}

		public VariableValueTable fillInstruction(TraceInstruction ins) {
			table.add(LocationRow.fromCodeUnit(ins));
			table.add(BytesRow.fromCodeUnit(ins, current.getViewSnap()));
			table.add(new InstructionRow(ins));
			return table;
		}

		public VariableValueTable fillCodeUnit(TraceCodeUnit unit, Program stProg, Address stAddr) {
			Symbol[] dynSymbols = unit.getSymbols();
			if (dynSymbols.length != 0) {
				table.add(new NameRow(dynSymbols[0].getName(true)));
			}
			else if (stProg != null) {
				Symbol[] stSymbols = stProg.getSymbolTable().getSymbols(stAddr);
				if (stSymbols.length != 0) {
					table.add(new NameRow(stSymbols[0].getName(true)));
				}
			}

			if (unit instanceof TraceData data) {
				if (data.getDataType() == DataType.DEFAULT) {
					return fillUndefinedUnit(data, stProg, stAddr);
				}
				return fillDefinedData(data);
			}
			else if (unit instanceof TraceInstruction ins) {
				return fillInstruction(ins);
			}
			else {
				throw new AssertionError();
			}
		}

		record MappedLocation(Program stProg, Address stAddr, Address dynAddr) {
		}

		protected MappedLocation mapLocation(Program programOrView, Address address) {
			if (programOrView instanceof TraceProgramView view) {
				ProgramLocation stLoc =
					mappingService.getStaticLocationFromDynamic(new ProgramLocation(view, address));
				return stLoc == null
						? new MappedLocation(null, null, address)
						: new MappedLocation(stLoc.getProgram(), stLoc.getAddress(), address);
			}
			ProgramLocation dynLoc = mappingService.getDynamicLocationFromStatic(current.getView(),
				new ProgramLocation(programOrView, address));
			return new MappedLocation(programOrView, address,
				dynLoc == null ? null : dynLoc.getAddress());
		}

		public CompletableFuture<VariableValueTable> fillMemory(Program programOrView,
				Address refAddress) {
			MappedLocation mapped = mapLocation(programOrView, refAddress);
			if (mapped.dynAddr == null) {
				return null;
			}
			WatchValuePcodeExecutorState state = DebuggerPcodeUtils.buildWatchState(tool, current);
			TraceCodeUnitsView codeUnits = current.getTrace().getCodeManager().codeUnits();
			TraceCodeUnit unit = codeUnits.getContaining(current.getViewSnap(), mapped.dynAddr);
			if (unit == null) {
				// Not sure this should ever happen....
				return null;
			}
			return CompletableFuture.supplyAsync(() -> {
				state.getVar(mapped.dynAddr, unit.getLength(), true, Reason.INSPECT);
				TraceCodeUnit unitAfterUpdate =
					codeUnits.getContaining(current.getViewSnap(), mapped.dynAddr);
				return fillCodeUnit(unitAfterUpdate, mapped.stProg, mapped.stAddr);
			});
		}

		public CompletableFuture<VariableValueTable> fillStack(Instruction ins,
				Address stackAddress) {
			Function function =
				ins.getProgram().getFunctionManager().getFunctionContaining(ins.getMinAddress());
			if (function == null) {
				return null;
			}
			Variable variable = VariableValueUtils.findStackVariable(function, stackAddress);
			return executeBackground(monitor -> {
				UnwoundFrame<WatchValue> frame =
					eval.getStackFrame(function, warnings, monitor, true);
				if (variable != null) {
					return fillFrameStorage(frame, variable.getName(), variable.getDataType(),
						variable.getProgram(), variable.getVariableStorage());
				}
				Address dynAddr = frame.getBasePointer().add(stackAddress.getOffset());
				TraceCodeUnit unit = current.getTrace()
						.getCodeManager()
						.codeUnits()
						.getContaining(current.getViewSnap(), dynAddr);
				if (unit instanceof TraceData data && ListingUnwoundFrame.isFrame(data)) {
					int offset = (int) dynAddr.subtract(data.getMinAddress());
					TraceData comp = data.getComponentContaining(offset);
					return fillCodeUnit(comp, null, null);
				}
				return fillCodeUnit(unit, null, null);
			});
		}

		public CompletableFuture<VariableValueTable> fillReference(CodeUnit unit,
				Address refAddress) {
			if (refAddress.isMemoryAddress()) {
				return fillMemory(unit.getProgram(), refAddress);
			}
			if (refAddress.isStackAddress() && unit instanceof Instruction ins) {
				return fillStack(ins, refAddress);
			}
			return null;
		}

		public VariableValueTable fillRegisterNoFrame(Register register) {
			TraceData data = eval.getRegisterUnit(register);
			if (data != null) {
				table.add(new NameRow(register.getName()));
				table.add(new TypeRow(data.getDataType()));
				IntegerRow intRow = IntegerRow.fromCodeUnit(data, current.getSnap());
				table.add(intRow);
				table.add(new ValueRow(data.getDefaultValueRepresentation(), intRow.state()));
				return table;
			}
			// Just display the raw register value
			table.add(new NameRow(register.getName()));
			WatchValue raw = eval.getRawRegisterValue(register);
			table.add(new IntegerRow(raw));
			return table;
		}

		public CompletableFuture<VariableValueTable> fillRegister(Instruction ins,
				Register register) {
			Function function =
				ins.getProgram().getFunctionManager().getFunctionContaining(ins.getMinAddress());
			Variable variable =
				function == null ? null : VariableValueUtils.findVariable(function, register);
			return executeBackground(monitor -> {
				UnwoundFrame<WatchValue> frame;
				if (function == null) {
					warnings.add(new CustomStackUnwindWarning(
						"Instruction is not in a function. Using innermost frame."));
					frame = VariableValueUtils.locateInnermost(tool, current);
				}
				else {
					frame = eval.getStackFrame(function, warnings, monitor, false);
				}
				if (frame == null) {
					return fillRegisterNoFrame(register);
				}

				if (variable != null) {
					return fillFrameStorage(frame, variable.getName(), variable.getDataType(),
						variable.getProgram(), variable.getVariableStorage());
				}

				if (frame.getLevel() == 0) {
					return fillRegisterNoFrame(register);
				}

				// Still raw register value, but this time it can be restored from stack
				table.add(new NameRow(register.getName()));
				if (!frame.isFake()) {
					table.add(new FrameRow(frame));
				}
				WatchValue value = frame.getValue(register);
				table.add(LocationRow.fromWatchValue(value, current.getPlatform().getLanguage()));
				table.add(new IntegerRow(value));
				return table;
			});
		}

		public CompletableFuture<VariableValueTable> fillOperand(OperandFieldLocation opLoc,
				Instruction ins) {
			RefType refType = ins.getOperandRefType(opLoc.getOperandIndex());
			if (refType.isFlow()) {
				return null;
			}
			Object operand = ins.getDefaultOperandRepresentationList(opLoc.getOperandIndex())
					.get(opLoc.getSubOperandIndex());
			if (operand instanceof Register register) {
				return fillRegister(ins, register);
			}
			Address refAddress = opLoc.getRefAddress();
			if (operand instanceof Scalar scalar && refAddress != null) {
				return fillReference(ins, refAddress);
			}
			if (operand instanceof Address address) {
				return fillReference(ins, address);
			}
			return null;
		}

		public CompletableFuture<VariableValueTable> fillStorage(Function function, String name,
				DataType type, Program program, VariableStorage storage,
				AddressSetView symbolStorage) {
			return executeBackground(monitor -> {
				UnwoundFrame<WatchValue> frame =
					VariableValueUtils.requiresFrame(program, storage, symbolStorage)
							? eval.getStackFrame(function, warnings, monitor, true)
							: eval.getGlobalsFakeFrame();
				return fillFrameStorage(frame, name, type, program, storage);
			});
		}

		public CompletableFuture<VariableValueTable> fillPcodeOp(Function function, String name,
				DataType type, PcodeOp op, AddressSetView symbolStorage) {
			return executeBackground(monitor -> {
				UnwoundFrame<WatchValue> frame = VariableValueUtils.requiresFrame(op, symbolStorage)
						? eval.getStackFrame(function, warnings, monitor, true)
						: eval.getGlobalsFakeFrame();
				return fillFrameOp(frame, function.getProgram(), name, type, op, symbolStorage);
			});
		}

		public VariableValueTable fillWatchValue(UnwoundFrame<WatchValue> frame, Address address,
				DataType type, WatchValue value) {
			table.add(LocationRow.fromWatchValue(value, current.getPlatform().getLanguage()));
			if (value.address() != null && !value.address().isRegisterAddress()) {
				table.add(new BytesRow(value));
			}
			table.add(new IntegerRow(value));
			if (type != DataType.DEFAULT) {
				String repr = eval.getRepresentation(frame, address, value, type);
				table.add(new ValueRow(repr, value.state()));
			}
			return table;
		}

		public VariableValueTable fillFrameStorage(UnwoundFrame<WatchValue> frame, String name,
				DataType type, Program program, VariableStorage storage) {
			table.add(new NameRow(name));
			if (!frame.isFake()) {
				table.add(new FrameRow(frame));
			}
			table.add(new StorageRow(storage));
			table.add(new TypeRow(type));
			WatchValue value = frame.getValue(program, storage);
			return fillWatchValue(frame, storage.getMinAddress(), type, value);
		}

		public VariableValueTable fillFrameOp(UnwoundFrame<WatchValue> frame, Program program,
				String name, DataType type, PcodeOp op, AddressSetView symbolStorage) {
			table.add(new NameRow(name));
			if (!frame.isFake()) {
				table.add(new FrameRow(frame));
			}
			table.add(new TypeRow(type));
			WatchValue value = frame.evaluate(program, op, symbolStorage);
			// TODO: What if the type is dynamic with non-fixed size?
			if (type.getLength() != value.length()) {
				value = frame.zext(value, type.getLength());
			}
			return fillWatchValue(frame, op.getOutput().getAddress(), type, value);
		}

		public CompletableFuture<VariableValueTable> fillHighVariable(HighVariable hVar,
				String name, AddressSetView symbolStorage) {
			Function function = hVar.getHighFunction().getFunction();
			VariableStorage storage = VariableValueUtils.fabricateStorage(hVar);
			if (storage.isUniqueStorage()) {
				table.add(new NameRow(name));
				table.add(new StorageRow(storage));
				table.add(new ValueRow("(Unique)", TraceMemoryState.KNOWN));
				return CompletableFuture.completedFuture(table);
			}
			return fillStorage(function, name, hVar.getDataType(), function.getProgram(), storage,
				symbolStorage);
		}

		public CompletableFuture<VariableValueTable> fillHighVariable(HighVariable hVar,
				AddressSetView symbolStorage) {
			return fillHighVariable(hVar, hVar.getName(), symbolStorage);
		}

		public CompletableFuture<VariableValueTable> fillComponent(ClangFieldToken token,
				AddressSetView symbolStorage) {
			Function function = token.getClangFunction().getHighFunction().getFunction();
			Program program = function.getProgram();
			PcodeOp op = token.getPcodeOp();
			Varnode vn = op.getOutput();
			HighVariable hVar = vn.getHigh();
			DataType type = DataTypeDecompilerHover.getFieldDataType(token);
			if (hVar.getDataType().isEquivalent(new PointerDataType(type))) {
				op = VariableValueUtils.findDeref(program.getAddressFactory(), vn);
			}
			return fillPcodeOp(function, token.getText(), type, op, symbolStorage);
		}

		public CompletableFuture<VariableValueTable> fillComposite(HighSymbol hSym,
				HighVariable hVar, AddressSetView symbolStorage) {
			return fillStorage(hVar.getHighFunction().getFunction(), hSym.getName(),
				hSym.getDataType(), hSym.getProgram(), hSym.getStorage(), symbolStorage);
		}

		public CompletableFuture<VariableValueTable> fillToken(ClangToken token) {
			if (token == null) {
				return null;
			}

			/**
			 * I can't get just the expression tree here, except as p-code AST, which doesn't seem
			 * to include token info. A line should contain the full expression, though. I'll grab
			 * the symbols' storage from it and ensure my evaluation recurses until it hits those
			 * symbols.
			 */
			AddressSet symbolStorage =
				VariableValueUtils.collectSymbolStorage(token.getLineParent());

			if (token instanceof ClangFieldToken fieldToken) {
				return fillComponent(fieldToken, symbolStorage);
			}

			HighVariable hVar = token.getHighVariable();
			if (hVar == null) {
				return null;
			}

			HighSymbol hSym = hVar.getSymbol();
			if (hSym == null) {
				// This is apparently the case for literals.
				return null;
			}
			VariableStorage storage = hSym.getStorage();

			String name = hVar.getName();
			if (name == null) {
				name = hSym.getName();
			}

			Varnode representative = hVar.getRepresentative();
			if (!storage.contains(representative.getAddress())) {
				// I'm not sure this can ever happen....
				return fillHighVariable(hVar, symbolStorage);
			}

			if (Arrays.asList(storage.getVarnodes()).equals(List.of(representative))) {
				// The var is the symbol
				return fillHighVariable(hVar, symbolStorage);
			}

			// Presumably, there's some component path from symbol to high var
			return fillComposite(hSym, hVar, symbolStorage);
		}

		public CompletableFuture<VariableValueTable> fillVariable(Variable variable) {
			Function function = variable.getFunction();
			return executeBackground(monitor -> {
				UnwoundFrame<WatchValue> frame =
					eval.getStackFrame(function, warnings, monitor, true);
				return fillFrameStorage(frame, variable.getName(), variable.getDataType(),
					variable.getProgram(), variable.getVariableStorage());
			});
		}
	}

	public CompletableFuture<VariableValueTable> fillVariableValueTable(VariableValueTable table,
			ProgramLocation programLocation, DebuggerCoordinates current,
			FieldLocation fieldLocation, Field field, StackUnwindWarningSet warnings) {
		if (traceManager == null || mappingService == null || current.getPlatform() == null) {
			return null;
		}
		VariableEvaluator eval;
		synchronized (cachedEvaluators) {
			eval = cachedEvaluators.computeIfAbsent(current, c -> new VariableEvaluator(tool, c));
		}
		TableFiller filler = new TableFiller(table, tool, current, eval, warnings);
		if (field instanceof ClangTextField clangField) {
			return filler.fillToken(clangField.getToken(fieldLocation));
		}
		if (programLocation == null) {
			return null;
		}
		Address refAddress = programLocation.getRefAddress();
		CodeUnit unit = programLocation.getProgram()
				.getListing()
				.getCodeUnitContaining(programLocation.getAddress());
		if (programLocation instanceof OperandFieldLocation opLoc &&
			unit instanceof Instruction ins) {
			return filler.fillOperand(opLoc, ins);
		}
		if (programLocation instanceof OperandFieldLocation && refAddress != null &&
			refAddress.isMemoryAddress()) {
			return filler.fillReference(unit, refAddress);
		}
		if (programLocation instanceof VariableLocation varLoc) {
			return filler.fillVariable(varLoc.getVariable());
		}
		return null;
	}

	@Override
	public JComponent getHoverComponent(Program program, ProgramLocation programLocation,
			FieldLocation fieldLocation, Field field) {
		if (!enabled || traceManager == null) {
			return null;
		}
		VariableValueTable table = new VariableValueTable();
		StackUnwindWarningSet warnings = new StackUnwindWarningSet();
		CompletableFuture<VariableValueTable> future;
		try {
			future = fillVariableValueTable(table, programLocation,
				traceManager.getCurrent(), fieldLocation, field, warnings);
		}
		catch (Exception e) {
			table.add(new ErrorRow(e));
			JComponent component = createTooltipComponent("<html>" + table.toHtml());
			addErrorDetailsListener(component, table);
			return component;
		}
		if (future == null) {
			return null;
		}
		if (!future.isDone()) {
			table.add(new StatusRow("In Progress"));
		}
		JComponent component = createTooltipComponent("<html>" + table.toHtml());
		if (!(component instanceof JToolTip tooltip)) {
			throw new AssertionError("Expected a JToolTip");
		}
		addErrorDetailsListener(component, table);
		future.handleAsync((__, ex) -> {
			table.remove(RowKey.STATUS);
			if (ex != null) {
				table.add(new ErrorRow(AsyncUtils.unwrapThrowable(ex)));
			}
			else {
				table.add(new WarningsRow(warnings));
			}
			tooltip.setTipText("<html>" + table.toHtml());
			Window window = SwingUtilities.getWindowAncestor(tooltip);
			if (window != null) {
				window.pack();
			} // else, the computation completed before tooltip was returned
			return null;
		}, SwingExecutorService.MAYBE_NOW);
		return tooltip;
	}

	protected void addErrorDetailsListener(JComponent component, VariableValueTable table) {
		component.addMouseListener(new MouseAdapter() {
			private boolean isShiftDoubleClick(MouseEvent evt) {
				if (evt.getClickCount() != 2) {
					return false;
				}
				if ((evt.getModifiersEx() & MouseEvent.SHIFT_DOWN_MASK) == 0) {
					return false;
				}
				return true;
			}

			@Override
			public void mouseClicked(MouseEvent evt) {
				if (isShiftDoubleClick(evt)) {
					table.reportDetails();
				}
			}
		});
	}

	public void traceClosed(Trace trace) {
		synchronized (cachedEvaluators) {
			cachedEvaluators.keySet().removeIf(coords -> coords.getTrace() == trace);
		}
	}
}
