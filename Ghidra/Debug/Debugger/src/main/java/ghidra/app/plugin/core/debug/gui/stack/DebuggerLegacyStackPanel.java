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
package ghidra.app.plugin.core.debug.gui.stack;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.event.*;
import java.util.*;
import java.util.function.*;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.table.*;

import docking.widgets.table.*;
import docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn;
import ghidra.app.services.*;
import ghidra.debug.api.modules.DebuggerStaticMappingChangeListener;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.AutoService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.*;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.*;
import ghidra.util.Swing;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;
import ghidra.util.table.column.AbstractGColumnRenderer;

public class DebuggerLegacyStackPanel extends JPanel {

	protected enum StackTableColumns
		implements EnumeratedTableColumn<StackTableColumns, StackFrameRow> {
		LEVEL("Level", Integer.class, StackFrameRow::getFrameLevel),
		PC("PC", Address.class, StackFrameRow::getProgramCounter),
		FUNCTION("Function", ghidra.program.model.listing.Function.class, StackFrameRow::getFunction),
		MODULE("Module", String.class, StackFrameRow::getModule),
		COMMENT("Comment", String.class, StackFrameRow::getComment, StackFrameRow::setComment, StackFrameRow::isCommentable);

		private final String header;
		private final Function<StackFrameRow, ?> getter;
		private final BiConsumer<StackFrameRow, Object> setter;
		private final Predicate<StackFrameRow> editable;
		private final Class<?> cls;

		@SuppressWarnings("unchecked")
		<T> StackTableColumns(String header, Class<T> cls, Function<StackFrameRow, T> getter,
				BiConsumer<StackFrameRow, T> setter, Predicate<StackFrameRow> editable) {
			this.header = header;
			this.cls = cls;
			this.getter = getter;
			this.setter = (BiConsumer<StackFrameRow, Object>) setter;
			this.editable = editable;
		}

		<T> StackTableColumns(String header, Class<T> cls, Function<StackFrameRow, T> getter) {
			this(header, cls, getter, null, null);
		}

		@Override
		public Class<?> getValueClass() {
			return cls;
		}

		@Override
		public Object getValueOf(StackFrameRow row) {
			return getter.apply(row);
		}

		@Override
		public void setValueOf(StackFrameRow row, Object value) {
			setter.accept(row, value);
		}

		@Override
		public String getHeader() {
			return header;
		}

		@Override
		public boolean isEditable(StackFrameRow row) {
			return setter != null && editable.test(row);
		}
	}

	protected static class StackTableModel
			extends DefaultEnumeratedColumnTableModel<StackTableColumns, StackFrameRow> {

		public StackTableModel(PluginTool tool) {
			super(tool, "Stack", StackTableColumns.class);
		}

		@Override
		public List<StackTableColumns> defaultSortOrder() {
			return List.of(StackTableColumns.LEVEL);
		}
	}

	class ForStackListener extends TraceDomainObjectListener {
		public ForStackListener() {
			listenFor(TraceEvents.STACK_ADDED, this::stackAdded);
			listenFor(TraceEvents.STACK_CHANGED, this::stackChanged);
			listenFor(TraceEvents.STACK_DELETED, this::stackDeleted);

			listenFor(TraceEvents.BYTES_CHANGED, this::bytesChanged);
		}

		private void stackAdded(TraceStack stack) {
			TraceThread curThread = current.getThread();
			if (curThread != stack.getThread()) {
				return;
			}
			loadStack();
		}

		private void stackChanged(TraceStack stack) {
			if (currentStack != stack) {
				return;
			}
			updateStack();
		}

		private void stackDeleted(TraceStack stack) {
			if (currentStack != stack) {
				return;
			}
			loadStack();
		}

		// For updating a synthetic frame
		private void bytesChanged(TraceAddressSpace space, TraceAddressSnapRange range) {
			TraceThread curThread = current.getThread();
			if (space.getThread() != curThread || space.getFrameLevel() != 0) {
				return;
			}
			TraceProgramView view = current.getView();
			if (view == null) {
				return;
			}
			if (!view.getViewport().containsAnyUpper(range.getLifespan())) {
				return;
			}
			List<StackFrameRow> stackData = stackTableModel.getModelData();
			if (stackData.isEmpty() || !(stackData.get(0) instanceof StackFrameRow.Synthetic)) {
				return;
			}
			StackFrameRow.Synthetic frameRow = (StackFrameRow.Synthetic) stackData.get(0);
			Trace trace = current.getTrace();
			Register pc = trace.getBaseLanguage().getProgramCounter();
			if (!TraceRegisterUtils.rangeForRegister(pc).intersects(range.getRange())) {
				return;
			}
			TraceMemorySpace regs =
				trace.getMemoryManager().getMemoryRegisterSpace(curThread, false);
			RegisterValue value = regs.getViewValue(current.getViewSnap(), pc);
			Address address = trace.getBaseLanguage()
					.getDefaultSpace()
					.getAddress(value.getUnsignedValue().longValue());
			frameRow.updateProgramCounter(address);
			stackTableModel.fireTableDataChanged();
		}
	}

	class ForFunctionsListener implements DebuggerStaticMappingChangeListener {
		@Override
		public void mappingsChanged(Set<Trace> affectedTraces, Set<Program> affectedPrograms) {
			Trace curTrace = current.getTrace();
			if (curTrace == null || !affectedTraces.contains(curTrace)) {
				return;
			}
			Swing.runIfSwingOrRunLater(() -> stackTableModel.fireTableDataChanged());
		}
	}

	final DebuggerStackProvider provider;

	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;
	// @AutoServiceConsumed via method
	DebuggerStaticMappingService mappingService;
	@AutoServiceConsumed
	private DebuggerListingService listingService; // TODO: Goto pc on double-click
	@AutoServiceConsumed
	private MarkerService markerService; // TODO: Mark non-current frame PCs, too. (separate plugin?)
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoServiceWiring;

	final TableCellRenderer boldCurrentRenderer = new AbstractGColumnRenderer<Object>() {
		@Override
		public String getFilterString(Object t, Settings settings) {
			return t == null ? "<null>" : t.toString();
		}

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {
			super.getTableCellRendererComponent(data);
			StackFrameRow row = (StackFrameRow) data.getRowObject();
			if (row != null && row.getFrameLevel() == current.getFrame()) {
				setBold();
			}
			return this;
		}
	};

	// Table rows access this for function name resolution
	DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;
	private Trace currentTrace; // Copy for transition

	private TraceStack currentStack;

	private ForStackListener forStackListener = new ForStackListener();
	private ForFunctionsListener forFunctionsListener = new ForFunctionsListener();

	protected final StackTableModel stackTableModel;
	protected GhidraTable stackTable;
	protected GhidraTableFilterPanel<StackFrameRow> stackFilterPanel;

	private DebuggerStackActionContext myActionContext;

	public DebuggerLegacyStackPanel(DebuggerStackPlugin plugin, DebuggerStackProvider provider) {
		super(new BorderLayout());
		this.provider = provider;
		this.autoServiceWiring = AutoService.wireServicesConsumed(plugin, this);

		stackTableModel = new StackTableModel(provider.getTool());
		stackTable = new GhidraTable(stackTableModel);
		add(new JScrollPane(stackTable));
		stackFilterPanel = new GhidraTableFilterPanel<>(stackTable, stackTableModel);
		add(stackFilterPanel, BorderLayout.SOUTH);

		stackTable.getSelectionModel().addListSelectionListener(evt -> {
			if (evt.getValueIsAdjusting()) {
				return;
			}
			contextChanged();
		});

		stackTable.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2 && e.getButton() == MouseEvent.BUTTON1) {
					activateSelectedFrame();
				}
			}
		});
		stackTable.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ENTER) {
					activateSelectedFrame();
					e.consume(); // lest it select the next row down
				}
			}
		});

		// TODO: Adjust default column widths?
		TableColumnModel columnModel = stackTable.getColumnModel();

		TableColumn levelCol = columnModel.getColumn(StackTableColumns.LEVEL.ordinal());
		levelCol.setPreferredWidth(25);
		levelCol.setCellRenderer(boldCurrentRenderer);
		TableColumn pcCol = columnModel.getColumn(StackTableColumns.PC.ordinal());
		pcCol.setCellRenderer(CustomToStringCellRenderer.MONO_OBJECT);
		pcCol.setCellRenderer(boldCurrentRenderer);
		TableColumn funcCol = columnModel.getColumn(StackTableColumns.FUNCTION.ordinal());
		funcCol.setCellRenderer(boldCurrentRenderer);
		TableColumn modCol = columnModel.getColumn(StackTableColumns.MODULE.ordinal());
		modCol.setCellRenderer(boldCurrentRenderer);
		TableColumn commCol = columnModel.getColumn(StackTableColumns.COMMENT.ordinal());
		commCol.setCellRenderer(boldCurrentRenderer);
	}

	protected void contextChanged() {
		StackFrameRow row = stackFilterPanel.getSelectedItem();
		myActionContext =
			row == null ? null : new DebuggerStackActionContext(provider, row, stackTable);
		provider.contextChanged();
	}

	protected void activateSelectedFrame() {
		if (myActionContext == null) {
			return;
		}
		if (traceManager == null) {
			return;
		}
		traceManager.activateFrame(myActionContext.getFrame().getFrameLevel());
	}

	protected void updateStack() {
		Set<TraceStackFrame> toAdd = new LinkedHashSet<>(currentStack.getFrames(current.getSnap()));
		for (Iterator<StackFrameRow> it = stackTableModel.getModelData().iterator(); it
				.hasNext();) {
			StackFrameRow row = it.next();
			if (!toAdd.remove(row.frame)) {
				it.remove();
			}
			else {
				row.update();
			}
		}

		for (TraceStackFrame frame : toAdd) {
			stackTableModel.add(new StackFrameRow(this, frame));
		}

		stackTableModel.fireTableDataChanged();
	}

	protected void doSetCurrentStack(TraceStack stack) {
		if (stack == null) {
			currentStack = null;
			stackTableModel.clear();
			contextChanged();
			return;
		}
		if (currentStack == stack && stack.hasFixedFrames()) {
			stackTableModel.fireTableDataChanged();
			return;
		}
		currentStack = stack;
		stackTableModel.clear();
		for (TraceStackFrame frame : currentStack.getFrames(current.getSnap())) {
			stackTableModel.add(new StackFrameRow(this, frame));
		}
	}

	/**
	 * Synthesize a stack with only one frame, taking PC from the registers
	 */
	protected void doSetSyntheticStack() {
		stackTableModel.clear();
		currentStack = null;

		Trace curTrace = current.getTrace();
		Register pc = curTrace.getBaseLanguage().getProgramCounter();
		if (pc == null) {
			contextChanged();
			return;
		}
		TraceMemorySpace regs = pc.getAddressSpace().isRegisterSpace()
				? curTrace.getMemoryManager().getMemoryRegisterSpace(current.getThread(), false)
				: curTrace.getMemoryManager().getMemorySpace(pc.getAddressSpace(), false);
		if (regs == null) {
			contextChanged();
			return;
		}
		RegisterValue value = regs.getViewValue(current.getViewSnap(), pc);
		if (value == null) {
			contextChanged();
			return;
		}
		Address address = curTrace.getBaseLanguage()
				.getDefaultSpace()
				.getAddress(value.getUnsignedValue().longValue(), true);
		stackTableModel.add(new StackFrameRow.Synthetic(this, address));
	}

	protected void loadStack() {
		TraceThread curThread = current.getThread();
		if (curThread == null) {
			doSetCurrentStack(null);
			return;
		}
		// TODO: getLatestViewStack? Conventionally, I don't expect any scratch stacks, yet.
		TraceStack stack =
			current.getTrace().getStackManager().getLatestStack(curThread, current.getViewSnap());
		if (stack == null) {
			doSetSyntheticStack();
		}
		else {
			doSetCurrentStack(stack);
		}
	}

	private void removeOldListeners() {
		if (currentTrace == null) {
			return;
		}
		currentTrace.removeListener(forStackListener);
	}

	private void addNewListeners() {
		if (currentTrace == null) {
			return;
		}
		currentTrace.addListener(forStackListener);
	}

	private void doSetTrace(Trace trace) {
		if (currentTrace == trace) {
			return;
		}
		removeOldListeners();
		this.currentTrace = trace;
		addNewListeners();
	}

	public void coordinatesActivated(DebuggerCoordinates coordinates) {
		current = coordinates;
		doSetTrace(current.getTrace());
		loadStack();
		selectCurrentFrame();
	}

	protected void selectCurrentFrame() {
		StackFrameRow row = stackTableModel.findFirst(r -> r.getFrameLevel() == current.getFrame());
		if (row == null) {
			// Strange
			stackTable.clearSelection();
		}
		else {
			stackFilterPanel.setSelectedItem(row);
		}
	}

	public DebuggerStackActionContext getActionContext() {
		return myActionContext;
	}

	@AutoServiceConsumed
	private void setMappingService(DebuggerStaticMappingService mappingService) {
		if (this.mappingService != null) {
			this.mappingService.removeChangeListener(forFunctionsListener);
		}
		this.mappingService = mappingService;
		if (this.mappingService != null) {
			this.mappingService.addChangeListener(forFunctionsListener);
		}
	}
}
