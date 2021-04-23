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
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.function.*;

import javax.swing.*;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import docking.ActionContext;
import docking.WindowPosition;
import docking.widgets.table.CustomToStringCellRenderer;
import docking.widgets.table.DefaultEnumeratedColumnTableModel;
import docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.services.*;
import ghidra.dbg.DebugModelConventions;
import ghidra.dbg.target.TargetStackFrame;
import ghidra.framework.plugintool.AutoService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.*;
import ghidra.trace.model.Trace.TraceMemoryBytesChangeType;
import ghidra.trace.model.Trace.TraceStackChangeType;
import ghidra.trace.model.memory.TraceMemoryRegisterSpace;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceAddressSpace;
import ghidra.trace.util.TraceRegisterUtils;
import ghidra.util.Swing;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;
import utilities.util.SuppressableCallback;
import utilities.util.SuppressableCallback.Suppression;

public class DebuggerStackProvider extends ComponentProviderAdapter {

	protected enum StackTableColumns
		implements EnumeratedTableColumn<StackTableColumns, StackFrameRow> {
		LEVEL("Level", Integer.class, StackFrameRow::getFrameLevel),
		PC("PC", Address.class, StackFrameRow::getProgramCounter),
		FUNCTION("Function", ghidra.program.model.listing.Function.class, StackFrameRow::getFunction),
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

		public StackTableModel() {
			super("Stack", StackTableColumns.class);
		}

		@Override
		public List<StackTableColumns> defaultSortOrder() {
			return List.of(StackTableColumns.LEVEL);
		}
	}

	protected static boolean sameCoordinates(DebuggerCoordinates a, DebuggerCoordinates b) {
		if (!Objects.equals(a.getTrace(), b.getTrace())) {
			return false;
		}
		if (!Objects.equals(a.getThread(), b.getThread())) {
			return false;
		}
		if (!Objects.equals(a.getTime(), b.getTime())) {
			return false;
		}
		if (!Objects.equals(a.getFrame(), b.getFrame())) {
			return false;
		}
		return true;
	}

	class ForStackListener extends TraceDomainObjectListener {
		public ForStackListener() {
			listenFor(TraceStackChangeType.ADDED, this::stackAdded);
			listenFor(TraceStackChangeType.CHANGED, this::stackChanged);
			listenFor(TraceStackChangeType.DELETED, this::stackDeleted);

			listenFor(TraceMemoryBytesChangeType.CHANGED, this::bytesChanged);
		}

		private void stackAdded(TraceStack stack) {
			if (stack.getSnap() != current.getViewSnap()) {
				return;
			}
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
			if (!current.getView().getViewport().containsAnyUpper(range.getLifespan())) {
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
			TraceMemoryRegisterSpace regs =
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

	//private final DebuggerStackPlugin plugin;

	// Table rows access these for function name resolution
	DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;
	private Trace currentTrace; // Copy for transition

	private TraceStack currentStack;

	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;
	// @AutoServiceConsumed  by method
	private DebuggerModelService modelService;
	// @AutoServiceConsumed via method
	DebuggerStaticMappingService mappingService;
	@AutoServiceConsumed
	private DebuggerListingService listingService; // TODO: Goto pc on double-click
	@AutoServiceConsumed
	private MarkerService markerService; // TODO: Mark non-current frame PCs, too. (separate plugin?)
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoServiceWiring;

	private ForStackListener forStackListener = new ForStackListener();
	private ForFunctionsListener forFunctionsListener = new ForFunctionsListener();

	private final SuppressableCallback<Void> cbFrameSelected = new SuppressableCallback<>();

	protected final StackTableModel stackTableModel = new StackTableModel();
	protected GhidraTable stackTable;
	protected GhidraTableFilterPanel<StackFrameRow> stackFilterPanel;

	private JPanel mainPanel = new JPanel(new BorderLayout());

	private DebuggerStackActionContext myActionContext;

	public DebuggerStackProvider(DebuggerStackPlugin plugin) {
		super(plugin.getTool(), DebuggerResources.TITLE_PROVIDER_STACK, plugin.getName());
		//this.plugin = plugin;

		this.autoServiceWiring = AutoService.wireServicesConsumed(plugin, this);

		setTitle(DebuggerResources.TITLE_PROVIDER_STACK);
		setIcon(DebuggerResources.ICON_PROVIDER_STACK);
		setHelpLocation(DebuggerResources.HELP_PROVIDER_STACK);
		setWindowMenuGroup(DebuggerPluginPackage.NAME);

		buildMainPanel();

		setDefaultWindowPosition(WindowPosition.LEFT);
		createActions();

		setVisible(true);
		contextChanged();
	}

	protected void buildMainPanel() {
		stackTable = new GhidraTable(stackTableModel);
		mainPanel.add(new JScrollPane(stackTable));
		stackFilterPanel = new GhidraTableFilterPanel<>(stackTable, stackTableModel);
		mainPanel.add(stackFilterPanel, BorderLayout.SOUTH);

		stackTable.getSelectionModel().addListSelectionListener(evt -> {
			if (evt.getValueIsAdjusting()) {
				return;
			}
			contextChanged();
			activateSelectedFrame();
		});

		stackTable.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() < 2 || e.getButton() != MouseEvent.BUTTON1) {
					return;
				}
				if (listingService == null) {
					return;
				}
				if (myActionContext == null) {
					return;
				}
				Address pc = myActionContext.getFrame().getProgramCounter();
				if (pc == null) {
					return;
				}
				listingService.goTo(pc, true);
			}

			@Override
			public void mouseReleased(MouseEvent e) {
				int selectedRow = stackTable.getSelectedRow();
				StackFrameRow row = stackTableModel.getRowObject(selectedRow);
				rowActivated(row);
			}
		});

		// TODO: Adjust default column widths?
		TableColumnModel columnModel = stackTable.getColumnModel();

		TableColumn levelCol = columnModel.getColumn(StackTableColumns.LEVEL.ordinal());
		levelCol.setPreferredWidth(25);
		TableColumn baseCol = columnModel.getColumn(StackTableColumns.PC.ordinal());
		baseCol.setCellRenderer(CustomToStringCellRenderer.MONO_OBJECT);
	}

	@Override
	public void contextChanged() {
		StackFrameRow row = stackFilterPanel.getSelectedItem();
		myActionContext =
			row == null ? null : new DebuggerStackActionContext(this, row, stackTable);
		super.contextChanged();
	}

	protected void activateSelectedFrame() {
		// TODO: Action to toggle sync?
		if (myActionContext == null) {
			return;
		}
		if (traceManager == null) {
			return;
		}
		cbFrameSelected.invoke(() -> {
			traceManager.activateFrame(myActionContext.getFrame().getFrameLevel());
		});
	}

	private void rowActivated(StackFrameRow row) {
		TraceStackFrame frame = row.frame;
		TraceThread thread = frame.getStack().getThread();
		Trace trace = thread.getTrace();
		TraceRecorder recorder = modelService.getRecorder(trace);
		if (recorder != null) {
			TargetStackFrame targetFrame = recorder.getTargetStackFrame(thread, frame.getLevel());
			if (targetFrame != null && targetFrame.isValid()) {
				DebugModelConventions.requestActivation(targetFrame);
			}
		}
	}

	protected void createActions() {
		// TODO: Anything?
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		if (myActionContext == null) {
			return super.getActionContext(event);
		}
		return myActionContext;
	}

	protected void updateStack() {
		Set<TraceStackFrame> toAdd = new LinkedHashSet<>(currentStack.getFrames());
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

		selectCurrentFrame();
	}

	protected void doSetCurrentStack(TraceStack stack) {
		if (stack == null) {
			currentStack = null;
			stackTableModel.clear();
			contextChanged();
			return;
		}
		if (currentStack == stack) {
			return;
		}
		currentStack = stack;
		stackTableModel.clear();
		for (TraceStackFrame frame : currentStack.getFrames()) {
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
		TraceMemoryRegisterSpace regs =
			curTrace.getMemoryManager().getMemoryRegisterSpace(current.getThread(), false);
		if (regs == null) {
			contextChanged();
			return;
		}
		Register pc = curTrace.getBaseLanguage().getProgramCounter();
		RegisterValue value = regs.getViewValue(current.getViewSnap(), pc);
		if (value == null) {
			contextChanged();
			return;
		}
		Address address = curTrace.getBaseLanguage()
				.getDefaultSpace()
				.getAddress(value.getUnsignedValue().longValue());
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
		selectCurrentFrame();
	}

	protected String computeSubTitle() {
		TraceThread curThread = current.getThread();
		return curThread == null ? "" : curThread.getName();
	}

	protected void updateSubTitle() {
		setSubTitle(computeSubTitle());
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
		if (sameCoordinates(current, coordinates)) {
			current = coordinates;
			return;
		}
		current = coordinates;

		doSetTrace(current.getTrace());

		loadStack();
		updateSubTitle();
	}

	protected void selectCurrentFrame() {
		try (Suppression supp = cbFrameSelected.suppress(null)) {
			StackFrameRow row =
				stackTableModel.findFirst(r -> r.getFrameLevel() == current.getFrame());
			if (row == null) {
				// Strange
				stackTable.clearSelection();
			}
			else {
				stackFilterPanel.setSelectedItem(row);
			}
		}
	}

	@AutoServiceConsumed
	public void setModelService(DebuggerModelService modelService) {
		this.modelService = modelService;
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
