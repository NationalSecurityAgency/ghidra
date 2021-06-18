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
package ghidra.app.plugin.core.debug.gui.thread;

import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import com.google.common.collect.Range;

import docking.ActionContext;
import docking.WindowPosition;
import docking.action.*;
import docking.widgets.HorizontalTabPanel;
import docking.widgets.HorizontalTabPanel.TabListCellRenderer;
import docking.widgets.table.*;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.*;
import ghidra.app.plugin.core.debug.gui.DebuggerSnapActionContext;
import ghidra.app.services.*;
import ghidra.app.services.DebuggerTraceManagerService.BooleanChangeAdapter;
import ghidra.dbg.DebugModelConventions;
import ghidra.dbg.target.TargetThread;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.AutoService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.trace.model.Trace;
import ghidra.trace.model.Trace.TraceSnapshotChangeType;
import ghidra.trace.model.Trace.TraceThreadChangeType;
import ghidra.trace.model.TraceDomainObjectListener;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.thread.TraceThreadManager;
import ghidra.trace.model.time.TraceSchedule;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.util.Swing;
import ghidra.util.database.ObjectKey;
import ghidra.util.datastruct.CollectionChangeListener;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;
import utilities.util.SuppressableCallback;
import utilities.util.SuppressableCallback.Suppression;

public class DebuggerThreadsProvider extends ComponentProviderAdapter {

	protected static long orZero(Long l) {
		return l == null ? 0 : l;
	}

	protected static boolean sameCoordinates(DebuggerCoordinates a, DebuggerCoordinates b) {
		if (!Objects.equals(a.getTrace(), b.getTrace())) {
			return false;
		}
		if (!Objects.equals(a.getRecorder(), b.getRecorder())) {
			return false; // For live read/writes
		}
		if (!Objects.equals(a.getThread(), b.getThread())) {
			return false;
		}
		if (!Objects.equals(a.getTime(), b.getTime())) {
			return false;
		}
		return true;
	}

	protected class StepSnapBackwardAction extends AbstractStepSnapBackwardAction {
		public static final String GROUP = DebuggerResources.GROUP_CONTROL;

		public StepSnapBackwardAction() {
			super(plugin);
			setToolBarData(new ToolBarData(ICON, GROUP, "1"));
			addLocalAction(this);
			setEnabled(false);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			if (current.getTime().isSnapOnly()) {
				traceManager.activateSnap(current.getSnap() - 1);
			}
			else {
				traceManager.activateSnap(current.getSnap());
			}
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if (current.getTrace() == null) {
				return false;
			}
			if (!current.getTime().isSnapOnly()) {
				return true;
			}
			if (current.getSnap() <= 0) {
				return false;
			}
			return true;
		}
	}

	protected class StepTickBackwardAction extends AbstractStepTickBackwardAction {
		public static final String GROUP = DebuggerResources.GROUP_CONTROL;

		public StepTickBackwardAction() {
			super(plugin);
			setToolBarData(new ToolBarData(ICON, GROUP, "2"));
			addLocalAction(this);
			setEnabled(false);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			if (current.getTrace() == null) {
				return;
			}
			TraceSchedule time = current.getTime().steppedBackward(current.getTrace(), 1);
			if (time == null) {
				return;
			}
			traceManager.activateTime(time);
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if (emulationService == null) {
				return false;
			}
			if (current.getTrace() == null) {
				return false;
			}
			if (current.getTime().steppedBackward(current.getTrace(), 1) == null) {
				return false;
			}
			return true;
		}
	}

	protected class StepTickForwardAction extends AbstractStepTickForwardAction {
		public static final String GROUP = DebuggerResources.GROUP_CONTROL;

		public StepTickForwardAction() {
			super(plugin);
			setToolBarData(new ToolBarData(ICON, GROUP, "3"));
			addLocalAction(this);
			setEnabled(false);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			if (current.getThread() == null) {
				return;
			}
			TraceSchedule time = current.getTime().steppedForward(current.getThread(), 1);
			traceManager.activateTime(time);
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if (emulationService == null) {
				return false;
			}
			if (current.getThread() == null) {
				return false;
			}
			return true;
		}
	}

	protected class StepSnapForwardAction extends AbstractStepSnapForwardAction {
		public static final String GROUP = DebuggerResources.GROUP_CONTROL;

		public StepSnapForwardAction() {
			super(plugin);
			setToolBarData(new ToolBarData(ICON, GROUP, "4"));
			addLocalAction(this);
			setEnabled(false);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			traceManager.activateSnap(current.getSnap() + 1);
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			Trace curTrace = current.getTrace();
			if (curTrace == null) {
				return false;
			}
			Long maxSnap = curTrace.getTimeManager().getMaxSnap();
			if (maxSnap == null || current.getSnap() >= maxSnap) {
				return false;
			}
			return true;
		}
	}

	protected class SeekTracePresentAction extends AbstractSeekTracePresentAction
			implements BooleanChangeAdapter {
		public static final String GROUP = "zz";

		public SeekTracePresentAction() {
			super(plugin);
			setToolBarData(new ToolBarData(ICON, GROUP));
			addLocalAction(this);
			setSelected(traceManager == null ? false : traceManager.isAutoActivatePresent());
			traceManager.addAutoActivatePresentChangeListener(this);
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			return traceManager != null;
		}

		@Override
		public void actionPerformed(ActionContext context) {
			if (traceManager == null) {
				return;
			}
			traceManager.setAutoActivatePresent(isSelected());
		}

		@Override
		public void changed(Boolean value) {
			if (isSelected() == value) {
				return;
			}
			setSelected(value);
		}
	}

	protected static class ThreadTableModel
			extends RowWrappedEnumeratedColumnTableModel< //
					ThreadTableColumns, ObjectKey, ThreadRow, TraceThread> {

		public ThreadTableModel(DebuggerThreadsProvider provider) {
			super("Threads", ThreadTableColumns.class, TraceThread::getObjectKey,
				t -> new ThreadRow(provider.modelService, t));
		}
	}

	private class ThreadsListener extends TraceDomainObjectListener {
		public ThreadsListener() {
			listenForUntyped(DomainObject.DO_OBJECT_RESTORED, e -> objectRestored());

			listenFor(TraceThreadChangeType.ADDED, this::threadAdded);
			listenFor(TraceThreadChangeType.CHANGED, this::threadChanged);
			listenFor(TraceThreadChangeType.LIFESPAN_CHANGED, this::threadChanged);
			listenFor(TraceThreadChangeType.DELETED, this::threadDeleted);

			listenFor(TraceSnapshotChangeType.ADDED, this::snapAdded);
			listenFor(TraceSnapshotChangeType.DELETED, this::snapDeleted);
		}

		private void objectRestored() {
			loadThreads();
		}

		private void threadAdded(TraceThread thread) {
			threadTableModel.addItem(thread);
		}

		private void threadChanged(TraceThread thread) {
			threadTableModel.updateItem(thread);
		}

		private void threadDeleted(TraceThread thread) {
			threadTableModel.deleteItem(thread);
		}

		private void snapAdded(TraceSnapshot snapshot) {
			updateTimelineMax();
			contextChanged();
		}

		private void snapDeleted() {
			updateTimelineMax();
		}
	}

	private class RecordersChangeListener implements CollectionChangeListener<TraceRecorder> {
		@Override
		public void elementAdded(TraceRecorder element) {
			Swing.runIfSwingOrRunLater(() -> traceTabs.repaint());
		}

		@Override
		public void elementModified(TraceRecorder element) {
			Swing.runIfSwingOrRunLater(() -> traceTabs.repaint());
		}

		@Override
		public void elementRemoved(TraceRecorder element) {
			Swing.runIfSwingOrRunLater(() -> traceTabs.repaint());
		}
	}

	private final DebuggerThreadsPlugin plugin;

	// @AutoServiceConsumed  by method
	private DebuggerModelService modelService;
	@AutoServiceConsumed // NB, also by method
	private DebuggerTraceManagerService traceManager;
	@AutoServiceConsumed // NB, also by method
	private DebuggerEmulationService emulationService;
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoWiring;

	DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;
	private Trace currentTrace; // Copy for transition
	private final SuppressableCallback<Void> cbCoordinateActivation = new SuppressableCallback<>();

	private final ThreadsListener threadsListener = new ThreadsListener();
	private final CollectionChangeListener<TraceRecorder> recordersListener =
		new RecordersChangeListener();
	/* package access for testing */
	final RangeTableCellRenderer<Long> rangeRenderer = new RangeTableCellRenderer<>();
	final RangeCursorTableHeaderRenderer<Long> headerRenderer =
		new RangeCursorTableHeaderRenderer<>();

	protected final ThreadTableModel threadTableModel = new ThreadTableModel(this);

	private JPanel mainPanel;

	HorizontalTabPanel<Trace> traceTabs;
	GTable threadTable;
	GhidraTableFilterPanel<ThreadRow> threadFilterPanel;
	JPopupMenu traceTabPopupMenu;

	private ActionContext myActionContext;

	DockingAction actionSaveTrace;
	StepSnapBackwardAction actionStepSnapBackward;
	StepTickBackwardAction actionStepTickBackward;
	StepTickForwardAction actionStepTickForward;
	StepSnapForwardAction actionStepSnapForward;
	SeekTracePresentAction actionSeekTracePresent;
	ToggleDockingAction actionSyncFocus;
	Set<Object> strongRefs = new HashSet<>(); // Eww

	public DebuggerThreadsProvider(final DebuggerThreadsPlugin plugin) {
		super(plugin.getTool(), DebuggerResources.TITLE_PROVIDER_THREADS, plugin.getName());
		this.plugin = plugin;

		this.autoWiring = AutoService.wireServicesConsumed(plugin, this);

		setIcon(DebuggerResources.ICON_PROVIDER_THREADS);
		setHelpLocation(DebuggerResources.HELP_PROVIDER_THREADS);
		setWindowMenuGroup(DebuggerPluginPackage.NAME);

		buildMainPanel();

		// TODO: Consider a custom cell renderer in the table instead of a timeline widget?
		// TODO: Should I receive clicks on that renderer to seek to a given snap?
		setDefaultWindowPosition(WindowPosition.BOTTOM);

		myActionContext = new DebuggerSnapActionContext(0);
		createActions();
		contextChanged();

		setVisible(true);
	}

	private <T> T strongRef(T t) {
		strongRefs.add(t);
		return t;
	}

	@AutoServiceConsumed
	public void setModelService(DebuggerModelService modelService) {
		if (this.modelService != null) {
			this.modelService.removeTraceRecordersChangedListener(recordersListener);
		}
		this.modelService = modelService;
		if (this.modelService != null) {
			this.modelService.addTraceRecordersChangedListener(recordersListener);
		}
	}

	@AutoServiceConsumed
	public void setTraceManager(DebuggerTraceManagerService traceManager) {
		if (traceManager != null && actionSeekTracePresent != null) {
			actionSeekTracePresent.setSelected(traceManager.isAutoActivatePresent());
			actionSyncFocus.setSelected(traceManager.isSynchronizeFocus());
		}
		contextChanged();
	}

	@AutoServiceConsumed
	public void setEmulationService(DebuggerEmulationService emulationService) {
		contextChanged();
	}

	private void removeOldListeners() {
		if (currentTrace == null) {
			return;
		}
		currentTrace.removeListener(threadsListener);
	}

	private void addNewListeners() {
		if (currentTrace == null) {
			return;
		}
		currentTrace.addListener(threadsListener);
	}

	private void doSetTrace(Trace trace) {
		if (currentTrace == trace) {
			return;
		}
		removeOldListeners();
		currentTrace = trace;
		addNewListeners();

		try (Suppression supp = cbCoordinateActivation.suppress(null)) {
			traceTabs.setSelectedItem(trace);
		}
		loadThreads();
	}

	private void doSetThread(TraceThread thread) {
		ThreadRow row = threadFilterPanel.getSelectedItem();
		TraceThread curThread = row == null ? null : row.getThread();
		if (curThread == thread) {
			return;
		}
		try (Suppression supp = cbCoordinateActivation.suppress(null)) {
			if (thread != null) {
				threadFilterPanel.setSelectedItem(threadTableModel.getRow(thread));
			}
			else {
				threadTable.clearSelection();
			}
		}
	}

	private void doSetSnap(long snap) {
		headerRenderer.setCursorPosition(snap);
		threadTable.getTableHeader().repaint();
	}

	public void traceOpened(Trace trace) {
		traceTabs.addItem(trace);
	}

	public void traceClosed(Trace trace) {
		traceTabs.removeItem(trace);
		// manager will issue activate-null event if current trace is closed
	}

	public void coordinatesActivated(DebuggerCoordinates coordinates) {
		if (sameCoordinates(current, coordinates)) {
			current = coordinates;
			return;
		}

		current = coordinates;

		doSetTrace(current.getTrace());
		doSetThread(current.getThread());
		doSetSnap(current.getSnap());

		setSubTitle(current.getTime().toString());

		contextChanged();
	}

	protected void loadThreads() {
		threadTableModel.clear();
		Trace curTrace = current.getTrace();
		if (curTrace == null) {
			return;
		}
		TraceThreadManager manager = curTrace.getThreadManager();
		threadTableModel.addAllItems(manager.getAllThreads());
		updateTimelineMax();
	}

	protected void updateTimelineMax() {
		long max = orZero(current.getTrace().getTimeManager().getMaxSnap());
		Range<Long> fullRange = Range.closed(0L, max + 1);
		rangeRenderer.setFullRange(fullRange);
		headerRenderer.setFullRange(fullRange);
		threadTable.getTableHeader().repaint();
	}

	@Override
	public void addLocalAction(DockingActionIf action) {
		super.addLocalAction(action);
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		if (myActionContext == null) {
			return super.getActionContext(event);
		}
		return myActionContext;
	}

	private void rowActivated(ThreadRow row) {
		TraceThread thread = row.getThread();
		Trace trace = thread.getTrace();
		TraceRecorder recorder = modelService.getRecorder(trace);
		if (recorder != null) {
			TargetThread targetThread = recorder.getTargetThread(thread);
			if (targetThread != null && targetThread.isValid()) {
				DebugModelConventions.requestActivation(targetThread);
			}
		}
	}

	protected void buildMainPanel() {
		traceTabPopupMenu = new JPopupMenu("Trace");

		mainPanel = new JPanel(new BorderLayout());

		threadTable = new GhidraTable(threadTableModel);
		threadTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		mainPanel.add(new JScrollPane(threadTable));

		threadFilterPanel = new GhidraTableFilterPanel<>(threadTable, threadTableModel);
		mainPanel.add(threadFilterPanel, BorderLayout.SOUTH);

		threadTable.getSelectionModel().addListSelectionListener(this::threadRowSelected);
		threadTable.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseReleased(MouseEvent e) {
				int selectedRow = threadTable.getSelectedRow();
				ThreadRow row = threadTableModel.getRowObject(selectedRow);
				rowActivated(row);
			}
		});

		traceTabs = new HorizontalTabPanel<>();
		traceTabs.getList().setCellRenderer(new TabListCellRenderer<>() {
			protected String getText(Trace value) {
				return value.getName();
			}

			protected Icon getIcon(Trace value) {
				if (modelService == null) {
					return super.getIcon(value);
				}
				TraceRecorder recorder = modelService.getRecorder(value);
				if (recorder == null || !recorder.isRecording()) {
					return super.getIcon(value);
				}
				return DebuggerResources.ICON_RECORD;
			}
		});
		JList<Trace> list = traceTabs.getList();
		list.getSelectionModel().addListSelectionListener(this::traceTabSelected);
		list.addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent e) {
				checkTraceTabPopupViaMouse(e);
			}

			@Override
			public void mouseReleased(MouseEvent e) {
				checkTraceTabPopupViaMouse(e);
			}
		});
		// TODO: The popup key? Only seems to have rawCode=0x93 (147) in Swing
		mainPanel.add(traceTabs, BorderLayout.NORTH);

		TableColumnModel columnModel = threadTable.getColumnModel();
		TableColumn colName = columnModel.getColumn(ThreadTableColumns.NAME.ordinal());
		colName.setPreferredWidth(100);
		TableColumn colCreated = columnModel.getColumn(ThreadTableColumns.CREATED.ordinal());
		colCreated.setPreferredWidth(10);
		TableColumn colDestroyed = columnModel.getColumn(ThreadTableColumns.DESTROYED.ordinal());
		colDestroyed.setPreferredWidth(10);
		TableColumn colState = columnModel.getColumn(ThreadTableColumns.STATE.ordinal());
		colState.setPreferredWidth(20);
		TableColumn colComment = columnModel.getColumn(ThreadTableColumns.COMMENT.ordinal());
		colComment.setPreferredWidth(100);
		TableColumn colPlot = columnModel.getColumn(ThreadTableColumns.PLOT.ordinal());
		colPlot.setPreferredWidth(200);
		colPlot.setCellRenderer(rangeRenderer);
		colPlot.setHeaderRenderer(headerRenderer);

		headerRenderer.addSeekListener(threadTable, ThreadTableColumns.PLOT.ordinal(), pos -> {
			long snap = Math.round(pos);
			if (current.getTrace() == null || snap < 0) {
				snap = 0;
			}
			traceManager.activateSnap(snap);
			myActionContext = new DebuggerSnapActionContext(snap);
			contextChanged();
		});
	}

	private void checkTraceTabPopupViaMouse(MouseEvent e) {
		if (!e.isPopupTrigger()) {
			return;
		}
		JList<Trace> list = traceTabs.getList();
		int i = list.locationToIndex(e.getPoint());
		if (i < 0) {
			return;
		}
		Rectangle cell = list.getCellBounds(i, i);
		if (!cell.contains(e.getPoint())) {
			return;
		}
		showTraceTabPopup(e.getComponent(), e.getPoint(), i);
	}

	private void showTraceTabPopup(Component comp, Point p, int i) {
		// TODO: Make this use action contexts and docking actions instead
		traceTabPopupMenu.removeAll();
		final Trace trace = traceTabs.getItem(i);
		JMenuItem closeItem =
			new JMenuItem("Close " + trace.getName(), DebuggerResources.ICON_CLOSE);
		closeItem.addActionListener(evt -> {
			traceManager.closeTrace(trace);
		});
		JMenuItem closeOthers = new JMenuItem("Close Others", DebuggerResources.ICON_CLOSE);
		closeOthers.addActionListener(evt -> {
			traceManager.closeOtherTraces(trace);
		});
		JMenuItem closeDead = new JMenuItem("Close Dead", DebuggerResources.ICON_CLOSE);
		closeDead.addActionListener(evt -> {
			traceManager.closeDeadTraces();
		});
		JMenuItem closeAll = new JMenuItem("Close All", DebuggerResources.ICON_CLOSE);
		closeAll.addActionListener(evt -> {
			for (Trace t : List.copyOf(traceManager.getOpenTraces())) {
				traceManager.closeTrace(t);
			}
		});
		traceTabPopupMenu.add(closeItem);
		traceTabPopupMenu.addSeparator();
		traceTabPopupMenu.add(closeOthers);
		traceTabPopupMenu.add(closeDead);
		traceTabPopupMenu.add(closeAll);
		traceTabPopupMenu.show(comp, p.x, p.y);
	}

	protected void createActions() {
		// TODO: Make other actions use builder?
		actionStepSnapBackward = new StepSnapBackwardAction();
		actionStepTickBackward = new StepTickBackwardAction();
		actionStepTickForward = new StepTickForwardAction();
		actionStepSnapForward = new StepSnapForwardAction();
		actionSeekTracePresent = new SeekTracePresentAction();
		actionSyncFocus = SynchronizeFocusAction.builder(plugin)
				.selected(traceManager != null && traceManager.isSynchronizeFocus())
				.enabledWhen(c -> traceManager != null)
				.onAction(c -> toggleSyncFocus(actionSyncFocus.isSelected()))
				.buildAndInstallLocal(this);
		traceManager.addSynchronizeFocusChangeListener(
			strongRef(new ToToggleSelectionListener(actionSyncFocus)));
	}

	private void toggleSyncFocus(boolean enabled) {
		if (traceManager == null) {
			return;
		}
		traceManager.setSynchronizeFocus(enabled);
	}

	private void traceTabSelected(ListSelectionEvent e) {
		if (e.getValueIsAdjusting()) {
			return;
		}
		Trace newTrace = traceTabs.getSelectedItem();
		myActionContext = new DebuggerThreadActionContext(newTrace, null);
		contextChanged();
		cbCoordinateActivation.invoke(() -> traceManager.activateTrace(newTrace));
	}

	private void threadRowSelected(ListSelectionEvent e) {
		if (e.getValueIsAdjusting()) {
			return;
		}
		ThreadRow row = threadFilterPanel.getSelectedItem();
		myActionContext = new DebuggerThreadActionContext(current.getTrace(),
			row == null ? null : row.getThread());
		contextChanged();
		if (row != null && traceManager != null) {
			cbCoordinateActivation.invoke(() -> traceManager.activateThread(row.getThread()));
		}
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}
}
