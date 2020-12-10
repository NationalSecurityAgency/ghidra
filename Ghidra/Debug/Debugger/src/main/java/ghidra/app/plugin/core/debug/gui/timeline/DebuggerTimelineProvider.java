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
package ghidra.app.plugin.core.debug.gui.timeline;

import static ghidra.app.plugin.core.debug.gui.DebuggerResources.*;

import java.awt.BorderLayout;
import java.awt.event.MouseEvent;
import java.util.*;

import javax.swing.*;

import docking.ActionContext;
import docking.WindowPosition;
import docking.action.DockingActionIf;
import docking.action.ToolBarData;
import docking.widgets.EventTrigger;
import docking.widgets.table.*;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.*;
import ghidra.app.plugin.core.debug.gui.DebuggerSnapActionContext;
import ghidra.app.plugin.core.debug.gui.objects.ObjectContainer;
import ghidra.app.plugin.core.debug.gui.timeline.DebuggerTimelinePanel.VetoableSnapRequestListener;
import ghidra.app.services.*;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.AutoService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.trace.model.Trace;
import ghidra.trace.model.Trace.TraceSnapshotChangeType;
import ghidra.trace.model.Trace.TraceThreadChangeType;
import ghidra.trace.model.TraceDomainObjectListener;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.modules.TraceModuleManager;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.thread.TraceThreadManager;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;

public class DebuggerTimelineProvider extends ComponentProviderAdapter {

	protected static boolean sameCoordinates(DebuggerCoordinates a, DebuggerCoordinates b) {
		if (!Objects.equals(a.getTrace(), b.getTrace())) {
			return false;
		}
		if (!Objects.equals(a.getSnap(), b.getSnap())) {
			return false;
		}
		return true;
	}

	private final DebuggerTimelinePlugin plugin;

	@AutoServiceConsumed
	private DebuggerModelService modelService;
	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoWiring;

	DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;
	private Trace currentTrace; // Copy for transition
	private TraceObject currentObject;

	private final ThreadsListener threadsListener = new ThreadsListener();
	private final VetoableSnapRequestListener snapListener = this::snapRequested;

	protected final EnumeratedColumnTableModel<TimelineRow> timelineTableModel =
		new DefaultEnumeratedColumnTableModel<>("Objects", TimelineTableColumns.class);

	private JSplitPane mainPanel = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
	protected GTable objectTable;
	private DebuggerTimelinePanel timelinePanel;
	private GhidraTableFilterPanel<TimelineRow> timelineFilterPanel;

	private ActionContext myActionContext;

	StepTraceBackwardAction actionStepTraceBackward;
	StepTraceForwardAction actionStepTraceForward;
	SeekTracePresentAction actionSeekTracePresent;

	private Map<String, TraceObject> map = new LinkedHashMap<String, TraceObject>();
	private Map<String, TimelineRow> rowMap = new LinkedHashMap<String, TimelineRow>();

	public DebuggerTimelineProvider(final DebuggerTimelinePlugin plugin) {
		super(plugin.getTool(), TITLE_PROVIDER_OBJECTS, plugin.getName());
		this.plugin = plugin;

		this.autoWiring = AutoService.wireServicesConsumed(plugin, this);

		setIcon(ICON_PROVIDER_OBJECTS);
		setHelpLocation(HELP_PROVIDER_OBJECTS);
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

	private void doSetTrace(Trace trace) {
		removeOldListeners();
		currentTrace = trace;
		addNewListeners();

		loadObjects();
	}

	private void doSetObject(TraceObject object) {
		// TODO: Use a map if speed becomes an issue
		timelineFilterPanel
				.setSelectedItem(timelineTableModel.findFirst(row -> row.getObject() == object));
		currentObject = object;
	}

	private void doSetSnap(long snap) {
		timelinePanel.setSnap(snap);
		myActionContext = new DebuggerSnapActionContext(snap);
	}

	public void coordinatesActivated(DebuggerCoordinates coordinates) {
		if (sameCoordinates(current, coordinates)) {
			current = coordinates;
			return;
		}
		current = coordinates;

		doSetTrace(current.getTrace());
		doSetSnap(current.getSnap());
		contextChanged();
	}

	public void setObject(TraceObject object) {
		if (currentObject == object) {
			return;
		}
		doSetObject(object);
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

	protected void loadObjects() {
		map.clear();
		rowMap.clear();
		timelineTableModel.clear();
		Trace curTrace = current.getTrace();
		if (curTrace == null) {
			return;
		}
		TraceThreadManager manager = curTrace.getThreadManager();
		Collection<? extends TraceThread> allThreads = manager.getAllThreads();
		for (TraceThread thread : allThreads) {
			TraceObject t = new TraceObject(thread);
			timelineTableModel.add(new TimelineRow(modelService, t));
		}
		TraceModuleManager modmgr = curTrace.getModuleManager();
		Collection<? extends TraceModule> allModules = modmgr.getAllModules();
		for (TraceModule module : allModules) {
			TraceObject t = new TraceObject(module);
			timelineTableModel.add(new TimelineRow(modelService, t));
		}
		timelinePanel.setMaxSnapAtLeast(curTrace.getTimeManager().getMaxSnap());
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

	private void snapRequested(long snap, EventTrigger trigger) {
		if (snap < 0) {
			snap = 0;
		}
		Trace curTrace = current.getTrace();
		if (curTrace == null) {
			snap = 0;
		}
		else {
			Long maxSnap = curTrace.getTimeManager().getMaxSnap();
			if (maxSnap == null) {
				maxSnap = 0L;
			}
			if (snap > maxSnap) {
				snap = maxSnap;
			}
		}
		if (trigger == EventTrigger.GUI_ACTION) {
			traceManager.activateSnap(snap);
		}
		myActionContext = new DebuggerSnapActionContext(snap);
		contextChanged();
	}

	protected void buildMainPanel() {
		mainPanel.setContinuousLayout(true);

		JPanel tablePanel = new JPanel(new BorderLayout());
		objectTable = new GhidraTable(timelineTableModel);
		objectTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		tablePanel.add(new JScrollPane(objectTable));
		timelineFilterPanel = new GhidraTableFilterPanel<>(objectTable, timelineTableModel);
		tablePanel.add(timelineFilterPanel, BorderLayout.SOUTH);
		mainPanel.setLeftComponent(tablePanel);

		timelinePanel = new DebuggerTimelinePanel(timelineFilterPanel.getTableFilterModel());
		mainPanel.setRightComponent(timelinePanel);

		mainPanel.setResizeWeight(0.4);

		objectTable.getSelectionModel().addListSelectionListener(evt -> {
			TimelineRow row = timelineFilterPanel.getSelectedItem();
			myActionContext = new DebuggerTimelineActionContext(row);
			contextChanged();
			if (row != null && traceManager != null) {
				TraceObject object = row.getObject();
				if (object.isThread()) {
					traceManager.activateThread((TraceThread) object.getObject());
				}
			}
		});
		timelinePanel.setSelectionModel(objectTable.getSelectionModel());
		timelinePanel.addSnapRequestedListener(snapListener);
	}

	protected void createActions() {
		actionStepTraceBackward = new StepTraceBackwardAction();
		actionStepTraceForward = new StepTraceForwardAction();
		actionSeekTracePresent = new SeekTracePresentAction();
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	public void update(ObjectContainer container) {
		String shortName = container.getShortName();
		if (shortName == null || !shortName.equals("Sequence")) {
			return;
		}

		TraceObject object = null;
		Trace curTrace = current.getTrace();
		try (UndoableTransaction tid =
			UndoableTransaction.start(curTrace, "Populate Snapshot", true)) {
			ObjectContainer ancestor = container;
			while (ancestor != null && !ancestor.getPrefixedName().contains("[")) {
				ancestor = ancestor.getParent();
			}
			if (ancestor == null) {
				return;
			}
			String objName = ancestor.getPrefixedName();
			TimelineRow row = null;
			if (map.containsKey(objName)) {
				object = map.get(objName);
				row = rowMap.get(objName);
			}
			else {
				object = new TraceObject(curTrace);
				object.setName(objName);
				map.put(objName, object);
				row = new TimelineRow(modelService, object);
				rowMap.put(objName, row);
				timelineTableModel.add(row);
			}
			String[] split = container.getName().split(" ");
			String searchString = container.getTargetObject().getJoinedPath(".");
			long pos = -1;
			if (searchString.contains("MinPos")) {
				System.err.println("minpos");
				pos = Long.parseLong(split[split.length - 1], 16);
				object.setCreationSnap(pos);
				curTrace.getTimeManager()
						.getSnapshot(pos, true)
						.setDescription(object + " created");
			}
			else if (searchString.contains("MaxPos")) {
				System.err.println("maxpos");
				pos = Long.parseLong(split[split.length - 1], 16);
				object.setDestructionSnap(pos);
				curTrace.getTimeManager()
						.getSnapshot(pos, true)
						.setDescription(object + " destroyed");
			}
			else if (searchString.contains("Position")) {
				/*
				pos = Long.parseLong(split[split.length - 1], 16);
				object.setCreationSnap(pos);
				curTrace.getTimeManager()
						.getSnapshot(pos, true)
						.setDescription(object + " mark set");
						*/
			}
			if (pos >= 0L) {
				timelinePanel.setMaxSnapAtLeast(pos);
			}
			timelineTableModel.notifyUpdated(row);
			mainPanel.validate();
			mainPanel.repaint();
		}
		catch (Exception e) {
			e.printStackTrace();
		}

		setObject(object);
	}

	protected class StepTraceBackwardAction extends AbstractStepTraceBackwardAction {
		public static final String GROUP = GROUP_GENERAL;

		public StepTraceBackwardAction() {
			super(plugin);
			setToolBarData(new ToolBarData(ICON, GROUP));
			addLocalAction(this);
			setEnabled(false);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			traceManager.activateSnap(current.getSnap() - 1);
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if (current.getTrace() == null) {
				return false;
			}
			// TODO: Can I track minTick?
			if (current.getSnap() <= 0) {
				return false;
			}
			return true;
		}
	}

	protected class StepTraceForwardAction extends AbstractStepTraceForwardAction {
		public static final String GROUP = GROUP_GENERAL;

		public StepTraceForwardAction() {
			super(plugin);
			setToolBarData(new ToolBarData(ICON, GROUP));
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

	protected class SeekTracePresentAction extends AbstractSeekTracePresentAction {
		public static final String GROUP = GROUP_GENERAL;

		public SeekTracePresentAction() {
			super(plugin);
			setToolBarData(new ToolBarData(ICON, GROUP));
			addLocalAction(this);
			setEnabled(false);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			if (current.getTrace() == null) {
				return;
			}
			TraceRecorder recorder = current.getRecorder();
			if (recorder == null) {
				return;
			}
			traceManager.activateSnap(recorder.getSnap());
		}

		@Override
		public boolean isEnabled() {
			if (current.getTrace() == null) {
				return false;
			}
			TraceRecorder recorder = current.getRecorder();
			if (recorder == null) {
				return false;
			}
			if (current.getSnap() == recorder.getSnap()) {
				return false;
			}
			return true;
		}
	}

	private class ThreadsListener extends TraceDomainObjectListener {
		public ThreadsListener() {
			listenForUntyped(DomainObject.DO_OBJECT_RESTORED, e -> objectRestored());

			listenFor(TraceThreadChangeType.ADDED, this::threadAdded);
			listenFor(TraceThreadChangeType.CHANGED, this::threadChanged);
			listenFor(TraceThreadChangeType.LIFESPAN_CHANGED, this::threadChanged);
			listenFor(TraceThreadChangeType.DELETED, this::threadDeleted);

			listenFor(TraceSnapshotChangeType.ADDED, this::snapshotAdded);
			listenFor(TraceSnapshotChangeType.DELETED, this::snapshotDeleted);
		}

		private void objectRestored() {
			loadObjects();
		}

		private void threadAdded(TraceThread thread) {
			timelineTableModel.add(new TimelineRow(modelService, new TraceObject(thread)));
		}

		private void threadChanged(TraceThread thread) {
			timelineTableModel.notifyUpdatedWith(row -> row.getObject() == thread);
		}

		private void threadDeleted(TraceThread thread) {
			timelineTableModel.deleteWith(row -> row.getObject() == thread);
		}

		private void snapshotAdded(TraceSnapshot snapshot) {
			long maxSnap = current.getTrace().getTimeManager().getMaxSnap();
			timelinePanel.setMaxSnapAtLeast(maxSnap);
		}

		private void snapshotDeleted(TraceSnapshot snapshot) {
			timelinePanel.setMaxSnapAtLeast(current.getTrace().getTimeManager().getMaxSnap());
		}
	}

}
