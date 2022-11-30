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

import java.awt.BorderLayout;
import java.awt.event.MouseEvent;
import java.util.Objects;

import javax.swing.*;

import org.apache.commons.lang3.ArrayUtils;

import docking.ActionContext;
import docking.WindowPosition;
import docking.action.*;
import docking.widgets.dialogs.InputDialog;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.*;
import ghidra.app.services.*;
import ghidra.app.services.DebuggerTraceManagerService.BooleanChangeAdapter;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.framework.plugintool.AutoService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.trace.model.Trace;
import ghidra.trace.model.Trace.TraceSnapshotChangeType;
import ghidra.trace.model.TraceDomainObjectListener;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.trace.model.time.schedule.TraceSchedule;
import ghidra.util.Msg;

public class DebuggerThreadsProvider extends ComponentProviderAdapter {

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

	private class ForSnapsListener extends TraceDomainObjectListener {
		private Trace currentTrace;

		public ForSnapsListener() {
			listenForUntyped(DomainObject.DO_OBJECT_RESTORED, this::objectRestored);

			listenFor(TraceSnapshotChangeType.ADDED, this::snapAdded);
			listenFor(TraceSnapshotChangeType.DELETED, this::snapDeleted);
		}

		private void setTrace(Trace trace) {
			if (currentTrace != null) {
				currentTrace.removeListener(this);
			}
			currentTrace = trace;
			if (currentTrace != null) {
				currentTrace.addListener(this);
			}
		}

		private void objectRestored(DomainObjectChangeRecord rec) {
			contextChanged();
		}

		private void snapAdded(TraceSnapshot snapshot) {
			contextChanged();
		}

		private void snapDeleted() {
			contextChanged();
		}
	}

	final DebuggerThreadsPlugin plugin;

	DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;
	Trace currentTrace; // Copy for transition

	// @AutoServiceConsumed by method
	DebuggerModelService modelService;
	// @AutoServiceConsumed by method
	private DebuggerTraceManagerService traceManager;
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoServiceWiring;

	private final BooleanChangeAdapter activatePresentChangeListener =
		this::changedAutoActivatePresent;
	private final BooleanChangeAdapter synchronizeFocusChangeListener =
		this::changedSynchronizeFocus;

	private final ForSnapsListener forSnapsListener = new ForSnapsListener();

	private JPanel mainPanel;

	DebuggerTraceTabPanel traceTabs;
	JPopupMenu traceTabPopupMenu;
	DebuggerThreadsPanel panel;
	DebuggerLegacyThreadsPanel legacyPanel;

	DockingAction actionSaveTrace;
	ToggleDockingAction actionSeekTracePresent;
	ToggleDockingAction actionSyncFocus;
	DockingAction actionGoToTime;

	ActionContext myActionContext;

	// strong ref
	ToToggleSelectionListener toToggleSelectionListener;

	public DebuggerThreadsProvider(final DebuggerThreadsPlugin plugin) {
		super(plugin.getTool(), DebuggerResources.TITLE_PROVIDER_THREADS, plugin.getName());
		this.plugin = plugin;

		this.autoServiceWiring = AutoService.wireServicesConsumed(plugin, this);

		setIcon(DebuggerResources.ICON_PROVIDER_THREADS);
		setHelpLocation(DebuggerResources.HELP_PROVIDER_THREADS);
		setWindowMenuGroup(DebuggerPluginPackage.NAME);

		buildMainPanel();

		setDefaultWindowPosition(WindowPosition.BOTTOM);

		createActions();
		contextChanged();

		setVisible(true);
	}

	@AutoServiceConsumed
	public void setTraceManager(DebuggerTraceManagerService traceManager) {
		if (this.traceManager != null) {
			this.traceManager
					.removeAutoActivatePresentChangeListener(activatePresentChangeListener);
			this.traceManager.removeSynchronizeFocusChangeListener(synchronizeFocusChangeListener);
		}
		this.traceManager = traceManager;
		if (traceManager != null) {
			traceManager.addAutoActivatePresentChangeListener(activatePresentChangeListener);
			traceManager.addSynchronizeFocusChangeListener(synchronizeFocusChangeListener);
			if (actionSeekTracePresent != null) {
				actionSeekTracePresent.setSelected(traceManager.isAutoActivatePresent());
			}
			if (actionSyncFocus != null) {
				actionSyncFocus.setSelected(traceManager.isSynchronizeFocus());
			}
		}
		contextChanged();
	}

	@AutoServiceConsumed
	public void setEmulationService(DebuggerEmulationService emulationService) {
		contextChanged();
	}

	private boolean isLegacy(Trace trace) {
		return trace != null && trace.getObjectManager().getRootSchema() == null;
	}

	public void coordinatesActivated(DebuggerCoordinates coordinates) {
		if (sameCoordinates(current, coordinates)) {
			current = coordinates;
			return;
		}

		current = coordinates;

		traceTabs.coordinatesActivated(coordinates);
		if (isLegacy(coordinates.getTrace())) {
			panel.coordinatesActivated(DebuggerCoordinates.NOWHERE);
			legacyPanel.coordinatesActivated(coordinates);
			if (ArrayUtils.indexOf(mainPanel.getComponents(), legacyPanel) == -1) {
				mainPanel.remove(panel);
				mainPanel.add(legacyPanel);
				mainPanel.validate();
			}
		}
		else {
			legacyPanel.coordinatesActivated(DebuggerCoordinates.NOWHERE);
			panel.coordinatesActivated(coordinates);
			if (ArrayUtils.indexOf(mainPanel.getComponents(), panel) == -1) {
				mainPanel.remove(legacyPanel);
				mainPanel.add(panel);
				mainPanel.validate();
			}
		}

		forSnapsListener.setTrace(coordinates.getTrace());

		setSubTitle(coordinates.getTime().toString());
		contextChanged();
	}

	@Override
	public void addLocalAction(DockingActionIf action) {
		super.addLocalAction(action);
	}

	void legacyThreadsPanelContextChanged() {
		myActionContext = legacyPanel.getActionContext();
	}

	void traceTabsContextChanged() {
		myActionContext = traceTabs.getActionContext();
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		if (myActionContext == null) {
			return super.getActionContext(event);
		}
		return myActionContext;
	}

	protected void buildMainPanel() {
		traceTabPopupMenu = new JPopupMenu("Trace");

		mainPanel = new JPanel(new BorderLayout());

		panel = new DebuggerThreadsPanel(this);
		legacyPanel = new DebuggerLegacyThreadsPanel(plugin, this);
		mainPanel.add(panel);

		traceTabs = new DebuggerTraceTabPanel(this);

		mainPanel.add(traceTabs, BorderLayout.NORTH);
	}

	protected void createActions() {
		actionSeekTracePresent = SeekTracePresentAction.builder(plugin)
				.enabledWhen(this::isSeekTracePresentEnabled)
				.onAction(this::toggledSeekTracePresent)
				.selected(traceManager == null ? false : traceManager.isAutoActivatePresent())
				.buildAndInstallLocal(this);

		actionSyncFocus = SynchronizeFocusAction.builder(plugin)
				.selected(traceManager != null && traceManager.isSynchronizeFocus())
				.enabledWhen(c -> traceManager != null)
				.onAction(c -> toggleSyncFocus(actionSyncFocus.isSelected()))
				.buildAndInstallLocal(this);
		actionGoToTime = GoToTimeAction.builder(plugin)
				.enabledWhen(c -> current.getTrace() != null)
				.onAction(c -> activatedGoToTime())
				.buildAndInstallLocal(this);
		traceManager.addSynchronizeFocusChangeListener(toToggleSelectionListener =
			new ToToggleSelectionListener(actionSyncFocus));
	}

	private boolean isSeekTracePresentEnabled(ActionContext context) {
		return traceManager != null;
	}

	private void toggledSeekTracePresent(ActionContext context) {
		if (traceManager == null) {
			return;
		}
		traceManager.setAutoActivatePresent(actionSeekTracePresent.isSelected());
	}

	private void changedAutoActivatePresent(boolean value) {
		if (actionSeekTracePresent == null || actionSeekTracePresent.isSelected()) {
			return;
		}
		actionSeekTracePresent.setSelected(value);
	}

	private void changedSynchronizeFocus(boolean value) {
		if (actionSyncFocus == null || actionSyncFocus.isSelected()) {
			return;
		}
		actionSyncFocus.setSelected(value);
	}

	private void toggleSyncFocus(boolean enabled) {
		if (traceManager == null) {
			return;
		}
		traceManager.setSynchronizeFocus(enabled);
	}

	private void activatedGoToTime() {
		InputDialog dialog =
			new InputDialog("Go To Time", "Schedule:", current.getTime().toString());
		tool.showDialog(dialog);
		if (dialog.isCanceled()) {
			return;
		}
		try {
			TraceSchedule time = TraceSchedule.parse(dialog.getValue());
			traceManager.activateTime(time);
		}
		catch (IllegalArgumentException e) {
			Msg.showError(this, getComponent(), "Go To Time", "Could not parse schedule");
		}
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}
}
