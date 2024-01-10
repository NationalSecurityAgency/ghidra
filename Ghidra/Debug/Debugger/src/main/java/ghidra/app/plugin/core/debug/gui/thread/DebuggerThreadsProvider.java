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
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.SynchronizeTargetAction;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.ToToggleSelectionListener;
import ghidra.app.services.*;
import ghidra.app.services.DebuggerTraceManagerService.BooleanChangeAdapter;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.model.DomainObjectEvent;
import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.framework.plugintool.AutoService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.trace.model.Trace;
import ghidra.trace.model.Trace.TraceSnapshotChangeType;
import ghidra.trace.model.TraceDomainObjectListener;
import ghidra.trace.model.time.TraceSnapshot;

public class DebuggerThreadsProvider extends ComponentProviderAdapter {

	protected static boolean sameCoordinates(DebuggerCoordinates a, DebuggerCoordinates b) {
		if (!Objects.equals(a.getTrace(), b.getTrace())) {
			return false;
		}
		if (!Objects.equals(a.getTarget(), b.getTarget())) {
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
			listenForUntyped(DomainObjectEvent.RESTORED, this::objectRestored);

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

	@AutoServiceConsumed
	DebuggerTargetService targetService;
	// @AutoServiceConsumed by method
	private DebuggerTraceManagerService traceManager;
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoServiceWiring;

	private final BooleanChangeAdapter synchronizeTargetChangeListener =
		this::changedSynchronizeTarget;

	private final ForSnapsListener forSnapsListener = new ForSnapsListener();

	private JPanel mainPanel;

	DebuggerTraceTabPanel traceTabs;
	JPopupMenu traceTabPopupMenu;
	DebuggerThreadsPanel panel;
	DebuggerLegacyThreadsPanel legacyPanel;

	DockingAction actionSaveTrace;
	// TODO: This should probably be moved to ModelProvider
	ToggleDockingAction actionSyncTarget;

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
					.removeSynchronizeActiveChangeListener(synchronizeTargetChangeListener);
		}
		this.traceManager = traceManager;
		if (traceManager != null) {
			traceManager.addSynchronizeActiveChangeListener(synchronizeTargetChangeListener);
			if (actionSyncTarget != null) {
				actionSyncTarget.setSelected(traceManager.isSynchronizeActive());
			}
		}
		contextChanged();
	}

	@AutoServiceConsumed
	public void setEmulationService(DebuggerEmulationService emulationService) {
		contextChanged();
	}

	public void coordinatesActivated(DebuggerCoordinates coordinates) {
		if (sameCoordinates(current, coordinates)) {
			current = coordinates;
			return;
		}

		current = coordinates;

		traceTabs.coordinatesActivated(coordinates);
		if (Trace.isLegacy(coordinates.getTrace())) {
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

	void threadsPanelContextChanged() {
		myActionContext = panel.getActionContext();
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
		actionSyncTarget = SynchronizeTargetAction.builder(plugin)
				.selected(traceManager != null && traceManager.isSynchronizeActive())
				.enabledWhen(c -> traceManager != null)
				.onAction(c -> toggleSyncFocus(actionSyncTarget.isSelected()))
				.buildAndInstallLocal(this);
		traceManager.addSynchronizeActiveChangeListener(
			toToggleSelectionListener = new ToToggleSelectionListener(actionSyncTarget));
	}

	private void changedSynchronizeTarget(boolean value) {
		if (actionSyncTarget == null || actionSyncTarget.isSelected()) {
			return;
		}
		actionSyncTarget.setSelected(value);
	}

	private void toggleSyncFocus(boolean enabled) {
		if (traceManager == null) {
			return;
		}
		traceManager.setSynchronizeActive(enabled);
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}
}
