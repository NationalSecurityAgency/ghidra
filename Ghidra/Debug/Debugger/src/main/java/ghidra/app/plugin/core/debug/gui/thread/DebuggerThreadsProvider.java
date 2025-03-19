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

import docking.ActionContext;
import docking.WindowPosition;
import docking.action.DockingActionIf;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.services.DebuggerEmulationService;
import ghidra.app.services.DebuggerTargetService;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.framework.model.DomainObjectEvent;
import ghidra.framework.plugintool.AutoService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.trace.model.Trace;
import ghidra.trace.model.TraceDomainObjectListener;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.trace.util.TraceEvents;

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

			listenFor(TraceEvents.SNAPSHOT_ADDED, this::snapAdded);
			listenFor(TraceEvents.SNAPSHOT_DELETED, this::snapDeleted);
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

	@AutoServiceConsumed
	DebuggerTargetService targetService;
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoServiceWiring;

	private final ForSnapsListener forSnapsListener = new ForSnapsListener();

	private JPanel mainPanel;

	JPopupMenu traceTabPopupMenu;
	DebuggerThreadsPanel panel;

	ActionContext myActionContext;

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
	public void setEmulationService(DebuggerEmulationService emulationService) {
		contextChanged();
	}

	public void coordinatesActivated(DebuggerCoordinates coordinates) {
		if (sameCoordinates(current, coordinates)) {
			current = coordinates;
			return;
		}

		current = coordinates;

		panel.coordinatesActivated(coordinates);

		forSnapsListener.setTrace(coordinates.getTrace());

		contextChanged();
	}

	@Override
	public void addLocalAction(DockingActionIf action) {
		super.addLocalAction(action);
	}

	void threadsPanelContextChanged() {
		myActionContext = panel.getActionContext();
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
		mainPanel.add(panel);
	}

	protected void createActions() {
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}
}
