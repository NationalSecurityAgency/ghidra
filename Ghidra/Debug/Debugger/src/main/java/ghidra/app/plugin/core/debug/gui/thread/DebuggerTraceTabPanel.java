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

import java.awt.Rectangle;
import java.awt.event.*;
import java.util.Objects;

import javax.swing.Icon;
import javax.swing.JList;
import javax.swing.event.ListSelectionEvent;

import docking.action.DockingAction;
import docking.widgets.HorizontalTabPanel;
import ghidra.app.plugin.core.debug.event.TraceClosedPluginEvent;
import ghidra.app.plugin.core.debug.event.TraceOpenedPluginEvent;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.*;
import ghidra.app.services.DebuggerTargetService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.debug.api.target.Target;
import ghidra.debug.api.target.TargetPublicationListener;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginEventListener;
import ghidra.trace.model.Trace;
import ghidra.util.Swing;
import utilities.util.SuppressableCallback;
import utilities.util.SuppressableCallback.Suppression;

public class DebuggerTraceTabPanel extends HorizontalTabPanel<Trace>
		implements PluginEventListener {

	private class TargetsChangeListener implements TargetPublicationListener {
		@Override
		public void targetPublished(Target target) {
			Swing.runIfSwingOrRunLater(() -> repaint());

		}

		@Override
		public void targetWithdrawn(Target target) {
			Swing.runIfSwingOrRunLater(() -> repaint());

		}
	}

	private final DebuggerThreadsPlugin plugin;
	private final DebuggerThreadsProvider provider;

	// @AutoServiceConsumed by method
	DebuggerTargetService targetService;
	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoServiceWiring;

	private final TargetsChangeListener targetsListener = new TargetsChangeListener();

	DockingAction actionCloseTrace;
	DockingAction actionCloseOtherTraces;
	DockingAction actionCloseDeadTraces;
	DockingAction actionCloseAllTraces;

	private final SuppressableCallback<Void> cbCoordinateActivation = new SuppressableCallback<>();

	private DebuggerTraceFileActionContext myActionContext;

	public DebuggerTraceTabPanel(DebuggerThreadsProvider provider) {
		this.plugin = provider.plugin;
		this.provider = provider;

		this.autoServiceWiring = AutoService.wireServicesConsumed(plugin, this);

		PluginTool tool = plugin.getTool();
		tool.addEventListener(TraceOpenedPluginEvent.class, this);
		tool.addEventListener(TraceClosedPluginEvent.class, this);

		list.setCellRenderer(new TabListCellRenderer<>() {
			protected String getText(Trace value) {
				return value.getName();
			}

			protected Icon getIcon(Trace value) {
				if (targetService == null) {
					return super.getIcon(value);
				}
				Target target = targetService.getTarget(value);
				if (target == null || !target.isValid()) {
					return super.getIcon(value);
				}
				return DebuggerResources.ICON_RECORD;
			}
		});
		list.getSelectionModel().addListSelectionListener(this::traceTabSelected);
		list.addFocusListener(new FocusAdapter() {
			@Override
			public void focusGained(FocusEvent e) {
				setTraceTabActionContext(null);
			}
		});
		list.addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent e) {
				setTraceTabActionContext(e);
			}
		});

		actionCloseTrace = CloseTraceAction.builderPopup(plugin)
				.withContext(DebuggerTraceFileActionContext.class)
				.popupWhen(c -> c.getTrace() != null)
				.onAction(c -> traceManager.closeTrace(c.getTrace()))
				.buildAndInstallLocal(provider);
		actionCloseAllTraces = CloseAllTracesAction.builderPopup(plugin)
				.withContext(DebuggerTraceFileActionContext.class)
				.popupWhen(c -> !traceManager.getOpenTraces().isEmpty())
				.onAction(c -> traceManager.closeAllTraces())
				.buildAndInstallLocal(provider);
		actionCloseOtherTraces = CloseOtherTracesAction.builderPopup(plugin)
				.withContext(DebuggerTraceFileActionContext.class)
				.popupWhen(c -> traceManager.getOpenTraces().size() > 1 && c.getTrace() != null)
				.onAction(c -> traceManager.closeOtherTraces(c.getTrace()))
				.buildAndInstallLocal(provider);
		actionCloseDeadTraces = CloseDeadTracesAction.builderPopup(plugin)
				.withContext(DebuggerTraceFileActionContext.class)
				.popupWhen(c -> !traceManager.getOpenTraces().isEmpty() && targetService != null)
				.onAction(c -> traceManager.closeDeadTraces())
				.buildAndInstallLocal(provider);
	}

	private Trace computeClickedTraceTab(MouseEvent e) {
		JList<Trace> list = getList();
		int i = list.locationToIndex(e.getPoint());
		if (i < 0) {
			return null;
		}
		Rectangle cell = list.getCellBounds(i, i);
		if (!cell.contains(e.getPoint())) {
			return null;
		}
		return getItem(i);
	}

	private Trace setTraceTabActionContext(MouseEvent e) {
		Trace newTrace = e == null ? getSelectedItem() : computeClickedTraceTab(e);
		actionCloseTrace.getPopupMenuData()
				.setMenuItemName(
					CloseTraceAction.NAME_PREFIX + (newTrace == null ? "..." : newTrace.getName()));
		myActionContext = new DebuggerTraceFileActionContext(newTrace);
		provider.traceTabsContextChanged();
		return newTrace;
	}

	public DebuggerTraceFileActionContext getActionContext() {
		return myActionContext;
	}

	public void coordinatesActivated(DebuggerCoordinates coordinates) {
		try (Suppression supp = cbCoordinateActivation.suppress(null)) {
			setSelectedItem(coordinates.getTrace());
		}
	}

	@AutoServiceConsumed
	public void setTargetService(DebuggerTargetService targetService) {
		if (this.targetService != null) {
			this.targetService.removeTargetPublicationListener(targetsListener);
		}
		this.targetService = targetService;
		if (this.targetService != null) {
			this.targetService.addTargetPublicationListener(targetsListener);
		}
	}

	@Override
	public void eventSent(PluginEvent event) {
		if (Objects.equals(event.getSourceName(), plugin.getName())) {
			return;
		}
		if (event instanceof TraceOpenedPluginEvent evt) {
			try (Suppression supp = cbCoordinateActivation.suppress(null)) {
				addItem(evt.getTrace());
			}
		}
		else if (event instanceof TraceClosedPluginEvent evt) {
			try (Suppression supp = cbCoordinateActivation.suppress(null)) {
				removeItem(evt.getTrace());
			}
		}
	}

	private void traceTabSelected(ListSelectionEvent e) {
		if (e.getValueIsAdjusting()) {
			return;
		}
		Trace newTrace = setTraceTabActionContext(null);
		cbCoordinateActivation.invoke(() -> {
			traceManager.activateTrace(newTrace);
		});
	}
}
