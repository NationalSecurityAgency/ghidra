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
package ghidra.app.plugin.core.debug.gui.trace;

import java.awt.event.MouseEvent;

import javax.swing.Icon;

import docking.action.DockingAction;
import docking.widgets.tab.GTabPanel;
import ghidra.app.plugin.core.debug.event.*;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.*;
import ghidra.app.plugin.core.debug.gui.thread.DebuggerTraceFileActionContext;
import ghidra.app.plugin.core.progmgr.MultiTabPlugin;
import ghidra.app.services.DebuggerTargetService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.debug.api.target.Target;
import ghidra.debug.api.target.TargetPublicationListener;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginEventListener;
import ghidra.trace.model.Trace;
import ghidra.util.Swing;
import utilities.util.SuppressableCallback;
import utilities.util.SuppressableCallback.Suppression;

public class DebuggerTraceTabPanel extends GTabPanel<Trace>
		implements PluginEventListener, DomainObjectListener {

	private class TargetsChangeListener implements TargetPublicationListener {
		@Override
		public void targetPublished(Target target) {
			Swing.runIfSwingOrRunLater(() -> refreshTab(target.getTrace()));
		}

		@Override
		public void targetWithdrawn(Target target) {
			Swing.runIfSwingOrRunLater(() -> refreshTab(target.getTrace()));
		}
	}

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

	public DebuggerTraceTabPanel(Plugin plugin) {
		super("Trace");
		this.autoServiceWiring = AutoService.wireServicesConsumed(plugin, this);

		PluginTool tool = plugin.getTool();
		tool.addEventListener(TraceOpenedPluginEvent.class, this);
		tool.addEventListener(TraceActivatedPluginEvent.class, this);
		tool.addEventListener(TraceClosedPluginEvent.class, this);

		setNameFunction(this::getNameForTrace);
		setIconFunction(this::getIconForTrace);
		setToolTipFunction(this::getTipForTrace);
		setSelectedTabConsumer(this::traceTabSelected);
		// Cannot use method ref here, since traceManager is still null
		setCloseTabConsumer(t -> traceManager.closeTrace(t));

		actionCloseTrace = CloseTraceAction.builderPopup(plugin)
				.withContext(DebuggerTraceFileActionContext.class)
				.popupWhen(c -> {
					Trace trace = c.getTrace();
					if (trace == null) {
						return false;
					}
					actionCloseTrace.getPopupMenuData()
							.setMenuItemName(CloseTraceAction.NAME_PREFIX + getNameForTrace(trace));
					return true;
				})
				.onAction(c -> traceManager.closeTrace(c.getTrace()))
				.buildAndInstall(tool);
		actionCloseAllTraces = CloseAllTracesAction.builderPopup(plugin)
				.withContext(DebuggerTraceFileActionContext.class)
				.popupWhen(c -> !traceManager.getOpenTraces().isEmpty())
				.onAction(c -> traceManager.closeAllTraces())
				.buildAndInstall(tool);
		actionCloseOtherTraces = CloseOtherTracesAction.builderPopup(plugin)
				.withContext(DebuggerTraceFileActionContext.class)
				.popupWhen(c -> traceManager.getOpenTraces().size() > 1 && c.getTrace() != null)
				.onAction(c -> traceManager.closeOtherTraces(c.getTrace()))
				.buildAndInstall(tool);
		actionCloseDeadTraces = CloseDeadTracesAction.builderPopup(plugin)
				.withContext(DebuggerTraceFileActionContext.class)
				.popupWhen(c -> !traceManager.getOpenTraces().isEmpty() && targetService != null)
				.onAction(c -> traceManager.closeDeadTraces())
				.buildAndInstall(tool);
	}

	private String getNameForTrace(Trace trace) {
		return DomainObjectDisplayUtils.getTabText(trace);
	}

	private Icon getIconForTrace(Trace trace) {
		if (targetService == null) {
			return null;
		}
		Target target = targetService.getTarget(trace);
		if (target == null || !target.isValid()) {
			return null;
		}
		return DebuggerResources.ICON_RECORD;
	}

	private String getTipForTrace(Trace trace) {
		return DomainObjectDisplayUtils.getToolTip(trace);
	}

	public DebuggerTraceFileActionContext getActionContext(MouseEvent e) {
		if (e == null) {
			return null;
		}
		Trace trace = getValueFor(e);
		if (trace == null) {
			return null;
		}
		return new DebuggerTraceFileActionContext(trace);
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

	protected void add(Trace trace) {
		addTab(trace);
		trace.removeListener(this);
		trace.addListener(this);
	}

	protected void remove(Trace trace) {
		trace.removeListener(this);
		removeTab(trace);
	}

	@Override
	public void eventSent(PluginEvent event) {
		if (event instanceof TraceOpenedPluginEvent evt) {
			try (Suppression supp = cbCoordinateActivation.suppress(null)) {
				add(evt.getTrace());
			}
		}
		else if (event instanceof TraceActivatedPluginEvent evt) {
			Trace trace = evt.getActiveCoordinates().getTrace();
			try (Suppression supp = cbCoordinateActivation.suppress(null)) {
				selectTab(trace);
			}
		}
		else if (event instanceof TraceClosedPluginEvent evt) {
			Trace trace = evt.getTrace();
			try (Suppression supp = cbCoordinateActivation.suppress(null)) {
				remove(trace);
			}
		}
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		if (ev.getSource() instanceof Trace trace) {
			refreshTab(trace);
		}
	}

	private void traceTabSelected(Trace newTrace) {
		cbCoordinateActivation.invoke(() -> {
			traceManager.activateTrace(newTrace);
		});
	}
}
