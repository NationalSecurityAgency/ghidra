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
package ghidra.app.plugin.core.debug.gui.control;

import java.util.ArrayList;
import java.util.List;

import javax.swing.Icon;

import docking.ActionContext;
import docking.Tool;
import docking.action.*;
import docking.actions.PopupActionProvider;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.model.DebuggerObjectActionContext;
import ghidra.app.services.*;
import ghidra.debug.api.control.ControlMode;
import ghidra.debug.api.target.ActionName;
import ghidra.debug.api.target.Target;
import ghidra.debug.api.target.Target.ActionEntry;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.Trace;
import ghidra.trace.model.program.TraceProgramView;

@PluginInfo(
	shortDescription = "Debugger model method actions",
	description = "Adds context actions to the GUI, generically, based on the model's methods",
	category = PluginCategoryNames.DEBUGGER,
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.RELEASED,
	eventsConsumed = {
	},
	servicesRequired = {
		DebuggerStaticMappingService.class,
	})
public class DebuggerMethodActionsPlugin extends Plugin implements PopupActionProvider {
	public static final String GROUP_METHODS = "Debugger Methods";

	class InvokeActionEntryAction extends DockingAction {
		private final ActionEntry entry;

		public InvokeActionEntryAction(ActionEntry entry) {
			super(entry.display(), DebuggerMethodActionsPlugin.this.getName());
			this.entry = entry;
			Icon icon = null;
			if (ActionName.REFRESH.equals(entry.name())) {
				// TODO: Allow method annotation to specify icon?
				icon = DebuggerResources.ICON_REFRESH;
			}
			setPopupMenuData(new MenuData(new String[] { getName() }, icon, GROUP_METHODS));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			TargetActionTask.runAction(tool, entry.display(), entry);
		}
	}

	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;
	@AutoServiceConsumed
	private DebuggerStaticMappingService mappingService;
	@AutoServiceConsumed
	private DebuggerConsoleService consoleService;
	@AutoServiceConsumed
	private DebuggerControlService controlService;
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoServiceWiring;

	public DebuggerMethodActionsPlugin(PluginTool tool) {
		super(tool);
		autoServiceWiring = AutoService.wireServicesProvidedAndConsumed(this);
		tool.addPopupActionProvider(this);
	}

	protected boolean isControlTarget() {
		if (controlService == null || traceManager == null) {
			return true;
		}
		Trace trace = traceManager.getCurrentTrace();
		if (trace == null) {
			return true;
		}
		ControlMode mode = controlService.getCurrentMode(trace);
		return mode.isTarget();
	}

	/**
	 * While it may be possible to retrieve sufficient context from the "current state," it's not
	 * always appropriate to display all of these actions. They should really only appear when an
	 * address is clearly intended, or when a trace object is clearly intended. We'll have to see
	 * how/if this works in the type-specific trace object tables, e.g., the Modules panel.
	 */
	protected boolean isAppropriate(ActionContext context) {
		if (context instanceof ProgramLocationActionContext) {
			return true;
		}
		if (context instanceof DebuggerObjectActionContext) {
			return true;
		}
		return false;
	}

	@Override
	public List<DockingActionIf> getPopupActions(Tool tool, ActionContext context) {
		if (!isControlTarget() || !isAppropriate(context)) {
			return List.of();
		}

		Target target = getTarget(context);
		if (target == null) {
			return List.of();
		}

		List<DockingActionIf> result = new ArrayList<>();
		for (ActionEntry entry : target.collectActions(null, context).values()) {
			if (entry.requiresPrompt() || entry.builtIn()) {
				continue;
			}
			result.add(new InvokeActionEntryAction(entry));
		}
		return result;
	}

	private Target getTarget(ActionContext context) {
		if (traceManager == null) {
			return null;
		}
		if (context instanceof ProgramActionContext ctx) {
			Program program = ctx.getProgram();
			if (program instanceof TraceProgramView view) {
				DebuggerCoordinates coords = traceManager.getCurrentFor(view.getTrace());
				return coords == null ? null : coords.getTarget();
			}
		}
		DebuggerCoordinates current = traceManager.getCurrent();
		return current == null ? null : current.getTarget();
	}
}
