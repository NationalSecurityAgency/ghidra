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

import java.util.*;

import docking.ActionContext;
import docking.Tool;
import docking.action.*;
import docking.actions.PopupActionProvider;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.services.*;
import ghidra.dbg.target.TargetMethod;
import ghidra.dbg.target.TargetMethod.ParameterDescription;
import ghidra.dbg.target.TargetMethod.TargetParameterMap;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.util.PathPredicates;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.util.MarkerLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.Trace;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.target.TraceObject;
import ghidra.util.Msg;

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

	private static String getDisplay(TargetMethod method) {
		String display = method.getDisplay();
		if (display != null) {
			return display;
		}
		return method.getName();
	}

	class InvokeMethodAction extends DockingAction {
		private final TargetMethod method;

		public InvokeMethodAction(TargetMethod method) {
			super(getDisplay(method), DebuggerMethodActionsPlugin.this.getName());
			this.method = method;
			setPopupMenuData(new MenuData(new String[] { getName() }, GROUP_METHODS));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			Map<String, Object> arguments = collectArguments(method.getParameters(), context);
			if (arguments == null) {
				// Context changed out from under me?
				return;
			}
			method.invoke(arguments).thenAccept(result -> {
				if (consoleService != null && method.getReturnType() != Void.class) {
					consoleService.log(null, getDisplay(method) + " returned " + result);
				}
			}).exceptionally(ex -> {
				tool.setStatusInfo(
					"Invocation of " + getDisplay(method) + " failed: " + ex.getMessage(), true);
				Msg.error(this, "Invocation of " + method.getPath() + " failed", ex);
				return null;
			});
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

	@Override
	public List<DockingActionIf> getPopupActions(Tool tool, ActionContext context) {
		if (!isControlTarget()) {
			return List.of();
		}
		TargetObject curObj = getCurrentTargetObject();
		if (curObj == null) {
			return List.of();
		}
		List<DockingActionIf> result = new ArrayList<>();
		PathPredicates matcher = curObj.getModel()
				.getRootSchema()
				.matcherForSuitable(TargetMethod.class, curObj.getPath());
		for (TargetObject obj : matcher.getCachedSuccessors(curObj.getModel().getModelRoot())
				.values()) {
			if (!(obj instanceof TargetMethod method)) {
				continue;
			}
			Map<String, Object> arguments = collectArguments(method.getParameters(), context);
			if (arguments == null) {
				continue;
			}
			result.add(new InvokeMethodAction(method));
		}
		return result;
	}

	private TargetObject getCurrentTargetObject() {
		if (traceManager == null) {
			return null;
		}
		DebuggerCoordinates current = traceManager.getCurrent();
		TraceRecorder recorder = current.getRecorder();
		if (recorder == null) {
			return null;
		}
		TraceObject object = current.getObject();
		if (object != null) {
			return recorder.getTargetObject(object);
		}
		return recorder.getFocus();
	}

	private Address dynamicAddress(ProgramLocation loc) {
		if (loc.getProgram() instanceof TraceProgramView) {
			return loc.getAddress();
		}
		if (traceManager == null) {
			return null;
		}
		ProgramLocation dloc =
			mappingService.getDynamicLocationFromStatic(traceManager.getCurrentView(), loc);
		if (dloc == null) {
			return null;
		}
		return dloc.getByteAddress();
	}

	private Map<String, Object> collectArguments(TargetParameterMap params, ActionContext context) {
		// The only required non-defaulted argument allowed must be an Address
		// There must be an Address parameter
		ParameterDescription<?> addrParam = null;
		for (ParameterDescription<?> p : params.values()) {
			if (p.type == Address.class) {
				if (addrParam != null) {
					return null;
				}
				addrParam = p;
			}
			else if (p.required && p.defaultValue == null) {
				return null;
			}
		}
		if (addrParam == null) {
			return null;
		}
		if (context instanceof ProgramLocationActionContext ctx) {
			Address address = dynamicAddress(ctx.getLocation());
			if (address == null) {
				return null;
			}
			return Map.of(addrParam.name, address);
		}
		if (context.getContextObject() instanceof MarkerLocation ml) {
			Address address = dynamicAddress(new ProgramLocation(ml.getProgram(), ml.getAddr()));
			if (address == null) {
				return null;
			}
			return Map.of(addrParam.name, address);
		}
		return null;
	}
}
