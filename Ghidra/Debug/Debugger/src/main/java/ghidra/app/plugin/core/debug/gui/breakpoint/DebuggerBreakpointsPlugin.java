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
package ghidra.app.plugin.core.debug.gui.breakpoint;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.AbstractDebuggerPlugin;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.*;
import ghidra.app.services.DebuggerLogicalBreakpointService;
import ghidra.app.services.DebuggerModelService;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;

@PluginInfo( // 
	shortDescription = "Debugger breakpoints manager", //
	description = "GUI to manage breakpoints", //
	category = PluginCategoryNames.DEBUGGER, //
	packageName = DebuggerPluginPackage.NAME, //
	status = PluginStatus.RELEASED, //
	servicesRequired = { //
		DebuggerLogicalBreakpointService.class, //
		DebuggerModelService.class, //
	},
	eventsConsumed = {
		TraceOpenedPluginEvent.class, //
		TraceClosedPluginEvent.class, //
		TraceActivatedPluginEvent.class, //
	} //
)
public class DebuggerBreakpointsPlugin extends AbstractDebuggerPlugin {
	protected DebuggerBreakpointsProvider provider;

	public DebuggerBreakpointsPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		super.init();
		provider = new DebuggerBreakpointsProvider(this);
	}

	@Override
	protected void dispose() {
		provider.dispose();
		tool.removeComponentProvider(provider);
		super.dispose();
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);
		if (event instanceof TraceOpenedPluginEvent) {
			TraceOpenedPluginEvent evt = (TraceOpenedPluginEvent) event;
			provider.traceOpened(evt.getTrace());
		}
		else if (event instanceof TraceClosedPluginEvent) {
			TraceClosedPluginEvent evt = (TraceClosedPluginEvent) event;
			provider.traceClosed(evt.getTrace());
		}
		else if (event instanceof TraceActivatedPluginEvent) {
			TraceActivatedPluginEvent evt = (TraceActivatedPluginEvent) event;
			provider.setTrace(evt.getActiveCoordinates().getTrace());
		}
	}
}
