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

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.AbstractDebuggerPlugin;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.*;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;

@PluginInfo( //
		shortDescription = "Debugger registers manager", //
		description = "GUI to view and modify register values", //
		category = PluginCategoryNames.DEBUGGER, //
		packageName = DebuggerPluginPackage.NAME, //
		status = PluginStatus.RELEASED, //
		eventsConsumed = { TraceOpenedPluginEvent.class, //
			TraceClosedPluginEvent.class, //
			TraceActivatedPluginEvent.class, //
		}, //
		servicesRequired = { //
			DebuggerTraceManagerService.class, //
		} // 
)
public class DebuggerThreadsPlugin extends AbstractDebuggerPlugin {
	protected DebuggerThreadsProvider provider;

	public DebuggerThreadsPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		provider = new DebuggerThreadsProvider(this);
		super.init();
	}

	@Override
	protected void dispose() {
		tool.removeComponentProvider(provider);
		super.dispose();
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);
		if (event instanceof TraceOpenedPluginEvent) {
			TraceOpenedPluginEvent ev = (TraceOpenedPluginEvent) event;
			provider.traceOpened(ev.getTrace());
		}
		if (event instanceof TraceActivatedPluginEvent) {
			TraceActivatedPluginEvent ev = (TraceActivatedPluginEvent) event;
			provider.coordinatesActivated(ev.getActiveCoordinates());
		}
		if (event instanceof TraceClosedPluginEvent) {
			TraceClosedPluginEvent ev = (TraceClosedPluginEvent) event;
			provider.traceClosed(ev.getTrace());
		}
	}
}
