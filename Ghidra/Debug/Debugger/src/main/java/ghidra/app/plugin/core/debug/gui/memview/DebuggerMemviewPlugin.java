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
package ghidra.app.plugin.core.debug.gui.memview;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.bento.BentoServicePlugin;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.TraceActivatedPluginEvent;
import ghidra.app.services.DebuggerListingService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;

@PluginInfo(
	shortDescription = "Displays memory vs time",
	description = "Provides visualiztion/navigation across time/address axes",
	category = PluginCategoryNames.DEBUGGER,
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.RELEASED,
	eventsConsumed = {
		TraceActivatedPluginEvent.class
	},
	servicesRequired = {
		DebuggerListingService.class,
		DebuggerTraceManagerService.class
	},
	servicesProvided = {
		MemviewService.class
	})
public class DebuggerMemviewPlugin extends BentoServicePlugin implements MemviewService {

	private DebuggerMemviewTraceListener listener;

	public DebuggerMemviewPlugin(PluginTool tool) {
		super(tool, "Memview");
	}

	@Override
	protected void init() {
		codeViewerService = tool.getService(DebuggerListingService.class);
		defaultProvider = new MemviewProvider(getTool(), this);
		listener = new DebuggerMemviewTraceListener((MemviewProvider) defaultProvider);
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);
		if (event instanceof TraceActivatedPluginEvent ev) {
			listener.coordinatesActivated(ev.getActiveCoordinates());
		}
	}

	@Override
	public void toggleTracking() {
		listener.toggleTrackTrace();
	}

}
