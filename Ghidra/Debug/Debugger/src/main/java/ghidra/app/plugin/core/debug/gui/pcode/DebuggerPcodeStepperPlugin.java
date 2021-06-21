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
package ghidra.app.plugin.core.debug.gui.pcode;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.AbstractDebuggerPlugin;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.TraceActivatedPluginEvent;
import ghidra.app.services.DebuggerEmulationService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;

@PluginInfo(
	shortDescription = "Debugger p-code stepper",
	description = "GUI to single-step emulation of p-code",
	category = PluginCategoryNames.DEBUGGER,
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.UNSTABLE,
	eventsConsumed = {
		TraceActivatedPluginEvent.class,
	},
	servicesRequired = {
		DebuggerTraceManagerService.class,
		DebuggerEmulationService.class,
	})
public class DebuggerPcodeStepperPlugin extends AbstractDebuggerPlugin {
	protected DebuggerPcodeStepperProvider provider;

	public DebuggerPcodeStepperPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		provider = new DebuggerPcodeStepperProvider(this);
		super.init();
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);
		if (event instanceof TraceActivatedPluginEvent) {
			TraceActivatedPluginEvent ev = (TraceActivatedPluginEvent) event;
			provider.coordinatesActivated(ev.getActiveCoordinates());
		}
	}
}
