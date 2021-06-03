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
package ghidra.app.plugin.core.debug.gui.time;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.AbstractDebuggerPlugin;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.TraceActivatedPluginEvent;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;

@PluginInfo( //
	shortDescription = "Lists recorded snapshots in a trace", //
	description = "Provides the component which lists snapshots and allows navigation", //
	category = PluginCategoryNames.DEBUGGER, //
	packageName = DebuggerPluginPackage.NAME, //
	status = PluginStatus.RELEASED, //
	eventsConsumed = { //
		TraceActivatedPluginEvent.class //
	}, //
	servicesRequired = { //
		DebuggerTraceManagerService.class //
	} //
)
public class DebuggerTimePlugin extends AbstractDebuggerPlugin {
	protected DebuggerTimeProvider provider;

	public DebuggerTimePlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		provider = new DebuggerTimeProvider(this);
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
		if (event instanceof TraceActivatedPluginEvent) {
			TraceActivatedPluginEvent ev = (TraceActivatedPluginEvent) event;
			provider.coordinatesActivated(ev.getActiveCoordinates());
		}
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		provider.writeConfigState(saveState);
	}

	@Override
	public void readConfigState(SaveState saveState) {
		provider.readConfigState(saveState);
	}
}
