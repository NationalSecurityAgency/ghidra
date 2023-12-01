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
package ghidra.app.plugin.core.debug.gui.tracermi.connection;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.TraceActivatedPluginEvent;
import ghidra.app.plugin.core.debug.event.TraceInactiveCoordinatesPluginEvent;
import ghidra.app.services.TraceRmiService;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;

@PluginInfo(
	shortDescription = "GUI elements to manage Trace RMI connections",
	description = """
			Provides a panel for managing Trace RMI connections. The panel also allows users to
			control the Trace RMI server and/or create manual connections.
			""",
	category = PluginCategoryNames.DEBUGGER,
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.STABLE,
	eventsConsumed = {
		TraceActivatedPluginEvent.class,
		TraceInactiveCoordinatesPluginEvent.class,
	},
	servicesRequired = {
		TraceRmiService.class,
	})
public class TraceRmiConnectionManagerPlugin extends Plugin {
	private final TraceRmiConnectionManagerProvider provider;

	public TraceRmiConnectionManagerPlugin(PluginTool tool) {
		super(tool);
		this.provider = new TraceRmiConnectionManagerProvider(this);
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);
		if (event instanceof TraceActivatedPluginEvent evt) {
			provider.coordinates(evt.getActiveCoordinates());
		}
		if (event instanceof TraceInactiveCoordinatesPluginEvent evt) {
			provider.coordinates(evt.getCoordinates());
		}
	}
}
