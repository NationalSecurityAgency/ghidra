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
package ghidra.app.plugin.core.debug.gui.stack.vars;

import ghidra.app.decompiler.component.hover.DecompilerHoverService;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.codebrowser.hover.ListingHoverService;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.TraceClosedPluginEvent;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;

@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = DebuggerPluginPackage.NAME,
	category = PluginCategoryNames.DEBUGGER,
	shortDescription = "Variable Values Hover",
	description = "Displays live variable values in a tooltip as you hover over a variable in " +
		"the listings or decompiler.",
	eventsConsumed = {
		TraceClosedPluginEvent.class
	},
	servicesProvided = {
		ListingHoverService.class,
		DecompilerHoverService.class
	})
public class VariableValueHoverPlugin extends Plugin {
	private VariableValueHoverService hoverService;

	public VariableValueHoverPlugin(PluginTool tool) {
		super(tool);
		hoverService = new VariableValueHoverService(tool);
		registerServiceProvided(ListingHoverService.class, hoverService);
		registerServiceProvided(DecompilerHoverService.class, hoverService);
	}

	public VariableValueHoverService getHoverService() {
		return hoverService;
	}

	@Override
	protected void dispose() {
		hoverService.dispose();
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);
		if (event instanceof TraceClosedPluginEvent evt) {
			hoverService.traceClosed(evt.getTrace());
		}
	}
}
