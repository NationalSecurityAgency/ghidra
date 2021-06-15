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
package ghidra.app.plugin.core.debug.gui.target;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.AbstractDebuggerPlugin;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.ModelActivatedPluginEvent;
import ghidra.app.services.DebuggerModelService;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginStatus;

@PluginInfo( //
	shortDescription = "Debugger targets manager", //
	description = "GUI to manage connections to external debuggers and trace recording", //
	category = PluginCategoryNames.DEBUGGER, //
	packageName = DebuggerPluginPackage.NAME, //
	status = PluginStatus.RELEASED, //
	eventsConsumed = {
		ModelActivatedPluginEvent.class, //
	}, //
	servicesRequired = { //
		DebuggerModelService.class, //
	} //
)
public class DebuggerTargetsPlugin extends AbstractDebuggerPlugin {
	@AutoServiceConsumed
	protected DebuggerModelService modelService;

	protected DebuggerTargetsProvider provider;

	public DebuggerTargetsPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		provider = new DebuggerTargetsProvider(this);
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
		if (event instanceof ModelActivatedPluginEvent) {
			ModelActivatedPluginEvent evt = (ModelActivatedPluginEvent) event;
			provider.modelActivated(evt.getActiveModel());
		}
	}
}
