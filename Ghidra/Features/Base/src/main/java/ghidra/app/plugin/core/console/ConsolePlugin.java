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
package ghidra.app.plugin.core.console;

import ghidra.app.CorePluginPackage;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "I/O Console",
	description = "Displays an I/O console.",
	servicesProvided = { ConsoleService.class },
	eventsConsumed = { ProgramLocationPluginEvent.class }
)
//@formatter:on
public class ConsolePlugin extends ProgramPlugin {

	private ConsoleComponentProvider provider;

	public ConsolePlugin(PluginTool tool) {
		super(tool, false, false);
		provider = new ConsoleComponentProvider(tool, getName());
		registerServiceProvided(ConsoleService.class, provider);
	}

	@Override
	protected void init() {
		super.init();
		provider.init();
	}

	@Override
	protected void dispose() {
		super.dispose();
		provider.dispose();
	}

	@Override
	protected void programActivated(Program program) {
		provider.setCurrentProgram(program);
	}

	@Override
	protected void programDeactivated(Program program) {
		provider.setCurrentProgram(null);
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);
		if (event instanceof ProgramLocationPluginEvent) {
			ProgramLocationPluginEvent plpe = (ProgramLocationPluginEvent) event;
			ProgramLocation pl = plpe.getLocation();
			provider.setCurrentAddress(pl.getAddress());
		}
	}

}
