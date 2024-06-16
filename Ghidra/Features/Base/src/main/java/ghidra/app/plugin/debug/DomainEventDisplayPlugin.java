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
package ghidra.app.plugin.debug;

import java.util.Date;

import ghidra.app.DeveloperPluginPackage;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import help.Help;
import help.HelpService;

/**
  * Debug Plugin to show domain object change events.
  */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = DeveloperPluginPackage.NAME,
	category = PluginCategoryNames.DIAGNOSTIC,
	shortDescription = "Displays domain object events",
	description = "This plugin provides a component to display domain object event " +
			"as they are generated. The maximum number of messages shown is " +
			DomainEventComponentProvider.LIMIT + ".  Useful for debugging.",
	eventsConsumed = { ProgramActivatedPluginEvent.class }
)
//@formatter:on
public class DomainEventDisplayPlugin extends Plugin implements DomainObjectListener {

	private Program currentProgram;
	private DomainEventComponentProvider provider;

	public DomainEventDisplayPlugin(PluginTool tool) {

		super(tool);

		provider = new DomainEventComponentProvider(tool, getName());

		// Note: this plugin in the 'Developer' category and as such does not need help
		HelpService helpService = Help.getHelpService();
		helpService.excludeFromHelp(provider);
	}

	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof ProgramActivatedPluginEvent) {
			ProgramActivatedPluginEvent ev = (ProgramActivatedPluginEvent) event;
			Program newProg = ev.getActiveProgram();
			if (currentProgram != null) {
				currentProgram.removeListener(this);
			}
			if (newProg != null) {
				newProg.addListener(this);
			}
		}
	}

	@Override
	public void dispose() {
		if (currentProgram != null) {
			currentProgram.removeListener(this);
		}
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		if (tool != null && provider.isVisible()) {
			outputEvent(ev);
		}
	}

	/**
	 * Display the change event.
	 */
	private void outputEvent(DomainObjectChangedEvent event) {
		for (int i = 0; i < event.numRecords(); i++) {
			DomainObjectChangeRecord changeRecord = event.getChangeRecord(i);
			String dateStr = new Date() + ": ";
			provider.displayEvent(dateStr + changeRecord + "\n");
		}
	}
}
