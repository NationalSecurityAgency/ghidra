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

import docking.help.Help;
import docking.help.HelpService;
import ghidra.app.DeveloperPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;

/**
  * Plugin to demonstrate handling of Program within a plugin and how to
  * set up the list of consumed plugin events.
  */

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = DeveloperPluginPackage.NAME,
	category = PluginCategoryNames.TESTING,
	shortDescription = "Show plugin events",
	description = "This plugin is a debug aid that prints " +
			"plugin event information. It can also be used as a sample " +
			"of how to handle plugin events and how to write a component provider."
)
//@formatter:on
public class EventDisplayPlugin extends Plugin {

	private EventDisplayComponentProvider provider;

	/**
	  * Constructor
	  */
	public EventDisplayPlugin(PluginTool tool) {

		super(tool);
		provider = new EventDisplayComponentProvider(tool, getName());

		// Note: this plugin is in the 'Developer' category and as such does not need help
		HelpService helpService = Help.getHelpService();
		helpService.excludeFromHelp(provider);

		tool.addListenerForAllPluginEvents(this);
	}

	@Override
	protected void dispose() {
		tool.removeListenerForAllPluginEvents(this);
	}

	/**
	 * Put event processing code here.
	 */
	@Override
	public void processEvent(PluginEvent event) {
		provider.processEvent(event);
	}
}
