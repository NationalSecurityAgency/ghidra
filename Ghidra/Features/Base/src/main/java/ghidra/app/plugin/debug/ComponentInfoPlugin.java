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

import docking.action.DockingAction;
import docking.action.builder.ActionBuilder;
import ghidra.app.DeveloperPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.docking.util.ComponentInfoDialog;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import help.Help;
import help.HelpService;

/**
  * Plugin to display information about components in the application
  */

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = DeveloperPluginPackage.NAME,
	category = PluginCategoryNames.DIAGNOSTIC,
	shortDescription = "Show component information",
	description = "A debug aid that displays a table of information about the components in the " +
		"application."
)
//@formatter:on
public class ComponentInfoPlugin extends Plugin {

	public ComponentInfoPlugin(PluginTool tool) {
		super(tool);

		//@formatter:off
		DockingAction action =
			new ActionBuilder("Component Display", getName())
			.menuPath("Help", "Component Diagnostics")
			.onAction(e -> showComponentDialog())
			.buildAndInstall(tool);
		//@formatter:on

		// Note: this plugin is in the 'Developer' category and as such does not need help
		HelpService helpService = Help.getHelpService();
		helpService.excludeFromHelp(action);
	}

	private void showComponentDialog() {
		tool.showDialog(new ComponentInfoDialog());
	}
}
