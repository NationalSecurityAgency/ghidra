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
package ghidra.app.plugin.core.codebrowser;

import docking.action.builder.ActionBuilder;
import docking.tool.ToolConstants;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;

/**
 * Plugin for adding some basic selection actions for Code Browser Listings.
 */

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Basic Selection actions",
	description = "This plugin provides actions for Code Browser Listing components"
)
//@formatter:on
public class CodeBrowserSelectionPlugin extends Plugin {

	public CodeBrowserSelectionPlugin(PluginTool tool) {
		super(tool);
		createActions();
	}

	private void createActions() {
		new ActionBuilder("Select All", getName())
				.menuPath(ToolConstants.MENU_SELECTION, "&All in View")
				.menuGroup("Select Group", "a")
				.keyBinding("ctrl A")
				.supportsDefaultToolContext(true)
				.helpLocation(new HelpLocation(HelpTopics.SELECTION, "Select All"))
				.withContext(CodeViewerActionContext.class)
				.inWindow(ActionBuilder.When.CONTEXT_MATCHES)
				.onAction(c -> ((CodeViewerProvider) c.getComponentProvider()).selectAll())
				.buildAndInstall(tool);

		new ActionBuilder("Clear Selection", getName())
				.menuPath(ToolConstants.MENU_SELECTION, "&Clear Selection")
				.menuGroup("Select Group", "b")
				.supportsDefaultToolContext(true)
				.helpLocation(new HelpLocation(HelpTopics.SELECTION, "Clear Selection"))
				.withContext(CodeViewerActionContext.class)
				.inWindow(ActionBuilder.When.CONTEXT_MATCHES)
				.onAction(c -> ((CodeViewerProvider) c.getComponentProvider())
						.setSelection(new ProgramSelection()))
				.buildAndInstall(tool);

		new ActionBuilder("Select Complement", getName())
				.menuPath(ToolConstants.MENU_SELECTION, "&Complement")
				.menuGroup("Select Group", "c")
				.supportsDefaultToolContext(true)
				.helpLocation(new HelpLocation(HelpTopics.SELECTION, "Select Complement"))
				.withContext(CodeViewerActionContext.class)
				.inWindow(ActionBuilder.When.CONTEXT_MATCHES)
				.onAction(c -> ((CodeViewerProvider) c.getComponentProvider()).selectComplement())
				.buildAndInstall(tool);

	}

}
