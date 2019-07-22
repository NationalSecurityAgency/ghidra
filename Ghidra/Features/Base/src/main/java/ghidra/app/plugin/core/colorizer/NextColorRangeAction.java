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
package ghidra.app.plugin.core.colorizer;

import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.nav.NextRangeAction;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.navigation.NavigationOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import docking.action.MenuData;
import docking.tool.ToolConstants;

public class NextColorRangeAction extends NextRangeAction {

	private final ColorizingPlugin plugin;

	public NextColorRangeAction(ColorizingPlugin plugin, PluginTool tool,
			NavigationOptions navOptions) {
		super(tool, "Next Color Range", plugin.getName(), navOptions);
		this.plugin = plugin;

		setMenuBarData(new MenuData(new String[] { ToolConstants.MENU_NAVIGATION,
			"Next Color Range" }, null, PluginCategoryNames.NAVIGATION, MenuData.NO_MNEMONIC,
			ColorizingPlugin.NAVIGATION_TOOLBAR_SUBGROUP));

		setDescription("Go to next color range");
		setHelpLocation(new HelpLocation("CodeBrowserPlugin", "Color_Navigation"));
	}

	@Override
	protected ProgramSelection getSelection(ProgramLocationActionContext context) {
		return new ProgramSelection(plugin.getColorizingService().getAllBackgroundColorAddresses());
	}

	void remove() {
		setToolBarData(null);
	}

}
