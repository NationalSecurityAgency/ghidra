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
import ghidra.app.nav.PreviousRangeAction;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.navigation.NavigationOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import docking.action.MenuData;
import docking.tool.ToolConstants;

public class PreviousColorRangeAction extends PreviousRangeAction {

	private final ColorizingPlugin plugin;

	public PreviousColorRangeAction(ColorizingPlugin plugin, PluginTool tool,
			NavigationOptions navOptions) {
		super(tool, "Previous Color Range", plugin.getName(), navOptions);
		this.plugin = plugin;

		setMenuBarData(new MenuData(new String[] { ToolConstants.MENU_NAVIGATION,
			"Previous Color Range" }, null, PluginCategoryNames.NAVIGATION, MenuData.NO_MNEMONIC,
			ColorizingPlugin.NAVIGATION_TOOLBAR_SUBGROUP));

		setDescription("Go to previous color range");
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
