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
package ghidra.app.plugin.gui;

import docking.action.builder.ActionBuilder;
import docking.theme.gui.ThemeDialog;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.main.ApplicationLevelOnlyPlugin;
import ghidra.framework.main.UtilityPluginPackage;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = UtilityPluginPackage.NAME,
	category = PluginCategoryNames.SUPPORT,
	shortDescription = "Manages themes for the Ghdira GUI",
	description = "Adds actions and options to manage Themes within Ghidra. " +
			"This plugin is available only in the Ghidra Project Window."
)
//@formatter:on
public class ThemeManagerPlugin extends Plugin implements ApplicationLevelOnlyPlugin {

	public ThemeManagerPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {

		new ActionBuilder("", getName()).menuPath("Edit", "Theme")
				.onAction(e -> showThemeProperties())
				.buildAndInstall(tool);

	}

	private void showThemeProperties() {
		ThemeDialog.editTheme();
	}

}
