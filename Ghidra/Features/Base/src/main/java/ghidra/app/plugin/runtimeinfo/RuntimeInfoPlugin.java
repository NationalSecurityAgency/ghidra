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
package ghidra.app.plugin.runtimeinfo;

import docking.action.builder.ActionBuilder;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.main.ApplicationLevelOnlyPlugin;
import ghidra.framework.main.UtilityPluginPackage;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = UtilityPluginPackage.NAME,
	category = PluginCategoryNames.SUPPORT,
	shortDescription = "Runtime Information",
	description = "Plugin for displaying runtime information"
)
//@formatter:on
public class RuntimeInfoPlugin extends Plugin implements ApplicationLevelOnlyPlugin {

	private InstalledProcessorsProvider installedProcessorsProvider;
	private RuntimeInfoProvider runtimeInfoProvider;

	/**
	 * Creates a new {@link RuntimeInfoPlugin}
	 * 
	 * @param tool The tool
	 */
	public RuntimeInfoPlugin(PluginTool tool) {
		super(tool);

		String supportedActionName = "Installed Processors";
		new ActionBuilder(supportedActionName, getName())
				.onAction(context -> showInstalledProcessors())
				.enabled(true)
				.menuPath("Help", supportedActionName)
				.menuGroup("YYY") // trying to put this just above the last menu entry
				.helpLocation(getInstalledProcessorsHelpLocation())
				.buildAndInstall(tool);

		String runtimeInfoActionName = "Runtime Information";
		new ActionBuilder(runtimeInfoActionName, getName())
				.onAction(context -> showRuntimeInfo())
				.enabled(true)
				.menuPath("Help", runtimeInfoActionName)
				.menuGroup("YYY")
				.helpLocation(getRuntimeInfoHelpLocation())
				.buildAndInstall(tool);
	}

	@Override
	protected void dispose() {
		super.dispose();
		if (installedProcessorsProvider != null) {
			installedProcessorsProvider.dispose();
			installedProcessorsProvider = null;
		}
		if (runtimeInfoProvider != null) {
			runtimeInfoProvider.dispose();
			runtimeInfoProvider = null;
		}
	}

	/**
	 * Gets this plugin's installed processors {@link HelpLocation}
	 * 
	 * @return This plugin's installed processors {@link HelpLocation}
	 */
	protected HelpLocation getInstalledProcessorsHelpLocation() {
		return new HelpLocation("RuntimeInfoPlugin", "InstalledProcessors");
	}

	/**
	 * Gets this plugin's runtime info {@link HelpLocation}
	 * 
	 * @return This plugin's runtime info {@link HelpLocation}
	 */
	protected HelpLocation getRuntimeInfoHelpLocation() {
		return new HelpLocation("RuntimeInfoPlugin", "RuntimeInfo");
	}

	/**
	 * Displays the {@link InstalledProcessorsProvider}
	 */
	private void showInstalledProcessors() {
		if (installedProcessorsProvider == null) {
			installedProcessorsProvider = new InstalledProcessorsProvider(this);
		}

		tool.showDialog(installedProcessorsProvider);
	}

	/**
	 * Displays the {@link RuntimeInfoProvider}
	 */
	private void showRuntimeInfo() {
		if (runtimeInfoProvider == null) {
			runtimeInfoProvider = new RuntimeInfoProvider(this);
		}

		tool.showDialog(runtimeInfoProvider);
	}
}
