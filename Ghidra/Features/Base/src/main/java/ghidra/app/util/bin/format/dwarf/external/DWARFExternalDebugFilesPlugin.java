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
package ghidra.app.util.bin.format.dwarf.external;

import docking.action.builder.ActionBuilder;
import docking.tool.ToolConstants;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.util.bin.format.dwarf.external.gui.ExternalDebugFilesConfigDialog;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "DWARF External Debug Files",
	description = "Configure how the DWARF analyzer finds external debug files."
)
//@formatter:on
public class DWARFExternalDebugFilesPlugin extends Plugin {
	public static final String HELP_TOPIC = "DWARFExternalDebugFilesPlugin";


	public DWARFExternalDebugFilesPlugin(PluginTool tool) {
		super(tool);

		createActions();
	}

	private void createActions() {
		new ActionBuilder("DWARF External Debug Config", this.getName())
				.menuPath(ToolConstants.MENU_EDIT, "DWARF External Debug Config")
				.menuGroup(ToolConstants.TOOL_OPTIONS_MENU_GROUP)
				.onAction(ac -> ExternalDebugFilesConfigDialog.show())
				.helpLocation(new HelpLocation(HELP_TOPIC, "Configuration"))
				.buildAndInstall(tool);
	}

}
