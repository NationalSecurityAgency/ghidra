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
package ghidra.app.plugin.core.eclipse;

import java.io.File;

import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.main.FrontEndOnly;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;

/**
 * Plugin responsible for registering Eclipse-related options.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Eclipse Integration Options",
	description = "Options Eclipse Integration"
)
//@formatter:on
public class EclipseIntegrationOptionsPlugin extends Plugin implements FrontEndOnly {

	public static final String PLUGIN_OPTIONS_NAME = "Eclipse Integration";

	public static final String ECLIPSE_INSTALL_DIR_OPTION = "Eclipse Installation Directory";
	private static final String ECLIPSE_INSTALL_DIR_DESC = "Path to Eclipse installation directory";
	private static final File ECLIPSE_INSTALL_DIR_DEFAULT = null;

	public static final String ECLIPSE_WORKSPACE_DIR_OPTION =
		"Eclipse Workspace Directory (optional)";
	private static final String ECLIPSE_WORKSPACE_DIR_DESC = "Optional path to Eclipse workspace " +
		"directory.  If defined and the directory does not exist, Eclipse will create it.  If " +
		"undefined, Eclipse will be responsible for selecting the workspace directory.";
	private static final File ECLIPSE_WORKSPACE_DIR_DEFAULT = null;

	public static final String SCRIPT_EDITOR_PORT_OPTION = "Script Editor Port";
	private static final String SCRIPT_EDITOR_PORT_DESC =
		"The port number used to communicate with Eclipse for script editing.  It must match " +
			"the port number set in the Eclipse GhidraDev plugin preference page in " +
			"order for them to communicate.";
	private static final int SCRIPT_EDITOR_PORT_DEFAULT = 12321;

	public static final String SYMBOL_LOOKUP_PORT_OPTION = "Symbol Lookup Port";
	private static final String SYMBOL_LOOKUP_PORT_DESC =
		"The port number used to communicate with Eclipse for script editing.  It must match " +
			"the port number set in the Eclipse GhidraDev plugin preference page in " +
			"order for them to communicate.";
	private static final int SYMBOL_LOOKUP_PORT_DEFAULT = 12322;

	public static final String AUTO_GHIDRADEV_INSTALL_OPTION = "Automatically install GhidraDev";
	private static final String AUTO_GHIDRADEV_INSTALLATION_DESC =
		"Automatically install the GhidraDev plugin into the \"dropins\" directory of the " +
			"specified Eclipse if it has not yet been installed.";
	private static final boolean AUTO_GHIDRADEV_INSTALL_DEFAULT = true;

	public EclipseIntegrationOptionsPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	public void init() {
		super.init();
		ToolOptions options = tool.getOptions(PLUGIN_OPTIONS_NAME);
		options.registerOption(ECLIPSE_INSTALL_DIR_OPTION, OptionType.FILE_TYPE,
			ECLIPSE_INSTALL_DIR_DEFAULT, null, ECLIPSE_INSTALL_DIR_DESC);
		options.registerOption(ECLIPSE_WORKSPACE_DIR_OPTION, OptionType.FILE_TYPE,
			ECLIPSE_WORKSPACE_DIR_DEFAULT, null, ECLIPSE_WORKSPACE_DIR_DESC);
		options.registerOption(SCRIPT_EDITOR_PORT_OPTION, SCRIPT_EDITOR_PORT_DEFAULT, null,
			SCRIPT_EDITOR_PORT_DESC);
		options.registerOption(SYMBOL_LOOKUP_PORT_OPTION, SYMBOL_LOOKUP_PORT_DEFAULT, null,
			SYMBOL_LOOKUP_PORT_DESC);
		options.registerOption(AUTO_GHIDRADEV_INSTALL_OPTION, AUTO_GHIDRADEV_INSTALL_DEFAULT, null,
			AUTO_GHIDRADEV_INSTALLATION_DESC);
		options.setOptionsHelpLocation(
			new HelpLocation("EclipseIntegration", "EclipseIntegration"));
	}
}
