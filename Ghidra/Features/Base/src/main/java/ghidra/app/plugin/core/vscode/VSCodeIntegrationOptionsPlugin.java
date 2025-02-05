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
package ghidra.app.plugin.core.vscode;

import java.io.File;

import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.OperatingSystem;
import ghidra.framework.main.ApplicationLevelOnlyPlugin;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;

/**
 * {@link Plugin} responsible for registering Visual Studio Code-related options
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Visual Studio Code Integration Options",
	description = "Options for Visual Studio Code Integration"
)
//@formatter:on
public class VSCodeIntegrationOptionsPlugin extends Plugin implements ApplicationLevelOnlyPlugin {

	public static final String PLUGIN_OPTIONS_NAME = "Visual Studio Code Integration";

	public static final String VSCODE_EXE_PATH_OPTION = "Visual Studio Code Executable Path";
	private static final String VSCODE_EXE_PATH_DESC = "Path to Visual Studio Code executable";
	private static final File VSCODE_EXE_PATH_DEFAULT = getDefaultVSCodeExecutable();

	public VSCodeIntegrationOptionsPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	public void init() {
		super.init();
		ToolOptions options = tool.getOptions(PLUGIN_OPTIONS_NAME);
		options.registerOption(VSCODE_EXE_PATH_OPTION, OptionType.FILE_TYPE,
			VSCODE_EXE_PATH_DEFAULT, null, VSCODE_EXE_PATH_DESC);
		options.setOptionsHelpLocation(
			new HelpLocation("VSCodeIntegration", "VSCodeIntegrationOptions"));
	}

	/**
	 * {@return the default Visual Studio Code executable location for the current platform}
	 */
	private static File getDefaultVSCodeExecutable() {
		return switch (OperatingSystem.CURRENT_OPERATING_SYSTEM) {
			case WINDOWS -> new File(System.getenv("LOCALAPPDATA"),
				"Programs/Microsoft VS Code/bin/code.cmd");
			case MAC_OS_X -> new File(
				"/Applications/Visual Studio Code.app/Contents/MacOS/Electron");
			case LINUX -> new File("/usr/bin/code");
			default -> null;
		};
	}
}
