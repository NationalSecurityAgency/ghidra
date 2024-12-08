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
package ghidra.app.plugin.core.debug.gui.tracermi.launcher;

import java.util.stream.Stream;

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.debug.spi.tracermi.TraceRmiLaunchOpinion;
import ghidra.framework.Application;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginUtils;
import ghidra.util.HelpLocation;

public abstract class AbstractTraceRmiLaunchOpinion implements TraceRmiLaunchOpinion {

	@Override
	public void registerOptions(Options options) {
		String pluginName = PluginUtils.getPluginNameFromClass(TraceRmiLauncherServicePlugin.class);
		options.registerOption(TraceRmiLauncherServicePlugin.OPTION_NAME_SCRIPT_PATHS,
			OptionType.STRING_TYPE, "", new HelpLocation(pluginName, "options"),
			"Paths to search for user-created debugger launchers",
			() -> new ScriptPathsPropertyEditor());
	}

	@Override
	public boolean requiresRefresh(String optionName) {
		return TraceRmiLauncherServicePlugin.OPTION_NAME_SCRIPT_PATHS.equals(optionName);
	}

	protected Stream<ResourceFile> getModuleScriptPaths() {
		return Application.findModuleSubDirectories("data/debugger-launchers").stream();
	}

	protected Stream<ResourceFile> getUserScriptPaths(PluginTool tool) {
		Options options = tool.getOptions(DebuggerPluginPackage.NAME);
		String scriptPaths =
			options.getString(TraceRmiLauncherServicePlugin.OPTION_NAME_SCRIPT_PATHS, "");
		return scriptPaths.lines().filter(d -> !d.isBlank()).map(ResourceFile::new);
	}

	protected Stream<ResourceFile> getScriptPaths(PluginTool tool) {
		return Stream.concat(getModuleScriptPaths(), getUserScriptPaths(tool));
	}

}
