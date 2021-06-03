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
package ghidra.app.plugin.core.script;

import java.io.IOException;
import java.io.PrintStream;
import java.net.Socket;

import generic.jar.ResourceFile;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.eclipse.EclipseConnection;
import ghidra.app.plugin.core.eclipse.EclipseIntegrationOptionsPlugin;
import ghidra.app.plugin.core.osgi.BundleHost;
import ghidra.app.script.*;
import ghidra.app.services.*;
import ghidra.framework.options.SaveState;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskListener;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Script Manager",
	description = "Manages scripts and automatically compiles and creates actions in the tool for each script.",
	servicesRequired = { ConsoleService.class, EclipseIntegrationService.class },
	servicesProvided = { GhidraScriptService.class }
)
//@formatter:on
public class GhidraScriptMgrPlugin extends ProgramPlugin implements GhidraScriptService {
	private final GhidraScriptComponentProvider provider;

	private final BundleHost bundleHost;

	/**
	 * {@link GhidraScriptMgrPlugin} is the entry point for all {@link GhidraScript} capabilities.
	 * 
	 * @param tool the tool this plugin is added to
	 */
	public GhidraScriptMgrPlugin(PluginTool tool) {
		super(tool, true, true, true);

		// Each tool starts a new script manager plugin, but we only ever want one bundle host.
		// GhidraScriptUtil (creates and) manages one instance.
		bundleHost = GhidraScriptUtil.acquireBundleHostReference();
		
		provider = new GhidraScriptComponentProvider(this, bundleHost);
	}

	@Override
	protected void dispose() {
		super.dispose();
		provider.dispose();
		GhidraScriptUtil.releaseBundleHostReference();
	}

	@Override
	public void readConfigState(SaveState saveState) {
		super.readConfigState(saveState);
		provider.readConfigState(saveState);
		GhidraScriptEditorComponentProvider.restoreState(saveState);
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		super.writeConfigState(saveState);
		provider.writeConfigState(saveState);
		GhidraScriptEditorComponentProvider.saveState(saveState);
	}

	GhidraState getCurrentState() {
		return new GhidraState(tool, tool.getProject(), currentProgram, currentLocation,
			currentSelection, currentHighlight);
	}

	GhidraScriptComponentProvider getProvider() {
		return provider;
	}

	ConsoleService getConsoleService() {
		return tool.getService(ConsoleService.class);
	}

	@Override
	public void runScript(String scriptName, TaskListener listener) {
		provider.runScript(scriptName, listener);
	}

	/**
	 * Attempts to run a script in a {@link RunScriptTask}. 
	 * 
	 * @param scriptFile the script's source file
	 */
	public void runScript(ResourceFile scriptFile) {
		provider.runScript(scriptFile);
	}

	@Override
	public void refreshScriptList() {
		provider.refresh();
	}

	@Override
	public boolean tryToEditFileInEclipse(ResourceFile file) {
		EclipseIntegrationService service = tool.getService(EclipseIntegrationService.class);
		ToolOptions options = service.getEclipseIntegrationOptions();
		int port = options.getInt(EclipseIntegrationOptionsPlugin.SCRIPT_EDITOR_PORT_OPTION, -1);
		if (port < 0 || port > Short.MAX_VALUE) {
			service.handleEclipseError(
				"Option \"" + EclipseIntegrationOptionsPlugin.SCRIPT_EDITOR_PORT_OPTION +
					"\" is not valid.  Cannot connect to Eclipse.",
				true, null);
			return false;
		}

		EclipseConnection connection = service.connectToEclipse(port);
		Socket socket = connection.getSocket();
		if (socket == null) {
			return false;
		}
		try (PrintStream output = new PrintStream(socket.getOutputStream())) {
			output.print("open_" + file.getAbsolutePath());
			return true;
		}
		catch (IOException e) {
			service.handleEclipseError("Unexpected exception opening stream for socket to Eclipse",
				false, e);
			return false;
		}
		finally {
			try {
				socket.close();
			}
			catch (IOException e) {
				// we tried
			}
		}
	}

	@Override
	protected void programClosed(Program program) {
		provider.programClosed(program);
	}
}
