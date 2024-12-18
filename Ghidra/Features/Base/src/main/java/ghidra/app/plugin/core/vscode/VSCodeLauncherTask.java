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
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.services.VSCodeIntegrationService;
import ghidra.framework.Application;
import ghidra.util.SystemUtilities;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Task} to launch Visual Studio Code
 */
class VSCodeLauncherTask extends Task {

	private VSCodeIntegrationService vscodeService;
	private File file;

	/**
	 * Constructs a new Visual Studio Code launcher task
	 * 
	 * @param vscodeService The Visual Studio Code integration service
	 * @param file The file to open in Visual Studio Code
	 */
	public VSCodeLauncherTask(VSCodeIntegrationService vscodeService, File file) {
		super("Visual Studio Code Launcher Task", true, true, true);
		this.vscodeService = vscodeService;
		this.file = file;
	}

	@Override
	public void run(TaskMonitor monitor) {

		if (SystemUtilities.isInDevelopmentMode()) {
			vscodeService.handleVSCodeError(
				"Launching Visual Studio Code is not supported in development mode.", false, null);
			return;
		}

		// Get required Visual Studio Code components.  If VSCode isn't found at the default
		// location present the user with the options window, and when they close that window, try 
		// again.
		File vscodeExecutableFile;
		try {
			vscodeExecutableFile = vscodeService.getVSCodeExecutableFile();
		}
		catch (IOException e1) {
			vscodeService.handleVSCodeError(e1.getMessage(), true, null);
			try {
				vscodeExecutableFile = vscodeService.getVSCodeExecutableFile();
			}
			catch (IOException e2) {
				vscodeService.handleVSCodeError(
					"Failed to launch Visual Studio Code.  The required Visual Studio Code components have not been configured.",
					false, null);
				return;
			}
		}

		// Setup the workspace
		File vscodeSettingsDir = new File(Application.getUserSettingsDirectory(), "vscode");
		File workspaceFile = new File(vscodeSettingsDir, "ghidra_scripts.code-workspace");
		try {
			vscodeService.addToVSCodeWorkspace(workspaceFile, file.getParentFile());
		}
		catch (IOException e) {
			vscodeService.handleVSCodeError("Failed to create Visual Studio Code workspace.", false,
				e);
			return;
		}

		// Launch Visual Studio Code
		monitor.setIndeterminate(true);
		monitor.setMessage("Launching Visual Studio Code...");
		try {
			List<String> args = new ArrayList<>();
			args.add(vscodeExecutableFile.getAbsolutePath());
			args.add("-a");
			args.add(workspaceFile.getAbsolutePath());
			args.add(file.getAbsolutePath());
			new ProcessBuilder(args).redirectErrorStream(true).start();
		}
		catch (Exception e) {
			vscodeService.handleVSCodeError(
				"Unexpected exception occurred while launching Visual Studio Code.", false, null);
			return;
		}
	}
}
