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
package ghidradev.ghidrasymbollookup;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;

import org.eclipse.core.resources.IProject;
import org.eclipse.core.resources.ResourcesPlugin;
import org.eclipse.swt.widgets.Display;

import ghidradev.EclipseMessageUtils;
import ghidradev.ghidrasymbollookup.preferences.GhidraSymbolLookupPreferences;
import ghidradev.ghidrasymbollookup.utils.CdtUtils;

public class SocketSetupRunnable implements Runnable {

	private ServerSocket serverSocket = null;
	private OpenDeclarations openDeclsDialog;
	private IProject project;
	private boolean isInitialized;

	public SocketSetupRunnable(ServerSocket serverSocket) {
		this.serverSocket = serverSocket;
	}

	@Override
	public void run() {
		while (!serverSocket.isClosed()) {
			try (Socket socket = serverSocket.accept();
					BufferedReader input =
						new BufferedReader(new InputStreamReader(socket.getInputStream()));
					PrintWriter output = new PrintWriter(socket.getOutputStream())) {

				String result = "";
				// Setup the project to look in and handle any problems like project being closed
				if (!isInitialized) {
					result = init();
				}

				// If the project is closed while running the plugin and you try to look in it again
				if (isInitialized && !project.isOpen()) {
					try {
						input.readLine();
					}
					catch (IOException e) {
						EclipseMessageUtils.error(
							"Unexpected exception receiving symbol name: " + e.getMessage());
					}
					isInitialized = false;
					result = init();
				}
				if (isInitialized) {
					String symbolName = null;
					try {
						symbolName = input.readLine();
					}
					catch (IOException e) {
						EclipseMessageUtils.error(
							"Unexpected exception looking for symbol: " + e.getMessage());
						e.printStackTrace();
					}

					if (isInitialized) {
						lookup(symbolName, output);
					}
					else {
						output.write("Failed to initialize CDT project");
						output.flush();
					}
				}
				else {
					output.write(result);
				}
			}
			catch (IOException e) {
				// Socket was closed
			}
		}
	}

	private String init() {
		String projectName = GhidraSymbolLookupPreferences.getSymbolLookupProjectName();
		final String errorMessageContainer[] = { "" };
		Display.getDefault().syncExec(() -> {
			while (!isInitialized) {
				if (projectName == null) {
					errorMessageContainer[0] =
						"Project name not defined in the Ghidra Symbol Lookup preference page.";
					EclipseMessageUtils.showWarnDialog("Ghidra Symbol Lookup",
						errorMessageContainer[0]);
					break;
				}
				project = ResourcesPlugin.getWorkspace().getRoot().getProject(projectName);
				if (!project.exists()) {
					errorMessageContainer[0] =
						"The project \"" + projectName + "\" does not exist " +
							"in your workspace. Please edit the \"Project Name\" field in " +
							"the Ghidra Symbol Lookup preference page.";
					EclipseMessageUtils.showWarnDialog("Project Does Not Exist",
						errorMessageContainer[0]);
					break;
				}
				if (!project.isOpen()) {
					errorMessageContainer[0] = "Please open the project \"" + project.getName() +
						"\" or choose a different one in the plugin preference page.";
					EclipseMessageUtils.showWarnDialog("Project Not Open",
						errorMessageContainer[0]);
					break;
				}
				if (!CdtUtils.isCdtProject(project)) {
					errorMessageContainer[0] =
						"The project \"" + project.getName() + "\" is not a C or C++ project." +
							"\nPlease edit the \"Project Name\" field in the Ghidra Symbol " +
							"Lookup preference page.";
					EclipseMessageUtils.showWarnDialog("Not a C/C++ Project",
						errorMessageContainer[0]);
					break;
				}
				openDeclsDialog = new OpenDeclarations(project);
				isInitialized = true;
			}
		});
		return errorMessageContainer[0];
	}

	private void lookup(String symbolName, PrintWriter output) {
		EclipseMessageUtils.info("Looking for symbol name: " + symbolName);
		boolean result = openDeclsDialog.open(symbolName);
		if (result) {
			output.write("Found symbol " + symbolName + "\n");
		}
		else {
			output.write("Couldn't find " + symbolName + "\n");
		}
		output.flush();
	}
}
