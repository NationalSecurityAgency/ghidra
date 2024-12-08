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
package ghidra.app.services;

import java.io.*;

import ghidra.framework.options.ToolOptions;

/**
 * Service that provides Visual Studio Code-related functionality
 */
public interface VSCodeIntegrationService {

	/**
	 * {@return the Visual Studio Code Integration options}
	 */
	public ToolOptions getVSCodeIntegrationOptions();

	/**
	 * {@return the Visual Studio Code executable file}
	 * 
	 * @throws FileNotFoundException if the executable file does not exist
	 */
	public File getVSCodeExecutableFile() throws FileNotFoundException;

	/**
	 * Launches Visual Studio Code
	 * 
	 * @param file The initial file to open in Visual Studio Code
	 */
	public void launchVSCode(File file);

	/**
	 * Displays the given Visual Studio Code related error message in an error dialog
	 * 
	 * @param error The error message to display in a dialog
	 * @param askAboutOptions True if we should ask the user if they want to be taken to the Visual
	 *   Studio Code options; otherwise, false
	 * @param t An optional throwable to tie to the message
	 */
	public void handleVSCodeError(String error, boolean askAboutOptions, Throwable t);

	/**
	 * Creates a new Visual Studio Code module project at the given directory
	 * 
	 * @param projectDir The new directory to create
	 * @throws IOException if the directory failed to be created
	 */
	public void createVSCodeModuleProject(File projectDir) throws IOException;
	
	/**
	 * Adds the given project directory to the the given Visual Studio Code workspace file
	 * A new workspace will be created if it doesn't already exist
	 * 
	 * @param workspaceFile The location of the workspace file
	 * @param projectDir An existing project directory to add to the workspace
	 * @throws IOException if the directory failed to be created
	 */
	public void addToVSCodeWorkspace(File workspaceFile, File projectDir) throws IOException;
}
