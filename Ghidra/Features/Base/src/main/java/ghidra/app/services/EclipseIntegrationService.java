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

import ghidra.app.plugin.core.eclipse.EclipseConnection;
import ghidra.framework.options.ToolOptions;
import ghidra.util.task.TaskMonitor;

/**
 * Service that provides Eclipse-related functionality.
 */
public interface EclipseIntegrationService {

	/**
	 * Gets the Eclipse Integration options.
	 * 
	 * @return The Eclipse Integration options.
	 */
	public ToolOptions getEclipseIntegrationOptions();

	/**
	 * Gets the Eclipse executable file.
	 * 
	 * @return The Eclipse executable file.
	 * @throws FileNotFoundException if the executable file does not exist.
	 */
	public File getEclipseExecutableFile() throws FileNotFoundException;

	/**
	 * Gets the Eclipse workspace directory.  If it is defined, the directory may or may not exist.
	 * If it is undefined, Eclipse will be in control of selecting a workspace directory to use.
	 * 
	 * @return The Eclipse workspace directory. The directory may or may not exist.  Could return
	 *   null if the workspace directory is undefined.
	 */
	public File getEclipseWorkspaceDir();

	/**
	 * Checks to see if a feature is installed in Eclipse.
	 * 
	 * @param filter A filename filter that matches the feature file to check.
	 * @return True if the specified feature is installed.
	 * @throws FileNotFoundException if Eclipse is not installed.
	 */
	public boolean isEclipseFeatureInstalled(FilenameFilter filter) throws FileNotFoundException;

	/**
	 * Attempts to connect to Eclipse on the given port.  This may result in Eclipse
	 * being launched.  If the launch and/or connection fails, an error message will
	 * be displayed.
	 * 
	 * @param port The port to connect to.
	 * @return The (possibly failed) connection.  Check the status of the {@link EclipseConnection}
	 *   for details on the connection.
	 */
	public EclipseConnection connectToEclipse(int port);

	/**
	 * Offers to install GhidraDev into Eclipse's dropins directory.
	 * 
	 * @param monitor The task monitor used to cancel the installation.
	 */
	public void offerGhidraDevInstallation(TaskMonitor monitor);

	/**
	 * Displays the given Eclipse related error message in an error dialog.
	 * 
	 * @param error The error message to display in a dialog.
	 * @param askAboutOptions True if we should ask the user if they want to be taken to the Eclipse
	 *   options; otherwise, false.
	 * @param t An optional throwable to tie to the message.
	 */
	public void handleEclipseError(String error, boolean askAboutOptions, Throwable t);
}
