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
package ghidra.python;

import java.io.*;

import ghidra.framework.Application;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

/**
 * Python utility method class.
 */
public class PythonUtils {

	public static final String PYTHON_NAME = "jython-2.7.2";
	public static final String PYTHON_CACHEDIR = "jython_cachedir";
	public static final String PYTHON_SRC = "python-src";

	/**
	 * Sets up the python home directory.  This is the directory that has the "Lib" directory in it.
	 *  
	 * @return The python home directory.
	 * @throws IOException If there was a disk-related problem setting up the home directory.
	 */
	public static File setupPythonHomeDir() throws IOException {

		File pythonModuleDir = Application.getMyModuleRootDirectory().getFile(false);
		File pythonHomeDir =
			Application.getModuleDataSubDirectory(pythonModuleDir.getName(), PYTHON_NAME).getFile(
				false);

		if (!pythonHomeDir.exists()) {
			throw new IOException("Failed to find the python home directory at: " + pythonHomeDir);
		}

		System.setProperty("python.home", pythonHomeDir.getAbsolutePath());

		return pythonHomeDir;
	}

	/**
	 * Sets up the python cache directory.  This is a temporary space that python source files
	 * get compiled to and cached.  It should NOT be in the Ghidra installation directory, because
	 * some installations will not have the appropriate directory permissions to create new files in.
	 * 
	 * @param monitor A monitor to use during the cache directory setup.
	 * @return The python cache directory.
	 * @throws IOException If there was a disk-related problem setting up the cache directory.
	 * @throws CancelledException If the user cancelled the setup.
	 */
	public static File setupPythonCacheDir(TaskMonitor monitor)
			throws CancelledException, IOException {

		File devDir = new File(Application.getUserSettingsDirectory(), "dev");
		File cacheDir = new File(devDir, PYTHON_CACHEDIR);
		if (!FileUtilities.mkdirs(cacheDir)) {
			throw new IOException("Failed to create the python cache directory at: " + cacheDir);
		}

		File pythonSrcDestDir = new File(cacheDir, PYTHON_SRC);
		if (!FileUtilities.createDir(pythonSrcDestDir)) {
			throw new IOException(
				"Failed to create the " + PYTHON_SRC + " directory at: " + pythonSrcDestDir);
		}

		File pythonModuleDir = Application.getMyModuleRootDirectory().getFile(false);
		File pythonSrcDir = new File(pythonModuleDir, PYTHON_SRC);
		if (!pythonSrcDir.exists()) {
			try {
				pythonSrcDir = Application.getModuleDataSubDirectory(pythonModuleDir.getName(),
					PYTHON_SRC).getFile(false);
			}
			catch (FileNotFoundException e) {
				throw new IOException("Failed to find the module's " + PYTHON_SRC + " directory");
			}
		}

		try {
			FileUtilities.copyDir(pythonSrcDir, pythonSrcDestDir, f -> f.getName().endsWith(".py"),
				monitor);
		}
		catch (IOException e) {
			throw new IOException(
				"Failed to copy " + PYTHON_SRC + " files to: " + pythonSrcDestDir);
		}

		System.setProperty("python.cachedir.skip", "false");
		System.setProperty("python.cachedir", cacheDir.getAbsolutePath());
		System.setProperty("python.path", pythonSrcDestDir.getAbsolutePath());

		return cacheDir;
	}
}
