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
package ghidra.jython;

import java.io.*;

import ghidra.framework.Application;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

/**
 * Python utility method class.
 */
public class JythonUtils {

	public static final String JYTHON_NAME = "jython-2.7.4";
	public static final String JYTHON_CACHEDIR = "jython_cachedir";
	public static final String JYTHON_SRC = "jython-src";

	/**
	 * Sets up the jython home directory.  This is the directory that has the "Lib" directory in it.
	 *  
	 * @return The jython home directory.
	 * @throws IOException If there was a disk-related problem setting up the home directory.
	 */
	public static File setupJythonHomeDir() throws IOException {

		File jythonModuleDir = Application.getMyModuleRootDirectory().getFile(false);
		File jythonHomeDir =
			Application.getModuleDataSubDirectory(jythonModuleDir.getName(), JYTHON_NAME)
					.getFile(false);

		if (!jythonHomeDir.exists()) {
			throw new IOException("Failed to find the jython home directory at: " + jythonHomeDir);
		}

		System.setProperty("jython.home", jythonHomeDir.getAbsolutePath());

		return jythonHomeDir;
	}

	/**
	 * Sets up the jython cache directory.  This is a temporary space that jython source files
	 * get compiled to and cached.  It should NOT be in the Ghidra installation directory, because
	 * some installations will not have the appropriate directory permissions to create new files in.
	 * 
	 * @param monitor A monitor to use during the cache directory setup.
	 * @return The jython cache directory.
	 * @throws IOException If there was a disk-related problem setting up the cache directory.
	 * @throws CancelledException If the user cancelled the setup.
	 */
	public static File setupJythonCacheDir(TaskMonitor monitor)
			throws CancelledException, IOException {

		File devDir = new File(Application.getUserSettingsDirectory(), "dev");
		File cacheDir = new File(devDir, JYTHON_CACHEDIR);
		if (!FileUtilities.mkdirs(cacheDir)) {
			throw new IOException("Failed to create the jython cache directory at: " + cacheDir);
		}

		File jythonSrcDestDir = new File(cacheDir, JYTHON_SRC);
		if (!FileUtilities.createDir(jythonSrcDestDir)) {
			throw new IOException(
				"Failed to create the " + JYTHON_SRC + " directory at: " + jythonSrcDestDir);
		}

		File jythonModuleDir = Application.getMyModuleRootDirectory().getFile(false);
		File jythonSrcDir = new File(jythonModuleDir, JYTHON_SRC);
		if (!jythonSrcDir.exists()) {
			try {
				jythonSrcDir = Application.getModuleDataSubDirectory(jythonModuleDir.getName(),
					JYTHON_SRC).getFile(false);
			}
			catch (FileNotFoundException e) {
				throw new IOException("Failed to find the module's " + JYTHON_SRC + " directory");
			}
		}

		try {
			FileUtilities.copyDir(jythonSrcDir, jythonSrcDestDir, f -> f.getName().endsWith(".py"),
				monitor);
		}
		catch (IOException e) {
			throw new IOException(
				"Failed to copy " + JYTHON_SRC + " files to: " + jythonSrcDestDir);
		}

		System.setProperty("python.cachedir.skip", "false");
		System.setProperty("python.cachedir", cacheDir.getAbsolutePath());
		System.setProperty("python.path", jythonSrcDestDir.getAbsolutePath());

		return cacheDir;
	}
}
