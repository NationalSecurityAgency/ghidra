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
package ghidradev.ghidraprojectcreator.utils;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import javax.naming.OperationNotSupportedException;

import org.eclipse.core.runtime.CoreException;
import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.core.runtime.IStatus;
import org.eclipse.core.runtime.Platform;
import org.eclipse.core.runtime.Status;
import org.eclipse.jdt.core.IClasspathEntry;
import org.eclipse.jdt.core.IJavaProject;

import ghidradev.Activator;

/**
 * Utility methods for interacting with PyDev.
 */
public class PyDevUtils {

	public final static String MIN_SUPPORTED_VERSION = "6.3.1";

	/**
	 * Checks to see if a supported version of PyDev is installed.
	 * 
	 * @return True if a supported version of PyDev is installed; otherwise, false.
	 */
	public static boolean isSupportedPyDevInstalled() {
		try {
			if (PyDevUtilsInternal.isPyDevInstalled()) {
				// Make sure the installed version of PyDev is new enough to support the following
				// operation.
				getJython27InterpreterNames();
				return true;
			}
		}
		catch (OperationNotSupportedException | NoClassDefFoundError e) {
			// Fall through to return false
		}

		return false;
	}

	/**
	 * Gets a list of discovered Jython 2.7 interpreter names.
	 *  
	 * @return a list of discovered Jython 2.7 interpreter names.
	 * @throws OperationNotSupportedException if PyDev is not installed or it does not support this 
	 *   operation.
	 */
	public static List<String> getJython27InterpreterNames() throws OperationNotSupportedException {
		try {
			return PyDevUtilsInternal.getJython27InterpreterNames();
		}
		catch (NoClassDefFoundError | NoSuchMethodError e) {
			throw new OperationNotSupportedException(e.getMessage());
		}
	}

	/**
	 * Adds the given Jython interpreter to PyDev.
	 * 
	 * @param interpreterName The name of the interpreter to add.
	 * @param interpreterFile The interpreter file to add.
	 * @param interpreterLibDir The interpreter library directory to add.
	 * @throws OperationNotSupportedException if PyDev is not installed or it does not support this 
	 *   operation.
	 */
	public static void addJythonInterpreter(String interpreterName, File interpreterFile,
			File interpreterLibDir)
			throws OperationNotSupportedException {
		try {
			PyDevUtilsInternal.addJythonInterpreter(interpreterName, interpreterFile,
				interpreterLibDir);
		}
		catch (NoClassDefFoundError | NoSuchMethodError e) {
			throw new OperationNotSupportedException(e.getMessage());
		}
	}

	/**
	 * Sets up Python for the given Java project.
	 * 
	 * @param javaProject The Java project to enable Python for.
	 * @param classpathEntries The classpath entries to add to the Python path.
	 * @param jythonInterpreterName The name of the Jython interpreter to use for Python support.
	 *   If this is null, Python support will be removed from the project.
	 * @param monitor The progress monitor used during link.
	 * @throws CoreException if there was an Eclipse-related problem with enabling Python for the 
	 *   project.	 
	 * @throws OperationNotSupportedException if PyDev is not installed or it does not support this 
	 *   operation.
	 */
	public static void setupPythonForProject(IJavaProject javaProject,
			List<IClasspathEntry> classpathEntries, String jythonInterpreterName,
			IProgressMonitor monitor) throws CoreException, OperationNotSupportedException {
		try {
			PyDevUtilsInternal.setupPythonForProject(javaProject, classpathEntries,
				jythonInterpreterName, monitor);
		}
		catch (NoClassDefFoundError | NoSuchMethodError e) {
			throw new OperationNotSupportedException(e.getMessage());
		}
	}

	/**
	 * Starts the PyDev remote debugger.
	 * 
	 * @throws OperationNotSupportedException if PyDev is not installed or it does not support this 
	 *   operation.
	 */
	public static void startPyDevRemoteDebugger() throws OperationNotSupportedException {
		try {
			PyDevUtilsInternal.startPyDevRemoteDebugger();
		}
		catch (NoClassDefFoundError | NoSuchMethodError e) {
			throw new OperationNotSupportedException(e.getMessage());
		}
	}

	/**
	 * Gets the PyDev Jython preference page ID.
	 *  
	 * @return the PyDev Jython preference page ID.
	 */
	public static String getJythonPreferencePageId() {
		return "org.python.pydev.ui.pythonpathconf.interpreterPreferencesPageJython";
	}

	/**
	 * Gets The PyDev source directory.
	 * 
	 * @return The PyDev source directory, or null if it was not found.
	 * @throws CoreException if there was a problem searching for the PyDev source directory.
	 */
	public static File getPyDevSrcDir() throws CoreException {
		String eclipsePath = Platform.getInstallLocation().getURL().getFile();
		
		List<File> searchDirs = new ArrayList<>();
		searchDirs.add(new File(eclipsePath, "plugins"));
		searchDirs.add(new File(eclipsePath, "dropins"));
		
		for (File searchRoot : searchDirs) {
			try (Stream<Path> paths = Files.walk(Paths.get(searchRoot.toURI()))) {
				Optional<File> pysrcDir = paths.filter(
					Files::isDirectory)
						.filter(p -> p.endsWith("pysrc"))
						.map(p -> p.toFile())
						.filter(f -> f.getParentFile().getName().startsWith("org.python.pydev"))
						.findFirst();
				if (pysrcDir.isPresent()) {
					return pysrcDir.get();
				}
			}
			catch (IOException e) {
				throw new CoreException(new Status(IStatus.ERROR, Activator.PLUGIN_ID,
					IStatus.ERROR, "Problem searching for PyDev source directory", e));
			}
		}
		
		return null;
	}
}
