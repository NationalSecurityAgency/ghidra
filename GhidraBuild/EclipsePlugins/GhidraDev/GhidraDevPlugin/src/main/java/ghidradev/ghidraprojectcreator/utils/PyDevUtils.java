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
import java.net.URI;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Stream;

import javax.naming.OperationNotSupportedException;

import org.eclipse.core.resources.IProject;
import org.eclipse.core.runtime.*;
import org.eclipse.jdt.core.IClasspathEntry;
import org.eclipse.jdt.core.IJavaProject;
import org.osgi.framework.*;

import ghidradev.Activator;

/**
 * Utility methods for interacting with PyDev.
 */
public class PyDevUtils {

	public final static String MIN_SUPPORTED_VERSION = "9.3.0";
	public final static String MAX_JYTHON_SUPPORTED_VERSION = "9.3.0";

	/**
	 * The various types of supported Python interpreters
	 */
	public static enum ProjectPythonInterpreterType {
		NONE,
		PYGHIDRA,
		JYTHON
	}

	/**
	 * The projects Python interpreter to use
	 * 
	 * @param name The name of the interpreter
	 * @param type The {@link ProjectPythonInterpreterType type} of the interpreter
	 */
	public static record ProjectPythonInterpreter(String name, ProjectPythonInterpreterType type) {}

	/**
	 * {@return true if a supported version of PyDev is installed for use with PyGhidra; otherwise, 
	 * false}
	 */
	public static boolean isSupportedPyGhidraPyDevInstalled() {
		Version min = Version.valueOf(MIN_SUPPORTED_VERSION);
		try {
			Version version = PyDevUtilsInternal.getPyDevVersion();
			if (version != null) {
				return version.compareTo(min) >= 0;
			}
		}
		catch (NoClassDefFoundError e) {
			// Fall through to return false
		}

		return false;
	}

	/**
	 * {@return true if a supported version of PyDev is installed for use with Jython; otherwise, 
	 * false}
	 */
	public static boolean isSupportedJythonPyDevInstalled() {
		Version min = Version.valueOf(MIN_SUPPORTED_VERSION);
		Version max = Version.valueOf(MAX_JYTHON_SUPPORTED_VERSION);
		try {
			Version version = PyDevUtilsInternal.getPyDevVersion();
			if (version != null) {
				// Make sure the installed version of PyDev is new enough to support the following
				// operation.
				getJythonInterpreterNames();
				return version.compareTo(min) >= 0 && version.compareTo(max) <= 0;
			}
		}
		catch (OperationNotSupportedException | NoClassDefFoundError e) {
			// Fall through to return false
		}

		return false;
	}

	/**
	 * Gets a list of discovered PyGhidra interpreter names.
	 * @param requiredFileMatch if not {@code null}, only interpreter names that correspond to the 
	 *   given interpreter file will be returned.
	 * @return a list of discovered PyGhidra interpreter names.
	 * @throws OperationNotSupportedException if PyDev is not installed or it does not support this 
	 *   operation.
	 */
	public static List<String> getPyGhidraInterpreterNames(File requiredFileMatch)
			throws OperationNotSupportedException {
		try {
			return PyDevUtilsInternal.getPyGhidraInterpreterNames(requiredFileMatch);
		}
		catch (NoClassDefFoundError | NoSuchMethodError e) {
			throw new OperationNotSupportedException(e.getMessage());
		}
	}

	/**
	 * Gets a list of discovered Jython interpreter names.
	 *  
	 * @return a list of discovered Jython interpreter names.
	 * @throws OperationNotSupportedException if PyDev is not installed or it does not support this 
	 *   operation.
	 */
	public static List<String> getJythonInterpreterNames() throws OperationNotSupportedException {
		try {
			return PyDevUtilsInternal.getJythonInterpreterNames();
		}
		catch (NoClassDefFoundError | NoSuchMethodError e) {
			throw new OperationNotSupportedException(e.getMessage());
		}
	}

	/**
	 * Adds the given PyGhidra interpreter to PyDev.
	 * 
	 * @param interpreterName The name of the interpreter to add.
	 * @param interpreterFile The interpreter file to add.
	 * @param pypredefDir The pypredef directory to use (could be null if not supported)
	 * @throws OperationNotSupportedException if PyDev is not installed or it does not support this 
	 *   operation.
	 */
	public static void addPyGhidraInterpreter(String interpreterName, File interpreterFile,
			File pypredefDir) throws OperationNotSupportedException {
		try {
			PyDevUtilsInternal.addPyGhidraInterpreter(interpreterName, interpreterFile,
				pypredefDir);
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
	 * @param pythonInterpreter The Python interpreter to use.
	 * @param monitor The progress monitor used during link.
	 * @throws CoreException if there was an Eclipse-related problem with enabling Python for the 
	 *   project.	 
	 * @throws OperationNotSupportedException if PyDev is not installed or it does not support this 
	 *   operation.
	 */
	public static void setupPythonForProject(IJavaProject javaProject,
			List<IClasspathEntry> classpathEntries, ProjectPythonInterpreter pythonInterpreter,
			IProgressMonitor monitor) throws CoreException, OperationNotSupportedException {
		try {
			PyDevUtilsInternal.setupPythonForProject(javaProject, classpathEntries,
				pythonInterpreter, monitor);
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
	 * Gets the PyDev Python preference page ID.
	 *  
	 * @return the PyDev Python preference page ID.
	 */
	public static String getPythonPreferencePageId() {
		return "org.python.pydev.ui.pythonpathconf.interpreterPreferencesPagePython";
	}

	/**
	 * Gets The PyDev source directory.
	 * 
	 * @return The PyDev source directory, or null if it was not found.
	 * @throws CoreException if there was a problem searching for the PyDev source directory.
	 */
	public static File getPyDevSrcDir() throws CoreException {
		Bundle[] bundles =
			FrameworkUtil.getBundle(PyDevUtilsInternal.class).getBundleContext().getBundles();

		Bundle pydevCoreBundle = Stream.of(bundles)
				.filter(bundle -> bundle.getSymbolicName().contains("org.python.pydev.core"))
				.findFirst()
				.orElse(null);

		if (pydevCoreBundle != null) {
			try {
				URL pydevDirUrl = FileLocator.toFileURL(pydevCoreBundle.getEntry("/"));
				URI pydevDirUri =
					new URI(pydevDirUrl.getProtocol(), pydevDirUrl.getPath(), null).normalize();
				Path pysrcDir = Paths.get(pydevDirUri).resolve("pysrc");
				if (Files.exists(pysrcDir)) {
					return pysrcDir.toFile();
				}
			}
			catch (Exception e) {
				throw new CoreException(new Status(IStatus.ERROR, Activator.PLUGIN_ID,
					IStatus.ERROR, "Problem searching for PyDev source directory", e));
			}
		}

		return null;
	}

	/**
	 * Checks to see if the given project is a Python project.
	 * 
	 * @param project The project to check.
	 * @return True if the given project is a Python project; otherwise, false.
	 * @throws OperationNotSupportedException if PyDev is not installed or it does not support this 
	 *   operation.
	 */
	public static boolean isPythonProject(IProject project) throws OperationNotSupportedException {
		try {
			return PyDevUtilsInternal.isPythonProject(project);
		}
		catch (NoClassDefFoundError | NoSuchMethodError e) {
			throw new OperationNotSupportedException(e.getMessage());
		}
	}

	/**
	 * Checks to see if the given project is a PyGhidra project.
	 * 
	 * @param project The project to check.
	 * @return True if the given project is a PyGhidra project; otherwise, false.
	 * @throws OperationNotSupportedException if PyDev is not installed or it does not support this 
	 *   operation.
	 */
	public static boolean isPyGhidraProject(IProject project)
			throws OperationNotSupportedException {
		try {
			return PyDevUtilsInternal.isPyGhidraProject(project);
		}
		catch (NoClassDefFoundError | NoSuchMethodError e) {
			throw new OperationNotSupportedException(e.getMessage());
		}
	}

	/**
	 * Gets the interpreter name of the given Python project.
	 * 
	 * @param project The project to get the interpreter name from.
	 * @return The interpreter name of the given Python project, or null it it's not a Python
	 *   project or doesn't have an interpreter.
	 * @throws OperationNotSupportedException if PyDev is not installed or it does not support this 
	 *   operation.
	 */
	public static String getInterpreterName(IProject project)
			throws OperationNotSupportedException {
		try {
			return PyDevUtilsInternal.getInterpreterName(project);
		}
		catch (NoClassDefFoundError | NoSuchMethodError e) {
			throw new OperationNotSupportedException(e.getMessage());
		}
	}

	/**
	 * Gets the PyDev "project" attribute.
	 * 
	 * @return The PyDev "project" attribute.
	 * @throws OperationNotSupportedException if PyDev is not installed or it does not support this 
	 *   operation.
	 */
	public static String getAttrProject() throws OperationNotSupportedException {
		try {
			return PyDevUtilsInternal.getAttrProject();
		}
		catch (NoClassDefFoundError e) {
			throw new OperationNotSupportedException(e.getMessage());
		}
	}

	/**
	 * Gets the PyDev "location" attribute.
	 * 
	 * @return The PyDev "location" attribute.
	 * @throws OperationNotSupportedException if PyDev is not installed or it does not support this 
	 *   operation.	 
	 */
	public static String getAttrLocation() throws OperationNotSupportedException {
		try {
			return PyDevUtilsInternal.getAttrLocation();
		}
		catch (NoClassDefFoundError e) {
			throw new OperationNotSupportedException(e.getMessage());
		}
	}

	/**
	 * Gets the PyDev "program arguments" attribute.
	 * 
	 * @return The PyDev "program arguments" attribute.
	 * @throws OperationNotSupportedException if PyDev is not installed or it does not support this 
	 *   operation.
	 */
	public static String getAttrProgramArguments() throws OperationNotSupportedException {
		try {
			return PyDevUtilsInternal.getAttrProgramArguments();
		}
		catch (NoClassDefFoundError e) {
			throw new OperationNotSupportedException(e.getMessage());
		}
	}

	/**
	 * Gets the PyDev "interpreter" attribute.
	 * 
	 * @return The PyDev "interpreter" attribute.
	 * @throws OperationNotSupportedException if PyDev is not installed or it does not support this 
	 *   operation.
	 */
	public static String getAttrInterpreter() throws OperationNotSupportedException {
		try {
			return PyDevUtilsInternal.getAttrInterpreter();
		}
		catch (NoClassDefFoundError e) {
			throw new OperationNotSupportedException(e.getMessage());
		}
	}

	/**
	 * Gets the PyDev "interpreter default" attribute.
	 * 
	 * @return The PyDev "interpreter default" attribute.
	 * @throws OperationNotSupportedException if PyDev is not installed or it does not support this 
	 *   operation.
	 */
	public static String getAttrInterpreterDefault() throws OperationNotSupportedException {
		try {
			return PyDevUtilsInternal.getAttrInterpreterDefault();
		}
		catch (NoClassDefFoundError e) {
			throw new OperationNotSupportedException(e.getMessage());
		}
	}
}
