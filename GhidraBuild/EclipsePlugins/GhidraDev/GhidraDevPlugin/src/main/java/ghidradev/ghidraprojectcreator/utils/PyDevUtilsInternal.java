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
import java.util.*;
import java.util.stream.Collectors;

import org.eclipse.core.resources.IProject;
import org.eclipse.core.runtime.*;
import org.eclipse.jdt.core.IClasspathEntry;
import org.eclipse.jdt.core.IJavaProject;
import org.osgi.framework.*;
import org.python.pydev.ast.interpreter_managers.InterpreterInfo;
import org.python.pydev.ast.interpreter_managers.InterpreterManagersAPI;
import org.python.pydev.core.*;
import org.python.pydev.debug.core.Constants;
import org.python.pydev.plugin.nature.PythonNature;

import com.python.pydev.debug.remote.client_api.PydevRemoteDebuggerServer;

import ghidradev.EclipseMessageUtils;
import ghidradev.ghidraprojectcreator.utils.PyDevUtils.ProjectPythonInterpreter;

/**
 * Utility methods for interacting with PyDev.
 * <p>
 * NOTE: Since PyDev may not be installed, all PyDev interactions must be done in this
 * class, and every method must throw {@link NoClassDefFoundError} so caller's can
 * handle PyDev being absent.  People wanting to interact with PyDev should go through the
 * public-facing version of this class...{@link PyDevUtils}.
 */
class PyDevUtilsInternal {

	/**
	 * Get the version of PyDev that is installed
	 * 
	 * @return The {@link Version} of the installed PyDev, or null if PyDev is not installed.
	 * @throws NoClassDefFoundError if PyDev is not installed.
	 */
	public static Version getPyDevVersion() throws NoClassDefFoundError {
		for (Bundle bundle : FrameworkUtil.getBundle(PyDevUtilsInternal.class)
				.getBundleContext()
				.getBundles()) {
			if (bundle.getSymbolicName().contains("pydev")) {
				// remove qualifier to make version comparisons more straightforward
				Version version = bundle.getVersion();
				return new Version(version.getMajor(), version.getMinor(), version.getMicro());
			}
		}
		return null;
	}

	/**
	 * Gets a list of discovered PyGhidra interpreter names.
	 *  
	 * @param requiredFileMatch if not {@code null}, only interpreter names that correspond to the 
	 *   given interpreter file will be returned.
	 * @return a list of discovered PyGhidra interpreter names.
	 * @throws NoClassDefFoundError if PyDev is not installed or it does not support this operation.
	 * @throws NoSuchMethodError if PyDev is not installed or it does not support this operation.
	 */
	public static List<String> getPyGhidraInterpreterNames(File requiredFileMatch)
			throws NoClassDefFoundError, NoSuchMethodError {

		List<String> interpreters = new ArrayList<>();
		IInterpreterManager iMan = InterpreterManagersAPI.getPythonInterpreterManager(true);

		for (IInterpreterInfo info : iMan.getInterpreterInfos()) {
			ISystemModulesManager modulesManager = info.getModulesManager();
			if (info.getInterpreterType() == IPythonNature.INTERPRETER_TYPE_PYTHON &&
				!modulesManager.getAllModulesStartingWith("pyghidra.__main__").isEmpty()) {
				if (requiredFileMatch == null ||
					requiredFileMatch.getAbsolutePath().equals(info.getExecutableOrJar())) {
					interpreters.add(info.getName());
				}
			}
		}

		return interpreters;
	}

	/**
	 * Gets a list of discovered Jython interpreter names.
	 *  
	 * @return a list of discovered Jython interpreter names.
	 * @throws NoClassDefFoundError if PyDev is not installed or it does not support this operation.
	 * @throws NoSuchMethodError if PyDev is not installed or it does not support this operation.
	 */
	public static List<String> getJythonInterpreterNames()
			throws NoClassDefFoundError, NoSuchMethodError {

		List<String> interpreters = new ArrayList<>();
		IInterpreterManager iMan = InterpreterManagersAPI.getJythonInterpreterManager(true);

		for (IInterpreterInfo info : iMan.getInterpreterInfos()) {
			if (info.getInterpreterType() == IPythonNature.INTERPRETER_TYPE_JYTHON &&
				info.getVersion().equals("2.7")) {
				interpreters.add(info.getName());
			}
		}

		return interpreters;
	}

	/**
	 * Adds the given PyGhidra interpreter to PyDev.
	 * 
	 * @param interpreterName The name of the interpreter to add.
	 * @param interpreterFile The interpreter to add.
	 * @param pypredefDir The pypredef directory to use (could be null if not supported)
	 * @throws NoClassDefFoundError if PyDev is not installed or it does not support this operation.
	 * @throws NoSuchMethodError if PyDev is not installed or it does not support this operation.
	 */
	public static void addPyGhidraInterpreter(String interpreterName, File interpreterFile,
			File pypredefDir) throws NoClassDefFoundError, NoSuchMethodError {
		IProgressMonitor monitor = new NullProgressMonitor();
		IInterpreterManager iMan = InterpreterManagersAPI.getPythonInterpreterManager(true);
		IInterpreterInfo[] interpreterInfos = iMan.getInterpreterInfos();
		for (IInterpreterInfo iInfo : interpreterInfos) {
			if (iInfo.getName().equals(interpreterName) &&
				iInfo.getExecutableOrJar().equals(interpreterFile.getAbsolutePath())) {
				return;
			}
		}
		IInterpreterInfo iInfo =
			iMan.createInterpreterInfo(interpreterFile.getAbsolutePath(), monitor, false);
		iInfo.setName(interpreterName);
		if (iInfo instanceof InterpreterInfo ii && pypredefDir != null) {
			ii.addPredefinedCompletionsPath(pypredefDir.getAbsolutePath());
		}
		IInterpreterInfo[] newInterpreterInfos =
			Arrays.copyOf(interpreterInfos, interpreterInfos.length + 1);
		newInterpreterInfos[interpreterInfos.length] = iInfo;
		iMan.setInfos(newInterpreterInfos, null, monitor);
	}

	/**
	 * Adds the given Jython interpreter to PyDev.
	 * 
	 * @param interpreterName The name of the interpreter to add.
	 * @param interpreterFile The interpreter to add.
	 * @param interpreterLibDir The interpreter library directory to add.
	 * @throws NoClassDefFoundError if PyDev is not installed or it does not support this operation.
	 * @throws NoSuchMethodError if PyDev is not installed or it does not support this operation.
	 */
	public static void addJythonInterpreter(String interpreterName, File interpreterFile,
			File interpreterLibDir) throws NoClassDefFoundError, NoSuchMethodError {
		IProgressMonitor monitor = new NullProgressMonitor();
		IInterpreterManager iMan = InterpreterManagersAPI.getJythonInterpreterManager(true);
		IInterpreterInfo iInfo =
			iMan.createInterpreterInfo(interpreterFile.getAbsolutePath(), monitor, false);
		iInfo.setName(interpreterName);
		if (iInfo instanceof InterpreterInfo) {
			InterpreterInfo info = (InterpreterInfo) iInfo;
			info.libs.add(interpreterLibDir.getAbsolutePath());
			info.libs.add(new File(interpreterLibDir, "site-packages").getAbsolutePath());
		}
		else {
			EclipseMessageUtils.error("Failed to add Jython Lib directory to python path");
		}
		IInterpreterInfo[] interpreterInfos = iMan.getInterpreterInfos();
		IInterpreterInfo[] newInterpreterInfos =
			Arrays.copyOf(interpreterInfos, interpreterInfos.length + 1);
		newInterpreterInfos[interpreterInfos.length] = iInfo;
		iMan.setInfos(newInterpreterInfos, null, monitor);
	}

	/**
	 * Sets up Python for the given Java project.
	 * 
	 * @param javaProject The Java project to setup Python for.
	 * @param classpathEntries The classpath entries to add to the Python path.
	 * @param pythonInterpreter The Python interpreter to use.
	 * @param monitor The progress monitor used during link.
	 * @throws CoreException If there was an Eclipse-related problem with enabling Python for the project.
	 * @throws NoClassDefFoundError if PyDev is not installed or it does not support this operation.
	 * @throws NoSuchMethodError if PyDev is not installed or it does not support this operation.
	 */
	public static void setupPythonForProject(IJavaProject javaProject,
			List<IClasspathEntry> classpathEntries, ProjectPythonInterpreter pythonInterpreter,
			IProgressMonitor monitor)
			throws CoreException, NoClassDefFoundError, NoSuchMethodError {

		PythonNature.removeNature(javaProject.getProject(), monitor);

		String version;
		String libs;
		switch (pythonInterpreter.type()) {
			case PYGHIDRA:
				version = IPythonNature.PYTHON_VERSION_INTERPRETER;
				libs = null;
				break;
			case JYTHON:
				version = IPythonNature.JYTHON_VERSION_INTERPRETER;
				libs = classpathEntries.stream()
						.map(e -> e.getPath().toOSString())
						.collect(Collectors.joining("|"));
				break;
			default:
				return;
		}

		PythonNature.addNature(javaProject.getProject(), monitor, version, null, libs,
			pythonInterpreter.name(), null);
	}

	/**
	 * Starts the PyDev remote debugger.
	 * 
	 * @throws NoClassDefFoundError if PyDev is not installed or it does not support this operation.
	 * @throws NoSuchMethodError if PyDev is not installed or it does not support this operation.
	 */
	public static void startPyDevRemoteDebugger() throws NoClassDefFoundError, NoSuchMethodError {
		PydevRemoteDebuggerServer.startServer();
	}

	/**
	 * Checks to see if the given project is a Python project.
	 * 
	 * @param project The project to check.
	 * @return True if the given project is a Python project; otherwise, false.
	 * @throws NoClassDefFoundError if PyDev is not installed or it does not support this operation.
	 */
	public static boolean isPythonProject(IProject project) throws NoClassDefFoundError {
		try {
			return project.hasNature(PythonNature.PYTHON_NATURE_ID);
		}
		catch (CoreException e) {
			return false;
		}
	}

	/**
	 * Checks to see if the given project is a PyGhidra project.
	 * 
	 * @param project The project to check.
	 * @return True if the given project is a PyGhidra project; otherwise, false.
	 * @throws NoClassDefFoundError if PyDev is not installed or it does not support this operation.
	 */
	public static boolean isPyGhidraProject(IProject project) throws NoClassDefFoundError {
		return isPythonProject(project) && GhidraProjectUtils.isGhidraProject(project);
	}

	/**
	 * Gets the interpreter name of the given Python project.
	 * 
	 * @param project The project to get the interpreter name from.
	 * @return The interpreter name of the given Python project, or null it it's not a Python
	 *   project or doesn't have an interpreter.
	 * @throws NoClassDefFoundError if PyDev is not installed or it does not support this operation.
	 * @throws NoSuchMethodError if PyDev is not installed or it does not support this operation.
	 */
	public static String getInterpreterName(IProject project)
			throws NoClassDefFoundError, NoSuchMethodError {
		PythonNature nature = PythonNature.getPythonNature(project);
		if (nature != null) {
			try {
				IInterpreterInfo info = nature.getProjectInterpreter();
				if (info != null) {
					return info.getName();
				}
			}
			catch (PythonNatureWithoutProjectException | MisconfigurationException e) {
				// Fall through
			}
		}
		return null;
	}

	/**
	 * Gets the PyDev "project" attribute.
	 * 
	 * @return The PyDev "project" attribute.
	 * @throws NoClassDefFoundError if PyDev is not installed or it does not support this operation.
	 */
	public static String getAttrProject() throws NoClassDefFoundError {
		return Constants.ATTR_PROJECT;
	}

	/**
	 * Gets the PyDev "location" attribute.
	 * 
	 * @return The PyDev "location" attribute.
	 * @throws NoClassDefFoundError if PyDev is not installed or it does not support this operation.
	 */
	public static String getAttrLocation() throws NoClassDefFoundError {
		return Constants.ATTR_LOCATION;
	}

	/**
	 * Gets the PyDev "program arguments" attribute.
	 * 
	 * @return The PyDev "program arguments" attribute.
	 * @throws NoClassDefFoundError if PyDev is not installed or it does not support this operation.
	 */
	public static String getAttrProgramArguments() throws NoClassDefFoundError {
		return Constants.ATTR_PROGRAM_ARGUMENTS;
	}

	/**
	 * Gets the PyDev "interpreter" attribute.
	 * 
	 * @return The PyDev "interpreter" attribute.
	 * @throws NoClassDefFoundError if PyDev is not installed or it does not support this operation.
	 */
	public static String getAttrInterpreter() throws NoClassDefFoundError {
		return Constants.ATTR_INTERPRETER;
	}

	/**
	 * Gets the PyDev "interpreter default" attribute.
	 * 
	 * @return The PyDev "interpreter default" attribute.
	 * @throws NoClassDefFoundError if PyDev is not installed or it does not support this operation.
	 */
	public static String getAttrInterpreterDefault() throws NoClassDefFoundError {
		return Constants.ATTR_INTERPRETER_DEFAULT;
	}

	private PyDevUtilsInternal() throws NoClassDefFoundError {
		// Prevent instantiation 
	}
}
