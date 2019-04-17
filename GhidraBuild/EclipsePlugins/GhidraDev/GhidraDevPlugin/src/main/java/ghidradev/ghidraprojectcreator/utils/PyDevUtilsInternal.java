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
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import org.eclipse.core.runtime.*;
import org.eclipse.jdt.core.IClasspathEntry;
import org.eclipse.jdt.core.IJavaProject;
import org.osgi.framework.Bundle;
import org.osgi.framework.FrameworkUtil;
import org.python.pydev.ast.interpreter_managers.InterpreterInfo;
import org.python.pydev.ast.interpreter_managers.InterpreterManagersAPI;
import org.python.pydev.core.*;
import org.python.pydev.plugin.nature.PythonNature;

import com.python.pydev.debug.remote.client_api.PydevRemoteDebuggerServer;

import ghidradev.EclipseMessageUtils;
import utilities.util.ArrayUtilities;

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
	 * Checks to see if PyDev is installed.
	 * 
	 * @return True if PyDev is installed; otherwise, false.
	 * @throws NoClassDefFoundError if PyDev is not installed.
	 */
	public static boolean isPyDevInstalled() throws NoClassDefFoundError {
		for (Bundle bundle : FrameworkUtil.getBundle(
			PyDevUtilsInternal.class).getBundleContext().getBundles()) {
			if (bundle.getSymbolicName().contains("pydev")) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Gets a list of discovered Jython 2.7 interpreter names.
	 *  
	 * @return a list of discovered Jython 2.7 interpreter names.
	 * @throws NoClassDefFoundError if PyDev is not installed or it does not support this operation.
	 * @throws NoSuchMethodError if PyDev is not installed or it does not support this operation.
	 */
	public static List<String> getJython27InterpreterNames()
			throws NoClassDefFoundError, NoSuchMethodError {

		List<String> interpreters = new ArrayList<>();
		IInterpreterManager iMan = InterpreterManagersAPI.getJythonInterpreterManager(true);

		for (IInterpreterInfo info : iMan.getInterpreterInfos()) {
			if (info.getInterpreterType() == IPythonNature.INTERPRETER_TYPE_JYTHON && info.getVersion().equals("2.7")) {
				interpreters.add(info.getName());
			}
		}

		return interpreters;
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
		iMan.setInfos(ArrayUtilities.copyAndAppend(iMan.getInterpreterInfos(), iInfo), null,
			monitor);
	}

	/**
	 * Sets up Python for the given Java project.
	 * 
	 * @param javaProject The Java project to setup Python for.
	 * @param classpathEntries The classpath entries to add to the Python path.
	 * @param jythonInterpreterName The name of the Jython interpreter to use for Python support.
	 *   If this is null, Python support will be removed from the project.
	 * @param monitor The progress monitor used during link.
	 * @throws CoreException If there was an Eclipse-related problem with enabling Python for the project.
	 * @throws NoClassDefFoundError if PyDev is not installed or it does not support this operation.
	 * @throws NoSuchMethodError if PyDev is not installed or it does not support this operation.
	 */
	public static void setupPythonForProject(IJavaProject javaProject,
			List<IClasspathEntry> classpathEntries, String jythonInterpreterName,
			IProgressMonitor monitor)
			throws CoreException, NoClassDefFoundError, NoSuchMethodError {

		PythonNature.removeNature(javaProject.getProject(), monitor);

		if (jythonInterpreterName != null) {
			String libs = classpathEntries.stream().map(e -> e.getPath().toOSString()).collect(
				Collectors.joining("|"));
			PythonNature.addNature(javaProject.getProject(), monitor,
				IPythonNature.JYTHON_VERSION_2_7, null, libs, jythonInterpreterName, null);
		}
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

	private PyDevUtilsInternal() throws NoClassDefFoundError {
		// Prevent instantiation 
	}
}
