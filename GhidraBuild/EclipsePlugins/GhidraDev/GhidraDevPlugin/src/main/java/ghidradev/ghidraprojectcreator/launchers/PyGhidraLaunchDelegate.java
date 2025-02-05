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
package ghidradev.ghidraprojectcreator.launchers;

import java.io.File;
import java.io.IOException;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

import javax.naming.OperationNotSupportedException;

import org.eclipse.core.resources.IFolder;
import org.eclipse.core.resources.IProject;
import org.eclipse.core.runtime.CoreException;
import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.debug.core.*;
import org.eclipse.debug.ui.IDebugUIConstants;
import org.eclipse.jdt.core.IJavaProject;
import org.eclipse.swt.widgets.Display;
import org.eclipse.ui.IPerspectiveDescriptor;
import org.eclipse.ui.PlatformUI;
import org.python.pydev.debug.ui.launching.RegularLaunchConfigurationDelegate;

import ghidra.launch.AppConfig;
import ghidradev.EclipseMessageUtils;
import ghidradev.ghidraprojectcreator.utils.GhidraProjectUtils;
import ghidradev.ghidraprojectcreator.utils.PyDevUtils;

/**
 * The PyGhidra Launch delegate handles the final launch of PyGhidra.
 * We can do any extra custom launch behavior here.
 */
public class PyGhidraLaunchDelegate extends RegularLaunchConfigurationDelegate {

	@Override
	public void launch(ILaunchConfiguration configuration, String mode, ILaunch launch,
			IProgressMonitor monitor) throws CoreException {

		try {
			ILaunchConfigurationWorkingCopy wc = configuration.getWorkingCopy();

			// Get project
			String projectName = wc.getAttribute(PyDevUtils.getAttrProject(), "");
			IJavaProject javaProject = GhidraProjectUtils.getGhidraProject(projectName);
			if (javaProject == null) {
				EclipseMessageUtils.showErrorDialog("Failed to launch project \"" + projectName +
					"\".\nDoes not appear to be a Ghidra project.");
				return;
			}
			IProject project = javaProject.getProject();

			// Get needed application.properties values
			String javaComplianceLevel = null;
			String ghidraVmErrorMsg = "";
			try {
				IFolder ghidraFolder = project.getFolder(GhidraProjectUtils.GHIDRA_FOLDER_NAME);
				String ghidraInstallPath = ghidraFolder.getLocation().toOSString();
				AppConfig appConfig = new AppConfig(new File(ghidraInstallPath));
				javaComplianceLevel = appConfig.getCompilerComplianceLevel();
			}
			catch (ParseException | IOException e) {
				ghidraVmErrorMsg = e.getMessage();
			}
			if (javaComplianceLevel == null) {
				EclipseMessageUtils
						.showErrorDialog("Failed to get JVM compliance level from project \"" +
							projectName + "\".\n" + ghidraVmErrorMsg);
				return;
			}

			// Set program location
			wc.setAttribute(PyDevUtils.getAttrLocation(),
				"${workspace_loc:%s/Ghidra/Ghidra/Features/PyGhidra/pypkg/src/pyghidra}"
						.formatted(project.getName()));

			// Set program arguments
			wc.setAttribute(PyDevUtils.getAttrProgramArguments(), "-v -g");

			// Set Python interpreter
			String interpreterName = PyDevUtils.getInterpreterName(project);
			wc.setAttribute(PyDevUtils.getAttrInterpreter(), interpreterName);
			wc.setAttribute(PyDevUtils.getAttrInterpreterDefault(), interpreterName);

			// Set environment variables
			Map<String, String> env = new HashMap<>();
			//env.put("GHIDRA_INSTALL_DIR", "${project_loc:/%s/Ghidra}".formatted(project.getName()));
			env.put("GHIDRA_INSTALL_DIR",
				"${resource_loc:/%s/Ghidra}".formatted(project.getName()));
			env.put("JAVA_HOME_OVERRIDE", "${ee_home:JavaSE-%s}".formatted(javaComplianceLevel));
			if (mode.equals("debug")) {
				env.put("PYGHIDRA_DEBUG", "1");
				handleDebugMode();
			}
			wc.setAttribute(ILaunchManager.ATTR_ENVIRONMENT_VARIABLES, env);

			super.launch(wc.doSave(), mode, launch, monitor);
		}
		catch (OperationNotSupportedException e) {
			EclipseMessageUtils.showErrorDialog("PyDev error",
				"Failed to launch. PyDev version is not supported.");
		}
	}

	/**
	 * Handles extra things that should happen when we are launching in debug mode.
	 */
	private static void handleDebugMode() {
		Display.getDefault().asyncExec(() -> {

			// Switch to debug perspective
			if (PlatformUI.getWorkbench() != null) {
				IPerspectiveDescriptor descriptor =
					PlatformUI.getWorkbench().getPerspectiveRegistry().findPerspectiveWithId(
						IDebugUIConstants.ID_DEBUG_PERSPECTIVE);
				EclipseMessageUtils.getWorkbenchPage().setPerspective(descriptor);
			}

			// Start PyDev debugger
			try {
				PyDevUtils.startPyDevRemoteDebugger();
			}
			catch (OperationNotSupportedException e) {
				EclipseMessageUtils.error(
					"Failed to start the PyDev remote debugger.  PyDev version is not supported.");
			}
		});
	}
}
