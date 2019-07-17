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

import javax.naming.OperationNotSupportedException;

import org.eclipse.core.resources.*;
import org.eclipse.core.runtime.*;
import org.eclipse.debug.core.*;
import org.eclipse.debug.ui.IDebugUIConstants;
import org.eclipse.jdt.core.IClasspathEntry;
import org.eclipse.jdt.core.IJavaProject;
import org.eclipse.jdt.launching.IJavaLaunchConfigurationConstants;
import org.eclipse.jdt.launching.JavaLaunchDelegate;
import org.eclipse.swt.widgets.Display;
import org.eclipse.ui.IPerspectiveDescriptor;
import org.eclipse.ui.PlatformUI;

import ghidra.launch.JavaConfig;
import ghidradev.EclipseMessageUtils;
import ghidradev.ghidraprojectcreator.utils.*;

/**
 * The Ghidra Launch delegate handles the final launch of Ghidra.
 * We can do any extra custom launch behavior here.
 */
public class GhidraLaunchDelegate extends JavaLaunchDelegate {

	@Override
	public void launch(ILaunchConfiguration configuration, String mode, ILaunch launch,
			IProgressMonitor monitor) throws CoreException {

		boolean isHeadless =
			configuration.getType().getIdentifier().equals(GhidraLaunchUtils.HEADLESS_LAUNCH);
		ILaunchConfigurationWorkingCopy wc = configuration.getWorkingCopy();
		
		// Get the launch properties associated with the version of Ghidra that is trying to launch
		String projectName =
			wc.getAttribute(IJavaLaunchConfigurationConstants.ATTR_PROJECT_NAME, "");
		IJavaProject javaProject = GhidraProjectUtils.getGhidraProject(projectName);
		if (javaProject == null) {
			EclipseMessageUtils.showErrorDialog("Failed to launch project \"" + projectName +
				"\".\nDoes not appear to be a Ghidra project.");
			return;
		}
		IFolder ghidraFolder =
			javaProject.getProject().getFolder(GhidraProjectUtils.GHIDRA_FOLDER_NAME);
		JavaConfig javaConfig;
		String ghidraInstallPath = ghidraFolder.getLocation().toOSString();
		try {
			javaConfig = new JavaConfig(new File(ghidraInstallPath));
		}
		catch (ParseException | IOException e) {
			EclipseMessageUtils.showErrorDialog(
				"Failed to launch project \"" + projectName + "\".\n" + e.getMessage());
			return;
		}

		// Set program arguments
		String customProgramArgs =
			configuration.getAttribute(GhidraLaunchUtils.ATTR_PROGAM_ARGUMENTS, "").trim();
		String programArgs =
			isHeadless ? "ghidra.app.util.headless.AnalyzeHeadless" : "ghidra.GhidraRun";
		programArgs += " " + customProgramArgs;
		wc.setAttribute(IJavaLaunchConfigurationConstants.ATTR_PROGRAM_ARGUMENTS, programArgs);
		if (isHeadless && customProgramArgs.isEmpty()) {
			EclipseMessageUtils.showInfoDialog("Ghidra Run Configuration",
				"Headless launch is being performed without any command line arguments!\n\n" +
					"Edit the \"" + configuration.getName() +
					"\" run configuration's program arguments to customize headless behavior. " +
					"See support/analyzeHeadlessREADME.html for more information.");
		}

		// Set VM arguments
		String vmArgs = javaConfig.getLaunchProperties().getVmArgs();
		vmArgs += " " + configuration.getAttribute(GhidraLaunchUtils.ATTR_VM_ARGUMENTS, "").trim();
		vmArgs += " " + "-Declipse.install.dir=\"" +
			Platform.getInstallLocation().getURL().getFile() + "\"";
		vmArgs += " " + "-Declipse.workspace.dir=\"" +
			ResourcesPlugin.getWorkspace().getRoot().getLocation() + "\"";
		vmArgs += " " + "-Declipse.project.dir=\"" + javaProject.getProject().getLocation() + "\"";
		vmArgs += " " + "-Declipse.project.dependencies=\"" +
			getProjectDependencyDirs(javaProject) + "\"";
		File pyDevSrcDir = PyDevUtils.getPyDevSrcDir();
		if (pyDevSrcDir != null) {
			vmArgs += " " + "-Declipse.pysrc.dir=\"" + pyDevSrcDir + "\"";
		}
		wc.setAttribute(IJavaLaunchConfigurationConstants.ATTR_VM_ARGUMENTS, vmArgs);

		// Handle special debug mode tasks
		if (mode.equals("debug")) {
			handleDebugMode();
		}

		super.launch(wc.doSave(), mode, launch, monitor);
	}

	/**
	 * For the given Java project, gets all of its classpath dependencies that are themselves 
	 * projects.  The result is formatted as a string of paths separated by 
	 * {@link File#pathSeparator}.
	 *   
	 * @param javaProject The Java project whose project dependencies we are getting.
	 * @return A string of paths separated by {@link File#pathSeparator} that represents the given
	 *   Java project's dependencies that are projects.  Could be empty if there are no 
	 *   dependencies.
	 * @throws CoreException if there was an Eclipse-related problem with getting the dependencies.
	 */
	private static String getProjectDependencyDirs(IJavaProject javaProject) throws CoreException {
		String paths = "";
		for (IClasspathEntry entry : javaProject.getRawClasspath()) {
			if (entry.getEntryKind() == IClasspathEntry.CPE_PROJECT) {
				if (!paths.isEmpty()) {
					paths += File.pathSeparator;
				}
				IResource resource =
					ResourcesPlugin.getWorkspace().getRoot().findMember(entry.getPath());
				if (resource != null) {
					paths += resource.getLocation();
				}
			}
		}
		return paths;
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
			if (PyDevUtils.isSupportedPyDevInstalled()) {
				try {
					PyDevUtils.startPyDevRemoteDebugger();
				}
				catch (OperationNotSupportedException e) {
					EclipseMessageUtils.error(
						"Failed to start the PyDev remote debugger.  PyDev version is not supported.");
				}
			}
		});
	}
}
