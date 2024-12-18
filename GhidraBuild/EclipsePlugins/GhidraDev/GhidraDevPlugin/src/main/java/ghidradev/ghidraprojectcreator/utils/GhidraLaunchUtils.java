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

import java.util.ArrayList;
import java.util.List;

import org.eclipse.core.runtime.CoreException;
import org.eclipse.core.runtime.IPath;
import org.eclipse.debug.core.*;
import org.eclipse.debug.internal.ui.DebugUIPlugin;
import org.eclipse.debug.internal.ui.launchConfigurations.LaunchConfigurationManager;
import org.eclipse.debug.internal.ui.launchConfigurations.LaunchHistory;
import org.eclipse.debug.ui.IDebugUIConstants;
import org.eclipse.jdt.core.IClasspathEntry;
import org.eclipse.jdt.core.IJavaProject;
import org.eclipse.jdt.launching.*;

import ghidra.Ghidra;

/**
 * Utility methods for working with Ghidra launchers in Eclipse.
 */
@SuppressWarnings("restriction")
public class GhidraLaunchUtils {

	/**
	 * Launch configuration ID for a Ghidra GUI launch. Must match corresponding value in 
	 * plugin.xml.
	 */
	public static final String GUI_LAUNCH = "GhidraGuiLaunchConfigurationType";

	/**
	 * Launch configuration ID for a Ghidra Headless launch. Must match corresponding value in 
	 * plugin.xml.
	 */
	public static final String HEADLESS_LAUNCH = "GhidraHeadlessLaunchConfigurationType";

	/**
	 * Program arguments that will get passed to the launched Ghidra.  These will be appended
	 * to the required program arguments that are required to launch Ghidra, which are hidden
	 * from the user.
	 */
	public static final String ATTR_PROGAM_ARGUMENTS = "ghidradev.ghidraProgramArguments";

	/**
	 * VM arguments that will get passed to the launched Ghidra.  These will be appended
	 * to the required VM arguments that are required to launch Ghidra, which are hidden
	 * from the user.
	 */
	public static final String ATTR_VM_ARGUMENTS = "ghidradev.ghidraVmArguments";

	/**
	 * Creates a new launch configuration for the given Java project.
	 * 
	 * @param javaProject The Java project to create a launch configuration for.
	 * @param launchConfigTypeId The type of launch configuration.
	 * @param launchConfigName The name of the launch configuration.
	 * @param runConfigMemory The run configuration's desired memory.  Could be null.
	 * @return A launch configuration working copy.
	 * @throws CoreException If there was an Eclipse-related problem with creating the launch 
	 *   configuration.
	 */
	public static ILaunchConfigurationWorkingCopy createLaunchConfig(IJavaProject javaProject,
			String launchConfigTypeId, String launchConfigName, String runConfigMemory)
			throws CoreException {
		ILaunchManager launchManager = DebugPlugin.getDefault().getLaunchManager();
		ILaunchConfigurationType launchType =
			launchManager.getLaunchConfigurationType(launchConfigTypeId);
		ILaunchConfigurationWorkingCopy wc = launchType.newInstance(null, launchConfigName);
		wc.setAttribute(IJavaLaunchConfigurationConstants.ATTR_PROJECT_NAME,
			javaProject.getProject().getName());
		setMainTypeName(wc);
		setMemory(wc, runConfigMemory);
		setClasspath(wc);
		setSource(wc);
		setFavorites(wc);
		return wc;
	}

	/**
	 * Gets the launch configuration with the given name.
	 * 
	 * @param name The name of the launch configuration to get.
	 * @return The launch configuration with the given name, or null if it doesn't exist.
	 * @throws CoreException If there was an Eclipse-related problem with getting the launch 
	 *   configuration.	 
	 */
	public static ILaunchConfiguration getLaunchConfig(String name) throws CoreException {
		ILaunchManager launchManager = DebugPlugin.getDefault().getLaunchManager();
		for (ILaunchConfiguration lc : launchManager.getLaunchConfigurations()) {
			if (lc.getName().equals(name)) {
				return lc;
			}
		}
		return null;
	}

	/**
	 * Gets the launch configuration with the given name and the given type ID.
	 * 
	 * @param name The name of the launch configuration to get.
	 * @param id The launch configuration type id of the launch configuration to get.
	 * @return The launch configuration with the given name and type, or null if it doesn't exist.
	 * @throws CoreException If there was an Eclipse-related problem with getting the launch 
	 *   configuration.	 
	 */
	public static ILaunchConfiguration getLaunchConfig(String name, String id)
			throws CoreException {
		ILaunchManager launchManager = DebugPlugin.getDefault().getLaunchManager();
		ILaunchConfigurationType type = launchManager.getLaunchConfigurationType(id);
		if (type != null) {
			for (ILaunchConfiguration lc : launchManager.getLaunchConfigurations(type)) {
				if (lc.getName().equals(name)) {
					return lc;
				}
			}
		}
		return null;
	}

	/**
	 * Sets the main type name attribute in the provided working copy.  For Ghidra projects, this 
	 * should be {@link Ghidra}.
	 * 
	 * @param wc The launch configuration working copy to modify.
	 * @return The modified working copy.
	 */
	public static ILaunchConfigurationWorkingCopy setMainTypeName(
			ILaunchConfigurationWorkingCopy wc) {
		wc.setAttribute(IJavaLaunchConfigurationConstants.ATTR_MAIN_TYPE_NAME,
			Ghidra.class.getName());
		return wc;
	}

	/**
	 * Appends the maximum Java heap size (-Xmx) to the VM arguments in the provided working copy.
	 * 
	 * @param memory The desired maximum Java heap size.  Could be null if the default is to be 
	 *   used.
	 * @param wc The launch configuration working copy to modify.
	 * @return The modified working copy.
	 * @throws CoreException if there was an Eclipse-related issue appending the VM argument.
	 * 
	 * @see #ATTR_VM_ARGUMENTS
	 */
	public static ILaunchConfigurationWorkingCopy setMemory(ILaunchConfigurationWorkingCopy wc,
			String memory) throws CoreException {
		if (memory != null) {
			String vmArgs = wc.getAttribute(ATTR_VM_ARGUMENTS, "");
			if (!vmArgs.isEmpty()) {
				vmArgs += " ";
			}
			wc.setAttribute(ATTR_VM_ARGUMENTS, vmArgs + "-Xmx" + memory);
		}
		return wc;
	}

	/**
	 * Removes all project jars from the classpath except Utility.jar.
	 * 
	 * @param wc The launch configuration working copy to modify.
	 * @return The modified working copy.
	 * @throws CoreException if there was an Eclipse-related issue modifying the classpath.
	 */
	public static ILaunchConfigurationWorkingCopy setClasspath(ILaunchConfigurationWorkingCopy wc)
			throws CoreException {
		List<String> newList = new ArrayList<>();
		for (IRuntimeClasspathEntry entry : JavaRuntime.computeUnresolvedRuntimeClasspath(wc)) {
			switch (entry.getClasspathEntry().getEntryKind()) {
				case IClasspathEntry.CPE_LIBRARY:
					if (entry.getPath().toOSString().endsWith("Utility.jar")) {
						newList.add(entry.getMemento());
					}
					break;
				case IClasspathEntry.CPE_CONTAINER:
					newList.add(entry.getMemento());
					break;
				case IClasspathEntry.CPE_PROJECT:
				case IClasspathEntry.CPE_SOURCE:
				case IClasspathEntry.CPE_VARIABLE:
				default:
					break;
			}
		}
		wc.setAttribute(IJavaLaunchConfigurationConstants.ATTR_CLASSPATH, newList);
		wc.setAttribute(IJavaLaunchConfigurationConstants.ATTR_DEFAULT_CLASSPATH, false);
		return wc;
	}

	/**
	 * Adds all project jars that have associated source to the source path
	 * 
	 * @param wc The launch configuration working copy to modify.
	 * @return The modified working copy.
	 * @throws CoreException if there was an Eclipse-related issue modifying the source path.
	 */
	public static ILaunchConfigurationWorkingCopy setSource(ILaunchConfigurationWorkingCopy wc)
			throws CoreException {
		List<String> newList = new ArrayList<>();
		IJavaProject javaProject = JavaRuntime.getJavaProject(wc);
		if (javaProject != null) {

			// Add current project (might need to add dependent projects later)
			newList.add(JavaRuntime.newProjectRuntimeClasspathEntry(javaProject).getMemento());

			// Add JDK
			newList.add(JavaRuntime
					.newRuntimeContainerClasspathEntry(
						JavaRuntime.newJREContainerPath(JavaRuntime.getVMInstall(javaProject)),
						IRuntimeClasspathEntry.STANDARD_CLASSES)
					.getMemento());

			// Add Ghidra jar source
			for (IClasspathEntry entry : javaProject.getRawClasspath()) {
				IPath sourcePath = entry.getSourceAttachmentPath();
				if (sourcePath != null) {
					newList.add(
						JavaRuntime.newArchiveRuntimeClasspathEntry(sourcePath).getMemento());
				}
			}
		}
		wc.setAttribute(IJavaLaunchConfigurationConstants.ATTR_SOURCE_PATH, newList);
		wc.setAttribute(IJavaLaunchConfigurationConstants.ATTR_DEFAULT_SOURCE_PATH, false);
		return wc;
	}

	/**
	 * Sets the favorites attribute in the provided working copy to include the launcher in both 
	 * the run and debug launch groups.
	 * 
	 * @param wc The launch configuration working copy to modify.
	 * @return The modified working copy.
	 * @throws CoreException If there was an Eclipse-related problem with setting the favorites
	 *   attribute.
	 */
	public static ILaunchConfigurationWorkingCopy setFavorites(ILaunchConfigurationWorkingCopy wc)
			throws CoreException {
		List<String> list =
			wc.getAttribute(IDebugUIConstants.ATTR_FAVORITE_GROUPS, new ArrayList<>());
		list.add(IDebugUIConstants.ID_DEBUG_LAUNCH_GROUP);
		list.add(IDebugUIConstants.ID_RUN_LAUNCH_GROUP);
		wc.setAttribute(IDebugUIConstants.ATTR_FAVORITE_GROUPS, list);
		return wc;
	}

	/**
	 * Adds the given launch configuration to the GUI's favorites list.  This is useful to do if
	 * you create a launch configuration and want it to appear in the favorites list before ever
	 * launching it.
	 * 
	 * @param launchConfig The launch configuration to add.
	 */
	public static void addToFavorites(ILaunchConfiguration launchConfig) {
		LaunchConfigurationManager mgr = DebugUIPlugin.getDefault().getLaunchConfigurationManager();
		LaunchHistory runHistory = mgr.getLaunchHistory(IDebugUIConstants.ID_RUN_LAUNCH_GROUP);
		LaunchHistory debugHistory = mgr.getLaunchHistory(IDebugUIConstants.ID_DEBUG_LAUNCH_GROUP);
		runHistory.addFavorite(launchConfig);
		debugHistory.addFavorite(launchConfig);
	}
}
