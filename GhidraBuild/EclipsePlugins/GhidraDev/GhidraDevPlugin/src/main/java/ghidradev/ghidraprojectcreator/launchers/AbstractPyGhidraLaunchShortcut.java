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

import javax.naming.OperationNotSupportedException;

import org.eclipse.core.resources.IProject;
import org.eclipse.core.resources.IResource;
import org.eclipse.core.runtime.*;
import org.eclipse.debug.core.*;
import org.eclipse.debug.ui.ILaunchShortcut;
import org.eclipse.jface.viewers.ISelection;
import org.eclipse.ui.IEditorInput;
import org.eclipse.ui.IEditorPart;

import ghidradev.Activator;
import ghidradev.EclipseMessageUtils;
import ghidradev.ghidraprojectcreator.testers.GhidraProjectPropertyTester;
import ghidradev.ghidraprojectcreator.utils.*;

/**
 * PyGhidra launch shortcut actions.  These shortcuts appear when you right click on a 
 * PyGhidra project or file and select "Run As" or "Debug As".
 * <p>
 * The {@link GhidraProjectPropertyTester} is used to determine whether or not the shortcuts appear.
 */
public abstract class AbstractPyGhidraLaunchShortcut implements ILaunchShortcut {

	private String launchConfigTypeId;
	private String launchConfigNameSuffix;

	/**
	 * Creates a new PyGhidra launch shortcut associated with the given launch configuration type ID.
	 * 
	 * @param launchConfigTypeId The launch configuration type ID of this PyGhidra launch shortcut.
	 * @param launchConfigNameSuffix A string to append to the name of the launch configuration.
	 */
	protected AbstractPyGhidraLaunchShortcut(String launchConfigTypeId,
			String launchConfigNameSuffix) {
		this.launchConfigTypeId = launchConfigTypeId;
		this.launchConfigNameSuffix = launchConfigNameSuffix;
	}

	@Override
	public void launch(ISelection selection, String mode) {
		IProject project = GhidraProjectUtils.getSelectedProject(selection);
		if (project != null) {
			launch(project, mode);
		}
	}

	@Override
	public void launch(IEditorPart editor, String mode) {
		IEditorInput input = editor.getEditorInput();
		IResource resource = input.getAdapter(IResource.class);
		if (resource != null) {
			launch(resource.getProject(), mode);
		}
	}

	/**
	 * Launches the given Python nature in the given mode with a PyGhidra launcher.
	 * 
	 * @param project The project to launch.
	 * @param mode The mode to launch in (run/debug).
	 */
	private void launch(IProject project, String mode) {
		ILaunchManager launchManager = DebugPlugin.getDefault().getLaunchManager();
		ILaunchConfigurationType launchType =
			launchManager.getLaunchConfigurationType(launchConfigTypeId);
		String launchConfigName = project.getName() + launchConfigNameSuffix;
		try {
			ILaunchConfiguration lc = GhidraLaunchUtils.getLaunchConfig(launchConfigName);
			ILaunchConfigurationWorkingCopy wc = null;
			if (lc == null) {
				wc = launchType.newInstance(null, launchConfigName);
				wc.setAttribute(PyDevUtils.getAttrProject(), project.getName());
			}
			else if (lc.getType().equals(launchType)) {
				wc = lc.getWorkingCopy();
			}
			else {
				throw new CoreException(new Status(IStatus.ERROR, Activator.PLUGIN_ID,
					IStatus.ERROR, "Failed to launch. Run configuration with name \"" +
						launchConfigName + "\" already exists.",
					null));
			}
			wc.doSave().launch(mode, null);
		}
		catch (CoreException | OperationNotSupportedException e) {
			EclipseMessageUtils.showErrorDialog(e.getMessage());
		}
	}
}
