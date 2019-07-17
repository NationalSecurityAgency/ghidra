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
package ghidradev.ghidraprojectcreator.wizards;

import static ghidradev.EclipseMessageUtils.*;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.text.ParseException;
import java.util.*;

import org.eclipse.buildship.core.GradleDistribution;
import org.eclipse.buildship.core.internal.CorePlugin;
import org.eclipse.buildship.core.internal.launch.GradleLaunchConfigurationManager;
import org.eclipse.buildship.core.internal.launch.GradleRunConfigurationAttributes;
import org.eclipse.core.resources.IProject;
import org.eclipse.core.resources.IResource;
import org.eclipse.core.runtime.CoreException;
import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.debug.core.ILaunchConfiguration;
import org.eclipse.debug.core.ILaunchManager;
import org.eclipse.jdt.core.IJavaProject;
import org.eclipse.jface.viewers.IStructuredSelection;
import org.eclipse.jface.wizard.Wizard;
import org.eclipse.ui.INewWizard;
import org.eclipse.ui.IWorkbench;

import ghidra.GhidraApplicationLayout;
import ghidra.launch.JavaConfig;
import ghidradev.ghidraprojectcreator.utils.GhidraProjectUtils;
import ghidradev.ghidraprojectcreator.wizards.pages.ChooseGhidraModuleProjectWizardPage;
import ghidradev.ghidraprojectcreator.wizards.pages.ConfigureGradleWizardPage;

/**
 * Wizard for exporting a Ghidra module project to a releasable extension zip bundle.  
 */
@SuppressWarnings("restriction")
public class ExportGhidraModuleWizard extends Wizard implements INewWizard {

	private ChooseGhidraModuleProjectWizardPage projectPage;
	private ConfigureGradleWizardPage gradlePage;

	/**
	 * Creates a new Ghidra module export wizard.
	 */
	public ExportGhidraModuleWizard() {
		setNeedsProgressMonitor(true);
	}

	@Override
	public void init(IWorkbench wb, IStructuredSelection selection) {
		projectPage = new ChooseGhidraModuleProjectWizardPage(
			GhidraProjectUtils.getSelectedProject(selection));
		gradlePage = new ConfigureGradleWizardPage(projectPage);
	}

	@Override
	public void addPages() {
		addPage(projectPage);
		addPage(gradlePage);
	}

	@Override
	public boolean performFinish() {
		IJavaProject javaProject = projectPage.getGhidraModuleProject();
		GradleDistribution gradleDist = gradlePage.getGradleDistribution();
		try {
			getContainer().run(true, false, monitor -> export(javaProject, gradleDist, monitor));
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			return false;
		}
		catch (InvocationTargetException e) {
			error(showWizardErrorDialog(getShell(), e), e);
			return false;
		}

		return true;
	}

	/**
	 * Exports the given Ghidra module project to an extension zip file.
	 *  
	 * @param javaProject The Ghidra module project to export.
	 * @param gradleDistribution The Gradle distribution to use to export.
	 * @param monitor The monitor to use during export.
	 * @throws InvocationTargetException if an error occurred during export.
	 */
	private void export(IJavaProject javaProject, GradleDistribution gradleDistribution,
			IProgressMonitor monitor)
			throws InvocationTargetException {
		try {
			IProject project = javaProject.getProject();
			info("Exporting " + project.getName());
			monitor.beginTask("Exporting " + project.getName(), 2);

			// Get path to Ghidra installation directory
			String ghidraInstallDirPath = project.getFolder(
				GhidraProjectUtils.GHIDRA_FOLDER_NAME).getLocation().toOSString();
			
			// Get project's java.  Gradle should use the same version.
			// TODO: It's more correct to get this from the project's classpath, since Ghidra's
			// saved Java home can change from launch to launch.  
			GhidraApplicationLayout ghidraLayout = new GhidraApplicationLayout(new File(ghidraInstallDirPath));
			File javaHomeDir = new JavaConfig(
				ghidraLayout.getApplicationInstallationDir().getFile(false)).getSavedJavaHome();
			if(javaHomeDir == null) {
				throw new IOException("Failed to get the Java home associated with the project.  " +
					"Perform a \"Link Ghidra\" operation on the project and try again.");
			}

			// Setup the Gradle build attributes
			List<String> tasks = new ArrayList<>();
			String workingDir = project.getLocation().toOSString();
			String gradleDist = gradleDistribution.toString();
			String gradleUserHome = "";
			String javaHome = javaHomeDir.getAbsolutePath();
			List<String> jvmArgs = new ArrayList<>();
			List<String> gradleArgs =
				Arrays.asList(new String[] { "-PGHIDRA_INSTALL_DIR=" + ghidraInstallDirPath });
			boolean showExecutionView = false;
			boolean showConsoleView = true;
			boolean overrideWorkspaceSettings = true;
			boolean isOffline = true;
			boolean isBuildScansEnabled = false;
			GradleRunConfigurationAttributes gradleAttributes =
				new GradleRunConfigurationAttributes(tasks, workingDir, gradleDist, gradleUserHome,
					javaHome, jvmArgs, gradleArgs, showExecutionView, showConsoleView,
					overrideWorkspaceSettings, isOffline, isBuildScansEnabled);

			// Launch Gradle
			GradleLaunchConfigurationManager lm = CorePlugin.gradleLaunchConfigurationManager();
			ILaunchConfiguration lc = lm.getOrCreateRunConfiguration(gradleAttributes);
			lc.launch(ILaunchManager.RUN_MODE, monitor, true, true);
			lc.delete();

			monitor.worked(1);

			project.refreshLocal(IResource.DEPTH_INFINITE, monitor);
			monitor.worked(1);

			info("Finished exporting " + project.getName());
		}
		catch (IOException | ParseException | CoreException e) {
			throw new InvocationTargetException(e);
		}
		finally {
			monitor.done();
		}
	}
}
