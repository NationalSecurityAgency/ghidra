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

import org.eclipse.core.resources.IProject;
import org.eclipse.core.resources.IResource;
import org.eclipse.core.runtime.CoreException;
import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.jdt.core.IJavaProject;
import org.eclipse.jface.viewers.ISelection;
import org.eclipse.jface.wizard.Wizard;

import ghidra.GhidraApplicationLayout;
import ghidra.launch.AppConfig;
import ghidradev.ghidraprojectcreator.utils.GhidraProjectUtils;
import ghidradev.ghidraprojectcreator.utils.PyDevUtils.ProjectPythonInterpreter;
import ghidradev.ghidraprojectcreator.wizards.pages.*;

/**
 * Wizard for linking a Java project's classpath and external links to a Ghidra installation directory.
 */
public class LinkGhidraWizard extends Wizard {

	private ChooseGhidraInstallationWizardPage ghidraInstallationPage;
	private ChooseJavaProjectWizardPage projectPage;
	private EnablePythonWizardPage pythonPage;

	public LinkGhidraWizard(ISelection selection) {
		setNeedsProgressMonitor(true);
		this.ghidraInstallationPage = new ChooseGhidraInstallationWizardPage();
		this.projectPage =
			new ChooseJavaProjectWizardPage((GhidraProjectUtils.getSelectedProject(selection)));
		this.pythonPage = new EnablePythonWizardPage(ghidraInstallationPage);
	}

	@Override
	public void addPages() {
		addPage(ghidraInstallationPage);
		addPage(projectPage);
		addPage(pythonPage);
	}

	@Override
	public boolean performFinish() {
		File ghidraInstallDir = ghidraInstallationPage.getGhidraInstallDir();
		IJavaProject javaProject = projectPage.getJavaProject();
		ProjectPythonInterpreter pythonInterpreter = pythonPage.getProjectPythonInterpreter();
		try {
			getContainer().run(true, false,
				monitor -> link(ghidraInstallDir, javaProject, pythonInterpreter, monitor));
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
	 * Links a Java project's classpath and external links to a Ghidra installation directory.
	 *  
	 * @param ghidraInstallDir The Ghidra installation directory to use.
	 * @param javaProject The Java project to link.
	 * @param pythonInterpreter The Python interpreter to use.
	 * @param monitor The monitor to use during project link.
	 * @throws InvocationTargetException if an error occurred during link.
	 */
	private void link(File ghidraInstallDir, IJavaProject javaProject,
			ProjectPythonInterpreter pythonInterpreter, IProgressMonitor monitor)
			throws InvocationTargetException {
		IProject project = javaProject.getProject();
		try {
			info("Linking " + project.getName());
			monitor.beginTask("Linking " + project.getName(), 2);

			GhidraApplicationLayout ghidraLayout = new GhidraApplicationLayout(ghidraInstallDir);
			AppConfig appConfig =
				new AppConfig(ghidraLayout.getApplicationInstallationDir().getFile(false));
			GhidraProjectUtils.linkGhidraToProject(javaProject, ghidraLayout, appConfig,
				pythonInterpreter, monitor);
			monitor.worked(1);

			project.refreshLocal(IResource.DEPTH_INFINITE, monitor);
			monitor.worked(1);

			info("Finished linking " + project.getName());
		}
		catch (IOException | ParseException | CoreException e) {
			throw new InvocationTargetException(e);
		}
		finally {
			monitor.done();
		}
	}
}
