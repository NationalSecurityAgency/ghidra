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

import org.eclipse.core.runtime.CoreException;
import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.jface.viewers.IStructuredSelection;
import org.eclipse.jface.wizard.Wizard;
import org.eclipse.ui.INewWizard;
import org.eclipse.ui.IWorkbench;

import ghidra.GhidraApplicationLayout;
import ghidradev.EclipseMessageUtils;
import ghidradev.ghidraprojectcreator.utils.GhidraScriptUtils;
import ghidradev.ghidraprojectcreator.wizards.pages.*;
import utilities.util.FileUtilities;

/**
 * Wizard to create a new Ghidra scripting project.
 */
public class CreateGhidraScriptProjectWizard extends Wizard implements INewWizard {

	private CreateGhidraProjectWizardPage projectPage;
	private ConfigureGhidraScriptProjectWizardPage projectConfigPage;
	private ChooseGhidraInstallationWizardPage ghidraInstallationPage;
	private EnablePythonWizardPage pythonPage;

	/**
	 * Creates a new Ghidra scripting project wizard.
	 */
	public CreateGhidraScriptProjectWizard() {
		setNeedsProgressMonitor(true);
	}

	@Override
	public void init(IWorkbench wb, IStructuredSelection selection) {
		projectPage = new CreateGhidraProjectWizardPage("GhidraScripts");
		projectConfigPage = new ConfigureGhidraScriptProjectWizardPage();
		ghidraInstallationPage = new ChooseGhidraInstallationWizardPage();
		pythonPage = new EnablePythonWizardPage(ghidraInstallationPage);
	}

	@Override
	public void addPages() {
		addPage(projectPage);
		addPage(projectConfigPage);
		addPage(ghidraInstallationPage);
		addPage(pythonPage);
	}

	@Override
	public boolean performFinish() {
		if (!validate()) {
			return false;
		}

		File ghidraInstallDir = ghidraInstallationPage.getGhidraInstallDir();
		String projectName = projectPage.getProjectName();
		File projectDir = projectPage.getProjectDir();
		boolean createRunConfig = projectPage.shouldCreateRunConfig();
		String runConfigMemory = projectPage.getRunConfigMemory();
		boolean linkUserScripts = projectConfigPage.shouldLinkUsersScripts();
		boolean linkSystemScripts = projectConfigPage.shouldLinkSystemScripts();
		String jythonInterpreterName = pythonPage.getJythonInterpreterName();
		try {
			getContainer().run(true, false,
				monitor -> create(ghidraInstallDir, projectName, projectDir, createRunConfig,
					runConfigMemory, linkUserScripts, linkSystemScripts, jythonInterpreterName,
					monitor));
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
	 * Creates a Ghidra script project.
	 *  
	 * @param ghidraInstallDir The Ghidra installation directory to use.
	 * @param projectName The name of the project to create.
	 * @param projectDir The project's directory.
	 * @param createRunConfig Whether or not to create a new run configuration for the project.
	 * @param runConfigMemory The run configuration's desired memory.  Could be null.
	 * @param linkUserScripts Whether or not to link in the user scripts directory.
	 * @param linkSystemScripts Whether or not to link in the system scripts directories.
	 * @param jythonInterpreterName The name of the Jython interpreter to use for Python support.
	 *   Could be null if Python support is not wanted.
	 * @param monitor The monitor to use during project creation.
	 * @throws InvocationTargetException if an error occurred during project creation.
	 */
	private void create(File ghidraInstallDir, String projectName, File projectDir,
			boolean createRunConfig, String runConfigMemory, boolean linkUserScripts,
			boolean linkSystemScripts, String jythonInterpreterName, IProgressMonitor monitor)
			throws InvocationTargetException {
		try {
			info("Creating " + projectName + " at " + projectDir);
			monitor.beginTask("Creating " + projectName, 2);

			GhidraApplicationLayout ghidraLayout = new GhidraApplicationLayout(ghidraInstallDir);
			monitor.worked(1);

			GhidraScriptUtils.createGhidraScriptProject(projectName, projectDir, createRunConfig,
				runConfigMemory, linkUserScripts, linkSystemScripts, ghidraLayout,
				jythonInterpreterName, monitor);
			monitor.worked(1);

			info("Finished creating " + projectName);
		}
		catch (IOException | ParseException | CoreException e) {
			throw new InvocationTargetException(e);
		}
		finally {
			monitor.done();
		}
	}

	/**
	 * Validates the wizard pages.  If they are invalid, an error popup will be displayed which
	 * will indicate the problem.
	 * 
	 * @return True if the data returned from the wizard pages are valid; otherwise, false
	 */
	private boolean validate() {
		if (FileUtilities.isPathContainedWithin(ghidraInstallationPage.getGhidraInstallDir(),
				projectPage.getProjectDir())) {
			EclipseMessageUtils.showErrorDialog("Invalid Project Root Directory",
				"Project root directory cannot reside inside of the selected Ghidra installation directory.");
			return false;
		}
		return true;
	}
}
