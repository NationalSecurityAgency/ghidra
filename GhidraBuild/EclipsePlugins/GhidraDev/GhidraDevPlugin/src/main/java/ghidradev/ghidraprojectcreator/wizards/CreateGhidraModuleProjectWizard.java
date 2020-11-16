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
import java.util.Set;

import org.eclipse.core.resources.IFile;
import org.eclipse.core.runtime.CoreException;
import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.jdt.core.IJavaProject;
import org.eclipse.jface.viewers.IStructuredSelection;
import org.eclipse.jface.wizard.Wizard;
import org.eclipse.ui.INewWizard;
import org.eclipse.ui.IWorkbench;

import ghidra.GhidraApplicationLayout;
import ghidradev.EclipseMessageUtils;
import ghidradev.ghidraprojectcreator.utils.GhidraModuleUtils;
import ghidradev.ghidraprojectcreator.utils.GhidraModuleUtils.ModuleTemplateType;
import ghidradev.ghidraprojectcreator.wizards.pages.*;
import utilities.util.FileUtilities;

/**
 * Wizard to create a new Ghidra module project.
 */
public class CreateGhidraModuleProjectWizard extends Wizard implements INewWizard {

	private IWorkbench workbench;

	private CreateGhidraProjectWizardPage projectPage;
	private ConfigureGhidraModuleProjectWizardPage projectConfigPage;
	private ChooseGhidraInstallationWizardPage ghidraInstallationPage;
	private EnablePythonWizardPage pythonPage;

	/**
	 * Creates a new Ghidra module project wizard.
	 */
	public CreateGhidraModuleProjectWizard() {
		setNeedsProgressMonitor(true);
	}

	@Override
	public void init(IWorkbench wb, IStructuredSelection selection) {
		workbench = wb;
		projectPage = new CreateGhidraProjectWizardPage();
		projectConfigPage = new ConfigureGhidraModuleProjectWizardPage();
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
		boolean createRunConfig = projectPage.shouldCreateRunConfig();
		String runConfigMemory = projectPage.getRunConfigMemory();
		File projectDir = projectPage.getProjectDir();
		String jythonInterpreterName = pythonPage.getJythonInterpreterName();
		Set<ModuleTemplateType> moduleTemplateTypes = projectConfigPage.getModuleTemplateTypes();
		try {
			getContainer().run(true, false,
				monitor -> create(ghidraInstallDir, projectName, projectDir, createRunConfig,
					runConfigMemory, moduleTemplateTypes, jythonInterpreterName, monitor));
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
	 * Creates a Ghidra module project.
	 * 
	 * @param ghidraInstallDir The Ghidra installation directory to use.
	 * @param projectName The name of the project to create.
	 * @param projectDir The project's directory.
	 * @param createRunConfig Whether or not to create a new run configuration for the project.
	 * @param runConfigMemory The run configuration's desired memory.  Could be null.
	 * @param moduleTemplateTypes The desired module template types.
	 * @param jythonInterpreterName The name of the Jython interpreter to use for Python support.
	 *   Could be null if Python support is not wanted.
	 * @param monitor The monitor to use during project creation.
	 * @throws InvocationTargetException if an error occurred during project creation.
	 */
	private void create(File ghidraInstallDir, String projectName, File projectDir,
			boolean createRunConfig, String runConfigMemory,
			Set<ModuleTemplateType> moduleTemplateTypes, String jythonInterpreterName,
			IProgressMonitor monitor) throws InvocationTargetException {
		try {
			info("Creating " + projectName + " at " + projectDir);
			monitor.beginTask("Creating " + projectName, 3);

			GhidraApplicationLayout ghidraLayout = new GhidraApplicationLayout(ghidraInstallDir);
			monitor.worked(1);

			IJavaProject javaProject =
				GhidraModuleUtils.createGhidraModuleProject(projectName, projectDir,
					createRunConfig, runConfigMemory, ghidraLayout, jythonInterpreterName, monitor);
			monitor.worked(1);

			IFile sourceFile = GhidraModuleUtils.configureModuleSource(javaProject,
				projectDir, ghidraLayout, moduleTemplateTypes, monitor);
			monitor.worked(1);

			if (sourceFile != null) {
				EclipseMessageUtils.displayInEditor(sourceFile, workbench);
			}

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
