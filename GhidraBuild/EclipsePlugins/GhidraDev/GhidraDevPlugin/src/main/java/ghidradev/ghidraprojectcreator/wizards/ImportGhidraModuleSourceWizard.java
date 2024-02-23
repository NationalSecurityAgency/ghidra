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
import org.eclipse.ui.IImportWizard;
import org.eclipse.ui.IWorkbench;

import ghidra.GhidraApplicationLayout;
import ghidradev.EclipseMessageUtils;
import ghidradev.ghidraprojectcreator.utils.GhidraModuleUtils;
import ghidradev.ghidraprojectcreator.wizards.pages.*;
import utilities.util.FileUtilities;

/**
 * Wizard for importing Ghidra module source to a new Ghidra module project.
 */
public class ImportGhidraModuleSourceWizard extends Wizard implements IImportWizard {

	private ChooseGhidraModuleSourceWizardPage sourcePage;
	private CreateGhidraProjectWizardPage projectPage;
	private ChooseGhidraInstallationWizardPage ghidraInstallationPage;
	private EnablePythonWizardPage pythonPage;

	public ImportGhidraModuleSourceWizard() {
		super();
	}
	 
	@Override
	public void init(IWorkbench wb, IStructuredSelection selection) {
		sourcePage = new ChooseGhidraModuleSourceWizardPage();
		projectPage = new CreateGhidraProjectWizardPage(false);
		ghidraInstallationPage = new ChooseGhidraInstallationWizardPage();
		pythonPage = new EnablePythonWizardPage(ghidraInstallationPage);
	}
	
	@Override
    public void addPages() {
		addPage(sourcePage);
		addPage(projectPage);
		addPage(ghidraInstallationPage);
		addPage(pythonPage);
    }

	@Override
	public boolean performFinish() {
		if (!validate()) {
			return false;
		}

		File moduleSourceDir = sourcePage.getSourceDir();
		File ghidraInstallDir = ghidraInstallationPage.getGhidraInstallDir();
		String projectName = projectPage.getProjectName();
		boolean createRunConfig = projectPage.shouldCreateRunConfig();
		String runConfigMemory = projectPage.getRunConfigMemory();
		String jythonInterpreterName = pythonPage.getJythonInterpreterName();
		try {
			getContainer().run(true, false,
				monitor -> importModuleSource(ghidraInstallDir, projectName, moduleSourceDir,
					createRunConfig, runConfigMemory, jythonInterpreterName, monitor));
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
	 * Imports a Ghidra module source directory to a new Ghidra module project.
	 * 
	 * @param ghidraInstallDir The Ghidra installation directory to use.
	 * @param projectName The name of the project to create.
	 * @param moduleSourceDir The module source directory to import.
	 * @param createRunConfig Whether or not to create a new run configuration for the project.
	 * @param runConfigMemory The run configuration's desired memory.  Could be null.
	 * @param jythonInterpreterName The name of the Jython interpreter to use for Python support.
	 *   Could be null if Python support is not wanted.
	 * @param monitor The monitor to use during project creation.
	 * @throws InvocationTargetException if an error occurred during project creation.
	 */
	private void importModuleSource(File ghidraInstallDir, String projectName, File moduleSourceDir,
			boolean createRunConfig, String runConfigMemory, String jythonInterpreterName,
			IProgressMonitor monitor) throws InvocationTargetException {
		try {
			info("Importing " + projectName + " at " + moduleSourceDir);
			monitor.beginTask("Importing " + projectName, 2);

			GhidraApplicationLayout ghidraLayout = new GhidraApplicationLayout(ghidraInstallDir);
			monitor.worked(1);

			GhidraModuleUtils.importGhidraModuleSource(projectName, moduleSourceDir,
				createRunConfig, runConfigMemory, ghidraLayout, jythonInterpreterName, monitor);
			monitor.worked(1);

			info("Finished importing " + projectName);
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
			sourcePage.getSourceDir())) {
			EclipseMessageUtils.showErrorDialog("Invalid Module Source Directory",
				"Module source directory cannot reside inside of the selected Ghidra installation directory.");
			return false;
		}
		return true;
	}

}
