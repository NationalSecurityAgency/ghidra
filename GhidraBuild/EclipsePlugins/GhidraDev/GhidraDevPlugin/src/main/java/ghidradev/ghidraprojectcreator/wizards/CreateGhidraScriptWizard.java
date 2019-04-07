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

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;

import org.eclipse.core.resources.IFile;
import org.eclipse.core.resources.IFolder;
import org.eclipse.core.runtime.CoreException;
import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.jdt.core.IPackageFragmentRoot;
import org.eclipse.jface.viewers.IStructuredSelection;
import org.eclipse.jface.wizard.Wizard;
import org.eclipse.ui.INewWizard;
import org.eclipse.ui.IWorkbench;

import ghidradev.EclipseMessageUtils;
import ghidradev.ghidraprojectcreator.utils.GhidraScriptUtils;
import ghidradev.ghidraprojectcreator.wizards.pages.CreateGhidraScriptWizardPage;

/**
 * Wizard to create a new Ghidra script file in an existing project.
 */
public class CreateGhidraScriptWizard extends Wizard implements INewWizard {

	private IWorkbench workbench;

	private CreateGhidraScriptWizardPage scriptPage;

	/**
	 * Creates a new Ghidra script wizard.
	 */
	public CreateGhidraScriptWizard() {
		setNeedsProgressMonitor(true);
	}

	@Override
	public void init(IWorkbench wb, IStructuredSelection selection) {
		workbench = wb;

		IPackageFragmentRoot selectedPackageFragmentRoot = null;
		Object firstElement = selection.getFirstElement();
		if (firstElement instanceof IPackageFragmentRoot) {
			selectedPackageFragmentRoot = (IPackageFragmentRoot) firstElement;
		}
		scriptPage = new CreateGhidraScriptWizardPage(selectedPackageFragmentRoot);
	}

	@Override
	public void addPages() {
		addPage(scriptPage);
	}

	@Override
	public boolean performFinish() {
		IFolder scriptFolder = scriptPage.getScriptFolder();
		String scriptName = scriptPage.getScriptName();
		String scriptAuthor = scriptPage.getScriptAuthor();
		String scriptCategory = scriptPage.getScriptCategory();
		String[] scriptDescription = scriptPage.getScriptDescription();
		try {
			getContainer().run(true, false, monitor -> create(scriptFolder, scriptName,
				scriptAuthor, scriptCategory, scriptDescription, monitor));
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
	 * Creates a Ghidra script.
	 *  
	 * @param scriptFolder The folder to create the script in.
	 * @param scriptName The name of the script to create.
	 * @param scriptAuthor The script's author.
	 * @param scriptCategory The script's category.
	 * @param scriptDescription The script's description lines.
	 * @param monitor The monitor to use during project/script creation.
	 * @throws InvocationTargetException if an error occurred during project/script creation.
	 */
	private void create(IFolder scriptFolder, String scriptName, String scriptAuthor,
			String scriptCategory, String[] scriptDescription, IProgressMonitor monitor)
			throws InvocationTargetException {
		try {
			info("Creating " + scriptName + " in " + scriptFolder.toString());
			monitor.beginTask("Creating " + scriptName + " in " + scriptFolder.toString(), 1);

			IFile scriptFile = GhidraScriptUtils.createGhidraScript(scriptFolder, scriptName,
				scriptAuthor, scriptCategory, scriptDescription, monitor);
			monitor.worked(1);

			if (scriptFile != null) {
				EclipseMessageUtils.displayInEditor(scriptFile, workbench);
			}

			info("Finished creating " + scriptName);
		}
		catch (IOException | CoreException e) {
			throw new InvocationTargetException(e);
		}
		finally {
			monitor.done();
		}
	}
}
