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
package ghidradev.ghidraprojectcreator.wizards.pages;

import org.eclipse.core.resources.IProject;
import org.eclipse.jdt.core.IJavaProject;
import org.eclipse.jface.wizard.WizardPage;
import org.eclipse.swt.SWT;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.*;

import ghidradev.ghidraprojectcreator.utils.GhidraProjectUtils;

/**
 * A wizard page that lets the user choose an open Ghidra module project.
 */
public class ChooseGhidraModuleProjectWizardPage extends WizardPage {

	private IProject selectedProject;
	private Combo projectCombo;

	/**
	 * Creates a new Ghidra module project chooser wizard page.
	 * 
	 * @param selectedProject The currently selected project in the project explorer.
	 */
	public ChooseGhidraModuleProjectWizardPage(IProject selectedProject) {
		super("ChooseGhidraModuleProjectWizardPage");
		setTitle("Choose Ghidra Module Project");
		setDescription("Choose an open Ghidra module project.");
		this.selectedProject = selectedProject;
	}

	@Override
	public void createControl(Composite parent) {

		Composite container = new Composite(parent, SWT.NULL);
		container.setLayout(new GridLayout(2, false));

		Label projectNameLabel = new Label(container, SWT.NULL);
		projectNameLabel.setText("Ghida module project:");
		projectCombo = new Combo(container, SWT.DROP_DOWN | SWT.READ_ONLY);
		GridData gd = new GridData(GridData.FILL_HORIZONTAL);
		projectCombo.setLayoutData(gd);
		projectCombo.addModifyListener(evt -> validate());
		for (IJavaProject javaProject : GhidraProjectUtils.getGhidraProjects()) {
			if (GhidraProjectUtils.isGhidraModuleProject(javaProject.getProject())) {
				IProject project = javaProject.getProject();
				projectCombo.add(project.getName());
				if (project.equals(selectedProject)) {
					projectCombo.setText(project.getName());
				}
			}
		}

		validate();
		setControl(container);
	}

	/**
	 * Gets the Java project.
	 * 
	 * @return The chosen Ghidra module project.  Only valid when the page is complete.
	 *   Could be null if unspecified, however, the page will not be valid until the project 
	 *   is valid, so it should never be null when called by other classes.
	 */
	public IJavaProject getGhidraModuleProject() {
		return GhidraProjectUtils.getGhidraProject(projectCombo.getText());
	}

	/**
	 * Validates the fields on the page and updates the page's status.
	 * Should be called every time a field on the page changes.
	 */
	private void validate() {

		String message = null;
		String projectName = projectCombo.getText();

		if (projectName.isEmpty()) {
			message = "Project name must be specified";
		}

		setErrorMessage(message);
		setPageComplete(message == null);
	}
}
