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

import org.eclipse.jface.wizard.WizardPage;
import org.eclipse.swt.SWT;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Composite;

import ghidradev.ghidraprojectcreator.utils.GhidraScriptUtils;

public class ConfigureGhidraScriptProjectWizardPage extends WizardPage {

	private Button userScriptsCheckboxButton;
	private Button systemScriptsCheckboxButton;

	/**
	 * Creates a new Ghidra script project configuration wizard page.
	 */
	public ConfigureGhidraScriptProjectWizardPage() {
		super("ConfigureGhidraScriptProjectWizardPage");
		setTitle("Configure Ghidra Script Project");
		setDescription("Configure a new Ghidra script project.");
	}

	@Override
	public void createControl(Composite parent) {

		Composite container = new Composite(parent, SWT.NULL);
		container.setLayout(new GridLayout(1, false));

		userScriptsCheckboxButton = new Button(container, SWT.CHECK);
		userScriptsCheckboxButton.setText(
			"Link user home script directory (" + GhidraScriptUtils.userScriptsDir + ")");
		userScriptsCheckboxButton.setToolTipText("Automatically links Ghidra's default user home " +
			"script directory to the new project.  This is recommended.");
		userScriptsCheckboxButton.setSelection(true);

		systemScriptsCheckboxButton = new Button(container, SWT.CHECK);
		systemScriptsCheckboxButton.setText("Link Ghidra installation script directories");
		systemScriptsCheckboxButton.setToolTipText("Automatically links any script directories " +
			"found in the Ghidra installation to the new project, which serve as good examples.");
		systemScriptsCheckboxButton.setSelection(true);

		setErrorMessage(null);
		setPageComplete(true);
		setControl(container);
	}

	/**
	 * Checks whether or not the user scripts directory should be linked into the project.
	 * 
	 * @return True if the user scripts directory should be linked into the project; otherwise, false.
	 */
	public boolean shouldLinkUsersScripts() {
		return userScriptsCheckboxButton.getSelection();
	}

	/**
	 * Checks whether or not the system scripts directory should be linked into the project.
	 * 
	 * @return True if the system scripts directory should be linked into the project; otherwise, false.
	 */
	public boolean shouldLinkSystemScripts() {
		return systemScriptsCheckboxButton.getSelection();
	}
}
