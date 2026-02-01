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

import java.io.File;

import org.eclipse.jface.wizard.WizardPage;
import org.eclipse.swt.SWT;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.*;

import ghidradev.ghidraprojectcreator.preferences.GhidraProjectCreatorPreferences;

/**
 * A wizard page that lets the user choose a Ghidra module source directory.
 */
public class ChooseGhidraModuleSourceWizardPage extends WizardPage {

	private Text sourceDirText;
	private Button sourceDirButton;

	/**
	 * Creates a new Ghidra module source chooser wizard page. 
	 */
	public ChooseGhidraModuleSourceWizardPage() {
		super("ChooseGhidraModuleSourceWizardPage");
		setTitle("Choose Ghidra Module Source");
		setDescription("Choose a Ghidra module source directory.");
	}

	@Override
	public void createControl(Composite parent) {

		Composite container = new Composite(parent, SWT.NULL);
		container.setLayout(new GridLayout(3, false));

		// Source directory
		Label sourceDirLabel = new Label(container, SWT.NULL);
		String sourceDirToolTip = "The Ghidra module source directory.";
		sourceDirLabel.setText("Source directory:");
		sourceDirLabel.setToolTipText(sourceDirToolTip);
		sourceDirText = new Text(container, SWT.BORDER | SWT.SINGLE);
		sourceDirText.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));
		sourceDirText.setText(GhidraProjectCreatorPreferences.getGhidraLastModuleSourceDirPath());
		sourceDirText.addModifyListener(evt -> validate());
		sourceDirText.setToolTipText(sourceDirToolTip);
		sourceDirButton = new Button(container, SWT.BUTTON1);
		sourceDirButton.setText("...");
		sourceDirButton.setToolTipText("Browse to select source directory");
		sourceDirButton.addListener(SWT.Selection, evt -> {
			DirectoryDialog dialog = new DirectoryDialog(container.getShell());
			String path = dialog.open();
			if (path != null) {
				sourceDirText.setText(path);
			}
		});

		validate();
		setControl(container);
	}

	/**
	 * Gets the module source directory.
	 * 
	 * @return The module source directory. Could be null if unspecified, however, the page will not
	 *   be valid until the module source directory is valid, so it should never be null when called
	 *   by other classes.
	 */
	public File getSourceDir() {
		if (sourceDirText.getText().isEmpty()) {
			return null;
		}
		return new File(sourceDirText.getText());
	}

	/**
	 * Validates the fields on the page and updates the page's status.
	 * Should be called every time a field on the page changes.
	 */
	private void validate() {
		String message = null;
		File sourceDir = new File(sourceDirText.getText());

		if (!sourceDir.isAbsolute()) {
			message = "Source directory must be an absolute path";
		}
		else if (!sourceDir.isDirectory()) {
			message = "Source directory does not exist";
		}
		else if (!new File(sourceDir, "Module.manifest").exists()) {
			message = "Source directory does not contain a Module.manifest file";
		}
		else if (!new File(sourceDir, "build.gradle").exists()) {
			message = "Source directory does not contain a build.gradle file";
		}
		else if (new File(sourceDir, ".project").exists()) {
			message = "Source directory already contains a .project file";
		}
		else if (new File(sourceDir, ".classpath").exists()) {
			message = "Source directory already contains a .classpath file";
		}

		setErrorMessage(message);
		setPageComplete(message == null);
		if (message == null) {
			GhidraProjectCreatorPreferences
					.setGhidraLastModuleSourceDirPath(sourceDirText.getText());
		}
	}
}
