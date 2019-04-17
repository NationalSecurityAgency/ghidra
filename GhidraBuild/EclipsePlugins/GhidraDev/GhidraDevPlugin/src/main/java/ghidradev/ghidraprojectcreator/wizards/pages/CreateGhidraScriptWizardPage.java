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

import org.eclipse.core.resources.IFolder;
import org.eclipse.core.resources.ResourcesPlugin;
import org.eclipse.core.runtime.IPath;
import org.eclipse.core.runtime.Path;
import org.eclipse.jdt.core.IPackageFragmentRoot;
import org.eclipse.jface.window.Window;
import org.eclipse.jface.wizard.WizardPage;
import org.eclipse.swt.SWT;
import org.eclipse.swt.layout.*;
import org.eclipse.swt.widgets.*;

import ghidradev.ghidraprojectcreator.utils.GhidraProjectUtils;
import ghidradev.ghidraprojectcreator.utils.PackageFragmentRootSelectionDialog;

/**
 * A wizard page that lets the user create a new Ghidra script.
 */
public class CreateGhidraScriptWizardPage extends WizardPage {

	private IPackageFragmentRoot selecttion;

	private Text scriptFolderText;
	private Button scriptFolderButton;
	private Text scriptNameText;
	private Button javaRadioButton;
	private Button pythonRadioButton;
	private Text scriptAuthorText;
	private Text scriptCategoryText;
	private Text scriptDescriptionText;

	/**
	 * Creates a new Ghidra script creation wizard page.
	 */
	public CreateGhidraScriptWizardPage() {
		super("CreateGhidraScriptWizardPage");
		setTitle("Create Ghidra Script");
		setDescription("Create a new Ghidra script.");
	}

	/**
	 * Creates a new Ghidra script creation wizard page.
	 * 
	 * @param selectedPackageFragmentRoot The current selection in the project explorer.
	 *   Could be null if nothing is selected.
	 */
	public CreateGhidraScriptWizardPage(IPackageFragmentRoot selectedPackageFragmentRoot) {
		this();
		this.selecttion = selectedPackageFragmentRoot;
	}

	@Override
	public void createControl(Composite parent) {

		Composite container = new Composite(parent, SWT.NULL);
		container.setLayout(new GridLayout(3, false));
		
		// Source folder
		Label sourceFolderLabel = new Label(container, SWT.NULL);
		sourceFolderLabel.setText("Script folder:");
		scriptFolderText = new Text(container, SWT.BORDER | SWT.SINGLE);
		scriptFolderText.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));
		scriptFolderText.setEditable(false);
		scriptFolderText.setText(selecttion != null ? selecttion.getPath().toString() : "");
		scriptFolderText.addModifyListener(evt -> validate());
		scriptFolderButton = new Button(container, SWT.BUTTON1);
		scriptFolderButton.setText("...");
		scriptFolderButton.addListener(SWT.Selection, evt -> {
			PackageFragmentRootSelectionDialog selectionDialog =
				new PackageFragmentRootSelectionDialog(getShell(), "Script Folder Selection",
					"Choose a script folder:", "Select script folder");
			if (selectionDialog.open() == Window.OK) {
				IFolder scriptFolder = ResourcesPlugin.getWorkspace().getRoot().getFolder(
					selectionDialog.getPackageFragmentRoot().getPath());
				if (scriptFolder != null) {
					scriptFolderText.setText(scriptFolder.getFullPath().toString());
				}
			}
		});
		
		// Script name
		Label scriptNameLabel = new Label(container, SWT.NULL);
		scriptNameLabel.setText("Script name:");
		scriptNameText = new Text(container, SWT.BORDER | SWT.SINGLE);
		scriptNameText.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));
		scriptNameText.addModifyListener(evt -> validate());
		new Label(container, SWT.NONE).setText(""); // empty grid cell

		// Script type
		Label scriptTypeLabel = new Label(container, SWT.NULL);
		scriptTypeLabel.setText("Script type:");
		Group scriptTypeGroup = new Group(container, SWT.SHADOW_ETCHED_OUT);
		scriptTypeGroup.setLayout(new RowLayout(SWT.HORIZONTAL));
		javaRadioButton = new Button(scriptTypeGroup, SWT.RADIO);
		javaRadioButton.setSelection(true);
		javaRadioButton.setText("Java");
		pythonRadioButton = new Button(scriptTypeGroup, SWT.RADIO);
		pythonRadioButton.setSelection(false);
		pythonRadioButton.setText("Python");
		new Label(container, SWT.NONE).setText(""); // empty grid cell

		// Script author
		Label scriptAuthorLabel = new Label(container, SWT.NULL);
		scriptAuthorLabel.setText("Script author:");
		scriptAuthorText = new Text(container, SWT.BORDER | SWT.SINGLE);
		scriptAuthorText.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));
		scriptAuthorText.addModifyListener(evt -> validate());
		new Label(container, SWT.NONE).setText(""); // empty grid cell

		// Script category
		Label scriptCategoryLabel = new Label(container, SWT.NULL);
		scriptCategoryLabel.setText("Script category:");
		scriptCategoryText = new Text(container, SWT.BORDER | SWT.SINGLE);
		scriptCategoryText.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));
		scriptCategoryText.addModifyListener(evt -> validate());
		new Label(container, SWT.NONE).setText(""); // empty grid cell

		// Script description
		Label scriptDescriptionLabel = new Label(container, SWT.NULL);
		scriptDescriptionLabel.setText("Script description:");
		scriptDescriptionText =
			new Text(container, SWT.MULTI | SWT.WRAP | SWT.V_SCROLL | SWT.BORDER);
		scriptDescriptionText.setLayoutData(new GridData(GridData.FILL_BOTH));
		scriptDescriptionText.addModifyListener(evt -> validate());
		new Label(container, SWT.NONE).setText(""); // empty grid cell

		validate();
		setControl(container);
	}

	/**
	 * Gets the script's target source folder. This is where the script will get created.
	 * 
	 * @return The script's target source folder.  Could be null if unspecified, however, the page 
	 *   will not be valid until the source folder is valid, so it should never be null when called 
	 *   by other classes.
	 */
	public IFolder getScriptFolder() {
		if (!scriptFolderText.getText().isEmpty()) {
			try {
				IPath path = new Path(scriptFolderText.getText());
				return ResourcesPlugin.getWorkspace().getRoot().getFolder(path);
			}
			catch (IllegalArgumentException e) {
				// Fall through to return null
			}
		}
		return null;
	}

	/**
	 * Gets the name of the script to create (including extension).
	 * 
	 * @return The name of the script to create (including extension).
	 *   Could be empty if unspecified, however, the page will not be valid until the script 
	 *   name is valid, so it should never be empty when called by other classes.
	 */
	public String getScriptName() {
		return scriptNameText.getText() + (javaRadioButton.getSelection() ? ".java" : ".py");
	}

	/**
	 * Gets the script author.
	 * 
	 * @return The script author.  This is an optional field, so it could be empty.
	 */
	public String getScriptAuthor() {
		return scriptAuthorText.getText();
	}

	/**
	 * Gets the script category.
	 * 
	 * @return The script category.  This is an optional field, so it could be empty.
	 */
	public String getScriptCategory() {
		return scriptCategoryText.getText();
	}

	/**
	 * Gets the script description as an array of lines.
	 * 
	 * @return The script description as an array of lines. This is an optional field, 
	 * so it could be empty.
	 */
	public String[] getScriptDescription() {
		return scriptDescriptionText.getText().split("\\n");
	}

	/**
	 * Validates the fields on the page and updates the page's status.
	 * Should be called every time a field on the page changes.
	 */
	private void validate() {

		final String BAD = GhidraProjectUtils.ILLEGAL_FILENAME_CHARS;
		final String BAD_START = GhidraProjectUtils.ILLEGAL_FILENAME_START_CHARS;


		String message = null;
		IFolder scriptFolder = getScriptFolder();
		String scriptName = scriptNameText.getText();


		if (scriptFolder == null) {
			message = "Script folder must be specified";
		}
		else if (!scriptFolder.exists()) {
			message = "Script folder does not exist";
		}
		else if (scriptName.isEmpty()) {
			message = "Script name must be specified";
		}
		else if ((BAD_START + BAD).chars().anyMatch(ch -> scriptName.charAt(0) == ch)) {
			message = "Script name cannot start with an invalid character:\n " + BAD_START + BAD;
		}
		else if (BAD.chars().anyMatch(ch -> scriptName.indexOf(ch) != -1)) {
			message = "Script name cannot contain invalid characters:\n " + BAD;
		}
		else if (scriptFolder.getFile(getScriptName()).exists()) {
			message = "Script already exists";
		}

		setErrorMessage(message);
		setPageComplete(message == null);
	}
}
