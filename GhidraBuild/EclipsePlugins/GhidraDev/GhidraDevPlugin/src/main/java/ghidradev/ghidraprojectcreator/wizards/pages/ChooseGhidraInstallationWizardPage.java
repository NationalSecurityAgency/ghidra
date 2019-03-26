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
import java.io.IOException;
import java.text.ParseException;

import org.eclipse.jface.preference.PreferenceDialog;
import org.eclipse.jface.wizard.WizardPage;
import org.eclipse.swt.SWT;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.*;
import org.eclipse.ui.dialogs.PreferencesUtil;

import ghidra.launch.JavaConfig;
import ghidra.launch.JavaFinder.JavaFilter;
import ghidradev.ghidraprojectcreator.preferences.GhidraProjectCreatorPreferencePage;
import ghidradev.ghidraprojectcreator.preferences.GhidraProjectCreatorPreferences;

/**
 * A wizard page that lets the user choose a Ghidra installation.
 */
public class ChooseGhidraInstallationWizardPage extends WizardPage {

	private Combo ghidraInstallDirCombo;
	private Button addGhidraInstallDirButton;

	/**
	 * Creates a new Ghidra installation wizard page.
	 */
	public ChooseGhidraInstallationWizardPage() {
		super("ChooseGhidraInstallationWizardPage");
		setTitle("Choose a Ghidra Installation");
		setDescription("Choose the Ghidra installation to use.");
	}

	@Override
	public void createControl(Composite parent) {
	
		Composite container = new Composite(parent, SWT.NULL);
		container.setLayout(new GridLayout(3, false));

		Label ghidraInstallDirLabel = new Label(container, SWT.NULL);
		ghidraInstallDirLabel.setText("Ghidra installation:");
		ghidraInstallDirCombo = new Combo(container, SWT.DROP_DOWN | SWT.READ_ONLY);
		ghidraInstallDirCombo.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));
		populateGhidraInstallationCombo();
		ghidraInstallDirCombo.addModifyListener(evt -> validate());
		ghidraInstallDirCombo.setToolTipText("The wizard requires a Ghidra installation to be " +
			"selected.  Click the + button to add or manage Ghidra installations.");
		addGhidraInstallDirButton = new Button(container, SWT.BUTTON1);
		addGhidraInstallDirButton.setText("+");
		addGhidraInstallDirButton.setToolTipText("Adds/manages Ghidra installations.");
		addGhidraInstallDirButton.addListener(SWT.Selection, evt -> {
			PreferenceDialog dialog = PreferencesUtil.createPreferenceDialogOn(null,
				GhidraProjectCreatorPreferencePage.class.getName(), null, null);
			dialog.open();
			populateGhidraInstallationCombo();
			validate();
		});

		validate();
		setControl(container);
	}

	/**
	 * Gets the Ghidra installation directory.
	 * 
	 * @return The Ghidra installation directory.
	 *   Could be null if unspecified, however, the page will not be valid until the Ghidra 
	 *   installation directory is valid, so it should never be null when called by other 
	 *   classes.
	 */
	public File getGhidraInstallDir() {
		return new File(ghidraInstallDirCombo.getText());
	}

	/**
	 * Validates the fields on the page and updates the page's status.
	 * Should be called every time a field on the page changes.
	 */
	private void validate() {
		String message = null;

		if (GhidraProjectCreatorPreferences.getGhidraInstallDirs().isEmpty()) {
			message = "No Ghidra installations found.  Click the + button to add one.";
		}
		else if (ghidraInstallDirCombo.getText().isEmpty()) {
			message = "Ghidra installation must be specified.";
		}
		else {
			try {
				File ghidraInstallDir = new File(ghidraInstallDirCombo.getText());
				GhidraProjectCreatorPreferencePage.validateGhidraInstallation(ghidraInstallDir);
				try {
					JavaConfig javaConfig = new JavaConfig(ghidraInstallDir);
					if (!javaConfig.isSupportedJavaHomeDir(javaConfig.getSavedJavaHome(),
						JavaFilter.JDK_ONLY)) {
						message = "A supported JDK is not associated with this Ghidra " +
							"installation. Please run this Ghidra and try again.";
					}
				}
				catch (ParseException | IOException e) {
					message = "Failed to determine Ghidra's JDK version.  " + e.getMessage();
				}
			}
			catch (IOException e) {
				message = e.getMessage();
			}
		}

		setErrorMessage(message);
		setPageComplete(message == null);
	}

	/**
	 * Populates the Ghidra installations combo box with the values found in preferences.
	 */
	private void populateGhidraInstallationCombo() {
		ghidraInstallDirCombo.removeAll();
		for (File dir : GhidraProjectCreatorPreferences.getGhidraInstallDirs()) {
			ghidraInstallDirCombo.add(dir.getAbsolutePath());
			if (dir.equals(GhidraProjectCreatorPreferences.getGhidraDefaultInstallDir())) {
				ghidraInstallDirCombo.setText(dir.getAbsolutePath());
			}
		}
	}
}
