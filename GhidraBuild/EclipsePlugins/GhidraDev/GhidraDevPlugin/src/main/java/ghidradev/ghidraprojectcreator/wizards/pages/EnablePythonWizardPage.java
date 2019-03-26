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
import java.nio.file.Files;
import java.util.List;

import javax.naming.OperationNotSupportedException;

import org.eclipse.jface.preference.PreferenceDialog;
import org.eclipse.jface.wizard.WizardPage;
import org.eclipse.swt.SWT;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.events.SelectionListener;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.*;
import org.eclipse.ui.dialogs.PreferencesUtil;

import ghidradev.EclipseMessageUtils;
import ghidradev.ghidraprojectcreator.utils.PyDevUtils;

/**
 * A wizard page that lets the user enable python for their project.
 */
public class EnablePythonWizardPage extends WizardPage {

	private ChooseGhidraInstallationWizardPage ghidraInstallationPage;
	private Button enablePythonCheckboxButton;
	private Combo jythonCombo;
	private Button addJythonButton;

	/**
	 * Creates a new Python enablement wizard page.
	 * 
	 * @param ghidraInstallationPage Ghidra installation wizard page.
	 */
	public EnablePythonWizardPage(ChooseGhidraInstallationWizardPage ghidraInstallationPage) {
		super("EnablePythonWizardPage");
		setTitle("Python Support");
		setDescription("Enable Python support for your project (requires PyDev plugin).");
		this.ghidraInstallationPage = ghidraInstallationPage;
	}

	@Override
	public void createControl(Composite parent) {

		Composite container = new Composite(parent, SWT.NULL);
		container.setLayout(new GridLayout(3, false));

		// Enable Python checkbox.
		enablePythonCheckboxButton = new Button(container, SWT.CHECK);
		enablePythonCheckboxButton.setText("Enable Python");
		enablePythonCheckboxButton.setToolTipText("Enables Python support using the PyDev " +
			"Eclipse plugin.  Requires PyDev version " + PyDevUtils.MIN_SUPPORTED_VERSION +
			" or later.");
		enablePythonCheckboxButton.setSelection(PyDevUtils.isSupportedPyDevInstalled());
		enablePythonCheckboxButton.addSelectionListener(new SelectionListener() {
			@Override
			public void widgetSelected(SelectionEvent evt) {
				validate();
			}

			@Override
			public void widgetDefaultSelected(SelectionEvent evt) {
				validate();
			}
		});
		new Label(container, SWT.NONE).setText(""); // filler
		new Label(container, SWT.NONE).setText(""); // filler

		// Jython interpreter combo box
		Label jythonLabel = new Label(container, SWT.NULL);
		jythonLabel.setText("Jython interpreter:");
		jythonCombo = new Combo(container, SWT.DROP_DOWN | SWT.READ_ONLY);
		jythonCombo.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));
		jythonCombo.setToolTipText("The wizard requires a Jython interpreter to be " +
			"selected.  Click the + button to add or manage Jython interpreters.");
		populateJythonCombo();
		jythonCombo.addModifyListener(evt -> validate());

		// Jython interpreter add button
		addJythonButton = new Button(container, SWT.BUTTON1);
		addJythonButton.setText("+");
		addJythonButton.setToolTipText("Adds/manages Jython interpreters.");
		addJythonButton.addListener(SWT.Selection, evt -> {
			try {
				if (PyDevUtils.getJython27InterpreterNames().isEmpty()) {
					File ghidraDir = ghidraInstallationPage.getGhidraInstallDir();
					File jythonFile = findJythonInterpreter(ghidraDir);
					File jythonLib = findJythonLibrary(ghidraDir);
					if (jythonFile != null) {
						if (EclipseMessageUtils.showQuestionDialog("Jython Found",
							"A Jython interpreter was found bundled with Ghidra. " +
								"Would you like to use it as your interpreter?")) {
							PyDevUtils.addJythonInterpreter("jython_" + ghidraDir.getName(),
								jythonFile, jythonLib);
							populateJythonCombo();
							validate();
							return;
						}
					}
				}
			}
			catch (OperationNotSupportedException e) {
				// Fall through to show PyDev's Jython preference page
			}
			PreferenceDialog dialog = PreferencesUtil.createPreferenceDialogOn(null,
				PyDevUtils.getJythonPreferencePageId(), null, null);
			dialog.open();
			populateJythonCombo();
			validate();
		});

		validate();
		setControl(container);
	}

	/**
	 * Checks whether or not Python should be enabled.
	 * 
	 * @return True if python should be enabled; otherwise, false.
	 */
	public boolean shouldEnablePython() {
		return enablePythonCheckboxButton.getSelection();
	}

	/**
	 * Gets the name of the Jython interpreter to use. 
	 * 
	 * @return The name of the Jython interpreter to use.  Could be null of Python isn't
	 *   enabled. 
	 */
	public String getJythonInterpreterName() {
		if (enablePythonCheckboxButton.getSelection()) {
			return jythonCombo.getText();
		}
		return null;
	}

	/**
	 * Validates the fields on the page and updates the page's status.
	 * Should be called every time a field on the page changes.
	 */
	private void validate() {
		String message = null;
		boolean pyDevInstalled = PyDevUtils.isSupportedPyDevInstalled();
		boolean pyDevEnabled = enablePythonCheckboxButton.getSelection();
		boolean comboEnabled = pyDevInstalled && pyDevEnabled;

		if (pyDevEnabled) {
			if (!pyDevInstalled) {
				message = "PyDev version " + PyDevUtils.MIN_SUPPORTED_VERSION +
					" or later is not installed.";
			}
			else {
				try {
					List<String> interpreters = PyDevUtils.getJython27InterpreterNames();
					if (interpreters.isEmpty()) {
						message = "No Jython interpreters found.  Click the + button to add one.";
					}
				}
				catch (OperationNotSupportedException e) {
					message = "PyDev version is not supported.";
					comboEnabled = false;
				}
			}
		}

		jythonCombo.setEnabled(comboEnabled);
		addJythonButton.setEnabled(comboEnabled);

		setErrorMessage(message);
		setPageComplete(message == null);
	}

	/**
	 * Populates the Jython combo box with discovered Jython names.
	 */
	private void populateJythonCombo() {
		jythonCombo.removeAll();
		try {
			for (String jythonName : PyDevUtils.getJython27InterpreterNames()) {
				jythonCombo.add(jythonName);
			}
		}
		catch (OperationNotSupportedException e) {
			// Nothing to do.  Combo should and will be empty.
		}
		if (jythonCombo.getItemCount() > 0) {
			jythonCombo.select(0);
		}
	}

	/**
	 * Find's a Jython interpreter file in the given Ghidra installation directory.
	 * 
	 * @param ghidraInstallDir The Ghidra installation directory to search.
	 * @return A Jython interpreter file from the given Ghidra installation directory, or
	 *   null if one could not be found.
	 */
	private File findJythonInterpreter(File ghidraInstallDir) {
		if (ghidraInstallDir == null || !ghidraInstallDir.isDirectory()) {
			return null;
		}

		try {
			return Files.find(ghidraInstallDir.toPath(), 10, (path, attrs) -> {
				String name = path.getFileName().toString();
				return attrs.isRegularFile() && name.startsWith("jython") && name.endsWith(".jar");
			}).map(p -> p.toFile()).findFirst().orElse(null);
		}
		catch (IOException e) {
			return null;
		}
	}

	/**
	 * Find's a Jython library directory in the given Ghidra installation directory.
	 * 
	 * @param ghidraInstallDir The Ghidra installation directory to search.
	 * @return A Jython library directory from the given Ghidra installation directory, or
	 *   null if one could not be found.
	 */
	private File findJythonLibrary(File ghidraInstallDir) {
		if (ghidraInstallDir == null || !ghidraInstallDir.isDirectory()) {
			return null;
		}

		try {
			return Files.find(ghidraInstallDir.toPath(), 10, (path, attrs) -> {
				String name = path.getFileName().toString();
				String parentName = path.getParent().getFileName().toString();
				return attrs.isDirectory() && name.equals("Lib") && parentName.startsWith("jython");
			}).map(p -> p.toFile()).findFirst().orElse(null);
		}
		catch (IOException e) {
			return null;
		}
	}
}
