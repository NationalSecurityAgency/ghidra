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

import java.io.*;
import java.nio.file.Files;
import java.util.List;

import javax.naming.OperationNotSupportedException;

import org.eclipse.jface.preference.PreferenceDialog;
import org.eclipse.jface.wizard.WizardPage;
import org.eclipse.swt.SWT;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.events.SelectionListener;
import org.eclipse.swt.layout.*;
import org.eclipse.swt.widgets.*;
import org.eclipse.ui.dialogs.PreferencesUtil;

import ghidra.launch.AppConfig;
import ghidradev.EclipseMessageUtils;
import ghidradev.ghidraprojectcreator.utils.PyDevUtils;
import ghidradev.ghidraprojectcreator.utils.PyDevUtils.ProjectPythonInterpreter;
import ghidradev.ghidraprojectcreator.utils.PyDevUtils.ProjectPythonInterpreterType;

/**
 * A wizard page that lets the user enable python for their project.
 */
public class EnablePythonWizardPage extends WizardPage {

	private ChooseGhidraInstallationWizardPage ghidraInstallationPage;
	private Button pyghidraButton;
	private Button jythonButton;
	private Button noneButton;
	private Combo pyghidraCombo;
	private Button addPyGhidraButton;
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
		container.setLayout(new GridLayout(1, false));

		// Project type selection
		SelectionListener projectTypeSelectionListener = new SelectionListener() {
			@Override
			public void widgetSelected(SelectionEvent evt) {
				validate(null);
			}

			@Override
			public void widgetDefaultSelected(SelectionEvent evt) {
				validate(null);
			}
		};
		Group projectTypeGroup = new Group(container, SWT.SHADOW_ETCHED_OUT);
		projectTypeGroup.setLayout(new RowLayout(SWT.HORIZONTAL));
		projectTypeGroup.setText("Project Type");
		pyghidraButton = new Button(projectTypeGroup, SWT.RADIO);
		pyghidraButton.setSelection(PyDevUtils.isSupportedPyGhidraPyDevInstalled());
		pyghidraButton.setText("PyGhidra");
		pyghidraButton.setToolTipText("Enables PyGhidra support using the PyDev " +
			"Eclipse plugin.  Requires PyDev version " + PyDevUtils.MIN_SUPPORTED_VERSION +
			" or later.");
		pyghidraButton.addSelectionListener(projectTypeSelectionListener);
		jythonButton = new Button(projectTypeGroup, SWT.RADIO);
		jythonButton.setSelection(false);
		jythonButton.setText("Jython");
		jythonButton.setToolTipText("Enables Jython support using the PyDev " +
			"Eclipse plugin.  Requires PyDev version " + PyDevUtils.MIN_SUPPORTED_VERSION +
			" - " + PyDevUtils.MAX_JYTHON_SUPPORTED_VERSION);
		jythonButton.addSelectionListener(projectTypeSelectionListener);
		noneButton = new Button(projectTypeGroup, SWT.RADIO);
		noneButton.setSelection(!PyDevUtils.isSupportedPyGhidraPyDevInstalled());
		noneButton.setText("None");
		noneButton.setToolTipText("Disables Python support for the project.");
		noneButton.addSelectionListener(projectTypeSelectionListener);

		Composite interpreterContainer = new Composite(container, SWT.NULL);
		interpreterContainer.setLayout(new GridLayout(3, false));
		interpreterContainer.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));

		// PyGhidra interpreter combo box
		Label pyGhidraLabel = new Label(interpreterContainer, SWT.NULL);
		pyGhidraLabel.setText("PyGhidra interpreter:");
		pyghidraCombo = new Combo(interpreterContainer, SWT.DROP_DOWN | SWT.READ_ONLY);
		pyghidraCombo.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));
		pyghidraCombo.setToolTipText("The wizard requires a Python interpreter to be " +
			"selected.  Click the + button to add or manage Python interpreters.");
		File savedPyGhidraInterpreter = populatePyGhidraCombo(null);
		pyghidraCombo.addModifyListener(evt -> validate(null));

		// PyGhidra interpreter add button
		addPyGhidraButton = new Button(interpreterContainer, SWT.BUTTON1);
		addPyGhidraButton.setText("+");
		addPyGhidraButton.setToolTipText("Adds/manages PyGhidra interpreters.");
		addPyGhidraButton.addListener(SWT.Selection, evt -> {
			try {
				File ghidraDir = ghidraInstallationPage.getGhidraInstallDir();
				File pyghidraInterpreter = findPyGhidraInterpreter();
				File pypredefDir = new File(ghidraDir, "docs/ghidra_stubs/pypredef");
				if (!pypredefDir.isDirectory()) {
					pypredefDir = null;
				}
				if (EclipseMessageUtils.showQuestionDialog("Python Found",
					"PyGhidra was previously launched with: \"" + pyghidraInterpreter +
						"\". Would you like to use it as your interpreter?")) {
					PyDevUtils.addPyGhidraInterpreter("pyghidra_" + ghidraDir.getName(),
						pyghidraInterpreter, pypredefDir);
					populatePyGhidraCombo(pyghidraInterpreter);
					validate(pyghidraInterpreter);
					return;
				}
			}
			catch (Exception e) {
				// Fall through to show PyDev's Python preference page
			}
			
			PreferenceDialog dialog = PreferencesUtil.createPreferenceDialogOn(null,
				PyDevUtils.getPythonPreferencePageId(), null, null);
			dialog.open();
			populatePyGhidraCombo(savedPyGhidraInterpreter);
			validate(null);
		});

		// Jython interpreter combo box
		Label jythonLabel = new Label(interpreterContainer, SWT.NULL);
		jythonLabel.setText("Jython interpreter:");
		jythonCombo = new Combo(interpreterContainer, SWT.DROP_DOWN | SWT.READ_ONLY);
		jythonCombo.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));
		jythonCombo.setToolTipText("The wizard requires a Jython interpreter to be " +
			"selected.  Click the + button to add or manage Jython interpreters.");
		populateJythonCombo();
		jythonCombo.addModifyListener(evt -> validate(null));

		// Jython interpreter add button
		addJythonButton = new Button(interpreterContainer, SWT.BUTTON1);
		addJythonButton.setText("+");
		addJythonButton.setToolTipText("Adds/manages Jython interpreters.");
		addJythonButton.addListener(SWT.Selection, evt -> {
			try {
				if (PyDevUtils.getJythonInterpreterNames().isEmpty()) {
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
							validate(null);
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
			validate(null);
		});

		validate(savedPyGhidraInterpreter);
		setControl(container);
	}

	@Override
	public void setVisible(boolean visible) {
		if (visible) {
			validate(populatePyGhidraCombo(null));
		}
		super.setVisible(visible);
	}

	/**
	 * {@return the project Python interpreter to use}
	 */
	public ProjectPythonInterpreter getProjectPythonInterpreter() {
		if (pyghidraButton.getSelection()) {
			return new ProjectPythonInterpreter(pyghidraCombo.getText(),
				ProjectPythonInterpreterType.PYGHIDRA);
		}
		if (jythonButton.getSelection()) {
			return new ProjectPythonInterpreter(jythonCombo.getText(),
				ProjectPythonInterpreterType.JYTHON);
		}
		return new ProjectPythonInterpreter(null, ProjectPythonInterpreterType.NONE);
	}

	/**
	 * Validates the fields on the page and updates the page's status.
	 * Should be called every time a field on the page changes.
	 * 
	 * @param pyghidraInterpreter The Python interpreter used to launch PyGhidra (could be null if 
	 *   unknown).
	 */
	private void validate(File pyghidraInterpreter) {
		String message = null;
		boolean pyghidraSupported = PyDevUtils.isSupportedPyGhidraPyDevInstalled();
		boolean jythonSupported = PyDevUtils.isSupportedJythonPyDevInstalled();

		if (pyghidraButton.getSelection()) {
			if (!pyghidraSupported) {
				message = "PyDev version " + PyDevUtils.MIN_SUPPORTED_VERSION +
					" or later is not installed.";
			}
			else {
				try {
					if (pyghidraInterpreter == null) {
						pyghidraInterpreter = findPyGhidraInterpreter();
					}
					if (pyghidraInterpreter == null) {
						message =
							"Please first launch PyGhidra to associate the Ghidra installation with a supported version of Python.";
						pyghidraSupported = false;
					}
					else {
						List<String> interpreters =
							PyDevUtils.getPyGhidraInterpreterNames(pyghidraInterpreter);
						if (interpreters.isEmpty()) {
							message ="No PyGhidra interpreters found. Click the + button or set project type to \"None\".";
						}
					}
				}
				catch (OperationNotSupportedException e) {
					message = "PyDev version is not supported for Jython.";
					pyghidraSupported = false;
				}
				catch (Exception e) {
					message =
						"Failed to lookup Python interpreter associated with the Ghidra installation.";
					pyghidraSupported = false;
				}
			}
		}
		else if (jythonButton.getSelection()) {
			if (!jythonSupported) {
				message = "PyDev version " + PyDevUtils.MIN_SUPPORTED_VERSION +
					" - " + PyDevUtils.MAX_JYTHON_SUPPORTED_VERSION + " is not installed.";
			}
			else {
				try {
					List<String> interpreters = PyDevUtils.getJythonInterpreterNames();
					if (interpreters.isEmpty()) {
						message =
							"No Jython interpreters found. Click the + button or set project type to \"None\".";
					}
				}
				catch (OperationNotSupportedException e) {
					message = "PyDev version is not supported for Jython.";
					jythonSupported = false;
				}
			}
		}

		pyghidraCombo.setEnabled(pyghidraButton.getSelection() && pyghidraSupported);
		addPyGhidraButton.setEnabled(pyghidraButton.getSelection() && pyghidraSupported);
		jythonCombo.setEnabled(jythonButton.getSelection() && jythonSupported);
		addJythonButton.setEnabled(jythonButton.getSelection() && jythonSupported);

		setErrorMessage(message);
		setPageComplete(message == null);
	}

	/**
	 * Populates the PyGhidra combo box with discovered PyGhidra interpreter names.
	 * 
	 * @param pyghidraInterpreter The Python interpreter used to launch PyGhidra (could be null if 
	 *   unknown).
	 * @return The Python interpreter used to launch PyGhidra (could be null if unknown).
	 */
	private File populatePyGhidraCombo(File pyghidraInterpreter) {
		pyghidraCombo.removeAll();
		try {
			if (pyghidraInterpreter == null) {
				pyghidraInterpreter = findPyGhidraInterpreter();
			}
			PyDevUtils.getPyGhidraInterpreterNames(pyghidraInterpreter).forEach(pyghidraCombo::add);
		}
		catch (Exception e) {
			// Nothing to do.  Combo should and will be empty.
		}
		if (pyghidraCombo.getItemCount() > 0) {
			pyghidraCombo.select(0);
		}
		return pyghidraInterpreter;
	}

	/**
	 * Populates the Jython combo box with discovered Jython interpreter names.
	 */
	private void populateJythonCombo() {
		jythonCombo.removeAll();
		try {
			PyDevUtils.getJythonInterpreterNames().forEach(jythonCombo::add);
		}
		catch (OperationNotSupportedException e) {
			// Nothing to do.  Combo should and will be empty.
		}
		if (jythonCombo.getItemCount() > 0) {
			jythonCombo.select(0);
		}
	}

	/**
	 * Find's the Python interpreter file that was used to launch PyGhidra.
	 * 
	 * @return The Python interpreter file that was used to launch PyGhidra, or null if one could 
	 * not be found.
	 * @throws Exception if there was a problem finding the Python interpreter.
	 */
	private File findPyGhidraInterpreter() throws Exception {
		File ghidraDir = ghidraInstallationPage.getGhidraInstallDir();
		AppConfig appConfig = new AppConfig(ghidraDir);
		List<String> cmd = appConfig.getSavedPythonCommand();
		if (cmd == null) {
			return null;
		}
		cmd.add("-c");
		cmd.add("import sys; print(sys.executable)");
		Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
		BufferedReader reader =
			new BufferedReader(new InputStreamReader(p.getInputStream()));
		String pythonExecutable = reader.readLine();
		if (p.waitFor() == 0) {
			return new File(pythonExecutable);
		}
		return null;
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
