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
import java.util.regex.Pattern;

import org.eclipse.core.resources.ResourcesPlugin;
import org.eclipse.core.runtime.CoreException;
import org.eclipse.debug.core.ILaunchConfiguration;
import org.eclipse.jface.wizard.WizardPage;
import org.eclipse.swt.SWT;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.events.SelectionListener;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.*;

import ghidradev.ghidraprojectcreator.preferences.GhidraProjectCreatorPreferences;
import ghidradev.ghidraprojectcreator.utils.GhidraLaunchUtils;
import ghidradev.ghidraprojectcreator.utils.GhidraProjectUtils;

/**
 * A wizard page that lets the user create a new Ghidra project.
 */
public class CreateGhidraProjectWizardPage extends WizardPage {

	private String suggestedProjectName;

	private Text projectNameText;
	private Text projectRootDirText;
	private Button projectDirButton;
	private Button createRunConfigCheckboxButton;
	private Text runConfigMemoryText;

	/**
	 * Creates a Ghidra new project wizard page with the given suggested project name.
	 * 
	 * @param suggestedProjectName The suggested project name.
	 */
	public CreateGhidraProjectWizardPage(String suggestedProjectName) {
		super("CreateGhidraProjectWizardPage");
		setTitle("Create Ghidra Project");
		setDescription("Create a new Ghidra project.");
		this.suggestedProjectName = suggestedProjectName;
	}
	
	/**
	 * Creates a Ghidra new project wizard page.
	 */
	public CreateGhidraProjectWizardPage() {
		this("");
	}

	@Override
	public void createControl(Composite parent) {

		Composite container = new Composite(parent, SWT.NULL);
		container.setLayout(new GridLayout(3, false));
		
		// Project name
		Label projectNameLabel = new Label(container, SWT.NULL);
		projectNameLabel.setText("Project name:");
		projectNameText = new Text(container, SWT.BORDER | SWT.SINGLE);
		projectNameText.setText(suggestedProjectName);
		projectNameText.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));
		projectNameText.addModifyListener(evt -> validate());
		new Label(container, SWT.NONE).setText(""); // empty grid cell

		// Project directory
		Label projectDirLabel = new Label(container, SWT.NULL);
		String projectDirToolTip = "The directory where this project will be created.";
		projectDirLabel.setText("Project root directory:");
		projectDirLabel.setToolTipText(projectDirToolTip);
		projectRootDirText = new Text(container, SWT.BORDER | SWT.SINGLE);
		projectRootDirText.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));
		projectRootDirText.setText(GhidraProjectCreatorPreferences.getGhidraLastProjectRootPath());
		projectRootDirText.addModifyListener(evt -> validate());
		projectRootDirText.setToolTipText(projectDirToolTip);
		projectDirButton = new Button(container, SWT.BUTTON1);
		projectDirButton.setText("...");
		projectDirButton.setToolTipText("Browse to select project root directory");
		projectDirButton.addListener(SWT.Selection, evt -> {
			DirectoryDialog dialog = new DirectoryDialog(container.getShell());
			String path = dialog.open();
			if (path != null) {
				projectRootDirText.setText(path);
			}
		});

		// Create run configuration checkbox
		createRunConfigCheckboxButton = new Button(container, SWT.CHECK);
		createRunConfigCheckboxButton.setText("Create run configuration");
		createRunConfigCheckboxButton.setToolTipText("Automatically create a Ghidra run " +
			"configuration that can be used to launch and debug this project in Ghidra.  Run " +
			"configurations can be created later and modified in the \"Run --> Run " +
			"Configurations\" menu.");
		createRunConfigCheckboxButton.setSelection(true);
		createRunConfigCheckboxButton.addSelectionListener(new SelectionListener() {
			@Override
			public void widgetSelected(SelectionEvent evt) {
				validate();
			}

			@Override
			public void widgetDefaultSelected(SelectionEvent evt) {
				validate();
			}
		});
		new Label(container, SWT.NONE).setText(""); // empty grid cell
		new Label(container, SWT.NONE).setText(""); // empty grid cell

		// Run configuration memory
		Label runConfigMemoryLabel = new Label(container, SWT.NULL);
		String runConfigMemoryToolTip = "The maximum Java heap size (-Xmx) Ghidra will use when " +
			"launched with the created run configuration (ex: 4G, 1500m, etc).  If left blank, " +
			"Java's default heap size will be used, which is determined by your system's memory " +
			"capacity.";
		runConfigMemoryLabel.setText("Run configuration memory:");
		runConfigMemoryLabel.setToolTipText(runConfigMemoryToolTip);
		runConfigMemoryText = new Text(container, SWT.BORDER | SWT.SINGLE);
		runConfigMemoryText.addModifyListener(evt -> validate());
		runConfigMemoryText.setToolTipText(runConfigMemoryToolTip);
		new Label(container, SWT.NONE).setText(""); // empty grid cell

		validate();
		setControl(container);
	}

	/**
	 * Gets the name of the project.
	 * 
	 * @return The name of the project.
	 */
	public String getProjectName() {
		return projectNameText.getText();
	}

	/**
	 * Gets the project directory. This is the directory where the .project file should live.
	 * 
	 * @return The project directory. This is the directory where the .project file should live.
	 *   Could be null if unspecified, however, the page will not be valid until the project 
	 *   directory is valid, so it should never be null when called by other classes.
	 */
	public File getProjectDir() {
		if (projectNameText.getText().isEmpty()) {
			return null;
		}
		if (projectRootDirText.getText().isEmpty()) {
			return null;
		}
		return new File(projectRootDirText.getText(), getProjectName());
	}

	/**
	 * Checks to see whether or not a run configuration for the new project should be automatically
	 * created.
	 * 
	 * @return True if a run configuration for the new project should be automatically created;
	 *   otherwise, false.
	 */
	public boolean shouldCreateRunConfig() {
		return createRunConfigCheckboxButton.getSelection();
	}

	/**
	 * Gets the run configuration's desired memory.
	 * 
	 * @return The run configuration's desired memory.  Could be null if unspecified.
	 */
	public String getRunConfigMemory() {
		if (!createRunConfigCheckboxButton.getSelection() ||
			runConfigMemoryText.getText().isEmpty()) {
			return null;
		}
		return runConfigMemoryText.getText();
	}

	/**
	 * Validates the fields on the page and updates the page's status.
	 * Should be called every time a field on the page changes.
	 */
	private void validate() {

		final String BAD = GhidraProjectUtils.ILLEGAL_FILENAME_CHARS;
		final String BAD_START = GhidraProjectUtils.ILLEGAL_FILENAME_START_CHARS;
		
		runConfigMemoryText.setEnabled(createRunConfigCheckboxButton.getSelection());
		runConfigMemoryText.setMessage(runConfigMemoryText.isEnabled() ? "default" : "");

		String message = null;
		String projectName = getProjectName();
		File projectDir = getProjectDir();
		boolean launchConfigExists = false;
		try {
			ILaunchConfiguration launchConfig = GhidraLaunchUtils.getLaunchConfig(projectName);
			if (launchConfig != null) {
				String launchConfigTypeId = launchConfig.getType().getIdentifier();
				launchConfigExists = !launchConfigTypeId.equals(GhidraLaunchUtils.GUI_LAUNCH) &&
					!launchConfigTypeId.equals(GhidraLaunchUtils.HEADLESS_LAUNCH);
			}
		}
		catch (CoreException e) {
			// launchConfigExists can remain false, we'll just overwrite the config
		}

		if (projectName.isEmpty()) {
			message = "Project name must be specified";
		}
		else if ((BAD_START + BAD).chars().anyMatch(ch -> projectName.charAt(0) == ch)) {
			message = "Project name cannot start with an invalid character:\n " + BAD_START + BAD;
		}
		else if (BAD.chars().anyMatch(ch -> projectName.indexOf(ch) != -1)) {
			message = "Project name cannot contain invalid characters:\n " + BAD;
		}
		else if (projectDir == null) {
			message = "Project root directory must be specified";
		}
		else if (projectDir.exists()) {
			message = "Project already exists at: " + projectDir.getAbsolutePath();
		}
		else if (ResourcesPlugin.getWorkspace().getRoot().getProject(projectName).exists()) {
			message = "\"" + projectName + "\" project already exists in workspace";
		}
		else if (shouldCreateRunConfig() && launchConfigExists) {
			message = "Run configuration \"" + projectName +
				"\" project already exists (check run configuration filters)";
		}
		else if (createRunConfigCheckboxButton.getSelection() &&
			!runConfigMemoryText.getText().isEmpty() &&
			!Pattern.matches("^\\d+[KkMmGg]$", runConfigMemoryText.getText())) {
			message = "Invalid run configuration memory value.  Value must match JVM -Xmx flag" +
				" syntax (4G, 1500m, etc).";
		}

		setErrorMessage(message);
		setPageComplete(message == null);
		if (message == null) {
			GhidraProjectCreatorPreferences.setGhidraLastProjectRootPath(
				projectRootDirText.getText());
		}
	}
}
