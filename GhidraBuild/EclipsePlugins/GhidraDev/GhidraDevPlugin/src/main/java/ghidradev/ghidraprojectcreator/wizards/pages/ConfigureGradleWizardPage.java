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

import org.eclipse.buildship.core.*;
import org.eclipse.core.resources.IFolder;
import org.eclipse.core.resources.IProject;
import org.eclipse.jface.wizard.WizardPage;
import org.eclipse.swt.SWT;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.events.SelectionListener;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.*;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.ApplicationProperties;
import ghidradev.EclipseMessageUtils;
import ghidradev.ghidraprojectcreator.preferences.GhidraProjectCreatorPreferences;
import ghidradev.ghidraprojectcreator.utils.GhidraProjectUtils;

public class ConfigureGradleWizardPage extends WizardPage {

	private Button gradleWrapperChoiceButton;
	private Button gradleLocalChoiceButton;
	private Text gradleLocalDirText;
	private Button gradlLocalDirButton;

	private ChooseGhidraModuleProjectWizardPage projectPage;
	private String gradleVersion;


	/**
	 * Creates a new Gradle configuration wizard page.
	 * 
	 * @param projectPage A {@link ChooseGhidraModuleProjectWizardPage} to get the project from. 
	 */
	public ConfigureGradleWizardPage(ChooseGhidraModuleProjectWizardPage projectPage) {
		super("ConfigureGradleWizardPage");
		setTitle("Configure Gradle");
		setDescription("Configure Gradle.");
		this.projectPage = projectPage;
	}

	@Override
	public void createControl(Composite parent) {

		Composite container = new Composite(parent, SWT.NULL);
		container.setLayout(new GridLayout(4, false));

		SelectionListener selectionListener = new SelectionListener() {
			@Override
			public void widgetSelected(SelectionEvent evt) {
				validate();
			}

			@Override
			public void widgetDefaultSelected(SelectionEvent evt) {
				validate();
			}
		};

		// Local Gradle
		String gradleLocalTooltip = "Use a local installation of Gradle.  For best results, " +
			"ensure that the version of this local Gradle matches the version specified on this wizard page's description.";
		gradleLocalChoiceButton = new Button(container, SWT.RADIO);
		gradleLocalChoiceButton.addSelectionListener(selectionListener);
		gradleLocalChoiceButton.setToolTipText(gradleLocalTooltip);
		Label gradleLocalDirLabel = new Label(container, SWT.NULL);
		gradleLocalDirLabel.setText("Local installation directory:");
		gradleLocalDirText = new Text(container, SWT.BORDER | SWT.SINGLE);
		gradleLocalDirText.setToolTipText(gradleLocalTooltip);
		gradleLocalDirText.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));
		gradleLocalDirText.addModifyListener(evt -> validate());
		gradlLocalDirButton = new Button(container, SWT.BUTTON1);
		gradlLocalDirButton.setText("...");
		gradlLocalDirButton.addListener(SWT.Selection, evt -> {
			DirectoryDialog dialog = new DirectoryDialog(container.getShell());
			String path = dialog.open();
			if (path != null) {
				gradleLocalDirText.setText(path);
			}
			validate();
		});

		// Gradle Wrapper
		String gradleWrapperTooltip = "Use the Gradle Wrapper, which will automatically download " +
			"the correct version of Gradle to use from the Internet.";
		gradleWrapperChoiceButton = new Button(container, SWT.RADIO);
		gradleWrapperChoiceButton.addSelectionListener(selectionListener);
		gradleWrapperChoiceButton.setToolTipText(gradleWrapperTooltip);
		Label gradleWrapperDirLabel = new Label(container, SWT.NULL);
		gradleWrapperDirLabel.setText("Gradle Wrapper");
		Label internetLabel = new Label(container, SWT.NONE);
		internetLabel.setText("INTERNET CONNECTION REQUIRED");
		internetLabel.setForeground(parent.getDisplay().getSystemColor(SWT.COLOR_RED));
		internetLabel.setToolTipText(gradleWrapperTooltip);
		new Label(container, SWT.NONE).setText(""); // empty grid cell

		// Set default value from preferences
		GradleDistribution lastGradleDistribution =
			GhidraProjectCreatorPreferences.getGhidraLastGradleDistribution();
		if (lastGradleDistribution instanceof LocalGradleDistribution) {
			gradleLocalChoiceButton.setSelection(true);
			LocalGradleDistribution localGradleDistribution =
				(LocalGradleDistribution) lastGradleDistribution;
			if (localGradleDistribution.getLocation() != null) {
				gradleLocalDirText.setText(localGradleDistribution.getLocation().getAbsolutePath());
			}
		}
		else if (lastGradleDistribution instanceof WrapperGradleDistribution ||
			lastGradleDistribution instanceof FixedVersionGradleDistribution) {
			gradleWrapperChoiceButton.setSelection(true);
		}
		else {
			gradleLocalChoiceButton.setSelection(true);
		}

		validate();
		setControl(container);
	}

	@Override
	public void setVisible(boolean visible) {
		super.setVisible(visible);

		// Update the page's description to reference the version of Gradle that should be used.
		if (visible) {
			IProject project = projectPage.getGhidraModuleProject().getProject();
			IFolder ghidraFolder = project.getFolder(GhidraProjectUtils.GHIDRA_FOLDER_NAME);
			File ghidraDir = ghidraFolder.getLocation().toFile();
			try {
				GhidraApplicationLayout ghidraLayout = new GhidraApplicationLayout(ghidraDir);
				ApplicationProperties props = ghidraLayout.getApplicationProperties();
				gradleVersion =
					props.getProperty(ApplicationProperties.APPLICATION_GRADLE_MIN_PROPERTY);
				if (gradleVersion != null && !gradleVersion.isEmpty()) {
					setDescription("Configure Gradle.  Version " + gradleVersion + " is expected.");
				}
			}
			catch (IOException e) {
				EclipseMessageUtils.error("Unable to determine required Gradle version.");
			}
		}
	}

	/**
	 * Gets the Gradle distribution to use.
	 * 
	 * @return The gradle distribution to use.
	 */
	public GradleDistribution getGradleDistribution() {
		if (gradleLocalChoiceButton.getSelection()) {
			return GradleDistribution.forLocalInstallation(new File(gradleLocalDirText.getText()));
		}
		else if (gradleVersion != null) {
			return GradleDistribution.forVersion(gradleVersion);
		}
		else {
			// This case should only happen if someone deleted the Gradle version from
			// application.properties.  In that case, we'll just try the standard wrapper and hope
			// for the best.
			return GradleDistribution.fromBuild();
		}
	}

	/**
	 * Validates the fields on the page and updates the page's status.
	 * Should be called every time a field on the page changes.
	 */
	private void validate() {
		String message = null;

		if (gradleLocalChoiceButton.getSelection()) {
			String path = gradleLocalDirText.getText().trim();
			File dir = new File(path);
			if (path.isEmpty()) {
				message = "Path to local Gradle installation must be specified.";
			}
			else if (!dir.exists()) {
				message = "Path to local Gradle installation does not exist.";
			}
			else if (!dir.isDirectory()) {
				message = "Path to local Gradle installation is not a directory.";
			}
			else if (!new File(dir, "bin/gradle").exists()) {
				message =
					"Path to local Gradle installation appears invalid.  Missing gradle binary.";
			}
		}

		if (message == null) {
			GhidraProjectCreatorPreferences.setGhidraLastGradleDistribution(
				getGradleDistribution());
		}
		else {
			GhidraProjectCreatorPreferences.setGhidraLastGradleDistribution(null);
		}

		setErrorMessage(message);
		setPageComplete(message == null);
	}
}
