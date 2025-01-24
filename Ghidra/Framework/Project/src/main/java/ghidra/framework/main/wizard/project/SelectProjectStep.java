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
package ghidra.framework.main.wizard.project;

import static ghidra.app.util.GenericHelpTopics.*;

import java.io.File;

import javax.swing.JComponent;

import docking.wizard.WizardModel;
import docking.wizard.WizardStep;
import ghidra.framework.model.ProjectLocator;
import ghidra.util.HelpLocation;
import ghidra.util.NamingUtilities;

/**
 * Wizard step in the new project wizard for choosing the new project's root folder location and
 * naming the project.
 */
public class SelectProjectStep extends WizardStep<ProjectWizardData> {
	private SelectProjectPanel panel;

	protected SelectProjectStep(WizardModel<ProjectWizardData> model) {
		// title and help will be set later based on the data
		super(model, "", null);
		panel = new SelectProjectPanel(() -> notifyStatusChanged());
	}

	@Override
	public void initialize(ProjectWizardData data) {
		boolean isShared = data.isSharedProject();

		if (isShared) {
			String repositoryName = data.getRepositoryName();
			if (panel.getProjectName().isBlank()) {
				panel.setProjectName(repositoryName);
			}
			setTitle("Select Local Project Location for Repository \"" + repositoryName + "\"");
			setHelpLocation(new HelpLocation(FRONT_END, "SelectProjectLocation"));
		}
		else {
			setTitle("Select Project Location");
			setHelpLocation(new HelpLocation(FRONT_END, "CreateNonSharedProject"));
		}
	}

	@Override
	public boolean isValid() {
		String dir = panel.getDirectoryName();
		String projectName = panel.getProjectName();
		return isValid(dir, projectName);
	}

	private boolean isValid(String dir, String projectName) {
		if (dir.isBlank()) {
			setStatusMessage("Please specify project directory");
			return false;
		}
		File projectDir = new File(dir);
		if (!projectDir.isDirectory()) {
			setStatusMessage("Project directory does not exist.");
			return false;
		}

		if (!NamingUtilities.isValidProjectName(projectName)) {
			setStatusMessage("Please specify valid project name");
			return false;
		}
		try {
			ProjectLocator locator = new ProjectLocator(dir, projectName);
			if (locator.getMarkerFile().exists() || locator.getProjectDir().exists()) {
				setStatusMessage("A project named " + locator.getName() +
					" already exists in " + projectDir.getAbsolutePath());
				return false;
			}
		}
		catch (IllegalArgumentException e) {
			setStatusMessage(e.getMessage());
			return false;
		}
		return true;
	}

	@Override
	public void populateData(ProjectWizardData data) {
		String dir = panel.getDirectoryName();
		String projectName = panel.getProjectName();
		data.setProjectLocator(new ProjectLocator(dir, projectName));
	}

	@Override
	public boolean canFinish(ProjectWizardData data) {
		ProjectLocator projectLocator = data.getProjectLocator();
		if (projectLocator != null) {
			return true;
		}
		String name = data.getRepositoryName();
		if (data.isSharedProject() && name != null) {
			String dir = panel.getDirectoryName();
			if (isValid(dir, name)) {
				data.setProjectLocator(new ProjectLocator(dir, name));
				return true;
			}
		}
		return false;
	}

	@Override
	public boolean apply(ProjectWizardData data) {
		return true;
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

}
