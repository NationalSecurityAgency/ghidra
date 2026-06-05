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

import javax.swing.JComponent;

import docking.wizard.WizardModel;
import docking.wizard.WizardStep;
import ghidra.app.util.GenericHelpTopics;
import ghidra.util.HelpLocation;

/**
 * Wizard step in the new project wizard for choosing the type of project.
 */
public class ProjectTypeStep extends WizardStep<ProjectWizardData> {
	private ProjectTypePanel panel;

	protected ProjectTypeStep(WizardModel<ProjectWizardData> model) {
		super(model, "Select Project Type",
			new HelpLocation(GenericHelpTopics.FRONT_END, "SelectProjectType"));

		panel = new ProjectTypePanel();
	}

	@Override
	public void initialize(ProjectWizardData data) {
		// do nothing
	}

	@Override
	public boolean isValid() {
		return true;
	}

	@Override
	public void populateData(ProjectWizardData data) {
		data.setIsSharedProject(panel.isSharedProject());
	}

	@Override
	public boolean apply(ProjectWizardData data) {
		return true;
	}

	@Override
	public boolean canFinish(ProjectWizardData data) {
		return true;
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

}
