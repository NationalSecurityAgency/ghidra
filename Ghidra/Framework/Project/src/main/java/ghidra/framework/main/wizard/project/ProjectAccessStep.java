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

import java.io.IOException;
import java.util.ArrayList;

import javax.swing.JComponent;

import docking.wizard.WizardModel;
import docking.wizard.WizardStep;
import ghidra.app.util.GenericHelpTopics;
import ghidra.framework.client.RepositoryServerAdapter;
import ghidra.framework.main.ProjectAccessPanel;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.remote.User;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

/**
 * Wizard step for configuring user access in a Ghidra server repository. Used by the
 * "new project", the "convert to shared" and the "change repository" wizards. This step
 * only gets shown if the user creates a new repository. 
 */
public class ProjectAccessStep extends WizardStep<ProjectWizardData> {
	private ProjectAccessPanel panel;
	private PluginTool tool;

	public ProjectAccessStep(WizardModel<ProjectWizardData> model, PluginTool tool) {
		// no title passed to constructor, it will be set later
		super(model, "", new HelpLocation(GenericHelpTopics.FRONT_END, "UserAccessList"));
		this.tool = tool;
	}

	@Override
	public void initialize(ProjectWizardData data) {
		setTitle("Specify Users for Repository: " + data.getRepositoryName());
		String repositoryName = data.getRepositoryName();
		RepositoryServerAdapter server = data.getServer();

		try {
			String[] allUsers = server.getAllUsers();
			ArrayList<User> userList = new ArrayList<>();
			userList.add(new User(server.getUser(), User.ADMIN));
			panel = new ProjectAccessPanel(allUsers, server.getUser(), userList,
				repositoryName, server.anonymousAccessAllowed(), false, tool);
		}
		catch (IOException e) {
			Msg.error(this, "Error creating project access panel");
		}

	}

	@Override
	public boolean isApplicable(ProjectWizardData data) {
		return data.isSharedProject() && data.isNewRepository();
	}

	@Override
	public boolean isValid() {
		if (panel == null) {
			return false;
		}
		return true;
	}

	@Override
	public void populateData(ProjectWizardData data) {
		User[] projectUsers = panel.getProjectUsers();
		boolean allowAnonymousAccess = panel.allowAnonymousAccess();
		data.setProjectUsers(projectUsers);
		data.setAllowAnonymousAccess(allowAnonymousAccess);
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

	@Override
	public boolean apply(ProjectWizardData data) {
		return true;
	}

	@Override
	public boolean canFinish(ProjectWizardData data) {
		return panel != null;
	}

}
