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
import ghidra.framework.client.RepositoryServerAdapter;
import ghidra.framework.model.ProjectManager;
import ghidra.framework.model.ServerInfo;
import ghidra.util.HelpLocation;

/**
 * Wizard step in the new project wizard for choosing the Ghidra server when creating a shared
 * project.
 */
public class ServerStep extends WizardStep<ProjectWizardData> {
	private ServerInfoPanel panel;
	private ProjectManager projectManager;

	protected ServerStep(WizardModel<ProjectWizardData> model, ProjectManager projectManager) {
		super(model, "Specify Server Information",
			new HelpLocation(GenericHelpTopics.FRONT_END, "SetupServerInfo"));
		this.projectManager = projectManager;
		panel = new ServerInfoPanel(this::notifyStatusChanged);
	}

	@Override
	public void initialize(ProjectWizardData data) {
		if (panel.getServerName().isBlank()) {
			ServerInfo info = getInitialServerInfo(data);
			if (info != null) {
				panel.setServerInfo(info);
			}
		}
	}

	private ServerInfo getInitialServerInfo(ProjectWizardData data) {
		if (data.getServerInfo() != null) {
			return data.getServerInfo();
		}
		return projectManager.getMostRecentServerInfo();
	}

	@Override
	public boolean isValid() {
		if (!panel.isValidInformation()) {
			setStatusMessage(panel.getStatusMessge());
			return false;
		}
		return true;
	}

	@Override
	public void populateData(ProjectWizardData data) {
		String serverName = panel.getServerName();
		int portNumber = panel.getPortNumber();
		data.setServerInfo(new ServerInfo(serverName, portNumber));
	}

	@Override
	public boolean canFinish(ProjectWizardData data) {
		return data.getServer() != null;
	}

	@Override
	public boolean apply(ProjectWizardData data) {
		ServerInfo serverInfo = data.getServerInfo();
		String serverName = serverInfo.getServerName();
		int port = serverInfo.getPortNumber();
		RepositoryServerAdapter server =
			projectManager.getRepositoryServerAdapter(serverName, port, true);
		if (!server.isConnected()) {
			setStatusMessage("Could not connect to server " + serverName + ", port " + port);
			return false;
		}

		data.setServer(server);
		return true;
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

	@Override
	public boolean isApplicable(ProjectWizardData data) {
		return data.isSharedProject();
	}

}
