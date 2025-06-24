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
import java.util.List;

import javax.swing.JComponent;

import docking.wizard.WizardModel;
import docking.wizard.WizardStep;
import ghidra.app.util.GenericHelpTopics;
import ghidra.framework.client.RepositoryServerAdapter;
import ghidra.framework.model.ServerInfo;
import ghidra.util.HelpLocation;
import ghidra.util.NamingUtilities;

/**
 * Wizard step in the new project wizard selecting or creating a new repository in a Ghidra server.
 */
public class RepositoryStep extends WizardStep<ProjectWizardData> {
	private RepositoryPanel panel;
	private RepositoryServerAdapter server;
	private String[] repositoryNames;

	protected RepositoryStep(WizardModel<ProjectWizardData> model) {
		super(model, "", new HelpLocation(GenericHelpTopics.FRONT_END, "SelectRepository"));
	}

	@Override
	public void initialize(ProjectWizardData data) {
		ServerInfo serverInfo = data.getServerInfo();
		setTitle("Specify Repository Name from server: " + serverInfo.getServerName());
		server = data.getServer();
		repositoryNames = getRepositoryNames();
		if (panel == null) {
			boolean readOnly = isServerReadOnly();
			panel = new RepositoryPanel(this::notifyStatusChanged, repositoryNames, readOnly);
		}
	}

	private boolean isServerReadOnly() {
		try {
			return server.isReadOnly();
		}
		catch (IOException e) {
			return true;
		}
	}

	private String[] getRepositoryNames() {
		try {
			return server.getRepositoryNames();
		}
		catch (IOException e) {
			return new String[0];
		}
	}

	@Override
	public boolean isValid() {
		String repositoryName = panel.getRepositoryName();
		if (panel.isCreateRepositorySelected()) {
			if (repositoryName.length() == 0) {
				return false;
			}
			if (!NamingUtilities.isValidProjectName(repositoryName)) {
				setStatusMessage("Invalid project repository name");
				return false;
			}
			if (List.of(repositoryNames).contains(repositoryName)) {
				setStatusMessage("Repository " + repositoryName + " already exists");
				return false;
			}
		}
		else if (repositoryName == null) {
			setStatusMessage("Please select a repository");
			return false;
		}
		return true;
	}

	@Override
	public void populateData(ProjectWizardData data) {
		data.setRepositoryName(panel.getRepositoryName());
		data.setIsNewRepository(panel.isCreateRepositorySelected());

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
		return data.getRepositoryName() != null;
	}

	@Override
	public boolean isApplicable(ProjectWizardData data) {
		return data.isSharedProject();
	}
}
