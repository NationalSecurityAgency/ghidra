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

import java.awt.Dimension;
import java.io.IOException;
import java.util.List;

import javax.swing.Icon;

import docking.wizard.WizardModel;
import docking.wizard.WizardStep;
import generic.theme.GIcon;
import ghidra.framework.client.*;
import ghidra.framework.model.ServerInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.UserAccessException;

/**
 * Wizard model for either converting a non-shared project to a share project OR for moving
 * a shared project to a different server/repository. 
 */
public class ProjectChooseRepositoryWizardModel extends WizardModel<ProjectWizardData> {
	private final static Icon CONVERT_ICON = new GIcon("icon.project.info.convert");

	private PluginTool tool;

	public ProjectChooseRepositoryWizardModel(PluginTool tool, String title) {
		this(tool, title, null);
	}

	public ProjectChooseRepositoryWizardModel(PluginTool tool, String title, ServerInfo server) {
		super(title, new ProjectWizardData(), CONVERT_ICON);
		this.tool = tool;

		// this will allow server steps to be applicable
		data.setIsSharedProject(true);
		data.setServerInfo(server);
	}

	@Override
	protected void addWizardSteps(List<WizardStep<ProjectWizardData>> steps) {
		steps.add(new ServerStep(this, tool.getProjectManager()));
		steps.add(new RepositoryStep(this));
		steps.add(new ProjectAccessStep(this, tool));

	}

	@Override
	public Dimension getPreferredSize() {
		return new Dimension(500, 300);
	}

	@Override
	protected boolean doFinish() {
		RepositoryAdapter repository = getOrCreateRepository();
		if (repository == null) {
			return false;
		}
		try {
			repository.connect();
		}
		catch (IOException e) {
			setStatusMessage("Can't connect to repository: " + data.getRepositoryName());
			return false;
		}

		data.setRepository(repository);
		return true;
	}

	@Override
	public void cancel() {
		RepositoryAdapter repository = data.getRepository();
		if (repository != null) {
			repository.disconnect();
			data.setRepository(null);
		}
		data.setServer(null);
	}

	private RepositoryAdapter getOrCreateRepository() {
		String repositoryName = data.getRepositoryName();
		RepositoryServerAdapter server = data.getServer();

		if (!data.isNewRepository()) {
			RepositoryAdapter repository = server.getRepository(repositoryName);
			if (repository == null) {
				setStatusMessage("Can't open repository: " + repositoryName);
			}
			return repository;
		}

		try {
			RepositoryAdapter repository = server.createRepository(repositoryName);
			repository.setUserList(data.getProjectUsers(), data.allowAnonymousAccess());
			return repository;
		}
		catch (DuplicateNameException e) {
			setStatusMessage("Repository " + repositoryName + " exists");
		}
		catch (UserAccessException exc) {
			setStatusMessage("Could not update the user list: " + exc.getMessage());
		}
		catch (NotConnectedException e) {
			String statusMessage = e.getMessage();
			if (statusMessage == null) {
				String serverName = data.getServerInfo().getServerName();
				statusMessage = "Not connected to server " + serverName;
			}
			setStatusMessage(statusMessage);
		}
		catch (IOException e) {
			setStatusMessage("Error occurred while updating the user list: " + e.getMessage());
		}
		return null;
	}

	public RepositoryAdapter getRepository() {
		return data.getRepository();
	}
}
