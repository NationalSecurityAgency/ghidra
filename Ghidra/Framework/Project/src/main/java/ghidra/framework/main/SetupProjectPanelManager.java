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
package ghidra.framework.main;

import java.awt.Dimension;
import java.io.IOException;
import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.List;

import javax.swing.BorderFactory;
import javax.swing.border.Border;

import docking.wizard.*;
import ghidra.app.util.GenericHelpTopics;
import ghidra.framework.client.*;
import ghidra.framework.model.ProjectManager;
import ghidra.framework.model.ServerInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.remote.User;
import ghidra.util.HelpLocation;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.UserAccessException;

/**
 * Manage the panels for the wizard that shows server info and repository panels.  
 * The panel order is 
 * (1) Server Info
 * (2) Repository panel
 * (3) Project access panel (if user is creating a new repository)
 *  This panel manager is used when the project is being converted to a shared project and
 *  when a shared project's information is to change.
 */
class SetupProjectPanelManager implements PanelManager {

	private WizardManager wizardMgr;
	private String[] knownUsers;
	private ServerInfoPanel serverPanel;
	private RepositoryPanel repositoryPanel;
	private ProjectAccessPanel projectAccessPanel;
	private WizardPanel currentWizardPanel;
	private boolean includeAnonymousAccessControl = false;
	private ProjectManager projectMgr;
	private RepositoryServerAdapter server;
	private RepositoryAdapter repository;
	private ServerInfo serverInfo;
	private ServerInfo currentServerInfo;
	private String statusMessage;
	private PluginTool tool;

	final static Border EMPTY_BORDER = BorderFactory.createEmptyBorder(80, 120, 0, 120);

	SetupProjectPanelManager(PluginTool tool, ServerInfo serverInfo) {
		serverPanel = new ServerInfoPanel(this);
		serverPanel.setHelpLocation(
			new HelpLocation(GenericHelpTopics.FRONT_END, "SetupServerInfo"));
		projectMgr = tool.getProjectManager();
		currentServerInfo = serverInfo;
		this.tool = tool;
	}

	@Override
	public boolean canFinish() {

		if (repositoryPanel == null) {
			return false;
		}
		if (repositoryPanel.isValidInformation()) {
			if (repositoryPanel.createRepository()) {
				return projectAccessPanel == null || projectAccessPanel.isValidInformation();
			}
			return true;
		}
		return false;
	}

	@Override
	public boolean hasNextPanel() {
		if (currentWizardPanel == serverPanel) {
			return true;
		}

		if (currentWizardPanel == repositoryPanel && repositoryPanel.createRepository()) {
			return true;
		}
		return false;
	}

	@Override
	public boolean hasPreviousPanel() {
		return currentWizardPanel != serverPanel;
	}

	@Override
	public WizardPanel getInitialPanel() {
		currentWizardPanel = serverPanel;
		return currentWizardPanel;
	}

	@Override
	public WizardPanel getNextPanel() {
		if (currentWizardPanel == null) {
			currentWizardPanel = serverPanel;
			if (currentServerInfo != null) {
				serverPanel.setServerInfo(currentServerInfo);
			}
			else {
				serverPanel.setServerInfo(projectMgr.getMostRecentServerInfo());
			}
		}
		else if (currentWizardPanel == serverPanel) {
			String serverName = serverPanel.getServerName();
			int portNumber = serverPanel.getPortNumber();
			if (!isServerInfoValid(serverName, portNumber)) {
				return serverPanel;
			}

			try {
				knownUsers = server.getAllUsers();
				String[] repositoryNames = server.getRepositoryNames();
				includeAnonymousAccessControl = server.anonymousAccessAllowed();
				if (repositoryPanel == null) {
					repositoryPanel =
						new RepositoryPanel(this, serverName, repositoryNames, server.isReadOnly());
					repositoryPanel.setHelpLocation(
						new HelpLocation(GenericHelpTopics.FRONT_END, "ChangeRepository"));
				}
				currentWizardPanel = repositoryPanel;
			}
			catch (RemoteException e) {
				statusMessage = "Error accessing remote server on " + serverName;
			}
			catch (NotConnectedException e) {
				statusMessage = e.getMessage();
				if (statusMessage == null) {
					statusMessage = "Not connected to server " + serverName + ": " + e;
				}
			}
			catch (IOException e) {
				statusMessage = "IOException: could not access remote server on " + serverName;
			}
		}
		else if (currentWizardPanel == repositoryPanel) {
			String repositoryName = repositoryPanel.getRepositoryName();
			if (!repositoryPanel.createRepository()) {
				currentWizardPanel = null;
				repository = server.getRepository(repositoryName);
				return currentWizardPanel;
			}

			checkNewRepositoryAccessPanel();
			currentWizardPanel = projectAccessPanel;
		}
		else if (currentWizardPanel == projectAccessPanel) {
			currentWizardPanel = null;
		}
		return currentWizardPanel;
	}

	@Override
	public WizardPanel getPreviousPanel() {
		if (currentWizardPanel == projectAccessPanel) {
			currentWizardPanel = repositoryPanel;
		}
		else if (currentWizardPanel == repositoryPanel) {
			currentWizardPanel = serverPanel;
		}
		else {
			currentWizardPanel = null;
		}
		return currentWizardPanel;
	}

	@Override
	public String getStatusMessage() {
		String msg = statusMessage;
		statusMessage = null;
		return msg;
	}

	@Override
	public void finish() {

		if (server != null) {
			boolean createNewRepository = repositoryPanel.createRepository();
			if (!createNewRepository) {
				if (repository == null) {
					repository = server.getRepository(repositoryPanel.getRepositoryName());
				}
			}
			else {
				try {
					String repositoryName = repositoryPanel.getRepositoryName();
					boolean allowAnonymousAccess;
					User[] accessList;
					if (projectAccessPanel != null &&
						projectAccessPanel.getRepositoryName().equals(repositoryName)) {
						accessList = projectAccessPanel.getProjectUsers();
						allowAnonymousAccess = projectAccessPanel.allowAnonymousAccess();
					}
					else {
						accessList = new User[] { new User(server.getUser(), User.ADMIN) };
						allowAnonymousAccess = false;
					}
					repository = server.createRepository(repositoryName);
					repository.setUserList(accessList, allowAnonymousAccess);
				}
				catch (DuplicateNameException e) {
					statusMessage = "Repository " + repositoryPanel.getRepositoryName() + " exists";
				}
				catch (UserAccessException exc) {
					statusMessage = "Could not update the user list: " + exc.getMessage();
					return;
				}
				catch (NotConnectedException e) {
					statusMessage = e.getMessage();
					if (statusMessage == null) {
						statusMessage =
							"Not connected to server " + serverInfo.getServerName() + ": " + e;
					}
					return;
				}
				catch (IOException exc) {
					String msg = exc.getMessage();
					if (msg == null) {
						msg = exc.toString();
					}
					statusMessage = "Error occurred while updating the user list: " + msg;
					return;
				}
			}
		}
		wizardMgr.close();
	}

	@Override
	public void cancel() {
		currentWizardPanel = null;
		repositoryPanel = null;
		projectAccessPanel = null;
		server = null;
		if (repository != null) {
			repository.disconnect();
			repository = null;
		}
	}

	@Override
	public void initialize() {
		currentWizardPanel = null;
		if (repositoryPanel != null) {
			repositoryPanel.initialize();
		}
		if (projectAccessPanel != null) {
			projectAccessPanel.initialize();
		}
	}

	@Override
	public Dimension getPanelSize() {
		return getMyPanelSize();
	}

	@Override
	public void setWizardManager(WizardManager wm) {
		wizardMgr = wm;
	}

	@Override
	public WizardManager getWizardManager() {
		return wizardMgr;
	}

	/**
	 * Get the repository adapter associated with the new project.
	 * After displaying this panel, this method should be invoked to obtain the 
	 * repository which will be opened for shared projects.  If the repository is
	 * not used to create a new project, its disconnect method should be invoked.
	 * @return null if project is not shared
	 */
	RepositoryAdapter getProjectRepository() {
		return repository;
	}

	String getProjectRepositoryName() {
		return repositoryPanel.getRepositoryName();
	}

	private void checkNewRepositoryAccessPanel() {

		String repositoryName = repositoryPanel.getRepositoryName();
		if (projectAccessPanel != null &&
			projectAccessPanel.getRepositoryName().equals(repositoryName)) {
			return;
		}

		List<User> userList = new ArrayList<>();
		userList.add(new User(server.getUser(), User.ADMIN));

		projectAccessPanel = new ProjectAccessPanel(knownUsers, server.getUser(), userList,
			repositoryName, includeAnonymousAccessControl, false, tool);

		projectAccessPanel.setHelpLocation(
			new HelpLocation(GenericHelpTopics.FRONT_END, "SetupUsers"));
	}

	/**
	 * Return true if a connection could be established using the given
	 * server name and port number.
	 */
	private boolean isServerInfoValid(String serverName, int portNumber) {
		if (server != null && serverInfo != null && serverInfo.getServerName().equals(serverName) &&
			serverInfo.getPortNumber() == portNumber && server.isConnected()) {
			return true;
		}

		server = null;
		serverInfo = null;
		repositoryPanel = null;

		server = projectMgr.getRepositoryServerAdapter(serverName, portNumber, true);
		if (server.isConnected()) {
			serverInfo = projectMgr.getMostRecentServerInfo();
			return true;
		}

		statusMessage = "Could not connect to server " + serverName + ", port " + portNumber;
		return false;
	}

	private Dimension getMyPanelSize() {

		ProjectAccessPanel panel1 = new ProjectAccessPanel(new String[] { "nobody" }, "user",
			new ArrayList<User>(), "MyRepository", true, false, tool);
		RepositoryPanel panel2 = new RepositoryPanel(this, "ServerOne",
			new String[] { "MyRepository", "NewStuff", "Repository_A", "Repository_B" }, false);
		Dimension d1 = panel1.getPreferredSize();
		Dimension d2 = panel2.getPreferredSize();
		return new Dimension(Math.max(d1.width, d2.width), Math.max(d1.height, d2.height));
	}
}
