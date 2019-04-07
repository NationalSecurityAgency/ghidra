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

import javax.swing.BorderFactory;
import javax.swing.border.Border;

import docking.wizard.*;
import ghidra.framework.client.*;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.preferences.Preferences;
import ghidra.framework.remote.User;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.UserAccessException;

/**
 * Manage the panels for the "New Project" wizard. The wizard handles 
 * creating a local project and a "shared" project.
 * If the project is shared, the panel order is 
 * (1) Server Info
 * (2) Repository panel
 * (3) Project access panel (if user has admin privileges AND user is 
 *      creating a new repository)
 * (4) Specify Project Location panel.
 * If the project is not shared, the only other panel to show is the
 * Specify Project Location panel.
 *  
 */
class NewProjectPanelManager implements PanelManager {

	private WizardManager wizardMgr;
	private String[] knownUsers;
	private ProjectTypePanel projectTypePanel;
	private SelectProjectPanel selectProjectPanel;
	private ServerInfoPanel serverPanel;
	private RepositoryPanel repositoryPanel;
	private ProjectAccessPanel projectAccessPanel;
	private WizardPanel currentWizardPanel;
	private boolean includeAnonymousAccessControl = false;
	private ProjectManager projectMgr;
	private RepositoryServerAdapter server;
	private RepositoryAdapter repository;
	private ServerInfo serverInfo;
	private ProjectLocator newProjectLocator;
	private String statusMessage;
	private PluginTool tool;

	final static Border EMPTY_BORDER = BorderFactory.createEmptyBorder(80, 120, 0, 120);

	NewProjectPanelManager(FrontEndTool tool) {
		projectTypePanel = new ProjectTypePanel(this);
		selectProjectPanel = new SelectProjectPanel(this);
		serverPanel = new ServerInfoPanel(this);
		projectMgr = tool.getProjectManager();
		this.tool = tool;
	}

	@Override
	public boolean canFinish() {

		if (!projectTypePanel.isValidInformation()) {
			return false;
		}
		if (!projectTypePanel.isSharedProject() && selectProjectPanel.isValidInformation()) {
			return true;
		}
		if (repositoryPanel == null) {
			return false;
		}
		if (repositoryPanel.isValidInformation() &&
			(projectAccessPanel == null ||
				projectAccessPanel != null && projectAccessPanel.isValidInformation()) &&
			selectProjectPanel.isValidInformation()) {
			return true;
		}
		return false;
	}

	@Override
	public boolean hasNextPanel() {
		if (currentWizardPanel == selectProjectPanel) {
			if (selectProjectPanel.isValidInformation() && projectTypePanel.isValidInformation() &&
				!projectTypePanel.isSharedProject()) {
				return false;
			}
		}
		return currentWizardPanel != selectProjectPanel;
	}

	@Override
	public boolean hasPreviousPanel() {
		return currentWizardPanel != projectTypePanel;
	}

	@Override
	public WizardPanel getInitialPanel() {
		currentWizardPanel = projectTypePanel;
		return currentWizardPanel;
	}

	@Override
	public WizardPanel getNextPanel() {

		if (currentWizardPanel == null) {
			currentWizardPanel = projectTypePanel;
		}
		else if (currentWizardPanel == projectTypePanel) {
			if (projectTypePanel.isSharedProject()) {
				currentWizardPanel = serverPanel;
				serverPanel.setServerInfo(projectMgr.getMostRecentServerInfo());
			}
			else {
				server = null;
				serverInfo = null;
				currentWizardPanel = selectProjectPanel;
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
				}
				currentWizardPanel = repositoryPanel;
			}
			catch (RemoteException e) {
				statusMessage = "Error accessing remote server on " + serverName;
			}
			catch (NotConnectedException e) {
				statusMessage = e.getMessage();
				if (statusMessage == null) {
					statusMessage = "Not Connected to server " + serverName;
				}
			}
			catch (IOException e) {
				statusMessage = "IOException: could not access remote server on " + serverName;
			}
		}
		else if (currentWizardPanel == repositoryPanel) {
			if (repository != null) {
				repository.disconnect();
				repository = null;
			}
			String repositoryName = repositoryPanel.getRepositoryName();
			selectProjectPanel.setProjectName(repositoryName);
			if (!repositoryPanel.createRepository()) {
				currentWizardPanel = selectProjectPanel;
				selectProjectPanel.setProjectName(repositoryName);
				repository = server.getRepository(repositoryName);
				statusMessage = selectProjectPanel.getStatusMessage();
				return currentWizardPanel;
			}

			checkNewRepositoryAccessPanel();
			currentWizardPanel = projectAccessPanel;
		}
		else if (currentWizardPanel == projectAccessPanel) {
			currentWizardPanel = selectProjectPanel;
			statusMessage = selectProjectPanel.getStatusMessage();
		}
		else {
			currentWizardPanel = null;
		}
		return currentWizardPanel;
	}

	/**
	 * Build repository access panel for new repository only.
	 * @throws IOException
	 */
	private void checkNewRepositoryAccessPanel() {

		String repositoryName = repositoryPanel.getRepositoryName();
		if (projectAccessPanel != null &&
			projectAccessPanel.getRepositoryName().equals(repositoryName)) {
			return;
		}

		ArrayList<User> userList = new ArrayList<>();
		userList.add(new User(server.getUser(), User.ADMIN));

		try {
			projectAccessPanel = new ProjectAccessPanel(knownUsers, server.getUser(), userList,
				repositoryName, server.anonymousAccessAllowed(), false, tool);
		}
		catch (IOException e) {
			Msg.error(this, "Error creating project access panel");
		}
	}

	@Override
	public WizardPanel getPreviousPanel() {
		if (currentWizardPanel == selectProjectPanel) {
			if (projectTypePanel.isSharedProject()) {
				if (repositoryPanel.createRepository()) {
					currentWizardPanel = projectAccessPanel;
				}
				else {
					currentWizardPanel = repositoryPanel;
				}
			}
			else {
				currentWizardPanel = projectTypePanel;
			}
		}
		else if (currentWizardPanel == projectAccessPanel) {
			currentWizardPanel = repositoryPanel;
		}
		else if (currentWizardPanel == repositoryPanel) {
			currentWizardPanel = serverPanel;
		}
		else if (currentWizardPanel == serverPanel) {
			currentWizardPanel = projectTypePanel;
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

		ProjectLocator projectLocator = selectProjectPanel.getProjectLocator();
		if (server != null) {
			boolean createNewRepository = repositoryPanel.createRepository();
			if (!createNewRepository) {
				if (repository == null) {
					repository = server.getRepository(repositoryPanel.getRepositoryName());
				}
			}
			else {
				try {
					repository = server.createRepository(repositoryPanel.getRepositoryName());
					repository.setUserList(projectAccessPanel.getProjectUsers(),
						projectAccessPanel.allowAnonymousAccess());
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
						statusMessage = "Not connected to server " + serverInfo.getServerName();
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
		Preferences.setProperty(Preferences.LAST_NEW_PROJECT_DIRECTORY,
			projectLocator.getLocation());
		Preferences.store();

		newProjectLocator = projectLocator;
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
		selectProjectPanel.initialize();
		serverPanel.initialize();
//		serverPanel.setServerInfo(serverInfo);
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
	 * Get the project that was created.
	 * @return null if no project was created
	 */
	ProjectLocator getNewProjectLocation() {
		return newProjectLocator;
	}

	/**
	 * Get the repository adapter associated with the new project.
	 * After displaying this panel, this method should be invoked to obtain the 
	 * repository which will be opended for shared projects.  If the repository is
	 * not used to create a new project, its disconnect method should be invoked.
	 * @return null if project is not shared
	 */
	RepositoryAdapter getProjectRepository() {
		return repository;
	}

	String getProjectRepositoryName() {
		return repositoryPanel.getRepositoryName();
	}

	boolean isSharedProject() {
		return projectTypePanel.isSharedProject();
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

		repositoryPanel = null;

		server = projectMgr.getRepositoryServerAdapter(serverName, portNumber, true);
		if (server.isConnected()) {
			serverInfo = projectMgr.getMostRecentServerInfo();
			return true;
		}

		server = null;
		serverInfo = null;
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
