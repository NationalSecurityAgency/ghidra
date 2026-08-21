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

import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.client.RepositoryServerAdapter;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.model.ServerInfo;
import ghidra.framework.remote.User;

/**
 * Wizard data for the {@link ProjectWizardModel} and its steps for the "new project" wizard. It
 * is also used by the {@link ProjectChooseRepositoryWizardModel} for the wizards to convert a 
 * non-shared project to shared and for changing the repository/server info of an existing 
 * shared project.
 */
public class ProjectWizardData {
	private boolean isSharedProject = false;
	private ServerInfo serverInfo;
	private RepositoryServerAdapter server;
	private String repositoryName;
	private boolean isNewRepository;
	private User[] projectUsers;
	private boolean allowAnonymousAccess;
	private ProjectLocator locator;
	private RepositoryAdapter repository;

	public void setIsSharedProject(boolean b) {
		this.isSharedProject = b;
	}

	public boolean isSharedProject() {
		return isSharedProject;
	}

	public void setProjectLocator(ProjectLocator locator) {
		this.locator = locator;
	}

	public ProjectLocator getProjectLocator() {
		return locator;
	}

	public void setServerInfo(ServerInfo serverInfo) {
		this.serverInfo = serverInfo;
	}

	public ServerInfo getServerInfo() {
		return serverInfo;
	}

	public void setServer(RepositoryServerAdapter server) {
		this.server = server;
	}

	public RepositoryServerAdapter getServer() {
		return server;
	}

	public void setRepositoryName(String repositoryName) {
		this.repositoryName = repositoryName;
	}

	public String getRepositoryName() {
		return repositoryName;
	}

	public void setIsNewRepository(boolean b) {
		isNewRepository = b;
	}

	public boolean isNewRepository() {
		return isNewRepository;
	}

	public void setProjectUsers(User[] projectUsers) {
		this.projectUsers = projectUsers;
	}

	public User[] getProjectUsers() {
		return projectUsers;
	}

	public void setAllowAnonymousAccess(boolean allowAnonymousAccess) {
		this.allowAnonymousAccess = allowAnonymousAccess;
	}

	public boolean allowAnonymousAccess() {
		return allowAnonymousAccess;
	}

	public void setRepository(RepositoryAdapter repository) {
		this.repository = repository;
	}

	public RepositoryAdapter getRepository() {
		return repository;
	}

}
