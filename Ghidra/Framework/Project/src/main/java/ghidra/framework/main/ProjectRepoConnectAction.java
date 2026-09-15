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

import java.io.IOException;

import javax.swing.Icon;

import docking.action.MenuData;
import generic.theme.GIcon;
import ghidra.framework.client.*;
import ghidra.framework.main.datatable.FrontendProjectTreeAction;
import ghidra.framework.main.datatable.ProjectDataContext;
import ghidra.framework.main.datatree.DataTree;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.ProjectData;
import ghidra.util.HelpLocation;

/**
 * {@link ProjectRepoConnectAction} action allows the user to initiate a shared repository
 * connection for a root shared project data tree node that is not currently connected.
 */
public class ProjectRepoConnectAction extends FrontendProjectTreeAction {

	private static final Icon CONNECT_ICON = new GIcon("icon.frontend.project.connected");

	private FrontEndPlugin plugin;

	public ProjectRepoConnectAction(FrontEndPlugin plugin, String group) {
		super("Connect Shared Repository", plugin.getName());
		this.plugin = plugin;
		setPopupMenuData(
			new MenuData(new String[] { "Connect Shared Repository" }, CONNECT_ICON, group));
		setHelpLocation(new HelpLocation("VersionControl", "ConnectToServer"));
	}

	@Override
	protected void actionPerformed(ProjectDataContext context) {
		RepositoryAdapter repository = getDisconnectedRepository(context);
		if (repository != null) {
			try {
				repository.connect();
			}
			catch (NotConnectedException e) {
				// don't think this can happen
			}
			catch (IOException e) {
				ClientUtil.handleException(repository, e, "Repository Connection",
					plugin.getTool().getToolFrame());
			}
		}
	}

	@Override
	protected boolean isEnabledForContext(ProjectDataContext context) {
		return getDisconnectedRepository(context) != null;
	}

	private RepositoryAdapter getDisconnectedRepository(ProjectDataContext context) {
		if (!(context.getComponent() instanceof DataTree)) {
			return null;
		}
		if (context.getFolderCount() != 1 || context.getFileCount() != 0) {
			return null;
		}
		DomainFolder domainFolder = context.getSelectedFolders().get(0);
		if (domainFolder.getParent() != null) {
			return null;
		}
		ProjectData projectData = domainFolder.getProjectData();
		if (projectData.getProjectLocator().isTransient()) {
			return null; // Transient projects are always connected
		}
		RepositoryAdapter repository = projectData.getRepository();
		if (repository != null && !repository.isConnected()) {
			return repository;
		}
		return null;
	}
}
