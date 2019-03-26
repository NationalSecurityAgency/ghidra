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

import docking.DialogComponentProvider;
import ghidra.framework.client.*;
import ghidra.framework.plugintool.Plugin;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.UserAccessException;

/**
 * Dialog showing all users associated with a repository and those with 
 * access to the current shared project. Users with admin rights can use
 * this dialog to edit user permissions.
 *
 */
class ProjectAccessDialog extends DialogComponentProvider {
	
	private RepositoryAdapter repository;
	private ProjectAccessPanel projectAccessPanel;
	
	/**
	 * Creates a new dialog.
	 * 
	 * @param plugin the currrent plugin
	 * @param repHandle the name of the repository
	 * @param knownUsers list of all users in the repository
	 * @param allowEditing if true, widgets for adding/removing users will be available
	 * @throws UserAccessException
	 * @throws IOException
	 * @throws NotConnectedException
	 */
	ProjectAccessDialog(Plugin plugin, RepositoryAdapter repHandle, String[] knownUsers, boolean allowEditing)
			throws UserAccessException, IOException, NotConnectedException {

		super("Project Access List for " + repHandle.getName(), true);
		
		this.repository = repHandle;
		
		setHelpLocation(new HelpLocation(plugin.getName(), "Edit_Project_Access_List"));

		if (allowEditing) {
			projectAccessPanel = new ProjectAccessPanel(knownUsers, repository, plugin.getTool());
		}
		else {
			projectAccessPanel = new ViewProjectAccessPanel(repository, plugin.getTool());
		}
		
		addWorkPanel(projectAccessPanel);
		
		if (allowEditing) {
			addOKButton();
			setOkEnabled(true);
			addCancelButton();
		}
		else {
			addCancelButton();
			setCancelButtonText("Close");
		}
	}
	
	@Override
	protected void cancelCallback() {
		close();
	}

	@Override
	protected void okCallback() {
		String statusMessage = null;
		try {
			repository.connect();
			repository.setUserList(projectAccessPanel.getProjectUsers(),
				projectAccessPanel.allowAnonymousAccess());
			close();
			Msg.info(this, "Successfully updated project access list.");
		}
		catch (UserAccessException exc) {
			statusMessage = "Could not update the user list: " + exc.getMessage();
		}
		catch (NotConnectedException e) {
			statusMessage = "Server connection is down: " + e.getMessage();
		}
		catch (IOException exc) {
			ClientUtil.handleException(repository, exc, "Update User List", getComponent());
		}
		if (statusMessage != null) {
			setStatusText(statusMessage);
		}
	}
}
