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
//Script to allow repository admins the ability to terminate multiple file checkouts belonging to a single user.
//@category MultiUser

import java.io.IOException;

import docking.widgets.OptionDialog;
import ghidra.app.script.GhidraScript;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.remote.RepositoryItem;
import ghidra.framework.remote.User;
import ghidra.framework.store.ItemCheckoutStatus;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class RemoveUserCheckoutsScript extends GhidraScript {

	@Override
	protected void run() throws Exception {
		
		Project project = state.getProject();
		
		ProjectData projectData = project.getProjectData();
		
		RepositoryAdapter repository = projectData.getRepository();
		if (repository == null) {
			printerr("Project is not a shared project");
			return;
		}
		
		User currentUser = repository.getUser();
		if (!currentUser.isAdmin()) {
			printerr("You are not a repository administrator for " + repository.getName());
			return;
		}
		
		String uname = askString("Remove User Checkouts" , "Enter user ID to be cleared");
		
		boolean found = false;
		for (User u : repository.getUserList()) {
			if (uname.equals(u.getName())) {
				found = true;
				break;
			}
		}
		if (!found) {
			if (OptionDialog.showYesNoDialogWithNoAsDefaultButton(null, "User Name Confirmation",
					"User '" + uname + "' not a registered server user.\nDo you still want to search for and remove checkouts for this user?") != OptionDialog.YES_OPTION) {
				return;
			}
		}
		
		if (projectData.getFileCount() > 1000) {
			if (OptionDialog.showYesNoDialogWithNoAsDefaultButton(null, "Large Repository Confirmation",
					"Repository contains a large number of failes and could be slow to search.\nDo you still want to search for and remove checkouts?") != OptionDialog.YES_OPTION) {
				return;
			}
		}
		
		int count = removeCheckouts(repository, "/", uname, monitor);
		popup("Removed " + count + " checkouts");
		
	}
	
	private String getPath(String folderPath, String childName) {
		if (!folderPath.endsWith("/")) {
			folderPath += "/";
		}
		return folderPath + childName;
	}
	
	private int removeCheckouts(RepositoryAdapter repository, String folderPath, String uid, TaskMonitor monitor) throws IOException, CancelledException {
		int count = 0;
		for (RepositoryItem item : repository.getItemList(folderPath)) {
			monitor.checkCanceled();
			count += removeCheckouts(repository, item, uid);
		}
		for (String subfolder : repository.getSubfolderList(folderPath)) {
			count += removeCheckouts(repository, getPath(folderPath, subfolder), uid, monitor);
		}
		return count;
	}
	
	private int removeCheckouts(RepositoryAdapter repository, RepositoryItem item, String uid) throws IOException {
		int count = 0;
		ItemCheckoutStatus[] checkouts = repository.getCheckouts(item.getParentPath(), item.getName());
		for (ItemCheckoutStatus checkout : checkouts) {
			if (uid.equals(checkout.getUser())) {
				try {
					repository.terminateCheckout(item.getParentPath(), item.getName(), checkout.getCheckoutId(), false);
					++count;
				} catch (IOException e) {
					printerr("Failed to remove checkout: " + e.getMessage());
				}
			}
		}
		return count;
	}

}
