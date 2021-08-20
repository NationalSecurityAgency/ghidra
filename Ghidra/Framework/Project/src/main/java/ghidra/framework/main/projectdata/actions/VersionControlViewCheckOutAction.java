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
package ghidra.framework.main.projectdata.actions;

import java.io.IOException;
import java.util.List;

import docking.action.MenuData;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.main.datatable.DomainFileContext;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.remote.User;
import ghidra.framework.store.ItemCheckoutStatus;
import ghidra.util.Msg;

/**
 * Action to view the current checkouts for a single domain file in the repository.
 */
public class VersionControlViewCheckOutAction extends VersionControlAction {

	/**
	 * Creates an action to view the current checkouts for a single domain file in the repository.
	 * @param plugin the plug-in that owns this action.
	 */
	public VersionControlViewCheckOutAction(Plugin plugin) {
		super("View Checkouts", plugin.getName(), plugin.getTool());
		setPopupMenuData(new MenuData(new String[] { "View Checkouts..." }, null, GROUP));

		setDescription("View current checkouts");

		setEnabled(false);
	}

	@Override
	public void actionPerformed(DomainFileContext context) {
		viewCheckouts(context.getSelectedFiles());
	}

	@Override
	public boolean isEnabledForContext(DomainFileContext context) {
		List<DomainFile> domainFiles = context.getSelectedFiles();
		if (domainFiles.size() != 1) {
			return false;
		}
		if (isFileSystemBusy()) {
			return false; // don't block; we should get called again later
		}

		DomainFile domainFile = domainFiles.get(0);
		return domainFile.isVersioned();
	}

	/**
	 * Displays a dialog containing the checkout information for a version controlled domain file.
	 * The dialog is only displayed if the repository is connected and a single version controlled 
	 * domain file is in the list from the DomainFileProvider.
	 */
	private void viewCheckouts(List<DomainFile> domainFiles) {

		if (!checkRepositoryConnected()) {
			return;
		}
		if (domainFiles.size() != 1) {
			return;
		}
		try {
			DomainFile domainFile = domainFiles.get(0);
			User user = repository != null ? repository.getUser() : null;
			ItemCheckoutStatus[] checkouts = domainFile.getCheckouts();
			if (checkouts.length == 0) {
				Msg.showInfo(getClass(), tool.getToolFrame(), "No Checkouts Exist",
					"No checkouts exist for " + domainFile.getName());
			}
			else {
				CheckoutsDialog dialog = new CheckoutsDialog(tool, user, domainFile, checkouts);
				tool.showDialog(dialog);
			}
		}
		catch (IOException e) {
			ClientUtil.handleException(repository, e, "Fetch Check Out Status",
				tool.getToolFrame());
		}

	}

}
