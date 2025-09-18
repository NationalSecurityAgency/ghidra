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

import java.awt.Component;
import java.io.IOException;

import javax.swing.Icon;

import docking.action.MenuData;
import docking.action.ToolBarData;
import docking.widgets.OptionDialog;
import generic.theme.GIcon;
import ghidra.framework.client.*;
import ghidra.framework.main.datatable.ProjectTreeAction;
import ghidra.framework.main.datatree.*;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.Plugin;
import ghidra.util.HelpLocation;

/**
 * {@link FindCheckoutsAction} provide the ability to initiate the show checkout status for
 * files selected within the {@link ProjectDataTreePanel}.  Since link-files cannot be checked-out
 * these files will never show checkouts and do not currently attempt to show checkout information 
 * for a referenced file.
 */
public class FindCheckoutsAction extends ProjectTreeAction {

	private static final Icon FIND_ICON = new GIcon("icon.projectdata.find.checkouts.search");

	private Plugin plugin;

	public FindCheckoutsAction(String owner, Plugin plugin) {
		super("Find Checkouts", owner);
		this.plugin = plugin;
		String group = "Repository";

		setToolBarData(new ToolBarData(FIND_ICON, group));
		setPopupMenuData(
			new MenuData(new String[] { "Find Checkouts..." }, FIND_ICON, "Repository"));
		setDescription("Find my checkouts recursively");
		setHelpLocation(new HelpLocation("VersionControl", "Find_Checkouts"));
		setEnabled(false);
	}

	@Override
	protected void actionPerformed(FrontEndProjectTreeContext context) {
		DomainFolder domainFolder = null;
		if (context.getFolderCount() == 1) {
			domainFolder = context.getSelectedFolders().get(0);
		}
		else if (context.getFileCount() == 1) {
			DomainFile domainFile = context.getSelectedFiles().get(0);
			LinkFileInfo linkInfo = domainFile.getLinkInfo();
			if (linkInfo != null && linkInfo.isFolderLink() && !linkInfo.isExternalLink()) {
				domainFolder = linkInfo.getLinkedFolder();
			}
		}
		if (domainFolder == null) {
			return;
		}
		ProjectData projectData = domainFolder.getProjectData();
		RepositoryAdapter repository = projectData.getRepository();
		if (repository != null && !repository.isConnected()) {
			if (OptionDialog.OPTION_ONE != OptionDialog.showOptionDialogWithCancelAsDefaultButton(
				null, "Find Checkouts...",
				"Action requires connection to repository.\nWould you like to connect now?",
				"Connect", OptionDialog.QUESTION_MESSAGE)) {
				return;
			}
			try {
				repository.connect();
			}
			catch (NotConnectedException e) {
				// ignore - likely caused by cancellation
				return;
			}
			catch (IOException e) {
				ClientUtil.handleException(repository, e, "Find Checkouts", null);
				return;
			}
		}
		findCheckouts(domainFolder, context.getTree());
	}

	@Override
	protected boolean isEnabledForContext(FrontEndProjectTreeContext context) {
		if (context.isReadOnlyProject() || !context.hasExactlyOneFileOrFolder()) {
			return false;
		}
		if (context.getFolderCount() == 1) {
			return true;
		}
		// Only allow a local folder-link to be treated as a folder
		DomainFile file = context.getSelectedFiles().get(0);
		LinkFileInfo linkInfo = file.getLinkInfo();
		return linkInfo != null && linkInfo.isFolderLink() && !linkInfo.isExternalLink();
	}

	private void findCheckouts(DomainFolder folder, Component comp) {
		FindCheckoutsDialog dialog = new FindCheckoutsDialog(plugin, folder);
		plugin.getTool().showDialog(dialog, comp);
	}

}
