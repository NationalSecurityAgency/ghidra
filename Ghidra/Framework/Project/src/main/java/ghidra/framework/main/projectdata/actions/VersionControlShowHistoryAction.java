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

import java.util.List;

import docking.action.MenuData;
import ghidra.framework.main.datatable.DomainFileContext;
import ghidra.framework.main.datatree.VersionHistoryDialog;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.Plugin;

/**
 * Action to show the version history for a single version controlled domain file in the repository.
 */
public class VersionControlShowHistoryAction extends VersionControlAction {

	/**
	 * Creates an action to show the version history for a single version controlled 
	 * domain file in the repository.
	 * @param plugin the plug-in that owns this action.
	 */
	public VersionControlShowHistoryAction(Plugin plugin) {
		super("Show History", plugin.getName(), plugin.getTool());
		String[] menuItemName = { "Show History..." };
		setPopupMenuData(new MenuData(menuItemName, null, GROUP));

		setDescription("Show version history");

		setEnabled(false);
	}

	@Override
	public void actionPerformed(DomainFileContext context) {
		showHistory(context.getSelectedFiles());
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
	 * Displays a dialog with the version history for the provided domain file.
	 */
	private void showHistory(List<DomainFile> domainFiles) {

		if (!checkRepositoryConnected()) {
			return;
		}

		if (domainFiles.size() != 1) {
			return;
		}

		VersionHistoryDialog dialog = new VersionHistoryDialog(domainFiles.get(0));
		tool.showDialog(dialog);
	}

}
