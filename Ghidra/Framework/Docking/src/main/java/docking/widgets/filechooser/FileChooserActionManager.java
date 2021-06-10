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
/*
 * Created on May 18, 2006
 */
package docking.widgets.filechooser;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;

class FileChooserActionManager {
	private final static String OWNER = "Ghidra File Chooser";

	private GhidraFileChooser chooser;
	private DockingAction renameAction;
	private DockingAction removeRecentAction;

	FileChooserActionManager(GhidraFileChooser chooser) {
		this.chooser = chooser;
		createActions();
	}

	void dispose() {
		renameAction.dispose();
		removeRecentAction.dispose();
	}

	private void createActions() {
		renameAction = new DockingAction("Rename", OWNER, false) {

			@Override
			public void actionPerformed(ActionContext context) {
				rename();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				Object contextObject = context.getContextObject();
				if (!(contextObject instanceof GhidraFileChooserDirectoryModelIf)) {
					return false;
				}

				File dir = chooser.getCurrentDirectory();
				if (dir == GhidraFileChooser.MY_COMPUTER || dir == GhidraFileChooser.RECENT) {
					return false;
				}

				GhidraFileChooserDirectoryModelIf model =
					(GhidraFileChooserDirectoryModelIf) contextObject;
				File file = model.getSelectedFile();
				return file != null;
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				Object contextObject = context.getContextObject();
				if (!(contextObject instanceof GhidraFileChooserDirectoryModelIf)) {
					return false;
				}
				GhidraFileChooserDirectoryModelIf model =
					(GhidraFileChooserDirectoryModelIf) contextObject;

				File file = model.getSelectedFile();
				return file != null;
			}
		};

		renameAction.setPopupMenuData(new MenuData(new String[] { "Rename" }, "A"));
		renameAction.markHelpUnnecessary();
		chooser.addAction(renameAction);

		removeRecentAction = new DockingAction("Remove Recent", OWNER, false) {

			@Override
			public void actionPerformed(ActionContext context) {
				removeRecent();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				Object contextObject = context.getContextObject();
				if (!(contextObject instanceof GhidraFileChooserDirectoryModelIf)) {
					return false;
				}
				GhidraFileChooserDirectoryModelIf model =
					(GhidraFileChooserDirectoryModelIf) contextObject;

				File file = model.getSelectedFile();
				return file != null && file instanceof RecentGhidraFile;
			}
		};

		removeRecentAction.setPopupMenuData(new MenuData(new String[] { "Remove Recent" }, "B"));
		removeRecentAction.markHelpUnnecessary();
		chooser.addAction(removeRecentAction);
	}

	private void rename() {
		File dir = chooser.getCurrentDirectory();
		if (dir == GhidraFileChooser.MY_COMPUTER || dir == GhidraFileChooser.RECENT) {
			chooser.setStatusText("Unable to rename inside directory \"" + dir + "\"");
			return;
		}

		GhidraFileChooserDirectoryModelIf model = chooser.getDirectoryModel();
		int[] rows = model.getSelectedRows();
		if (rows.length == 1) {
			model.edit();
		}
	}

	private void removeRecent() {

		List<RecentGhidraFile> toRemove = new ArrayList<>();
		GhidraFileChooserDirectoryModelIf model = chooser.getDirectoryModel();
		int[] rows = model.getSelectedRows();
		for (int row : rows) {
			File file = model.getFile(row);
			if (file instanceof RecentGhidraFile) {
				toRemove.add((RecentGhidraFile) file);
			}
		}

		chooser.removeRecentFiles(toRemove);
	}

	DockingAction getRenameAction() {
		return renameAction;
	}

	DockingAction getRemoveRecentAction() {
		return removeRecentAction;
	}
}
