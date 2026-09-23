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
package ghidra.app.plugin.core.datamgr.actions;

import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.OptionDialog;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import generic.theme.GThemeDefaults.Colors.Messages;
import ghidra.app.plugin.core.datamgr.*;
import ghidra.app.plugin.core.datamgr.tree.ArchiveNode;
import ghidra.app.plugin.core.datamgr.tree.ProjectArchiveNode;
import ghidra.app.plugin.core.processors.SetLanguageDialog;
import ghidra.program.model.dtarchive.PersistentDataTypeArchive;
import ghidra.program.model.dtarchive.ProjectDataTypeArchive;
import ghidra.program.model.dtarchive.DataTypeArchive.LanguageUpdateOption;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.IncompatibleLanguageException;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;

/**
 * Action for setting the Architecture for a DataTypeAchive.
 */
public class SetArchiveArchitectureAction extends DockingAction {

	private final DataTypeManagerPlugin plugin;

	public SetArchiveArchitectureAction(DataTypeManagerPlugin plugin) {
		super("Set Archive Architecture", plugin.getName());
		this.plugin = plugin;

		setPopupMenuData(new MenuData(new String[] { "Set Architecture..." }, null, "SetArch"));

		setDescription("Set program-architecture associated with a data type archive");

		setEnabled(true);
	}

	private TreePath getSelectionPath(ActionContext context) {
		Object contextObject = context.getContextObject();
		GTree gtree = (GTree) contextObject;
		TreePath[] selectionPaths = gtree.getSelectionPaths();
		if (selectionPaths.length != 1) {
			return null;
		}
		return selectionPaths[0];
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DataTypesActionContext)) {
			return false;
		}
		TreePath selectionPath = getSelectionPath(context);
		if (selectionPath == null) {
			return false;
		}
		GTreeNode node = (GTreeNode) selectionPath.getLastPathComponent();
		if (node instanceof ArchiveNode archiveNode) {
			return archiveNode.getArchive().isUpdatable();
		}
		return false;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		TreePath selectionPath = getSelectionPath(context);
		if (selectionPath == null) {
			return;
		}
		GTreeNode node = (GTreeNode) selectionPath.getLastPathComponent();
		if (!(node instanceof ArchiveNode archiveNode)) {
			return;
		}

		if (node instanceof ProjectArchiveNode projectNode) {
			ProjectDataTypeArchive pa = projectNode.getArchive();
			if (!pa.hasExclusiveAccess()) {
				Msg.showError(this, null, "Set Program Architecture Failed",
					"Setting program-architecture on Project Archive requires exclusive checkout.");
				return;
			}
		}

		PersistentDataTypeArchive archive = archiveNode.getArchive();
		if (archive.isChanged()) {
			if (OptionDialog.OPTION_ONE != OptionDialog.showOptionDialogWithCancelAsDefaultButton(
				null, "Save Archive Changes",
				"Archive has unsaved changes which must be saved before continuing." +
					"\nThis is required to allow for a reversion to the previous saved state.",
				"Save")) {
				return;
			}
			plugin.getArchiveManager().save(archiveNode.getArchive());
		}

		SetLanguageDialog dialog = new SetLanguageDialog(plugin.getTool(),
			archive.getProgramArchitecture(),
			"Select Program Architecture for Archive: " + archive.getName());
		LanguageID languageId = dialog.getLanguageDescriptionID();
		CompilerSpecID compilerSpecId = dialog.getCompilerSpecDescriptionID();
		if ((languageId == null) || (compilerSpecId == null)) {
			return;
		}
		try {
			Language language = DefaultLanguageService.getLanguageService().getLanguage(languageId);

			StringBuilder buf = new StringBuilder();
			buf.append(languageId.getIdAsString());
			buf.append(" / ");
			buf.append(compilerSpecId.getIdAsString());
			String newProgramArchitectureSummary = buf.toString();

			String programArchitectureSummary = archive.getProgramArchitectureSummary();
			String msg =
				"<html>Set program-architecture for Archive?<BR><font color=\"" + Messages.NORMAL +
					"\">" + archive.getPath() + "</font><pre>";
			if (programArchitectureSummary != null) {
				msg +=
					"\nChange Language/Compiler\n  from:  <font color=\"" + Messages.NORMAL +
						"\">" +
						programArchitectureSummary + "</font>\n    to:  ";
			}
			else {
				msg += "\n\nLanguage/Compiler: ";
			}
			msg += "<font color=\"" + Messages.NORMAL + "\">";
			msg += newProgramArchitectureSummary;
			msg += "</font></pre>";
			int response = OptionDialog.showOptionDialogWithCancelAsDefaultButton(null,
				"Confirm Archive Architecture Change", msg, "Set Architecture",
				OptionDialog.WARNING_MESSAGE);
			if (response != OptionDialog.OPTION_ONE) {
				return;
			}

			new TaskLauncher(new SetProgramArchitectureTask(archive, language,
				compilerSpecId));
		}
		catch (LanguageNotFoundException e) {
			Msg.showError(this, null, "Archive Update Failed",
				"Failed to set program-architecture for Archive: " + archive.getName() + "\n" +
					e.getMessage());
		}
	}

	private class SetProgramArchitectureTask extends Task {

		private final PersistentDataTypeArchive archive;
		private final Language language;
		private final CompilerSpecID compilerSpecId;

		public SetProgramArchitectureTask(PersistentDataTypeArchive archive, Language language,
				CompilerSpecID compilerSpecId) {
			super("Updating Program-Architecture for Archive", true, false, true, false);
			this.archive = archive;
			this.language = language;
			this.compilerSpecId = compilerSpecId;
		}

		@Override
		public void run(TaskMonitor monitor) throws CancelledException {

			boolean success = false;
			try {
				try {
					archive.setProgramArchitecture(language, compilerSpecId,
						LanguageUpdateOption.TRANSLATE, monitor);
					success = true;
				}
				catch (IncompatibleLanguageException e) {
					int resp = OptionDialog.showOptionDialog(null, "Archive Architecture Change",
						"<html>Unable to translate storage for specified architecture change.<BR><font color=\"" +
							Messages.NORMAL + "\">" + archive.getPath() +
							"</font><BR><BR>Would you like to Clear custom storage information or Cancel change?",
						"Clear");
					if (resp == OptionDialog.CANCEL_OPTION) {
						success = true; // keep archive open
						return;
					}
					LanguageUpdateOption updateOption = LanguageUpdateOption.CLEAR;
					if (resp == OptionDialog.OPTION_TWO) {
						updateOption = LanguageUpdateOption.UNCHANGED;
					}
					archive.setProgramArchitecture(language, compilerSpecId, updateOption, monitor);
					success = true;
				}
			}
			catch (CancelledException e) {
				throw e;
			}
			catch (Exception e) {
				Msg.showError(this, null, "Archive Update Failed",
					"Failed to set program-architecture for Archive: " + archive.getName() + "\n" +
						e.getMessage());
			}
			finally {
				if (!success) {
					// not sure why this is needed; put back if so and explain why			
					// Swing.runNow(() -> {
					//		/* flush event queue before closing archive */
					// });

					ArchiveManager archiveManager = plugin.getArchiveManager();
					archiveManager.reopenArchive(archive);
				}
			}
		}

	}

}
