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
package ghidra.app.plugin.core.datamgr.actions.associate;

import javax.swing.Icon;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.OptionDialog;
import generic.theme.GIcon;
import ghidra.app.plugin.core.datamgr.*;
import ghidra.app.plugin.core.datamgr.util.DataTypeUtils;
import ghidra.program.model.data.*;
import ghidra.util.Msg;
import resources.MultiIcon;
import resources.icons.EmptyIcon;
import resources.icons.TranslateIcon;

public class CommitSingleDataTypeAction extends DockingAction {

	private static Icon COMMIT_ICON = new GIcon("icon.plugin.datatypes.commit.single.type");

	private final DataTypeManagerPlugin plugin;

	public CommitSingleDataTypeAction(DataTypeManagerPlugin plugin) {
		super("Commit To Archive", plugin.getName());
		this.plugin = plugin;
		setPopupMenuData(new MenuData(new String[] { "Commit To Archive" }, "Sync"));

		setEnabled(true);
		MultiIcon multiIcon = new MultiIcon(new EmptyIcon(16, 16));
		multiIcon.addIcon(new TranslateIcon(COMMIT_ICON, 4, 5));
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DataTypeContext dtc)) {
			return false;
		}

		DataType dataType = dtc.getSelectedDataType();
		if (dataType == null) {
			return false;
		}

		ArchiveManager archiveManager = plugin.getArchiveManager();
		DataTypeSyncState syncStatus = DataTypeSynchronizer.getSyncStatus(archiveManager, dataType);

		switch (syncStatus) {
			case UNKNOWN:
				return false;
			case CONFLICT:
			case COMMIT:
			case ORPHAN:
				return true;
			case UPDATE:
			case IN_SYNC:
				return false;
		}
		return false;
	}

	@Override
	public void actionPerformed(ActionContext context) {

		DataType dataType = ((DataTypeContext) context).getSelectedDataType();
		DataTypeManager dtm = dataType.getDataTypeManager();
		ArchiveManager archiveManager = plugin.getArchiveManager();
		DataTypeSyncState syncStatus = DataTypeSynchronizer.getSyncStatus(archiveManager, dataType);

		if (syncStatus == DataTypeSyncState.CONFLICT) {
			int result = OptionDialog.showOptionDialog(context.getSourceComponent(),
				"Lose Changes in Archive?",
				"This data type has changes in the archive that will be\n" +
					"overwritten if you commit this data type",
				"Continue?", OptionDialog.WARNING_MESSAGE);
			if (result == OptionDialog.CANCEL_OPTION) {
				return;
			}
		}

		SourceArchive sourceArchive = dataType.getSourceArchive();
		DataTypeManager sourceDTM =
			plugin.getArchiveManager().getDataTypeManager(sourceArchive);
		if (sourceDTM == null) {
			Msg.showInfo(this, context.getSourceComponent(), "Commit Failed",
				"Source Archive not open: " + sourceArchive.getName());
			return;
		}

		if (!sourceDTM.isUpdatable()) {
			DataTypeUtils.showUnmodifiableArchiveErrorMessage(context.getSourceComponent(),
				"Commit Failed!", sourceDTM);
			return;
		}

		if (!dataType.getDataTypeManager().isUpdatable()) {
			DataTypeUtils.showUnmodifiableArchiveErrorMessage(context.getSourceComponent(),
				"Commit Failed", dataType.getDataTypeManager());
			return;
		}

		plugin.commit(dataType);

		// Source archive data type manager was already checked for null above.
		DataTypeSynchronizer synchronizer =
			new DataTypeSynchronizer(archiveManager, dtm, sourceArchive);
		synchronizer.reSyncOutOfSyncInTimeOnlyDataTypes();
	}
}
