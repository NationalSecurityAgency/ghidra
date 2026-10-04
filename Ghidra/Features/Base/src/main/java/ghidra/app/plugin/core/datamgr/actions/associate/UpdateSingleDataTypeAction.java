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
import resources.MultiIcon;
import resources.icons.EmptyIcon;
import resources.icons.TranslateIcon;

public class UpdateSingleDataTypeAction extends DockingAction {

	private static Icon UPDATE_ICON = new GIcon("icon.plugin.datatypes.associate.single.type");

	private final DataTypeManagerPlugin plugin;

	public UpdateSingleDataTypeAction(DataTypeManagerPlugin plugin) {
		super("Update From Archive", plugin.getName());
		this.plugin = plugin;
		setPopupMenuData(new MenuData(new String[] { "Update From Archive" }, "Sync"));
		setEnabled(true);
		MultiIcon multiIcon = new MultiIcon(new EmptyIcon(16, 16));
		multiIcon.addIcon(new TranslateIcon(UPDATE_ICON, 4, 5));
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DataTypeContext dtContext)) {
			return false;
		}

		DataType dt = dtContext.getSelectedDataType();
		if (dt == null) {
			return false;
		}

		ArchiveManager archiveManager = plugin.getArchiveManager();
		DataTypeSyncState syncStatus = DataTypeSynchronizer.getSyncStatus(archiveManager, dt);
		switch (syncStatus) {
			case UNKNOWN:
				return false;
			case CONFLICT:
			case UPDATE:
				return true;
			case IN_SYNC:
			case COMMIT:
			case ORPHAN:
				return false;
		}
		return false;
	}

	@Override
	public void actionPerformed(ActionContext context) {

		DataTypeContext dtContext = (DataTypeContext) context;
		DataType dt = dtContext.getSelectedDataType();

		DataTypeManager dtm = dt.getDataTypeManager();
		ArchiveManager archiveManager = plugin.getArchiveManager();
		SourceArchive sourceArchive = dt.getSourceArchive();
		DataTypeSyncState syncStatus = DataTypeSynchronizer.getSyncStatus(archiveManager, dt);
		if (syncStatus == DataTypeSyncState.CONFLICT) {
			int result =
				OptionDialog.showOptionDialog(context.getSourceComponent(), "Lose Local Changes?",
					"This data type has local changes that will be\n" +
						"overwritten if you update this data type",
					"Continue?", OptionDialog.WARNING_MESSAGE);
			if (result == OptionDialog.CANCEL_OPTION) {
				return;
			}
		}

		if (!dtm.isUpdatable()) {
			DataTypeUtils.showUnmodifiableArchiveErrorMessage(context.getSourceComponent(),
				"Update Failed", dtm);
			return;
		}

		plugin.update(dt);

		DataTypeManager sourceDTM = archiveManager.getDataTypeManager(sourceArchive);
		if (sourceDTM != null) {
			DataTypeSynchronizer synchronizer =
				new DataTypeSynchronizer(archiveManager, dtm, sourceArchive);
			synchronizer.reSyncOutOfSyncInTimeOnlyDataTypes();
		}
	}
}
