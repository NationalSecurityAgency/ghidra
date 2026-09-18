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

import java.awt.Component;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.plugin.core.datamgr.*;
import ghidra.app.plugin.core.datamgr.util.DataTypeUtils;
import ghidra.program.model.data.*;
import ghidra.util.Msg;

public class RevertDataTypeAction extends DockingAction {

	private final DataTypeManagerPlugin plugin;

	public RevertDataTypeAction(DataTypeManagerPlugin plugin) {
		super("Revert Data Type", plugin.getName());
		this.plugin = plugin;
		setPopupMenuData(new MenuData(new String[] { "Revert Changes" }, "Sync"));
		setEnabled(true);
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
			case COMMIT:
			case CONFLICT:
				return true;
			case IN_SYNC:
			case ORPHAN:
			case UPDATE:
				return false;
		}
		return false;
	}

	@Override
	public void actionPerformed(ActionContext context) {

		DataType dataType = ((DataTypeContext) context).getSelectedDataType();
		DataTypeManager dtm = dataType.getDataTypeManager();
		ArchiveManager archiveManager = plugin.getArchiveManager();
		SourceArchive sourceArchive = dataType.getSourceArchive();
		Component component = context.getSourceComponent();
		if (!dtm.isUpdatable()) {
			DataTypeUtils.showUnmodifiableArchiveErrorMessage(component, "Revert Failed", dtm);
			return;
		}

		DataTypeManager sourceDtm = archiveManager.getDataTypeManager(sourceArchive);
		if (sourceDtm == null) {
			Msg.showInfo(getClass(), component, "Revert Failed",
				"Source Archive not open: " + sourceArchive.getName());
			return;
		}

		plugin.revert(dataType);

		// Source archive data type manager was already checked for null above.
		DataTypeSynchronizer synchronizer =
			new DataTypeSynchronizer(archiveManager, dtm, sourceArchive);
		synchronizer.reSyncOutOfSyncInTimeOnlyDataTypes();
	}

}
