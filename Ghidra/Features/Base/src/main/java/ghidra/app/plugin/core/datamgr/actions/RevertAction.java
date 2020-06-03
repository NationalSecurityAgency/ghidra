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

import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.DataTypeSyncInfo;
import ghidra.app.plugin.core.datamgr.archive.DataTypeManagerHandler;
import ghidra.app.plugin.core.datamgr.tree.ArchiveNode;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.SourceArchive;
import ghidra.util.HelpLocation;

import java.util.List;

import docking.action.MenuData;

public class RevertAction extends SyncAction {

	public static final String MENU_NAME = "Revert Datatypes From";

	public RevertAction(DataTypeManagerPlugin plugin,
			DataTypeManagerHandler dataTypeManagerHandler, DataTypeManager dtm,
			ArchiveNode archiveNode, SourceArchive sourceArchive, boolean isEnabled) {

		super("Revert Datatype Changes", plugin, dataTypeManagerHandler, dtm, archiveNode,
			sourceArchive, isEnabled);
		setPopupMenuData(new MenuData(new String[] { MENU_NAME, sourceArchive.getName() }));
		setHelpLocation(new HelpLocation(plugin.getName(), getHelpTopic()));

	}

	@Override
	protected int getMenuOrder() {
		return 3;
	}

	@Override
	protected String getHelpTopic() {
		return "Revert_Data_Types";
	}

	@Override
	protected boolean isAppropriateForAction(DataTypeSyncInfo info) {

		switch (info.getSyncState()) {
			case COMMIT:
			case CONFLICT:
				return true;
			default:
				return false;
		}
	}

	@Override
	protected boolean isPreselectedForAction(DataTypeSyncInfo info) {
		return false;
	}

	@Override
	protected String getOperationName() {
		return "Revert";
	}

	@Override
	protected void applyOperation(DataTypeSyncInfo info) {
		info.revert();
	}

	@Override
	protected String getConfirmationMessage(List<DataTypeSyncInfo> selectedInfos) {
		return "This will permanently discard the changes to these datatypes in this program or archive.\n\n" +
			"Are you sure you want to REVERT " + selectedInfos.size() + " datatype(s)?";
	}

	@Override
	protected boolean requiresArchiveOpenForEditing() {
		return false;
	}

	@Override
	protected String getTitle(String sourceName, String clientName) {
		return "Revert Datatype Changes In \"" + clientName + "\" From Archive \"" + sourceName +
			"\"";
	}

}
