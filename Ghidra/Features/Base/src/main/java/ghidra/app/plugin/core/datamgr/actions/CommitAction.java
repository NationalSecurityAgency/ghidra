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

import ghidra.app.plugin.core.datamgr.*;
import ghidra.app.plugin.core.datamgr.archive.DataTypeManagerHandler;
import ghidra.app.plugin.core.datamgr.tree.ArchiveNode;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.SourceArchive;
import ghidra.util.HelpLocation;

import java.util.List;

import docking.action.MenuData;

public class CommitAction extends SyncAction {

	public static final String MENU_NAME = "Commit Datatypes To";

	public CommitAction(DataTypeManagerPlugin plugin,
			DataTypeManagerHandler dataTypeManagerHandler, DataTypeManager dtm,
			ArchiveNode archiveNode, SourceArchive sourceArchive, boolean isEnabled) {

		super("Commit Changes To Archive", plugin, dataTypeManagerHandler, dtm, archiveNode,
			sourceArchive, isEnabled);
		setPopupMenuData(new MenuData(new String[] { MENU_NAME, sourceArchive.getName() }));
		setHelpLocation(new HelpLocation(plugin.getName(), getHelpTopic()));

	}

	@Override
	protected int getMenuOrder() {
		return 2;
	}

	@Override
	protected String getHelpTopic() {
		return "Commit_Data_Types";
	}

	@Override
	protected boolean isAppropriateForAction(DataTypeSyncInfo info) {

		switch (info.getSyncState()) {
			case COMMIT:
			case CONFLICT:
			case ORPHAN:
				return true;
			default:
				return false;
		}
	}

	@Override
	protected boolean isPreselectedForAction(DataTypeSyncInfo info) {
		return info.getSyncState() == DataTypeSyncState.COMMIT;
	}

	@Override
	protected String getOperationName() {
		return "Commit";
	}

	@Override
	protected void applyOperation(DataTypeSyncInfo info) {
		info.commit();
	}

	@Override
	protected String getConfirmationMessage(List<DataTypeSyncInfo> infos) {
		StringBuffer buf = new StringBuffer();
		if (containsConflicts(infos)) {
			buf.append("You are committing one or more conflicts which will OVERWRITE\n");
			buf.append("changes in the source archive!\n\n");
		}
		buf.append("Are you sure you want to COMMIT " + infos.size() + " datatype(s)?");
		return buf.toString();
	}

	@Override
	protected boolean requiresArchiveOpenForEditing() {
		return true;
	}

	@Override
	protected String getTitle(String sourceName, String clientName) {
		return "Commit Datatype Changes From \"" + clientName + "\" To Archive \"" + sourceName +
			"\"";
	}
}
