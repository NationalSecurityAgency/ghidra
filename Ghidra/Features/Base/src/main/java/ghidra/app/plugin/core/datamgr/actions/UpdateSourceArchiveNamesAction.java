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
import ghidra.app.plugin.core.datamgr.DataTypesActionContext;
import ghidra.app.plugin.core.datamgr.archive.DataTypeManagerHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.SourceArchive;
import ghidra.util.HelpLocation;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;

public class UpdateSourceArchiveNamesAction extends DockingAction {

	public static final String NAME = "Update Source Archive Names";

	private final DataTypeManagerPlugin plugin;
	private final DataTypeManager dtm;

	public UpdateSourceArchiveNamesAction(DataTypeManagerPlugin plugin, DataTypeManager dtm) {
		super(NAME, plugin.getName());
		this.plugin = plugin;
		this.dtm = dtm;

		setPopupMenuData(new MenuData(new String[] { NAME }));
		setHelpLocation(new HelpLocation(plugin.getName(), "Update_Source_Archive_Names"));
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DataTypesActionContext)) {
			return false;
		}

		DataTypeManagerHandler handler = plugin.getDataTypeManagerHandler();

		// TODO: nothing can be done to protect against dtm being closed 
		// Must ensure that dtm closing must trigger associated Archive
		// close and cleanup from tree

		for (SourceArchive archive : dtm.getSourceArchives()) {
			DataTypeManager archiveDtm = handler.getDataTypeManager(archive);
			if (archiveDtm == null) {
				continue;
			}
			String archiveName = archiveDtm.getName();
			if (!archive.getName().equals(archiveName)) {
				return true;
			}
		}
		return false;
	}

	@Override
	public void actionPerformed(ActionContext context) {

		DataTypeManagerHandler handler = plugin.getDataTypeManagerHandler();

		// TODO: nothing can be done to protect against dtm being closed 
		// Must ensure that dtm closing must trigger associated Archive
		// close and cleanup from tree

		int txId = dtm.startTransaction(NAME);
		try {
			for (SourceArchive archive : dtm.getSourceArchives()) {
				DataTypeManager archiveDtm = handler.getDataTypeManager(archive);
				if (archiveDtm == null) {
					continue;
				}
				String archiveName = archiveDtm.getName();
				if (!archive.getName().equals(archiveName)) {
					archive.setName(archiveName);
				}
			}
		}
		finally {
			dtm.endTransaction(txId, true);
		}
	}

}
