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
import ghidra.app.plugin.core.datamgr.tree.DataTypeNode;
import ghidra.app.plugin.core.datamgr.util.DataTypeUtils;
import ghidra.program.model.data.*;
import ghidra.util.Msg;

import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;

public class RevertDataTypeAction extends DockingAction {

	private final DataTypeManagerPlugin plugin;

	public RevertDataTypeAction(DataTypeManagerPlugin plugin) {
		super("Revert Data Type", plugin.getName());
		this.plugin = plugin;
		setPopupMenuData(new MenuData(new String[] { "Revert" }, "Sync"));
		setEnabled(true);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DataTypesActionContext)) {
			return false;
		}

		Object contextObject = context.getContextObject();
		GTree gTree = (GTree) contextObject;
		TreePath[] selectionPaths = gTree.getSelectionPaths();
		if (selectionPaths == null || selectionPaths.length != 1) {
			return false;
		}

		GTreeNode node = (GTreeNode) selectionPaths[0].getLastPathComponent();
		if (!(node instanceof DataTypeNode)) {
			return false;
		}

		DataTypeNode dataTypeNode = (DataTypeNode) node;
		DataType dataType = dataTypeNode.getDataType();
		DataTypeManagerHandler handler = plugin.getDataTypeManagerHandler();
		DataTypeSyncState syncStatus = DataTypeSynchronizer.getSyncStatus(handler, dataType);

		switch (syncStatus) {
			case UNKNOWN:
				return false;
			case COMMIT:
				return true;
			case CONFLICT:
			case IN_SYNC:
			case ORPHAN:
			case UPDATE:
				return false;
		}
		return false;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		GTree gTree = (GTree) context.getContextObject();

		TreePath[] selectionPaths = gTree.getSelectionPaths();
		if (selectionPaths == null || selectionPaths.length != 1) {
			return;
		}

		GTreeNode node = (GTreeNode) selectionPaths[0].getLastPathComponent();
		if (node instanceof DataTypeNode) {
			DataTypeNode dataTypeNode = (DataTypeNode) node;
			DataType dataType = dataTypeNode.getDataType();
			DataTypeManager dtm = dataType.getDataTypeManager();
			DataTypeManagerHandler handler = plugin.getDataTypeManagerHandler();
			SourceArchive sourceArchive = dataType.getSourceArchive();
			if (!dtm.isUpdatable()) {
				DataTypeUtils.showUnmodifiableArchiveErrorMessage(gTree, "Revert Failed", dtm);
				return;
			}
			DataTypeManager sourceDTM = handler.getDataTypeManager(sourceArchive);
			if (sourceDTM == null) {
				Msg.showInfo(getClass(), gTree, "Revert Failed", "Source Archive not open: " +
					sourceArchive.getName());
				return;
			}
			plugin.revert(dataType);

			// Source archive data type manager was already checked for null above.
			DataTypeSynchronizer synchronizer =
				new DataTypeSynchronizer(handler, dtm, sourceArchive);
			synchronizer.reSyncOutOfSyncInTimeOnlyDataTypes();
		}
	}

}
