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

import javax.swing.ImageIcon;
import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.OptionDialog;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.datamgr.*;
import ghidra.app.plugin.core.datamgr.archive.DataTypeManagerHandler;
import ghidra.app.plugin.core.datamgr.tree.DataTypeNode;
import ghidra.app.plugin.core.datamgr.util.DataTypeUtils;
import ghidra.program.model.data.*;
import ghidra.util.Msg;
import resources.MultiIcon;
import resources.ResourceManager;
import resources.icons.EmptyIcon;
import resources.icons.TranslateIcon;

public class CommitSingleDataTypeAction extends DockingAction {

	private static ImageIcon COMMIT_ICON = ResourceManager.loadImage("images/smallRightArrow.png");

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
		GTree gTree = (GTree) context.getContextObject();
		TreePath[] selectionPaths = gTree.getSelectionPaths();
		if (selectionPaths == null || selectionPaths.length != 1) {
			return;
		}
		GTreeNode node = (GTreeNode) selectionPaths[0].getLastPathComponent();
		if (!(node instanceof DataTypeNode)) {
			return;
		}
		DataTypeNode dataTypeNode = (DataTypeNode) node;
		DataType dataType = dataTypeNode.getDataType();
		DataTypeManager dtm = dataType.getDataTypeManager();
		DataTypeManagerHandler handler = plugin.getDataTypeManagerHandler();
		DataTypeSyncState syncStatus = DataTypeSynchronizer.getSyncStatus(handler, dataType);

		if (syncStatus == DataTypeSyncState.CONFLICT) {
			int result = OptionDialog.showOptionDialog(gTree, "Lose Changes in Archive?",
				"This data type has changes in the archive that will be\n" +
					"overwritten if you commit this data type",
				"Continue?", OptionDialog.WARNING_MESSAGE);
			if (result == OptionDialog.CANCEL_OPTION) {
				return;
			}
		}
		SourceArchive sourceArchive = dataType.getSourceArchive();
		DataTypeManager sourceDTM =
			plugin.getDataTypeManagerHandler().getDataTypeManager(sourceArchive);
		if (sourceDTM == null) {
			Msg.showInfo(getClass(), gTree, "Commit Failed",
				"Source Archive not open: " + sourceArchive.getName());
			return;
		}
		if (!sourceDTM.isUpdatable()) {
			DataTypeUtils.showUnmodifiableArchiveErrorMessage(gTree, "Commit Failed!", sourceDTM);
			return;
		}
		if (!dataType.getDataTypeManager().isUpdatable()) {
			DataTypeUtils.showUnmodifiableArchiveErrorMessage(gTree, "Commit Failed",
				dataType.getDataTypeManager());
			return;
		}
		plugin.commit(dataType);

		// Source archive data type manager was already checked for null above.
		DataTypeSynchronizer synchronizer = new DataTypeSynchronizer(handler, dtm, sourceArchive);
		synchronizer.reSyncOutOfSyncInTimeOnlyDataTypes();
	}
}
