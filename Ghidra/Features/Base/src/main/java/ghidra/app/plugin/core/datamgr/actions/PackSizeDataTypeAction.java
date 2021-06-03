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
import docking.widgets.dialogs.NumberInputDialog;
import docking.widgets.tree.GTree;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.tree.DataTypeNode;
import ghidra.app.plugin.core.datamgr.tree.DataTypeTreeNode;
import ghidra.program.model.data.*;
import ghidra.util.Msg;

public class PackSizeDataTypeAction extends DockingAction {

	private DataTypeManagerPlugin plugin;

	public PackSizeDataTypeAction(DataTypeManagerPlugin plugin) {
		super("Pack Size Data Type", plugin.getName());
		this.plugin = plugin;
		setPopupMenuData(new MenuData(new String[] { "Pack for Size..." }, "Edit"));
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		Object contextObject = context.getContextObject();
		if (!(contextObject instanceof GTree)) {
			return false;
		}
		GTree gTree = (GTree) contextObject;
		TreePath[] selectionPaths = gTree.getSelectionPaths();
		if (selectionPaths.length != 1) {
			return false;
		}
		DataTypeTreeNode node = (DataTypeTreeNode) selectionPaths[0].getLastPathComponent();

		if (!(node instanceof DataTypeNode)) {
			return false;
		}
		setEnabled(node.isModifiable());
		return true;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		GTree gTree = (GTree) context.getContextObject();
		TreePath[] selectionPaths = gTree.getSelectionPaths();
		TreePath treePath = selectionPaths[0];
		final DataTypeNode dataTypeNode = (DataTypeNode) treePath.getLastPathComponent();
		DataType dataType = dataTypeNode.getDataType();
		DataTypeManager dataTypeManager = dataType.getDataTypeManager();
		if (dataTypeManager == null) {
			Msg.error(this,
				"Can't pack data type " + dataType.getName() + " without a data type manager.");
			return;
		}

		NumberInputDialog numberInputDialog =
			new NumberInputDialog("explicit pack value", 0, 0, 16);
		if (!numberInputDialog.show()) {
			return;
		}
		int packSize = numberInputDialog.getValue();

		int transactionID = -1;
		boolean commit = false;
		try {
			// start a transaction
			transactionID =
				dataTypeManager.startTransaction("pack(" + packSize + ") of " + dataType.getName());
			packDataType(dataType, packSize);
			commit = true;
		}
		catch (IllegalArgumentException iie) {
			Msg.showError(this, null, "Invalid Pack Value", iie.getMessage());
		}
		finally {
			// commit the changes
			dataTypeManager.endTransaction(transactionID, commit);
		}
	}

	private void packDataType(DataType dataType, int packSize) throws IllegalArgumentException {
		if (!(dataType instanceof Composite)) {
			Msg.error(this,
				"Can't pack data type " + dataType.getName() + ". It's not a composite.");
			return;
		}
		((Composite) dataType).pack(packSize);
	}

}
