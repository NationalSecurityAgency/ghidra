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
import docking.widgets.tree.GTree;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.tree.DataTypeNode;
import ghidra.app.plugin.core.datamgr.tree.DataTypeTreeNode;
import ghidra.program.model.data.*;
import ghidra.util.Msg;

public class PackDataTypeAction extends DockingAction {


	public PackDataTypeAction(DataTypeManagerPlugin plugin) {
		super("Pack Data Type", plugin.getName());
		setPopupMenuData(new MenuData(new String[] { "Pack (default)" }, "Edit"));
//		setHelpLocation(new HelpLocation(plugin.getName(), getName()));
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		DataTypeNode node = getSelectedDataTypeNode(context);
		if (node == null) {
			return false;
		}
		DataType dataType = node.getDataType();
		if (dataType instanceof BuiltInDataType || dataType instanceof Pointer ||
			dataType instanceof MissingBuiltInDataType) {
			return false;
		}
		if (!node.isModifiable()) {
			return false;
		}
		return true;
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		DataTypeNode node = getSelectedDataTypeNode(context);
		if (node == null) {
			return false;
		}
		DataType dataType = node.getDataType();
		if (dataType instanceof Composite) {
			return !((Composite) dataType).isPackingEnabled();
		}
		return false;
	}

	private DataTypeNode getSelectedDataTypeNode(ActionContext context) {
		Object contextObject = context.getContextObject();
		if (!(contextObject instanceof GTree)) {
			return null;
		}
		GTree gTree = (GTree) contextObject;
		TreePath[] selectionPaths = gTree.getSelectionPaths();
		if (selectionPaths.length != 1) {
			return null;
		}
		DataTypeTreeNode node = (DataTypeTreeNode) selectionPaths[0].getLastPathComponent();

		if (!(node instanceof DataTypeNode)) {
			return null;
		}
		return (DataTypeNode) node;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		GTree gTree = (GTree) context.getContextObject();
		TreePath[] selectionPaths = gTree.getSelectionPaths();
		for (TreePath treePath : selectionPaths) {
			final DataTypeNode dataTypeNode = (DataTypeNode) treePath.getLastPathComponent();
			DataType dataType = dataTypeNode.getDataType();
			DataTypeManager dataTypeManager = dataType.getDataTypeManager();
			DataOrganization dataOrganization = dataTypeManager.getDataOrganization();
			alignDataType(dataType, dataOrganization);
		}
	}

	private void alignDataType(DataType dataType, DataOrganization dataOrganization) {
		DataTypeManager dataTypeManager = dataType.getDataTypeManager();
		if (dataTypeManager == null) {
			Msg.error(this, "Can't align data type " + dataType.getName() +
				" without a data type manager.");
			return;
		}
		if (!(dataType instanceof Structure)) {
			Msg.error(this, "Can't align data type " + dataType.getName() +
				". It's not a structure.");
			return;
		}
		int transactionID = -1;
		boolean commit = false;
		try {
			// start a transaction
			transactionID = dataTypeManager.startTransaction("align " + dataType.getName());
			((Structure) dataType).setPackingEnabled(true);
			commit = true;
		}
		finally {
			// commit the changes
			dataTypeManager.endTransaction(transactionID, commit);
		}
	}

}
