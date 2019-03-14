/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
import ghidra.app.plugin.core.datamgr.tree.DataTypeArchiveGTree;
import ghidra.program.model.data.*;

import java.awt.Component;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.widgets.tree.GTreeNode;

abstract class AbstractTypeDefAction extends DockingAction {

	protected final DataTypeManagerPlugin plugin;

	AbstractTypeDefAction(String name, DataTypeManagerPlugin plugin) {
		super(name, plugin.getName());
		this.plugin = plugin;
	}

	protected DataType createTypeDef(DataTypeManager dataTypeManager, DataType dataType,
			CategoryPath categoryPath, ActionContext context, GTreeNode parentNode,
			String typeDefName) {

		DataTypeArchiveGTree gTree = (DataTypeArchiveGTree) context.getContextObject();
		if (dataTypeManager == null || dataTypeManager instanceof BuiltInDataTypeManager) {
			dataTypeManager = plugin.getProgramDataTypeManager();
		}

		if (dataType instanceof FunctionDefinition) {
			dataType = PointerDataType.getPointer(dataType, dataTypeManager);
		}

		ComponentProvider componentProvider = context.getComponentProvider();
		Component comp = componentProvider != null ? componentProvider.getComponent() : null;
		if (!DataTypeManagerPlugin.isValidTypeDefBaseType(comp, dataType)) {
			return null;
		}

		return createNewDataType(gTree, dataType, categoryPath, dataTypeManager, typeDefName);
	}

	private DataType createNewDataType(Component parentComponent, DataType dataType,
			CategoryPath categoryPath, DataTypeManager dataTypeManager, String name) {
		DataType newdt = null;
		int transactionID = dataTypeManager.startTransaction("Create Typedef");
		try {
			DataType typedef = new TypedefDataType(categoryPath, name, dataType);
			newdt = dataTypeManager.addDataType(typedef, plugin.getConflictHandler());
		}
		finally {
			dataTypeManager.endTransaction(transactionID, true);
		}

		return newdt;
	}
}
