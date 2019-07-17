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

import java.util.*;

import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.tree.GTree;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.DataTypesActionContext;
import ghidra.app.plugin.core.datamgr.tree.DataTypeNode;
import ghidra.program.database.DatabaseObject;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.util.*;
import ghidra.util.exception.AssertException;

public class FindDataTypesContainingAction extends DockingAction {
//	private final DataTypeManagerPlugin plugin;

	public FindDataTypesContainingAction(DataTypeManagerPlugin plugin) {
		super("Find Data Types Containing", plugin.getName());
//        this.plugin = plugin;

		setPopupMenuData(
			new MenuData(new String[] { "Find Data Types Containing..." }, null, "ZVeryLast"));

		setHelpLocation(new HelpLocation("DataTypeManagerPlugin", "Data_Type_Manager_Plugin"));
		setEnabled(true);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return (context instanceof DataTypesActionContext);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		if (!(context instanceof DataTypesActionContext)) {
			return;
		}
		Object contextObject = context.getContextObject();
		GTree gTree = (GTree) contextObject;
		TreePath[] selectionPaths = gTree.getSelectionPaths();
		StringBuffer text = new StringBuffer();

		if (selectionPaths.length != 1) {
			Msg.showInfo(getClass(), gTree, "Find Data Types Containing",
				"You must select a single data type in the tree.");
			return;
		}
		TreePath path = gTree.getSelectionPath();
		Object node = path.getLastPathComponent();
		if (!(node instanceof DataTypeNode)) {
			Msg.showInfo(getClass(), gTree, "Find Data Types Containing",
				"You must select a single data type in the tree.");
			return;
		}
		DataTypeNode dataTypeNode = (DataTypeNode) node;
		DataType dataType = dataTypeNode.getDataType();
		Iterator<DataType> parentDtIterator = getDataTypesContaining(dataType, gTree);
		if (!parentDtIterator.hasNext()) {
			DataTypeManager dataTypeManager = dataType.getDataTypeManager();
			ArchiveType type = dataTypeManager.getType();
			String typeName = " archive";
			if (type.equals(ArchiveType.PROGRAM)) {
				typeName = " program";
			}
			else if (type.equals(ArchiveType.BUILT_IN)) {
				typeName = "";
			}
			Msg.showInfo(getClass(), gTree,
				"Find Data Types Containing \"" + dataType.getPathName() + "\"",
				"<HTML><B>" + HTMLUtilities.friendlyEncodeHTML(dataType.getPathName()) +
					"</B> isn't contained in any other data types in the <B>" +
					HTMLUtilities.friendlyEncodeHTML(dataTypeManager.getName()) + "</B>" +
					typeName + "!!!</HTML>");
			return;
		}

		text.append("<HTML>");
		text.append("<B>" + HTMLUtilities.friendlyEncodeHTML(dataType.getPathName()) +
			"</B> is contained in:<BR>");
		int count = 0;
		while (parentDtIterator.hasNext()) {
			DataType parentDt = parentDtIterator.next();
			count++;
			if (count >= 50) {
				text.append("<BR><BR>Too many to display...");
				break;
			}
			text.append(
				"<BR>    " + HTMLUtilities.friendlyEncodeHTML(parentDt.getPathName()));
		}
		text.append("</HTML>");

		Msg.showInfo(getClass(), gTree,
			"Find Data Types Containing \"" + dataType.getPathName() + "\"", text.toString());
	}

	protected Iterator<DataType> getDataTypesContaining(DataType dataType, GTree gTree) {
		DataTypeManager dataTypeManager = dataType.getDataTypeManager();
		if (dataTypeManager == null) {
			Msg.showInfo(getClass(), gTree,
				"Find Data Types Containing \"" + dataType.getName() + "\"",
				"\"" + dataType.getName() + "\" doesn't have a data type manager.");
			return new DataTypeArrayIterator(new DataType[0]);
		}
		if (dataType instanceof DatabaseObject) {
			return new DataTypeArrayIterator(dataType.getParents());
		}
		return new DataTypeContainingIterator(dataType);
	}

	private class DataTypeArrayIterator implements Iterator<DataType> {
		DataType[] dataTypes;
		int nextIndex = 0;

		private DataTypeArrayIterator(DataType[] dataTypes) {
			this.dataTypes = dataTypes;
		}

		@Override
		public boolean hasNext() {
			return nextIndex < dataTypes.length;
		}

		@Override
		public DataType next() {
			return dataTypes[nextIndex++];
		}

		@Override
		public void remove() {
		}
	}

	private class DataTypeContainingIterator implements Iterator<DataType> {
		DataType dataType;
		Iterator<DataType> iterator;
		DataType nextDataType = null;

		private DataTypeContainingIterator(DataType dataType) {
			this.dataType = dataType;
			DataTypeManager dataTypeManager = dataType.getDataTypeManager();
			if (dataTypeManager == null) {
				iterator = new DataTypeArrayIterator(new DataType[0]);
			}
			else {
				iterator = dataTypeManager.getAllDataTypes();
			}
		}

		@Override
		public boolean hasNext() {
			if (nextDataType != null) {
				return true;
			}
			while (iterator.hasNext()) {
				DataType dt = iterator.next();
				Collection<DataType> containedDataTypes = getDirectContainedDatatypes(dt);
				for (DataType containedDt : containedDataTypes) {
					if (containedDt == dataType) {
						nextDataType = dt;
						return true;
					}
				}
			}
			return false;
		}

		@Override
		public DataType next() {
			if (nextDataType == null) {
				hasNext();
			}
			DataType tempDataType = nextDataType;
			nextDataType = null;
			return tempDataType;
		}

		@Override
		public void remove() {
		}
	}

	private static List<DataType> getDirectContainedDatatypes(DataType dt) {
		List<DataType> list = new ArrayList<DataType>();
		if (dt instanceof Array) {
			Array array = (Array) dt;
			list.add(array.getDataType());
		}
		else if (dt instanceof Pointer) {
			Pointer ptr = (Pointer) dt;
			DataType ptrDt = ptr.getDataType();
			if (ptrDt != null) {
				list.add(ptrDt);
			}
		}
		else if (dt instanceof Composite) {
			Composite composite = (Composite) dt;
			int n = composite.getNumComponents();
			for (int i = 0; i < n; i++) {
				DataTypeComponent component = composite.getComponent(i);
				list.add(component.getDataType());
			}
		}
		else if (dt instanceof TypeDef) {
			TypeDef typedef = (TypeDef) dt;
			list.add(typedef.getDataType());
		}
		else if (dt instanceof Enum) {
		}
		else if (dt instanceof FunctionDefinition) {
			FunctionDefinition funDef = (FunctionDefinition) dt;
			list.add(funDef.getReturnType());
			ParameterDefinition[] arguments = funDef.getArguments();
			for (ParameterDefinition parameter : arguments) {
				list.add(parameter.getDataType());
			}
		}
		else if (dt instanceof BuiltInDataType) {
		}
		else if (dt instanceof MissingBuiltInDataType) {
		}
		else if (dt.equals(DataType.DEFAULT)) {

		}
		else {
			throw new AssertException("Unknown data Type:" + dt.getDisplayName());
		}
		return list;
	}
}
