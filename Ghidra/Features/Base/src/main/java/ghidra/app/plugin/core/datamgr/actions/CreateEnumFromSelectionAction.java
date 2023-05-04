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
import docking.widgets.dialogs.InputDialog;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.DataTypesActionContext;
import ghidra.app.plugin.core.datamgr.tree.DataTypeNode;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.util.*;

public class CreateEnumFromSelectionAction extends DockingAction {
	private final DataTypeManagerPlugin plugin;

	public CreateEnumFromSelectionAction(DataTypeManagerPlugin plugin) {
		super("Enum From Selection", plugin.getName());
		this.plugin = plugin;

		setPopupMenuData(new MenuData(new String[] { "Create Enum From Selection" }, null, "Edit"));
		setHelpLocation(new HelpLocation("DataTypeManagerPlugin", "CreateEnumFromSelection"));
		setEnabled(true);
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		if (!(context instanceof DataTypesActionContext)) {
			return false;
		}

		GTree gtree = (GTree) context.getContextObject();
		TreePath[] selectionPaths = gtree.getSelectionPaths();
		if (selectionPaths == null || selectionPaths.length <= 1) {
			return false;
		}

		return !containsInvalidNodes(selectionPaths);
	}

	@Override
	public void actionPerformed(ActionContext context) {

		DataTypeManager dtm = plugin.getProgram().getDataTypeManager();
		Category category = dtm.getRootCategory();
		String newName = getEnumName(category);
		if (newName == null) {
			return; // cancelled
		}

		List<Enum> enums = getSelectedEnums(context);
		createMergedEnum(category, enums, newName);

		selectNewEnum((GTree) context.getContextObject(), dtm.getName(), newName);
	}

	private void selectNewEnum(GTree gTree, String parentName, String name) {
		// Select new node in tree; run later to give the tree a chance to add the the new node
		Swing.runLater(() -> {
			GTreeNode rootNode = gTree.getViewRoot();
			gTree.setSelectedNodeByNamePath(
				new String[] { rootNode.getName(), parentName, name });
		});
	}

	private List<Enum> getSelectedEnums(ActionContext context) {
		GTree gTree = (GTree) context.getContextObject();
		TreePath[] paths = gTree.getSelectionPaths();
		List<Enum> enums = new ArrayList<>();
		for (TreePath path : paths) {
			DataTypeNode dtNode = (DataTypeNode) path.getLastPathComponent();
			enums.add((Enum) dtNode.getDataType());
		}
		return enums;
	}

	private String getEnumName(Category category) {
		DataTypeManager dtm = plugin.getProgram().getDataTypeManager();
		PluginTool tool = plugin.getTool();
		CategoryPath categoryPath = category.getCategoryPath();
		InputDialog inputDialog =
			new InputDialog("Enter Enum Name", "Please enter a name for the new Enum: ");
		tool.showDialog(inputDialog);
		if (inputDialog.isCanceled()) {
			return null;
		}

		String newName = inputDialog.getValue();
		DataType dt = dtm.getDataType(categoryPath, newName);
		while (dt != null) {
			InputDialog dialog = new InputDialog("Duplicate Enum Name",
				"Please enter a unique name for the new Enum: ");
			tool.showDialog(dialog);
			if (dialog.isCanceled()) {
				return null;
			}
			newName = dialog.getValue();
			dt = dtm.getDataType(categoryPath, newName);
		}

		return newName;
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DataTypesActionContext)) {
			return false;
		}

		GTree gtree = (GTree) context.getContextObject();
		TreePath[] selectionPaths = gtree.getSelectionPaths();
		if (selectionPaths == null || selectionPaths.length <= 1) {
			return false;
		}

		return !containsInvalidNodes(selectionPaths);
	}

	private boolean containsInvalidNodes(TreePath[] selectionPaths) {

		// determine if all selected nodes are Enums
		for (TreePath path : selectionPaths) {
			GTreeNode node = (GTreeNode) path.getLastPathComponent();
			if (!(node instanceof DataTypeNode)) {
				return true;
			}
			DataTypeNode dataTypeNode = (DataTypeNode) node;
			DataType dataType = dataTypeNode.getDataType();
			if (!(dataType instanceof Enum)) {
				return true;
			}
		}
		return false;
	}

	private void createMergedEnum(Category category, List<Enum> enumsToMerge,
			String enumName) {

		int maxEnumSize = computeNewEnumSize(enumsToMerge);
		DataTypeManager dtm = category.getDataTypeManager();
		SourceArchive sourceArchive = dtm.getLocalSourceArchive();
		Enum baseEnum = new EnumDataType(category.getCategoryPath(), enumName, maxEnumSize, dtm);

		baseEnum.setSourceArchive(sourceArchive);

		for (Enum enumToMerge : enumsToMerge) {
			mergeEnum(baseEnum, enumToMerge);
		}

		addEnumDataType(category, baseEnum);

		dtm.flushEvents();
	}

	private void mergeEnum(Enum baseEnum, Enum enumToMerge) {

		boolean hasConflict = false;
		for (String name : enumToMerge.getNames()) {

			if (isDuplicateEntry(baseEnum, enumToMerge, name)) {
				continue;
			}

			long value = enumToMerge.getValue(name);
			String comment = "";
			if (isConflictingEntry(baseEnum, enumToMerge, name)) {
				name = getUniqueName(baseEnum, name);
				comment = "NOTE: Duplicate name with different value";
				hasConflict = true;
			}

			baseEnum.add(name, value, comment);
		}

		if (hasConflict) {
			Msg.showWarn(this, null, "Duplicate Entry Name(s)",
				"Merged Enum " + baseEnum.getName() + " has one or more entries with duplicate " +
					"names.\nUnderscore(s) have been appended to make them unique.");
		}
	}

	private void addEnumDataType(Category category, Enum mergedEnum) {
		DataTypeManager dtm = category.getDataTypeManager();
		int id = dtm.startTransaction("Create New Enum Data Type");
		try {
			dtm.addDataType(mergedEnum, DataTypeConflictHandler.REPLACE_HANDLER);
		}
		finally {
			dtm.endTransaction(id, true);
		}
	}

	private String getUniqueName(Enum baseEnum, String name) {

		List<String> existingNames = Arrays.asList(baseEnum.getNames());
		while (existingNames.contains(name)) {
			name = name + "_";
		}
		return name;
	}

	private boolean isDuplicateEntry(Enum baseEnum, Enum enumToMerge, String name) {

		List<String> existingNames = Arrays.asList(baseEnum.getNames());
		if (!existingNames.contains(name)) {
			return false;
		}

		long existingValue = baseEnum.getValue(name);
		long newValue = enumToMerge.getValue(name);
		return newValue == existingValue;
	}

	private boolean isConflictingEntry(Enum mergedEnum, Enum enumToMerge, String name) {

		List<String> existingNames = Arrays.asList(mergedEnum.getNames());

		if (!existingNames.contains(name)) {
			return false;
		}

		long valueToAdd = enumToMerge.getValue(name);
		long existingValue = mergedEnum.getValue(name);
		if (valueToAdd == existingValue) {
			return false;
		}

		return true;
	}

	private int computeNewEnumSize(List<Enum> enums) {
		int max = 1;
		for (Enum element : enums) {
			max = Math.max(max, element.getLength());
		}
		return max;
	}

}
