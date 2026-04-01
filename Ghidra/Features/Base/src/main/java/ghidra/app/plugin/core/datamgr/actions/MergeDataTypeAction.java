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

import javax.swing.*;
import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.DockingWindowManager;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.label.GLabel;
import docking.widgets.tree.GTree;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.DataTypesActionContext;
import ghidra.app.plugin.core.datamgr.tree.DataTypeNode;
import ghidra.app.plugin.core.datamgr.tree.DataTypeTreeNode;
import ghidra.app.util.datatype.DataTypeSelectionDialog;
import ghidra.app.util.datatype.DataTypeSelectionEditor;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.database.data.ProgramDataTypeManager;
import ghidra.program.database.data.merge.DataTypeMergeException;
import ghidra.program.database.data.merge.DataTypeMerger;
import ghidra.program.model.data.*;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import ghidra.util.layout.VerticalLayout;

/**
 * Replace the selected data type with the chosen data type
 */
public class MergeDataTypeAction extends DockingAction {

	private DataTypeManagerPlugin plugin;

	public MergeDataTypeAction(DataTypeManagerPlugin plugin) {
		super("Merge Data Types", plugin.getName());

		this.plugin = plugin;
		setPopupMenuData(
			new MenuData(new String[] { "Merge..." }, "EditAdvanced"));
		setHelpLocation(new HelpLocation("DataTypeManagerPlugin", "merge_datatypes"));
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		DataTypeTreeNode node = getSelectedDataTypeTreeNode(context);
		if (node == null) {
			return false;
		}

		if (!(node instanceof DataTypeNode dtNode)) {
			return false;
		}

		DataType dataType = dtNode.getDataType();
		if (!DataTypeUtilities.supportsMerge(dataType)) {
			return false;
		}
		
		DataTypeManager dataTypeManager = dataType.getDataTypeManager();

		// for now, only allow merging on program datatypes.
		if (!(dataTypeManager instanceof ProgramDataTypeManager)) {
			return false;
		}

		if (!dtNode.isModifiable()) {
			return false;
		}

		if (dataType instanceof BadDataType) {
			// Although BAD datatype should not appear in tree, if it does replace is
			// not supported.  Delete should be used instead.
			return false;
		}
		return true;
	}

	private DataTypeTreeNode getSelectedDataTypeTreeNode(ActionContext context) {
		if (!(context instanceof DataTypesActionContext)) {
			return null;
		}

		GTree gTree = (GTree) context.getContextObject();
		TreePath[] selectionPaths = gTree.getSelectionPaths();
		if (selectionPaths == null || selectionPaths.length == 0) {
			return null;
		}

		if (selectionPaths.length > 1) {
			return null;
		}

		DataTypeTreeNode node = (DataTypeTreeNode) selectionPaths[0].getLastPathComponent();
		return node;
	}

	@Override
	public void actionPerformed(ActionContext context) {

		DataTypeTreeNode node = getSelectedDataTypeTreeNode(context);
		String name = node.getName();
		DataType mergeToDt = ((DataTypeNode) node).getDataType();
		DataTypeManager dtm = mergeToDt.getDataTypeManager();

		PluginTool tool = plugin.getTool();
		DataTypeSelectionDialog selectionDialog = new DataTypeMergeSelectionDialog(name);
		tool.showDialog(selectionDialog);
		DataType selectedDt = selectionDialog.getUserChosenDataType();
		if (selectedDt == null) {
			return; // cancelled
		}

		DataTypeManager newDtm = selectedDt.getDataTypeManager();
		if (!(newDtm instanceof ProgramDataTypeManager)) {
			Msg.showError(this, null, "Merge Failed", "Merge source must be a program datatype.");
			return;
		}

		int txId = dtm.startTransaction("Merge Data Type");
		try {
			merge(mergeToDt, selectedDt);
		}
		finally {
			dtm.endTransaction(txId, true);
		}
	}

	private void merge(DataType mergeToDt, DataType mergeFromDt) {
		try {
			DataTypeMerger<?> merger = DataTypeUtilities.getMerger(mergeToDt, mergeFromDt);
			DataType merged = merger.merge();

			if (confirmMerger(merger, merged, mergeToDt, mergeFromDt)) {
				DataTypeManager dtm = mergeToDt.getDataTypeManager();
				// first replace the guts of the original 'mergeTo' datatype with the results
				mergeToDt.replaceWith(merged);
				// now replace all uses of the mergeFromDt with the merged datatype and remove it
				dtm.replaceDataType(mergeFromDt, mergeToDt, false);
			}
		}
		catch (DataTypeMergeException e) {
			DataTypeMergeErrorDialog dialog =
				new DataTypeMergeErrorDialog(mergeToDt, mergeFromDt, e.getMessage());
			DockingWindowManager.showDialog(dialog);
		}
		catch (DataTypeDependencyException e) {
			Msg.showError(this, null, "Merge Failed",
				"Merge failed.  Existing type '%s', replacement type '%s'.".formatted(
					mergeFromDt.getName(),
					mergeToDt.getName()),
				e);
		}
	}

	private boolean confirmMerger(DataTypeMerger<?> merger, DataType merged, DataType mergeTo,
			DataType mergeFrom) {
		DataTypeMergeConfirmationDialog dialog =
			new DataTypeMergeConfirmationDialog(merged, mergeTo, mergeFrom, merger.getWarnings());

		DockingWindowManager.showDialog(dialog);
		return !dialog.wasCancelled();

	}

	private class DataTypeMergeSelectionDialog extends DataTypeSelectionDialog {

		private String name;

		public DataTypeMergeSelectionDialog(String name) {
			super(plugin.getTool(), plugin.getProgram().getDataTypeManager(), -1,
				AllowedDataTypes.ALL);
			this.name = name;
			setHelpLocation(getHelpLocation());
		}

		@Override
		protected JComponent createEditorPanel(DataTypeSelectionEditor dtEditor) {

			setTitle("Merge '" + name + "'");

			JPanel updatedPanel = new JPanel();
			updatedPanel.setBorder(BorderFactory.createEmptyBorder(5, 10, 10, 0));
			updatedPanel.setLayout(new VerticalLayout(5));

			GLabel label = new GLabel("Choose the data type to merge: ");
			label.setBorder(BorderFactory.createEmptyBorder(5, 0, 5, 0));
			updatedPanel.add(label);

			updatedPanel.add(dtEditor.getEditorComponent());

			return updatedPanel;
		}

	}
}
