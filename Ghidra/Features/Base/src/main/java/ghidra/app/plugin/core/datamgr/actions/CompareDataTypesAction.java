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
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.label.GLabel;
import docking.widgets.tree.GTree;
import ghidra.app.plugin.core.datamgr.*;
import ghidra.app.plugin.core.datamgr.tree.DataTypeNode;
import ghidra.app.plugin.core.datamgr.tree.DataTypeTreeNode;
import ghidra.app.util.datatype.DataTypeSelectionDialog;
import ghidra.app.util.datatype.DataTypeSelectionEditor;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import ghidra.util.layout.VerticalLayout;

/**
 * An action available from a selected data type that allows the user to choose a second type
 * to be shown in a comparison window.
 */
public class CompareDataTypesAction extends DockingAction {

	private DataTypeManagerPlugin plugin;

	public CompareDataTypesAction(DataTypeManagerPlugin plugin) {
		super("Compare", plugin.getName());

		this.plugin = plugin;
		setPopupMenuData(new MenuData(new String[] { "Compare..." }, "EditAdvanced"));
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		DataTypeTreeNode node = getSelectedDataTypeTreeNode(context);
		return node instanceof DataTypeNode;
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		DataTypeTreeNode node = getSelectedDataTypeTreeNode(context);
		if (node == null) {
			return false;
		}

		if (!(node instanceof DataTypeNode)) {
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

		PluginTool tool = plugin.getTool();
		int noSizeRestriction = -1;
		DataTypeSelectionDialog selectionDialog = new DataTypeSelectionDialog(tool,
			plugin.getProgram().getDataTypeManager(), noSizeRestriction, AllowedDataTypes.ALL) {

			@Override
			protected JComponent createEditorPanel(DataTypeSelectionEditor dtEditor) {

				setTitle("Choose Type to Compare");

				JPanel updatedPanel = new JPanel();
				updatedPanel.setBorder(BorderFactory.createEmptyBorder(5, 10, 10, 0));
				updatedPanel.setLayout(new VerticalLayout(5));

				GLabel label = new GLabel("Choose comparison data type: ");
				label.setBorder(BorderFactory.createEmptyBorder(5, 0, 5, 0));
				updatedPanel.add(label);

				updatedPanel.add(dtEditor.getEditorComponent());

				return updatedPanel;
			}

		};
		selectionDialog.setHelpLocation(getHelpLocation());
		tool.showDialog(selectionDialog);
		DataType otherDt = selectionDialog.getUserChosenDataType();
		if (otherDt == null) {
			return; // cancelled
		}

		DataTypeTreeNode node = getSelectedDataTypeTreeNode(context);
		DataType selectedDt = ((DataTypeNode) node).getDataType();
		DataTypeCompareProvider provider =
			new DataTypeCompareProvider(tool, plugin.getName(), selectedDt, otherDt);
		provider.setVisible(true);
	}
}
