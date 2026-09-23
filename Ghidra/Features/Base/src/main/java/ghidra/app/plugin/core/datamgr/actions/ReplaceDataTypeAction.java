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

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.label.GLabel;
import ghidra.app.plugin.core.datamgr.DataTypeContext;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.util.datatype.DataTypeSelectionDialog;
import ghidra.app.util.datatype.DataTypeSelectionEditor;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.dtarchive.DataTypeStore;
import ghidra.util.Msg;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import ghidra.util.layout.VerticalLayout;

/**
 * Replace the selected data type with the chosen data type
 */
public class ReplaceDataTypeAction extends DockingAction {

	private DataTypeManagerPlugin plugin;

	public ReplaceDataTypeAction(DataTypeManagerPlugin plugin) {
		super("Replace", plugin.getName());

		this.plugin = plugin;
		setPopupMenuData(new MenuData(new String[] { "Replace..." }, "EditAdvanced"));
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		if (!(context instanceof DataTypeContext dtc)) {
			return false;
		}

		DataType dataType = dtc.getSelectedDataType();
		return dataType != null;
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DataTypeContext dtc)) {
			return false;
		}

		DataType dataType = dtc.getSelectedDataType();
		if (dataType == null) {
			return false;
		}

		DataTypeManager dtm = dataType.getDataTypeManager();
		DataTypeStore dtStore = dtm.getDataStore();
		if (!dtStore.isChangeable()) {
			return false;
		}

		if (dataType instanceof BadDataType) {
			// Although BAD datatype should not appear in tree, if it does replace is
			// not supported.  Delete should be used instead.
			return false;
		}
		return true;
	}

	@Override
	public void actionPerformed(ActionContext context) {

		DataTypeContext dtc = (DataTypeContext) context;
		DataType oldDt = dtc.getSelectedDataType();
		String name = oldDt.getName();

		PluginTool tool = plugin.getTool();
		int noSizeRestriction = -1;
		DataTypeSelectionDialog selectionDialog = new DataTypeSelectionDialog(tool,
			plugin.getProgram().getDataTypeManager(), noSizeRestriction, AllowedDataTypes.ALL) {

			@Override
			protected JComponent createEditorPanel(DataTypeSelectionEditor dtEditor) {

				setTitle("Replace '" + name + "'");

				JPanel updatedPanel = new JPanel();
				updatedPanel.setBorder(BorderFactory.createEmptyBorder(5, 10, 10, 0));
				updatedPanel.setLayout(new VerticalLayout(5));

				GLabel label = new GLabel("Choose the replacement data type: ");
				label.setBorder(BorderFactory.createEmptyBorder(5, 0, 5, 0));
				updatedPanel.add(label);

				updatedPanel.add(dtEditor.getEditorComponent());

				return updatedPanel;
			}

		};
		selectionDialog.setHelpLocation(getHelpLocation());
		tool.showDialog(selectionDialog);
		DataType newDt = selectionDialog.getUserChosenDataType();
		if (newDt == null) {
			return; // cancelled
		}

		DataTypeManager newDtm = newDt.getDataTypeManager();
		DataTypeStore sourceStore = newDtm.getDataStore();
		DataTypeManager oldDtm = oldDt.getDataTypeManager();
		DataTypeStore destinationStore = oldDtm.getDataStore();

		DataTypeManager dtm = oldDt.getDataTypeManager();
		if (sourceStore != destinationStore) {
			oldDt = oldDt.clone(oldDt.getDataTypeManager());
		}

		int txId = dtm.startTransaction("Replace Data Type");
		try {
			dtm.replaceDataType(oldDt, newDt, true);
		}
		catch (DataTypeDependencyException e) {
			Msg.showError(this, null, "Replace Failed", "Replace failed.  Existing type " + newDt +
				"; replacement type " + oldDt + ". " + e.getMessage());
		}
		finally {
			dtm.endTransaction(txId, true);
		}
	}
}
