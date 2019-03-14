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
package ghidra.app.plugin.core.datamgr.editor;

import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.tree.DataTypeNode;
import ghidra.program.model.data.DataType;

import java.awt.Component;

import javax.swing.*;
import javax.swing.event.CellEditorListener;
import javax.swing.event.ChangeEvent;
import javax.swing.tree.*;

import docking.widgets.tree.GTreeNode;

/**
 * A implementation of {@link DefaultTreeCellEditor} that adds the ability to launch custom
 * editors instead of the default editor.  This class will also handle re-selecting the
 * edited node after editing has successfully completed.
 */
public class DataTypesTreeCellEditor extends DefaultTreeCellEditor {

	private final DataTypeManagerPlugin plugin;
	private GTreeNode lastEditedNode;

	public DataTypesTreeCellEditor(JTree tree, DefaultTreeCellRenderer renderer,
			DataTypeManagerPlugin plugin) {
		super(tree, renderer);
		this.plugin = plugin;

		// listener to re-select the edited node after editing is finished (for default editing)
		addCellEditorListener(new CellEditorListener() {
			@Override
			public void editingCanceled(ChangeEvent e) {
				lastEditedNode = null;
			}

			@Override
			public void editingStopped(ChangeEvent e) {
				if (lastEditedNode != null) {
					handleEditingFinished((CellEditor) e.getSource());
				}
			}
		});
	}

	private void handleEditingFinished(final CellEditor cellEditor) {

		// this is called before the changes have been put into place and we
		// need to wait until the
		// node has been changed before attempting to select it
		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				Object cellEditorValue = cellEditor.getCellEditorValue();
				if (cellEditorValue == null || !(cellEditorValue instanceof String)) {
					return;
				}

				// reselect the cell that was edited
				GTreeNode newNode = lastEditedNode.getChild(cellEditorValue.toString());
				if (newNode == null) {
					return;
				}
				TreePath path = newNode.getTreePath();
				tree.setSelectionPath(path);
				tree.scrollPathToVisible(path);
				lastEditedNode = null;
			}
		});
	}

	@Override
	public Component getTreeCellEditorComponent(final JTree jTree, Object value,
			boolean isSelected, boolean expanded, boolean leaf, int row) {

		if (isCustom(value)) {
			edit(value);
			SwingUtilities.invokeLater(new Runnable() { // we are going to bring a stand-alone editor
				@Override
				public void run() { // the tree is not longer involved, so tell it
					jTree.cancelEditing();
				}
			});
			return renderer.getTreeCellRendererComponent(jTree, value, isSelected, expanded, leaf,
				row, true);
		}

		lastEditedNode = ((GTreeNode) value).getParent();
		return super.getTreeCellEditorComponent(jTree, value, isSelected, expanded, leaf, row);
	}

	private void edit(Object value) {
		DataTypeNode dataTypeNode = (DataTypeNode) value;
		if (dataTypeNode.isModifiable()) {
			DataType dt = dataTypeNode.getDataType();
			plugin.getEditorManager().edit(dt);
		}
	}

	private boolean isCustom(Object value) {
		if (!(value instanceof DataTypeNode)) {
			return false;
		}

		DataTypeNode node = (DataTypeNode) value;
		return node.hasCustomEditor();
	}

}
