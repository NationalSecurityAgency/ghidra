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
package docking.widgets.tree.support;

import java.awt.Component;

import javax.swing.*;
import javax.swing.tree.DefaultTreeCellEditor;
import javax.swing.tree.DefaultTreeCellRenderer;

import docking.DockingUtils;
import docking.UndoRedoKeeper;
import docking.widgets.tree.GTreeNode;

public class GTreeCellEditor extends DefaultTreeCellEditor {

	private UndoRedoKeeper undoRedoKeeper;

	public GTreeCellEditor(JTree tree, DefaultTreeCellRenderer renderer) {
		super(tree, renderer);

		if (realEditor instanceof DefaultCellEditor) {
			Component c = ((DefaultCellEditor) realEditor).getComponent();
			if (c instanceof JTextField) {
				JTextField tf = (JTextField) c;
				undoRedoKeeper = DockingUtils.installUndoRedo(tf);
			}
		}
	}

	@Override
	public boolean stopCellEditing() {
		if (super.stopCellEditing()) {
			clearUndoRedo();
			return true;
		}
		return false;
	}

	@Override
	public void cancelCellEditing() {
		super.cancelCellEditing();
		clearUndoRedo();
	}

	private void clearUndoRedo() {
		if (undoRedoKeeper != null) {
			undoRedoKeeper.clear();
		}
	}

	@Override
	public Component getTreeCellEditorComponent(JTree jTree, Object value, boolean isSelected,
			boolean expanded, boolean leaf, int row) {

		GTreeNode node = (GTreeNode) value;
		if (node.isLeaf()) {
			renderer.setLeafIcon(node.getIcon(expanded));
		}
		else {
			renderer.setOpenIcon(node.getIcon(true));
			renderer.setClosedIcon(node.getIcon(false));
		}

		return super.getTreeCellEditorComponent(jTree, value, isSelected, expanded, leaf, row);
	}

}
