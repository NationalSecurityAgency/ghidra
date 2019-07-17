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
package docking.widgets.tree.support;

import java.awt.Component;

import javax.swing.JTree;
import javax.swing.tree.DefaultTreeCellEditor;
import javax.swing.tree.DefaultTreeCellRenderer;

import docking.widgets.tree.GTreeNode;

public class GTreeCellEditor extends DefaultTreeCellEditor {
	public GTreeCellEditor(JTree tree, DefaultTreeCellRenderer renderer) {
		super(tree, renderer);
	}
	
	@Override
	public Component getTreeCellEditorComponent(JTree jTree, Object value,
			boolean isSelected, boolean expanded, boolean leaf, int row) {

		GTreeNode node = (GTreeNode)value;
		if (node.isLeaf()) {
			renderer.setLeafIcon(node.getIcon(expanded));
		}
		else {
			renderer.setOpenIcon(node.getIcon(true));
			renderer.setClosedIcon(node.getIcon(false));
		}
		return super.getTreeCellEditorComponent(jTree, value, isSelected, expanded,
				leaf, row);
	}

}
