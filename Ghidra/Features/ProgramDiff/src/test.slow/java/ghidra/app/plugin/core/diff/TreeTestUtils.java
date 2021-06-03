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
package ghidra.app.plugin.core.diff;

import java.util.List;

import javax.swing.JTree;
import javax.swing.tree.TreeModel;
import javax.swing.tree.TreePath;

import docking.widgets.tree.GTreeNode;
import generic.test.AbstractGenericTest;

public class TreeTestUtils {
	public static TreePath findTreePathToText(JTree tree, String text) {
		TreeModel tm = tree.getModel();
		GTreeNode rootNode = (GTreeNode) tm.getRoot();
		return findPathToText(tree, rootNode, text);
	}

	protected static TreePath findPathToText(JTree tree, GTreeNode node, String text) {
		if (text.equals(node.getName())) {
			return node.getTreePath();
		}
		List<GTreeNode> allChildren = node.getChildren();
		for (GTreeNode childNode : allChildren) {
			TreePath treePath = findPathToText(tree, childNode, text);
			if (treePath != null) {
				return treePath;
			}
		}
		return null;
	}

	/**
	 * Selects a tree node in the indicated tree with the specified text. 
	 * The matching tree node is determined by comparing the specified text 
	 * with the string returned by the tree node's toString() method.
	 * <br> Note: This method affects the expansion state of the tree. It
	 * will expand nodes starting at the root until a match is found or all
	 * of the tree is checked.
	 * @param tree the tree
	 * @param text the tree node's text
	 */
	public static void selectTreeNodeByText(final JTree tree, final String text) {

		AbstractGenericTest.runSwing(new Runnable() {
			@Override
			public void run() {
				TreePath path = findTreePathToText(tree, text);
				if (path == null) {
					throw new RuntimeException("tree path is null.");
				}
				tree.expandPath(path);
			}
		});

		AbstractGenericTest.waitForSwing();

		AbstractGenericTest.runSwing(new Runnable() {
			@Override
			public void run() {
				TreePath path = findTreePathToText(tree, text);
				if (path == null) {
					throw new RuntimeException("tree path is null.");
				}
				tree.getSelectionModel().setSelectionPath(path);
			}
		});
	}
}
