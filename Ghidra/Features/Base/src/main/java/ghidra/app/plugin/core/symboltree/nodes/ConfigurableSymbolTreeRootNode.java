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
package ghidra.app.plugin.core.symboltree.nodes;

import java.util.List;

import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.symboltree.DisconnectedSymbolTreeProvider;
import ghidra.program.model.listing.Program;

/**
 * A version of the Symbol Tree's root node that allows users to disable categories.  The categories
 * themselves track their enabled state.  This class supports the cloning of a 
 * {@link DisconnectedSymbolTreeProvider} by copying the categories' enable state.
 */
public class ConfigurableSymbolTreeRootNode extends SymbolTreeRootNode {

	public ConfigurableSymbolTreeRootNode(Program program) {
		super(program);
	}

	public void transferSettings(ConfigurableSymbolTreeRootNode otherRoot) {

		if (!isLoaded()) {
			return;
		}

		List<GTreeNode> myChildren = getChildren();
		List<GTreeNode> otherChildren = otherRoot.getChildren();
		for (GTreeNode node : myChildren) {
			SymbolCategoryNode myCategoryNode = getModelNode((SymbolCategoryNode) node);
			SymbolCategoryNode otherCategoryNode = getMatchingNode(otherChildren, myCategoryNode);
			otherCategoryNode.setEnabled(myCategoryNode.isEnabled());
		}
	}

	private SymbolCategoryNode getMatchingNode(List<GTreeNode> nodes,
			SymbolCategoryNode nodeToMatch) {

		for (GTreeNode node : nodes) {
			if (nodeToMatch.equals(node)) {
				return getModelNode((SymbolCategoryNode) node);
			}
		}

		return null;
	}

	private SymbolCategoryNode getModelNode(SymbolCategoryNode node) {
		GTree gTree = node.getTree();
		if (gTree != null) {
			SymbolCategoryNode modelNode = (SymbolCategoryNode) gTree.getModelNode(node);
			if (node != modelNode) {
				return modelNode;
			}
		}
		return node;
	}

}
