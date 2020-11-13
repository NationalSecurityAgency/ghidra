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
package ghidra.app.plugin.core.script;

import java.util.List;

import javax.swing.Icon;

import docking.widgets.tree.GTreeNode;
import resources.ResourceManager;

class RootNode extends GTreeNode {
	private static Icon icon = ResourceManager.loadImage("images/play.png");

	@Override
	public Icon getIcon(boolean expanded) {
		return icon;
	}

	@Override
	public String getName() {
		return "Scripts";
	}

	@Override
	public String getToolTip() {
		return null;
	}

	@Override
	public boolean isLeaf() {
		return false;
	}

	void insert(String[] categoryPath) {
		GTreeNode parent = this;
		for (String categoryName : categoryPath) {

			GTreeNode child = getChildRegardlessOfFilter(parent, categoryName);
			if (child == null) {
				child = new ScriptCategoryNode(categoryName);
				insertSorted(parent, child);
			}
			parent = child;
		}
	}

	private GTreeNode getChildRegardlessOfFilter(GTreeNode parent, String name) {
		List<GTreeNode> children = parent.getChildren();
		for (GTreeNode child : children) {
			if (child.getName().equals(name)) {
				return child;
			}
		}
		return null;
	}

	private void insertSorted(GTreeNode parent, GTreeNode newChild) {
		List<GTreeNode> allChildren = parent.getChildren();
		for (GTreeNode child : allChildren) {
			String nodeName = child.getName();
			String newNodeName = newChild.getName();
			if (nodeName.compareToIgnoreCase(newNodeName) > 0) {
				parent.addNode(parent.getIndexOfChild(child), newChild);
				return;
			}
		}
		parent.addNode(newChild);
	}

}
