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
package docking.widgets.tree;

import javax.swing.Icon;

/**
 * Artificial node used by the GTree to set as a parent on the real root node of a GTree.  It allows
 * nodes to access the GTree because it overrides getTree to return the GTree. This eliminates the
 * need for clients to create special root nodes that have getTree/setTree
 */
class GTreeRootParentNode extends GTreeNode {
	private GTree tree;

	GTreeRootParentNode(GTree tree) {
		this.tree = tree;
	}

	@Override
	public GTree getTree() {
		return tree;
	}

	@Override
	public String getName() {
		return null;
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return null;
	}

	@Override
	public String getToolTip() {
		return null;
	}

	@Override
	public boolean isLeaf() {
		return false;
	}
}
