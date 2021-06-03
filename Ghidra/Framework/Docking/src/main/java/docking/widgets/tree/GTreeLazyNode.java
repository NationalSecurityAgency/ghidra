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

import java.util.List;

/**
 * Base class for GTreeNodes that populate their children on demand (typically when expanded). 
 * Also, children of this node can be unloaded by calling {@link #unloadChildren()}.  This
 * can be used by nodes in large trees to save memory by unloading children that are no longer
 * in the current tree view (collapsed).  Of course, that decision would need to be balanced
 * against the extra time to reload the nodes in the event that a filter is applied. Also, if
 * some external event occurs that changes the set of children for a GTreeLazyNode, you can call
 * {@link #unloadChildren()} to clear any previously loaded children.
 */
public abstract class GTreeLazyNode extends GTreeNode {

	/**
	 * Subclasses must be able to generate their children nodes on demand by implementing this method.
	 * @return the list of GTreeNodes that make up the children for this node.
	 */
	@Override
	protected abstract List<GTreeNode> generateChildren();

	/**
	 * Sets this lazy node back to the "unloaded" state such that if
	 * its children are accessed, it will reload its children as needed.
	 */
	public void unloadChildren() {
		if (isLoaded()) {
			setChildren(null);
		}
	}

	@Override
	public void addNode(GTreeNode node) {
		if (isLoaded()) {
			super.addNode(node);
		}
	}

	@Override
	public void addNode(int index, GTreeNode node) {
		if (isLoaded()) {
			super.addNode(index, node);
		}
	}

	@Override
	public void addNodes(List<GTreeNode> nodes) {
		if (isLoaded()) {
			super.addNodes(nodes);
		}
	}

	@Override
	public void removeAll() {
		unloadChildren();
	}

	@Override
	public void removeNode(GTreeNode node) {
		if (!isLoaded()) {
			return;
		}
		super.removeNode(node);
	}
}
