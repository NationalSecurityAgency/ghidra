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

import java.util.*;

import docking.widgets.tree.GTreeNode;

/**
 * Implements an iterator over all GTreeNodes in some gTree (or subtree).  The nodes are
 * return in breadth first order.
 */
public class BreadthFirstIterator implements Iterator<GTreeNode> {
	private Queue<GTreeNode> nodeQueue = new LinkedList<GTreeNode>();
	private GTreeNode lastNode;

	public BreadthFirstIterator(GTreeNode node) {
		nodeQueue.add(node);
	}

	@Override
	public boolean hasNext() {
		return !nodeQueue.isEmpty();
	}

	@Override
	public GTreeNode next() {
		lastNode = nodeQueue.poll();
		if (lastNode != null) {
			List<GTreeNode> children = lastNode.getChildren();
			nodeQueue.addAll(children);
		}
		return lastNode;
	}

	@Override
	public void remove() {
		GTreeNode parent = lastNode.getParent();
		if (parent == null) {
			throw new IllegalArgumentException("Can't delete root node!");
		}
		parent.removeNode(lastNode);
		nodeQueue.removeAll(lastNode.getChildren());
	}
}
