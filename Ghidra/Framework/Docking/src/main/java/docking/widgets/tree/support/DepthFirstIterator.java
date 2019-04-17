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

import java.util.ConcurrentModificationException;
import java.util.Iterator;

import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;

public class DepthFirstIterator implements Iterator<GTreeNode> {
	private GTreeNode root;
	private GTreeNode next;
	private GTreeNode lastNode;
	private final GTree tree;
	private final long mod;
	public DepthFirstIterator(GTree tree, GTreeNode node) {
		this.tree = tree;
		this.root = node;
		this.next = node;
		this.mod = tree.getModificationID();
	}

	public boolean hasNext() {
		return next != null;
	}

	public GTreeNode next() {
		checkForConcurrentModification();
		lastNode = next;
		next = findNext(next);
		return lastNode;
	}

	private void checkForConcurrentModification() {
		if (tree.getModificationID() != mod) {
			throw new ConcurrentModificationException();
		}
	}

	public void remove() {
		checkForConcurrentModification();
		GTreeNode parent = lastNode.getParent();
		if (parent == null) {
			throw new IllegalArgumentException("Can't delete root node!");
		}
		parent.removeNode(lastNode);
	}

	private GTreeNode findNext(GTreeNode node) {
		if (node.getChildCount() > 0) {
			return node.getChild(0);
		}
		while(node != root) {
			GTreeNode parent = node.getParent();
			int nextIndexInParent = node.getIndexInParent()+1;
			if (nextIndexInParent < parent.getChildCount()) {
				return parent.getChild(nextIndexInParent);
			}
			node = parent;
		}
		return null;
	}
}
