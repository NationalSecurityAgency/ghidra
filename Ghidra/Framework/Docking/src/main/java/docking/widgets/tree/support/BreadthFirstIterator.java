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
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;

public class BreadthFirstIterator implements Iterator<GTreeNode> {
	Queue<GTreeNode> nodeQueue = new LinkedList<GTreeNode>();
	GTreeNode lastNode;
	private boolean filtered;
	private long mod;
	private GTree tree;

	public BreadthFirstIterator(GTree tree, GTreeNode node) {
		this(tree, node, true);
	}

	public BreadthFirstIterator(GTree tree, GTreeNode node, boolean filtered) {
		nodeQueue.add(node);
		mod = tree.getModificationID();
		this.tree = tree;
		this.filtered = filtered;
	}

	public Stream<GTreeNode> stream() {
		Iterable<GTreeNode> iterable = () -> this;
		Stream<GTreeNode> stream = StreamSupport.stream(iterable.spliterator(), false);
		return stream;
	}

	@Override
	public boolean hasNext() {
		return !nodeQueue.isEmpty();
	}

	@Override
	public GTreeNode next() {
		checkForConcurrentModification();
		lastNode = nodeQueue.poll();
		if (lastNode != null) {
			if (filtered) {
				List<GTreeNode> children = lastNode.getChildren();
				nodeQueue.addAll(children);
			}
			else {
				List<GTreeNode> children = lastNode.getAllChildren();
				nodeQueue.addAll(children);
			}
		}
		return lastNode;
	}

	@Override
	public void remove() {
		checkForConcurrentModification();
		GTreeNode parent = lastNode.getParent();
		if (parent == null) {
			throw new IllegalArgumentException("Can't delete root node!");
		}
		parent.removeNode(lastNode);
		if (filtered) {
			nodeQueue.removeAll(lastNode.getChildren());
		}
		else {
			nodeQueue.removeAll(lastNode.getAllChildren());
		}
	}

	private void checkForConcurrentModification() {
		if (tree.getModificationID() != mod) {
			throw new ConcurrentModificationException();
		}
	}
}
