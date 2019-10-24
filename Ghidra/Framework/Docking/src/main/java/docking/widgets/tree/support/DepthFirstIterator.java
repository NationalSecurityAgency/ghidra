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

import java.util.Iterator;
import java.util.Stack;

import org.apache.commons.collections4.IteratorUtils;

import docking.widgets.tree.GTreeNode;

/**
 * Implements an iterator over all GTreeNodes in some gTree (or subtree).  The nodes are
 * return in depth first order.
 */
public class DepthFirstIterator implements Iterator<GTreeNode> {
	private Stack<Iterator<GTreeNode>> stack = new Stack<>();
	private Iterator<GTreeNode> it;
	private GTreeNode lastNode;

	public DepthFirstIterator(GTreeNode node) {
		it = IteratorUtils.singletonIterator(node);
	}

	@Override
	public boolean hasNext() {
		return !stack.isEmpty() || it.hasNext();
	}

	@Override
	public GTreeNode next() {
		if (!it.hasNext()) {
			if (stack.isEmpty()) {
				return null;
			}
			it = stack.pop();
		}
		lastNode = it.next();
		if (lastNode.getChildCount() > 0) {
			if (it.hasNext()) {
				stack.push(it);
			}
			it = lastNode.getChildren().iterator();
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
	}

}
