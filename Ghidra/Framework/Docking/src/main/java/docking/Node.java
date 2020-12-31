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
package docking;

import java.util.List;

import javax.swing.JComponent;

import org.jdom.Element;

/**
 * Base class for the various node objects used to build the component hierarchy.
 */
abstract class Node {
	Node parent;
	boolean invalid = true;
	DockingWindowManager winMgr;

	/**
	 * Construct a new Node.
	 * @param winMgr the DockingWindowManager that this node belongs to.
	 */
	Node(DockingWindowManager winMgr) {
		this.winMgr = winMgr;
	}

	/**
	 * Returns this node's window manager
	 * @return the window manager
	 */
	DockingWindowManager getDockingWindowManager() {
		return winMgr;
	}

	/**
	 * Gets all children of this node; an empty list if no children exist.
	 * 
	 * @return all children of this node.
	 */
	abstract List<Node> getChildren();

	/**
	 * Recursively closes all nodes.
	 */
	abstract void close();

	/**
	 * Returns a component that manages all the components from the nodes below it
	 * @return the component
	 */
	abstract JComponent getComponent();

	/**
	 * Determine if this node contains the specified component
	 * 
	 * @param info component information
	 * @return true if this node contains the specified component
	 */
	abstract boolean contains(ComponentPlaceholder info);

	/**
	 * Returns an JDOM element object that contains the configuration state of this node 
	 * and its children
	 * @return the element
	 */
	abstract Element saveToXML();

	/**
	 * Removes the given node as a child.
	 * @param node the node to be removed.
	 */
	abstract void removeNode(Node node);

	/**
	 * Replaces the oldNode child with the newNode.
	 * @param oldNode the node to be replaced.
	 * @param newNode the node to replace the old node.
	 */
	abstract void replaceNode(Node oldNode, Node newNode);

	abstract WindowNode getTopLevelNode();

	/**
	 * Puts into the given list all active components in this node
	 * @param list the results list
	 */
	abstract void populateActiveComponents(List<ComponentPlaceholder> list);

	/**
	 * Marks this node and all ancestors as invalid and needing to be rebuilt.
	 */
	void invalidate() {
		invalid = true;
		if (parent != null) {
			parent.invalidate();
		}
	}

	/**
	 * Generates a node corresponding to the given XML element
	 * 
	 * @param elem the XML element for which to generate a node
	 * @param mgr the DockingWindowsManager for the new node
	 * @param parentNode the parent node for the new node
	 * @param restoredPlaceholders a 'results' list into which will be placed any restored
	 *        placeholders
	 * @return the new node generated from the XML element
	 */
	Node processChildElement(Element elem, DockingWindowManager mgr, Node parentNode,
			List<ComponentPlaceholder> restoredPlaceholders) {
		if (elem.getName().equals("SPLIT_NODE")) {
			return new SplitNode(elem, mgr, parentNode, restoredPlaceholders);
		}
		else if (elem.getName().equals("COMPONENT_NODE")) {
			return new ComponentNode(elem, mgr, parentNode, restoredPlaceholders);
		}
		return null;
	}

	/**
	 * Returns a descriptive name for this node.
	 * @return a descriptive name for this node.
	 */
	abstract String getDescription();

	/**
	 * Prints the hierarchy of nodes represented by this node
	 * 
	 * @return a string representation of the hierarchy of nodes represented by this node.
	 */
	String printTree() {
		StringBuilder buffy = new StringBuilder();
		printNodes(buffy, getTopLevelNode(), 0);
		return buffy.toString();
	}

	private String printNodes(StringBuilder buffy, Node node, int level) {
		String indent = indent(level * 3);
		if (node == null) {
			buffy.append("<detached> " + getClass().getSimpleName());
			return buffy.toString();
		}
		String name = node.getDescription();
		if (this == node) {
			buffy.append(indent);
			buffy.append("***   ");
			buffy.append(name);
			buffy.append("   ***").append('\n');
		}
		else {
			buffy.append(indent).append(name).append('\n');
		}

		List<Node> children = node.getChildren();
		for (Node n : children) {
			printNodes(buffy, n, level + 1);
		}
		return buffy.toString();
	}

	private String indent(int n) {
		StringBuilder buffy = new StringBuilder();
		for (int i = 0; i < n; i++) {
			buffy.append(' ');
		}
		return buffy.toString();
	}

	void dispose() {
		// stub for subclasses
	}
}
