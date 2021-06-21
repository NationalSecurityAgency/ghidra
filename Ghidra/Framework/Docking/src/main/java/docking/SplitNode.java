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

import java.awt.Dimension;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;

import org.jdom.Element;

import ghidra.util.Msg;

/**
 * Node for managing a JSplitPane view of two component trees.
 */
class SplitNode extends Node {
	private Node child1;
	private Node child2;
	private JComponent comp;
	private SplitPanel splitPane;
	private boolean isHorizontal;
	//private int dividerLocation = -1;
	private float dividerPosition = 0;
	private Dimension splitPaneSize;

	/**
	 * Constructs a new SplitNode object
	 * @param winMgr the DockingWindowsManager that this node belongs to.
	 * @param child1 the node managing the first component tree.
	 * @param child2 the node managing the second component tree.
	 * @param isHorizontal true for horizontal layout
	 */
	SplitNode(DockingWindowManager winMgr, Node child1, Node child2, boolean isHorizontal) {
		super(winMgr);
		this.isHorizontal = isHorizontal;
		this.child1 = child1;
		this.child2 = child2;
		child1.parent = this;
		child2.parent = this;
	}

	/**
	 * Constructs a new SplitNode from the XML JDOM element
	 * @param elem the XML JDOM element containing the configuration information.
	 * @param mgr the DockingWindowsManager for this node.
	 * @param parent the parent node for this node.
	 * @param restoredPlaceholders the list into which any restored placeholders will be placed
	 */
	SplitNode(Element elem, DockingWindowManager mgr, Node parent,
			List<ComponentPlaceholder> restoredPlaceholders) {
		super(mgr);
		this.parent = parent;
		dividerPosition =
			(float) Integer.parseInt(elem.getAttributeValue("DIVIDER_LOCATION")) / 1000;
		int width = Integer.parseInt(elem.getAttributeValue("WIDTH"));
		int height = Integer.parseInt(elem.getAttributeValue("HEIGHT"));
		splitPaneSize = new Dimension(width, height);
		String orient = elem.getAttributeValue("ORIENTATION");
		isHorizontal = orient.equals("HORIZONTAL");

		List<?> list = elem.getChildren();
		child1 = processChildElement((Element) list.get(0), mgr, this, restoredPlaceholders);
		child2 = processChildElement((Element) list.get(1), mgr, this, restoredPlaceholders);

	}

	@Override
	void close() {
		child1.close();
		child2.close();
	}

	@Override
	JComponent getComponent() {
		if (invalid) {
			if (splitPane != null) {
				dividerPosition = ((SplitPanel) comp).getDividerPosition();
				splitPaneSize = comp.getSize();
			}

			splitPane = null;
			comp = null;
			JComponent comp1 = child1.getComponent();
			JComponent comp2 = child2.getComponent();
			if (comp1 != null && comp2 != null) {
				splitPane = new SplitPanel(this, comp1, comp2, isHorizontal);
				splitPane.setBorder(BorderFactory.createEmptyBorder());
				if (splitPaneSize != null) {
					splitPane.setSize(splitPaneSize);
					splitPane.setDividerPosition(dividerPosition);
				}
				comp = splitPane;
			}
			else if (comp1 != null) {
				comp = comp1;
			}
			else {
				comp = comp2;
			}
			invalid = false;
		}
		return comp;
	}

	@Override
	void removeNode(Node node) {
		if (node == child1) {
			parent.replaceNode(this, child2);
		}
		else if (node == child2) {
			parent.replaceNode(this, child1);
		}
	}

	@Override
	void replaceNode(Node oldNode, Node newNode) {
		if (oldNode != child1 && oldNode != child2) {
			throw new IllegalArgumentException();
		}
		if (oldNode == child1) {
			child1 = newNode;
		}
		else {
			child2 = newNode;
		}
		newNode.parent = this;
		invalidate();
		winMgr.scheduleUpdate();
	}

	@Override
	Element saveToXML() {
		Element root = new Element("SPLIT_NODE");
		if (splitPane != null) {
			dividerPosition = splitPane.getDividerPosition();
			splitPaneSize = splitPane.getSize();
		}

		if (splitPaneSize == null) {
			splitPaneSize = new Dimension(100, 100);

			// TODO we are not sure what purpose this serves.  We are leaving this here until
			//      we are sure removing it has no ill effects.
			//dividerPosition = 0.5f;
		}

		root.setAttribute("WIDTH", "" + splitPaneSize.width);
		root.setAttribute("HEIGHT", "" + splitPaneSize.height);
		root.setAttribute("DIVIDER_LOCATION", "" + Math.round(dividerPosition * 1000));
		root.setAttribute("ORIENTATION", isHorizontal ? "HORIZONTAL" : "VERTICAL");
		root.addContent(child1.saveToXML());
		root.addContent(child2.saveToXML());
		return root;
	}

	@Override
	boolean contains(ComponentPlaceholder info) {
		if (child1 != null && child1.contains(info)) {
			return true;
		}
		if (child2 != null && child2.contains(info)) {
			return true;
		}
		return false;
	}

	@Override
	void populateActiveComponents(List<ComponentPlaceholder> list) {
		child1.populateActiveComponents(list);
		child2.populateActiveComponents(list);
	}

	@Override
	WindowNode getTopLevelNode() {
		if (parent != null) {
			return parent.getTopLevelNode();
		}
		return null;
	}

	@Override
	List<Node> getChildren() {
		List<Node> list = new ArrayList<>();
		if (child1 != null) {
			list.add(child1);
		}
		if (child2 != null) {
			list.add(child2);
		}
		return list;
	}

	@Override
	public String toString() {
		return printTree();
	}

	@Override
	String getDescription() {
		return "Split Node";
	}

	@Override
	void dispose() {
		child1.dispose();
		child2.dispose();
	}
}

//==================================================================================================
// Inner Classes
//==================================================================================================

class MySplitPane extends JSplitPane {

	@Override
	public Dimension getMinimumSize() {
		Msg.debug(this, "getMinSize" + super.getMinimumSize());
		Dimension d1 = getLeftComponent().getMinimumSize();
		Dimension d2 = getRightComponent().getMinimumSize();
		if (getOrientation() == JSplitPane.HORIZONTAL_SPLIT) {
			d1 = new Dimension(d1.width + d2.width, Math.max(d1.height, d2.height));
		}
		else {
			d1 = new Dimension(Math.max(d1.width, d2.width), d1.height + d2.height);
		}
		Msg.debug(this, "my min size = " + d1);
		return d1;
	}

	public MySplitPane(int orientation, JComponent comp1, JComponent comp2) {
		super(orientation, comp1, comp2);
	}

	@Override
	public Dimension getPreferredSize() {
		Msg.debug(this, "get Preferred Size" + super.getMinimumSize());
		Dimension d1 = getLeftComponent().getPreferredSize();
		Dimension d2 = getRightComponent().getPreferredSize();
		if (getOrientation() == JSplitPane.HORIZONTAL_SPLIT) {
			d1 = new Dimension(d1.width + d2.width, Math.max(d1.height, d2.height));
		}
		else {
			d1 = new Dimension(Math.max(d1.width, d2.width), d1.height + d2.height);
		}
		return d1;
	}

}
