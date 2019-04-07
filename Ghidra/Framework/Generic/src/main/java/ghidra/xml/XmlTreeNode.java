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
package ghidra.xml;

import java.util.Iterator;
import java.util.LinkedList;

import org.xml.sax.SAXParseException;

/**
 * A class to represent a corresponding start and end tag. This value is one
 * node on the XML parse tree.
 * 
 */
public class XmlTreeNode {
	private final XmlElement startElement;
	private final XmlElement endElement;
	private final LinkedList<XmlTreeNode> children;

	/**
	 * Constructs a new XML tree node given the specified parser.
	 * 
	 * @param parser
	 *            the XML parser
	 * @throws SAXParseException
	 *             if an XML parser error occurs
	 */
	public XmlTreeNode(XmlPullParser parser) throws SAXParseException {
		children = new LinkedList<XmlTreeNode>();
		startElement = parser.start();

		XmlElement child = parser.peek();
		while (child != null && child.isStart()) {
			children.add(new XmlTreeNode(parser));
			child = parser.peek();
		}
		endElement = parser.end(startElement);
	}

	/**
	 * Returns the start element of this node.
	 * 
	 * @return the start element of this node
	 */
	public XmlElement getStartElement() {
		return startElement;
	}

	/**
	 * Returns the end element of this node.
	 * 
	 * @return the end element of this node
	 */
	public XmlElement getEndElement() {
		return endElement;
	}

	/**
	 * Returns the number of children below this node.
	 * 
	 * @return the number of children below this node
	 */
	public int getChildCount() {
		return children.size();
	}

	/**
	 * Returns an iterator over all of the children of this node.
	 * 
	 * @return an iterator over all of the children of this node
	 */
	public Iterator<XmlTreeNode> getChildren() {
		return children.iterator();
	}

	/**
	 * Returns an iterator over all of the children of this node with the
	 * specfied name.
	 * 
	 * @param name
	 *            the name of the desired children
	 * @return an iterator over all of the children of this node with the
	 *         specfied name
	 */
	public Iterator<XmlTreeNode> getChildren(String name) {
		return new TagIterator(name);
	}

	/**
	 * Returns the first child element with the specified name.
	 * 
	 * @param name
	 *            the name of the desired child element
	 * @return the first child element with the specified name
	 */
	public XmlTreeNode getChild(String name) {
		Iterator<XmlTreeNode> it = getChildren(name);
		if (it.hasNext()) {
			return it.next();
		}
		return null;
	}

	public XmlTreeNode getChildAt(int index) {
		return children.get(index);
	}

	class TagIterator implements Iterator<XmlTreeNode> {
		private Iterator<XmlTreeNode> it;
		private XmlTreeNode nextNode;
		private String tag;

		TagIterator(String tag) {
			this.tag = tag;
			it = children.iterator();
		}

		private void findNext() {
			while (it.hasNext()) {
				nextNode = it.next();
				if (nextNode.getStartElement().getName().equals(tag)) {
					return;
				}
			}
			nextNode = null;
		}

		public void remove() {
			it.remove();
		}

		public boolean hasNext() {
			if (nextNode == null) {
				findNext();
			}
			return nextNode != null;
		}

		public XmlTreeNode next() {
			if (hasNext()) {
				XmlTreeNode node = nextNode;
				nextNode = null;
				return node;
			}
			return null;
		}
	}

	/**
	 * Deletes the specified child node.
	 * 
	 * @param node
	 *            the node to delete
	 */
	public void deleteChildNode(XmlTreeNode node) {
		Iterator<XmlTreeNode> it = children.iterator();
		while (it.hasNext()) {
			if (it.next() == node) {
				it.remove();
				return;
			}
		}
	}
}
