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
package ghidra.util.xml;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.jdom.Element;
import org.junit.Test;

import generic.test.AbstractGenericTest;

public class XmlUtilitiesTest extends AbstractGenericTest {

	/**
	 * @param arg0
	 */
	public XmlUtilitiesTest() {
		super();
	}

	@Test
	public void testXmlToBytes() {
		Element root = new Element("ROOT");
		Element rowElem = new Element("ROW");

		Element colElem = new Element("COL");
		colElem.setAttribute("WIDTH", "200");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "AAA");
		colElem.setAttribute("WIDTH", "100");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		root.addContent(rowElem);

		byte[] bytes = XmlUtilities.xmlToByteArray(root);
		Element e = XmlUtilities.byteArrayToXml(bytes);

		assertEquals("ROOT", e.getName());
		List<?> list = e.getChildren();
		assertEquals(1, list.size());
		Element c1 = (Element) list.get(0);
		assertEquals("ROW", c1.getName());
		list = c1.getChildren();
		assertEquals(2, list.size());
		c1 = (Element) list.get(0);
		assertEquals("COL", c1.getName());
		Element c2 = (Element) list.get(1);
		assertEquals("FIELD", c2.getName());

		assertEquals("200", c1.getAttributeValue("WIDTH"));
		assertEquals("true", c1.getAttributeValue("ENABLED"));

	}

	@Test
	public void testHasInvalidXMLChars() {
		assertTrue(XmlUtilities.hasInvalidXMLCharacters("\0"));

		// Strange code alert: ch is unsigned and this loop relies on overflowing ch and wrapping back to 0
		// since we already know ch '\0' is bad.
		// Test each character to ensure it can be added to an XML element attribute
		// and successfully outputted as a xml document.
		for (char ch = 1; ch != 0; ch++) {
			if (!XmlUtilities.hasInvalidXMLCharacters("" + ch)) {
				testCharAsAttrValue(ch);
			}
		}
	}

	private static void testCharAsAttrValue(char ch) {
		Element node = new Element("node");
		node.setAttribute("attr", "" + ch);

		@SuppressWarnings("unused")
		String tmp = XmlUtilities.toString(node);
	}
}
