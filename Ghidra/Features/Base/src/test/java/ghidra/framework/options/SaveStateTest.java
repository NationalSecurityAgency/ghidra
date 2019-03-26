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
/*
 * (c) Copyright 2001 MyCorporation.
 * All Rights Reserved.
 */
package ghidra.framework.options;

import static org.junit.Assert.*;

import java.io.*;

import org.jdom.Document;
import org.jdom.Element;
import org.jdom.input.SAXBuilder;
import org.jdom.output.XMLOutputter;
import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.util.xml.GenericXMLOutputter;
import ghidra.util.xml.XmlUtilities;

/**
 * @version 1.0
 * 
 */
public class SaveStateTest extends AbstractGenericTest {

	private SaveState ss;

	/**
	 * Constructor for SaveStateTest.
	 * 
	 * @param arg0
	 */
	public SaveStateTest() {
		super();
	}

	@Before
	public void setUp() {
		ss = new SaveState();
	}

	@Test
	public void testString() throws Exception {
		ss.putString("TEST", null);
		String s = ss.getString("TEST", "FRED");
		assertNull(s);

		String validKey = "TEST2";
		ss.putString(validKey, "Value");
		s = ss.getString(validKey, null);
		assertNotNull(s);

		// persist the state
		File saveFileTemp = createTempFile("xmlTest");
		Element element = ss.saveToXml();
		saveElement(element, saveFileTemp);

		// read in the state
		InputStream is = new FileInputStream(saveFileTemp);
		SAXBuilder sax = XmlUtilities.createSecureSAXBuilder(false, false);
		Element root = sax.build(is).getRootElement();

		// make sure our value is inside
		SaveState loadedState = new SaveState(root);
		String value = loadedState.getString(validKey, null);
		assertNotNull(value);

		saveFileTemp.deleteOnExit();
	}

	private void saveElement(Element element, File saveFile) throws Exception {
		OutputStream os = null;
		try {
			os = new FileOutputStream(saveFile);
			Document doc = new Document(element);
			XMLOutputter xmlout = new GenericXMLOutputter();
			xmlout.output(doc, os);
			os.close();
		}
		finally {
			if (os != null) {
				os.close();
			}
		}
	}

	@Test
	public void testStringArray() {
		String[] array1 =
			new String[] { "Dennis", "Bill", "Brian", "Mike", null, "Ellen", "Steve" };
		ss.putStrings("ARRAY", array1);
		String[] array2 = ss.getStrings("ARRAY", null);
		for (int i = 0; i < array1.length; ++i) {
			assertEquals(array1[i], array2[i]);
		}
	}

	@Test
	public void testByte() {
		ss.putByte("FOURTYTWO", (byte) 42);
		assertTrue(ss.hasValue("FOURTYTWO"));
		assertEquals((byte) 42, ss.getByte("FOURTYTWO", (byte) 0));
		assertTrue(!ss.hasValue("XXX"));
		assertEquals((byte) 5, ss.getByte("XXX", (byte) 5));
	}

	@Test
	public void testByteArray() {
		byte[] array1 = new byte[] { (byte) 0, (byte) 5, (byte) 9, (byte) 42, (byte) 77 };
		ss.putBytes("ARRAY", array1);
		byte[] array2 = ss.getBytes("ARRAY", null);
		for (int i = 0; i < array1.length; ++i) {
			assertEquals(array1[i], array2[i]);
		}
	}

	@Test
	public void testShort() {
		ss.putShort("FOURTYTWO", (short) 42);
		assertTrue(ss.hasValue("FOURTYTWO"));
		assertEquals((short) 42, ss.getShort("FOURTYTWO", (short) 0));
		assertTrue(!ss.hasValue("XXX"));
		assertEquals((short) 5, ss.getShort("XXX", (short) 5));
	}

	@Test
	public void testInt() {
		ss.putInt("FOURTYTWO", 42);
		assertTrue(ss.hasValue("FOURTYTWO"));
		assertEquals(42, ss.getInt("FOURTYTWO", 0));
		assertTrue(!ss.hasValue("XXX"));
		assertEquals(5, ss.getInt("XXX", 5));
	}

	@Test
	public void testIntArray() {
		int[] array1 = new int[] { 0, 5, 9, 42, 77 };
		ss.putInts("ARRAY", array1);
		int[] array2 = ss.getInts("ARRAY", null);
		for (int i = 0; i < array1.length; ++i) {
			assertEquals(array1[i], array2[i]);
		}
	}

	@Test
	public void testLong() {
		ss.putLong("FOURTYTWO", 42);
		assertTrue(ss.hasValue("FOURTYTWO"));
		assertEquals(42, ss.getLong("FOURTYTWO", 0));
		assertTrue(!ss.hasValue("XXX"));
		assertEquals(5, ss.getLong("XXX", 5));
	}

	@Test
	public void testFloat() {
		ss.putFloat("PI", (float) 3.14159);
		assertTrue(ss.hasValue("PI"));
		assertEquals((float) 3.14159, ss.getFloat("PI", (float) 0.0), (float) 0.01);
		assertTrue(!ss.hasValue("XXX"));
		assertEquals(5, ss.getFloat("XXX", 5), (float) 0.01);
	}

	@Test
	public void testDouble() {
		ss.putDouble("PI", 3.14159);
		assertTrue(ss.hasValue("PI"));
		assertEquals(3.14159, ss.getDouble("PI", 0.0), 0.01);
		assertTrue(!ss.hasValue("XXX"));
		assertEquals(5, ss.getDouble("XXX", 5), 0.01);
	}

	@Test
	public void testSome() {
		ss.putDouble("PI", 3.14159);
		ss.putByte("BYTE", (byte) 0xEE);
		ss.putLong("LONG", 65536);
		ss.putString("STRING", "See Jane Run");
		ss.putBoolean("BOOL_A", false);
		ss.putBoolean("BOOL_B", true);

		assertEquals(3.1459, ss.getDouble("PI", 0.0), 0.01);
		assertEquals("See Jane Run", ss.getString("STRING", "BOB"));
		assertEquals(true, ss.getBoolean("BOOL_B", false));
		assertEquals((byte) 0xEE, ss.getByte("BYTE", (byte) 0));
		assertEquals(false, ss.getBoolean("BOOL_A", true));
	}

	@Test
	public void testXML() {
		Element elem1 = new Element("ELEM_1");
		Element elem2 = new Element("ELEM_2");
		elem1.setAttribute("NAME", "VALUE");
		elem1.addContent(elem2);
		ss.putXmlElement("XML", elem1);
		Element elem3 = ss.getXmlElement("XML");
		Element elem4 = (Element) elem3.getChildren().get(0);
		assertEquals(elem1, elem3);
		assertEquals(elem1.getName(), elem3.getName());
		assertEquals(elem2, elem4);
		assertEquals(elem2.getName(), elem4.getName());
	}

	@Test
	public void testXMLEntityEscapingForSCR_4675() throws Exception {
		String stringWithGreaterThanAndLessThan =
			"The following statement is true: 1 < 3 > 2 " + "with some trailing text";
		String greaterThanLessThanKey = "GT_LT_KEY";
		ss.putString(greaterThanLessThanKey, stringWithGreaterThanAndLessThan);

		String stringWithLargeHexDigit =
			"The following is a large hex digit: \u0128, \u0132, \307 and \253 " +
				"with some trailing text &#xFF;";
		String hexDigitKey = "HEX_DIGIT_KEY";
		ss.putString(hexDigitKey, stringWithLargeHexDigit);

		String stringWithAmpersandApostropheAndQuote = "That is the Jones' \"love & happiness\".";
		String ampersandApostropheQuoteKey = "AMP_APOS_KEY";
		ss.putString(ampersandApostropheQuoteKey, stringWithAmpersandApostropheAndQuote);

		// persist the state
		File saveFileTemp = null;
		Element root = null;
		try {
			saveFileTemp = createTempFile("xmlTest");
			Element element = ss.saveToXml();
			saveElement(element, saveFileTemp);

			// read in the state
			InputStream is = new FileInputStream(saveFileTemp);
			SAXBuilder sax = XmlUtilities.createSecureSAXBuilder(false, false);
			root = sax.build(is).getRootElement();
		}
		catch (Exception e) {
			throw e;
		}
		finally {
			if (saveFileTemp != null) {
				saveFileTemp.delete();
			}
		}

		// make sure our value is the same as we put in (no escaped entities)
		SaveState loadedState = new SaveState(root);
		String value = loadedState.getString(greaterThanLessThanKey, null);
		assertNotNull(value);
		assertEquals("The XML string saved with special characters was not read in correctly",
			stringWithGreaterThanAndLessThan, value);

		value = loadedState.getString(hexDigitKey, null);
		assertNotNull(value);
		assertEquals("The XML string saved with special characters was not read in correctly",
			stringWithLargeHexDigit, value);

		value = loadedState.getString(ampersandApostropheQuoteKey, null);
		assertNotNull(value);
		assertEquals("The XML string saved with special characters was not read in correctly",
			stringWithAmpersandApostropheAndQuote, value);
	}

	@Test
	public void testIsEmpty() {
		assertTrue(ss.isEmpty());
		ss.putBoolean("BOOL", false);
		assertTrue(!ss.isEmpty());
	}

	@Test
	public void testFileInputOutput() throws IOException {
		ss.putBoolean("B1", true);
		ss.putInt("I1", 7);
		ss.putString("S1", "Hey There");
		File file = createTempFile("SaveStateTest", "xml");
		ss.saveToFile(file);

		SaveState ss2 = new SaveState(file);
		assertEquals(true, ss2.getBoolean("B1", false));
		assertEquals(7, ss2.getInt("I1", 1));
		assertEquals("Hey There", ss2.getString("S1", ""));
		file.delete();
	}
}
