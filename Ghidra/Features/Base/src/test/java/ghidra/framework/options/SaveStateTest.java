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
package ghidra.framework.options;

import static org.junit.Assert.*;

import java.awt.Color;
import java.awt.Font;
import java.io.*;
import java.util.Arrays;
import java.util.Date;

import javax.swing.KeyStroke;

import org.jdom.Document;
import org.jdom.Element;
import org.jdom.input.SAXBuilder;
import org.jdom.output.XMLOutputter;
import org.junit.Before;
import org.junit.Test;

import com.google.gson.JsonObject;

import generic.test.AbstractGenericTest;
import ghidra.app.plugin.core.overview.addresstype.AddressType;
import ghidra.program.model.lang.Endian;
import ghidra.util.xml.GenericXMLOutputter;
import ghidra.util.xml.XmlUtilities;

public class SaveStateTest extends AbstractGenericTest {

	private SaveState ss;

	@Before
	public void setUp() {
		ss = new SaveState("foo");
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

		SaveState restoredState = saveAndRestoreToXml();

		String value = restoredState.getString(validKey, null);
		assertNotNull(value);
	}

	@Test
	public void testColor() throws Exception {
		ss.putColor("TEST", Color.RED);
		Color c = ss.getColor("TEST", null);
		assertEquals(Color.RED, c);

		SaveState restoredState = saveAndRestoreToXml();

		// make sure our value is inside
		c = restoredState.getColor("TEST", null);
		assertEquals(Color.RED, c);
	}

	@Test
	public void testDate() throws Exception {
		Date date = SaveState.DATE_FORMAT.parse("2020-12-22T14:20:24-0500");
		ss.putDate("TEST", date);
		Date d = ss.getDate("TEST", null);
		assertEquals(date, d);

		SaveState restoredState = saveAndRestoreToXml();

		// make sure our value is inside
		d = restoredState.getDate("TEST", null);
		assertEquals(date, d);
	}

	@Test
	public void testFile() throws Exception {
		File file = createTempFile("myFile", "txt");
		file.deleteOnExit();
		ss.putFile("TEST", file);
		File f = ss.getFile("TEST", null);
		assertEquals(file, f);

		SaveState restoredState = saveAndRestoreToXml();

		// make sure our value is inside
		f = restoredState.getFile("TEST", null);
		assertEquals(file, f);
	}

	@Test
	public void testKeyStroke() throws Exception {
		KeyStroke keyStroke = KeyStroke.getKeyStroke("ctrl X");
		assertNotNull(keyStroke);

		ss.putKeyStroke("TEST", keyStroke);
		KeyStroke k = ss.getKeyStroke("TEST", null);
		assertEquals(keyStroke, k);

		SaveState restoredState = saveAndRestoreToXml();

		// make sure our value is inside
		k = restoredState.getKeyStroke("TEST", null);
		assertEquals(keyStroke, k);
	}

	@Test
	public void testFont() throws Exception {
		Font font = Font.decode("Dialog-BOLD-12");
		ss.putFont("TEST", font);
		Font f = ss.getFont("TEST", null);
		assertEquals(font, f);

		SaveState restoredState = saveAndRestoreToXml();

		// make sure our value is inside
		f = restoredState.getFont("TEST", null);
		assertEquals(font, f);
	}

	@Test
	public void testSubSaveState() throws Exception {
		SaveState subState = new SaveState("sub");
		subState.putInt("a", 5);
		subState.putString("foo", "bar");

		ss.putSaveState("TEST", subState);
		ss.putString("xxx", "zzzz");
		SaveState restoredState = saveAndRestoreToXml();

		// make sure our value is inside
		assertEquals("zzzz", restoredState.getString("xxx", null));
		SaveState restoredSub = restoredState.getSaveState("TEST");
		assertEquals(2, restoredSub.getNames().length);
		assertEquals(5, restoredSub.getInt("a", 0));
		assertEquals("bar", restoredSub.getString("foo", ""));
	}

	private SaveState saveAndRestoreToXml() throws Exception {
		// persist the state
		File saveFileTemp = createTempFile("xmlTest");
		Element element = ss.saveToXml();
		saveElement(element, saveFileTemp);

		// read in the state
		InputStream is = new FileInputStream(saveFileTemp);
		SAXBuilder sax = XmlUtilities.createSecureSAXBuilder(false, false);
		Element root = sax.build(is).getRootElement();
		SaveState loadedState = new SaveState(root);
		saveFileTemp.deleteOnExit();
		return loadedState;
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
	public void testStringArray() throws Exception {
		String[] array1 =
			new String[] { "Dennis", "Bill", "Brian", "Mike", null, "Ellen", "Steve" };
		String[] after =
			new String[] { "Dennis", "Bill", "Brian", "Mike", "Ellen", "Steve" };

		ss.putStrings("ARRAY", array1);
		String[] array2 = ss.getStrings("ARRAY", null);

		assertArrayEquals(array1, array2);

		SaveState restoredState = saveAndRestoreToXml();

		assertArrayEquals(after, restoredState.getStrings("ARRAY", null));
	}

	@Test
	public void testByte() throws Exception {
		ss.putByte("FOURTYTWO", (byte) 42);
		assertTrue(ss.hasValue("FOURTYTWO"));
		assertEquals((byte) 42, ss.getByte("FOURTYTWO", (byte) 0));
		assertTrue(!ss.hasValue("XXX"));
		assertEquals((byte) 5, ss.getByte("XXX", (byte) 5));

		SaveState restoredState = saveAndRestoreToXml();
		assertEquals((byte) 42, restoredState.getByte(("FOURTYTWO"), (byte) 0));
	}

	@Test
	public void testByteArray() throws Exception {
		byte[] array1 = new byte[] { (byte) 0, (byte) 5, (byte) 9, (byte) 42, (byte) 77 };
		ss.putBytes("ARRAY", array1);
		byte[] array2 = ss.getBytes("ARRAY", null);
		assertArrayEquals(array1, array2);

		SaveState restoredState = saveAndRestoreToXml();
		assertArrayEquals(array1, restoredState.getBytes("ARRAY", null));

	}

	@Test
	public void testShort() throws Exception {
		ss.putShort("FOURTYTWO", (short) 42);
		assertTrue(ss.hasValue("FOURTYTWO"));
		assertEquals((short) 42, ss.getShort("FOURTYTWO", (short) 0));
		assertTrue(!ss.hasValue("XXX"));
		assertEquals((short) 5, ss.getShort("XXX", (short) 5));

		SaveState restoredState = saveAndRestoreToXml();
		assertEquals((short) 42, restoredState.getShort(("FOURTYTWO"), (short) 0));
	}

	@Test
	public void testInt() throws Exception {
		ss.putInt("FOURTYTWO", 42);
		assertTrue(ss.hasValue("FOURTYTWO"));
		assertEquals(42, ss.getInt("FOURTYTWO", 0));
		assertTrue(!ss.hasValue("XXX"));
		assertEquals(5, ss.getInt("XXX", 5));

		SaveState restoredState = saveAndRestoreToXml();
		assertEquals(42, restoredState.getInt(("FOURTYTWO"), 0));
	}

	@Test
	public void testIntArray() throws Exception {
		int[] array1 = new int[] { 0, 5, 9, 42, 77 };
		ss.putInts("ARRAY", array1);
		int[] array2 = ss.getInts("ARRAY", null);
		Arrays.equals(array1, array2);

		SaveState restoredState = saveAndRestoreToXml();

		// make sure our value is inside
		int[] restoredArray = restoredState.getInts("ARRAY", null);
		Arrays.equals(array1, restoredArray);
	}

	@Test
	public void testLong() throws Exception {
		ss.putLong("FOURTYTWO", 42);
		assertTrue(ss.hasValue("FOURTYTWO"));
		assertEquals(42, ss.getLong("FOURTYTWO", 0));
		assertTrue(!ss.hasValue("XXX"));
		assertEquals(5, ss.getLong("XXX", 5));

		SaveState restoredState = saveAndRestoreToXml();
		assertEquals(42L, restoredState.getLong(("FOURTYTWO"), 0));
	}

	@Test
	public void testFloat() throws Exception {
		ss.putFloat("PI", (float) 3.14159);
		assertTrue(ss.hasValue("PI"));
		assertEquals((float) 3.14159, ss.getFloat("PI", (float) 0.0), (float) 0.01);
		assertTrue(!ss.hasValue("XXX"));
		assertEquals(5, ss.getFloat("XXX", 5), (float) 0.01);

		SaveState restoredState = saveAndRestoreToXml();
		assertEquals(3.14159, restoredState.getFloat(("PI"), 0), 0.001f);
	}

	@Test
	public void testDouble() throws Exception {
		ss.putDouble("PI", 3.14159);
		assertTrue(ss.hasValue("PI"));
		assertEquals(3.14159, ss.getDouble("PI", 0.0), 0.01);
		assertTrue(!ss.hasValue("XXX"));
		assertEquals(5, ss.getDouble("XXX", 5), 0.01);

		SaveState restoredState = saveAndRestoreToXml();
		assertEquals(3.14159, restoredState.getDouble(("PI"), 0), 0.000001);
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

	@Test
	public void testJsonStringRoundTrip() {
		ss.putString("foo", "Hey");
		SaveState restored = jsonRoundTrip(ss);
		assertEquals("Hey", restored.getString("foo", "there"));
	}

	@Test
	public void testJsonColorRoundTrip() {
		ss.putColor("foo", Color.BLUE);
		SaveState restored = jsonRoundTrip(ss);
		assertEquals(Color.BLUE, restored.getColor("foo", null));
	}

	@Test
	public void testJsonDatRoundTrip() throws Exception {
		Date date = SaveState.DATE_FORMAT.parse("2020-12-22T14:20:24-0500");
		ss.putDate("foo", date);
		SaveState restored = jsonRoundTrip(ss);
		assertEquals(date, restored.getDate("foo", null));
	}

	@Test
	public void testJsonFileRoundTrip() throws IOException {
		File file = createTempFile("myFile", "txt");
		ss.putFile("foo", file);
		SaveState restored = jsonRoundTrip(ss);
		assertEquals(file, restored.getFile("foo", null));
		file.deleteOnExit();
	}

	@Test
	public void testJsonKeyStrokRoundTrip() {
		KeyStroke keyStroke = KeyStroke.getKeyStroke("ctrl X");
		assertNotNull(keyStroke);

		ss.putKeyStroke("foo", keyStroke);
		SaveState restored = jsonRoundTrip(ss);
		assertEquals(keyStroke, restored.getKeyStroke("foo", null));
	}

	@Test
	public void testJsonFontRoundTrip() {
		Font font = Font.decode("Dialog-BOLD-12");
		ss.putFont("foo", font);
		SaveState restored = jsonRoundTrip(ss);
		assertEquals(font, restored.getFont("foo", null));
	}

	@Test
	public void testJsonSubSaveStateRoundTrip() {
		SaveState subState = new SaveState("sub");
		subState.putInt("a", 5);
		subState.putString("foo", "bar");
		ss.putSaveState("foo", subState);
		ss.putString("bar", "xyz");

		SaveState restored = jsonRoundTrip(ss);
		assertEquals("xyz", restored.getString("bar", null));
		SaveState restoredSub = restored.getSaveState("foo");
		assertEquals(2, restoredSub.getNames().length);
		assertEquals(5, restoredSub.getInt("a", 0));
		assertEquals("bar", restoredSub.getString("foo", ""));
	}

	@Test
	public void testJsonByteRoundTrip() {
		ss.putByte("foo", (byte) 42);
		SaveState restored = jsonRoundTrip(ss);
		assertEquals((byte) 42, restored.getByte("foo", (byte) 0));
	}

	@Test
	public void testJsonShortRoundTrip() {
		ss.putShort("foo", (short) 42);
		SaveState restored = jsonRoundTrip(ss);
		assertEquals((short) 42, restored.getShort("foo", (short) 0));
	}

	@Test
	public void testJsonIntRoundTrip() {
		ss.putInt("foo", 123456789);
		SaveState restored = jsonRoundTrip(ss);
		assertEquals(123456789, restored.getInt("foo", 0));
	}

	@Test
	public void testJsonLongRoundTrip() {
		ss.putLong("foo", 12345678901234L);
		SaveState restored = jsonRoundTrip(ss);
		assertEquals(12345678901234L, restored.getLong("foo", 0));
	}

	@Test
	public void testJsonFloatRoundTrip() {
		ss.putFloat("foo", 12.123f);
		SaveState restored = jsonRoundTrip(ss);
		assertEquals(12.123f, restored.getFloat("foo", 0), 0.0001f);
	}

	@Test
	public void testJsonDoubleRoundTrip() {
		ss.putDouble("foo", 12.123456);
		SaveState restored = jsonRoundTrip(ss);
		assertEquals(12.123456, restored.getDouble("foo", 0), 0.00000001);
	}

	@Test
	public void testJsonBooleanRoundTrip() {
		ss.putBoolean("foo", true);
		SaveState restored = jsonRoundTrip(ss);
		assertEquals(true, restored.getBoolean("foo", false));
	}

	@Test
	public void testJsonStringArrayRoundTrip() {
		String[] strings = new String[] { "aaa", "bbb", null, "ccc" };
		String[] after = new String[] { "aaa", "bbb", "ccc" };
		ss.putStrings("foo", strings);
		SaveState restored = jsonRoundTrip(ss);
		assertArrayEquals(after, restored.getStrings("foo", null));
	}

	@Test
	public void testJsonByteArrayRoundTrip() {
		byte[] bytes = new byte[] { (byte) 1, (byte) 2, (byte) 3 };
		ss.putBytes("foo", bytes);
		SaveState restored = jsonRoundTrip(ss);
		assertArrayEquals(bytes, restored.getBytes("foo", null));
	}

	@Test
	public void testJsonShortArrayRoundTrip() {
		short[] shorts = new short[] { (short) 1, (short) 2, (short) 3 };
		ss.putShorts("foo", shorts);
		SaveState restored = jsonRoundTrip(ss);
		assertArrayEquals(shorts, restored.getShorts("foo", null));
	}

	@Test
	public void testJsonIntArrayRoundTrip() {
		int[] ints = new int[] { 1, 2, 3, 4, 5 };
		ss.putInts("foo", ints);
		SaveState restored = jsonRoundTrip(ss);
		assertArrayEquals(ints, restored.getInts("foo", null));
	}

	@Test
	public void testJsonLongArrayRoundTrip() {
		long[] longs = new long[] { 1, 2, 3, 4, 5 };
		ss.putLongs("foo", longs);
		SaveState restored = jsonRoundTrip(ss);
		assertArrayEquals(longs, restored.getLongs("foo", null));
	}

	@Test
	public void testJsonFloatArrayRoundTrip() {
		float[] floats = new float[] { 1.1f, 2.2f, 3.3f, 4.4f, 5.5f };
		ss.putFloats("foo", floats);
		SaveState restored = jsonRoundTrip(ss);
		assertArrayEquals(floats, restored.getFloats("foo", null), .1f);
	}

	@Test
	public void testJsonDoubleArrayRoundTrip() {
		double[] doubles = new double[] { 1.1, 2.2, 3.3, 4.4, 5.5 };
		ss.putDoubles("foo", doubles);
		SaveState restored = jsonRoundTrip(ss);
		assertArrayEquals(doubles, restored.getDoubles("foo", null), .1);
	}

	@Test
	public void testJsonBooleanArrayRoundTrip() {
		boolean[] booleans = new boolean[] { true, false, true, true, false };
		ss.putBooleans("foo", booleans);
		SaveState restored = jsonRoundTrip(ss);
		assertArrayEquals(booleans, restored.getBooleans("foo", null));
	}

	@Test
	public void testJsonEnumRoundTrip() {
		ss.putEnum("foo", AddressType.FUNCTION);
		SaveState restored = jsonRoundTrip(ss);
		assertEquals(AddressType.FUNCTION, restored.getEnum("foo", null));
	}

	@Test
	public void testJsonXmlRoundTrip() {
		Element element = new Element("ABC");
		element.setAttribute("AAA", "aaa");
		element.setAttribute("BBB", "bbb");
		element.setAttribute("CCC", "ccc");
		ss.putXmlElement("Foo", element);
		SaveState restored = jsonRoundTrip(ss);
		Element restoredElement = restored.getXmlElement("Foo");
		assertEquals("aaa", restoredElement.getAttributeValue("AAA"));
		assertEquals("bbb", restoredElement.getAttributeValue("BBB"));
		assertEquals("ccc", restoredElement.getAttributeValue("CCC"));
	}

	private SaveState jsonRoundTrip(SaveState saveState) {
		JsonObject saveToJason = saveState.saveToJson();
		return new SaveState(saveToJason);
	}

//	private void printJson(SaveState saveState) {
//		JsonObject saveToJson = saveState.saveToJson();
//		Gson gson = new GsonBuilder().setPrettyPrinting().create();
//		System.out.println(gson.toJson(saveToJson));
//	}

	@Test
	public void testJsonFullRountTripThoughFile() throws IOException {
		ss.putString("Name", "Bob");
		ss.putBoolean("Retired", true);
		ss.putInt("Age", 65);
		ss.putEnum("Endian", Endian.BIG);
		int[] ints = new int[] { 90, 95, 82, 93 };
		ss.putInts("grades", ints);

		File file = createTempFile("SaveStateTest", "json");
		ss.saveToJsonFile(file);
		SaveState restoredSaveState = SaveState.readJsonFile(file);

		assertEquals("Bob", restoredSaveState.getString("Name", ""));
		assertEquals(true, restoredSaveState.getBoolean("Retired", false));
		assertEquals(65, restoredSaveState.getInt("Age", 0));
		assertEquals(Endian.BIG, restoredSaveState.getEnum("Endian", Endian.LITTLE));
		assertArrayEquals(ints, restoredSaveState.getInts("grades", null));

	}

}
