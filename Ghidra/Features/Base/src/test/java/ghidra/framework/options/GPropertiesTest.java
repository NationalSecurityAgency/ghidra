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
import generic.theme.GThemeDefaults.Colors.Palette;
import ghidra.app.plugin.core.overview.addresstype.AddressType;
import ghidra.program.model.lang.Endian;
import ghidra.util.xml.GenericXMLOutputter;
import ghidra.util.xml.XmlUtilities;

public class GPropertiesTest extends AbstractGenericTest {

	private GProperties properties;

	@Before
	public void setUp() {
		properties = new GProperties("foo");
	}

	@Test
	public void testString() throws Exception {
		properties.putString("TEST", null);
		String s = properties.getString("TEST", "FRED");
		assertNull(s);

		String validKey = "TEST2";
		properties.putString(validKey, "Value");
		s = properties.getString(validKey, null);
		assertNotNull(s);

		GProperties restoredState = saveAndRestoreToXml();

		String value = restoredState.getString(validKey, null);
		assertNotNull(value);
	}

	@Test
	public void testColor() throws Exception {
		properties.putColor("TEST", Palette.RED);
		Color c = properties.getColor("TEST", null);
		assertEquals(Palette.RED.getRGB(), c.getRGB());

		GProperties restoredState = saveAndRestoreToXml();

		// make sure our value is inside
		c = restoredState.getColor("TEST", null);
		assertEquals(Palette.RED.getRGB(), c.getRGB());
	}

	@Test
	public void testDate() throws Exception {
		Date date = GProperties.DATE_FORMAT.parse("2020-12-22T14:20:24-0500");
		properties.putDate("TEST", date);
		Date d = properties.getDate("TEST", null);
		assertEquals(date, d);

		GProperties restoredState = saveAndRestoreToXml();

		// make sure our value is inside
		d = restoredState.getDate("TEST", null);
		assertEquals(date, d);
	}

	@Test
	public void testFile() throws Exception {
		File file = createTempFile("myFile", "txt");
		file.deleteOnExit();
		properties.putFile("TEST", file);
		File f = properties.getFile("TEST", null);
		assertEquals(file, f);

		GProperties restoredState = saveAndRestoreToXml();

		// make sure our value is inside
		f = restoredState.getFile("TEST", null);
		assertEquals(file, f);
	}

	@Test
	public void testKeyStroke() throws Exception {
		KeyStroke keyStroke = KeyStroke.getKeyStroke("ctrl X");
		assertNotNull(keyStroke);

		properties.putKeyStroke("TEST", keyStroke);
		KeyStroke k = properties.getKeyStroke("TEST", null);
		assertEquals(keyStroke, k);

		GProperties restoredState = saveAndRestoreToXml();

		// make sure our value is inside
		k = restoredState.getKeyStroke("TEST", null);
		assertEquals(keyStroke, k);
	}

	@Test
	public void testFont() throws Exception {
		Font font = Font.decode("Dialog-BOLD-12");
		properties.putFont("TEST", font);
		Font f = properties.getFont("TEST", null);
		assertEquals(font, f);

		GProperties restoredState = saveAndRestoreToXml();

		// make sure our value is inside
		f = restoredState.getFont("TEST", null);
		assertEquals(font, f);
	}

	@Test
	public void testSubGProperties() throws Exception {
		GProperties subState = new GProperties("sub");
		subState.putInt("a", 5);
		subState.putString("foo", "bar");

		properties.putGProperties("TEST", subState);
		properties.putString("xxx", "zzzz");
		GProperties restoredState = saveAndRestoreToXml();

		// make sure our value is inside
		assertEquals("zzzz", restoredState.getString("xxx", null));
		GProperties restoredSub = restoredState.getGProperties("TEST");
		assertEquals(2, restoredSub.getNames().length);
		assertEquals(5, restoredSub.getInt("a", 0));
		assertEquals("bar", restoredSub.getString("foo", ""));
	}

	private GProperties saveAndRestoreToXml() throws Exception {
		// persist the state
		File saveFileTemp = createTempFile("xmlTest");
		Element element = properties.saveToXml();
		saveElement(element, saveFileTemp);

		// read in the state
		InputStream is = new FileInputStream(saveFileTemp);
		SAXBuilder sax = XmlUtilities.createSecureSAXBuilder(false, false);
		Element root = sax.build(is).getRootElement();
		GProperties loadedState = new GProperties(root);
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
		String[] after = new String[] { "Dennis", "Bill", "Brian", "Mike", "Ellen", "Steve" };

		properties.putStrings("ARRAY", array1);
		String[] array2 = properties.getStrings("ARRAY", null);

		assertArrayEquals(array1, array2);

		GProperties restoredState = saveAndRestoreToXml();

		assertArrayEquals(after, restoredState.getStrings("ARRAY", null));
	}

	@Test
	public void testByte() throws Exception {
		properties.putByte("FOURTYTWO", (byte) 42);
		assertTrue(properties.hasValue("FOURTYTWO"));
		assertEquals((byte) 42, properties.getByte("FOURTYTWO", (byte) 0));
		assertTrue(!properties.hasValue("XXX"));
		assertEquals((byte) 5, properties.getByte("XXX", (byte) 5));

		GProperties restoredState = saveAndRestoreToXml();
		assertEquals((byte) 42, restoredState.getByte(("FOURTYTWO"), (byte) 0));
	}

	@Test
	public void testByteArray() throws Exception {
		byte[] array1 = new byte[] { (byte) 0, (byte) 5, (byte) 9, (byte) 42, (byte) 77 };
		properties.putBytes("ARRAY", array1);
		byte[] array2 = properties.getBytes("ARRAY", null);
		assertArrayEquals(array1, array2);

		GProperties restoredState = saveAndRestoreToXml();
		assertArrayEquals(array1, restoredState.getBytes("ARRAY", null));

	}

	@Test
	public void testShort() throws Exception {
		properties.putShort("FOURTYTWO", (short) 42);
		assertTrue(properties.hasValue("FOURTYTWO"));
		assertEquals((short) 42, properties.getShort("FOURTYTWO", (short) 0));
		assertTrue(!properties.hasValue("XXX"));
		assertEquals((short) 5, properties.getShort("XXX", (short) 5));

		GProperties restoredState = saveAndRestoreToXml();
		assertEquals((short) 42, restoredState.getShort(("FOURTYTWO"), (short) 0));
	}

	@Test
	public void testInt() throws Exception {
		properties.putInt("FOURTYTWO", 42);
		assertTrue(properties.hasValue("FOURTYTWO"));
		assertEquals(42, properties.getInt("FOURTYTWO", 0));
		assertTrue(!properties.hasValue("XXX"));
		assertEquals(5, properties.getInt("XXX", 5));

		GProperties restoredState = saveAndRestoreToXml();
		assertEquals(42, restoredState.getInt(("FOURTYTWO"), 0));
	}

	@Test
	public void testIntArray() throws Exception {
		int[] array1 = new int[] { 0, 5, 9, 42, 77 };
		properties.putInts("ARRAY", array1);
		int[] array2 = properties.getInts("ARRAY", null);
		Arrays.equals(array1, array2);

		GProperties restoredState = saveAndRestoreToXml();

		// make sure our value is inside
		int[] restoredArray = restoredState.getInts("ARRAY", null);
		Arrays.equals(array1, restoredArray);
	}

	@Test
	public void testLong() throws Exception {
		properties.putLong("FOURTYTWO", 42);
		assertTrue(properties.hasValue("FOURTYTWO"));
		assertEquals(42, properties.getLong("FOURTYTWO", 0));
		assertTrue(!properties.hasValue("XXX"));
		assertEquals(5, properties.getLong("XXX", 5));

		GProperties restoredState = saveAndRestoreToXml();
		assertEquals(42L, restoredState.getLong(("FOURTYTWO"), 0));
	}

	@Test
	public void testFloat() throws Exception {
		properties.putFloat("PI", (float) 3.14159);
		assertTrue(properties.hasValue("PI"));
		assertEquals((float) 3.14159, properties.getFloat("PI", (float) 0.0), (float) 0.01);
		assertTrue(!properties.hasValue("XXX"));
		assertEquals(5, properties.getFloat("XXX", 5), (float) 0.01);

		GProperties restoredState = saveAndRestoreToXml();
		assertEquals(3.14159, restoredState.getFloat(("PI"), 0), 0.001f);
	}

	@Test
	public void testDouble() throws Exception {
		properties.putDouble("PI", 3.14159);
		assertTrue(properties.hasValue("PI"));
		assertEquals(3.14159, properties.getDouble("PI", 0.0), 0.01);
		assertTrue(!properties.hasValue("XXX"));
		assertEquals(5, properties.getDouble("XXX", 5), 0.01);

		GProperties restoredState = saveAndRestoreToXml();
		assertEquals(3.14159, restoredState.getDouble(("PI"), 0), 0.000001);
	}

	@Test
	public void testSome() {
		properties.putDouble("PI", 3.14159);
		properties.putByte("BYTE", (byte) 0xEE);
		properties.putLong("LONG", 65536);
		properties.putString("STRING", "See Jane Run");
		properties.putBoolean("BOOL_A", false);
		properties.putBoolean("BOOL_B", true);

		assertEquals(3.1459, properties.getDouble("PI", 0.0), 0.01);
		assertEquals("See Jane Run", properties.getString("STRING", "BOB"));
		assertEquals(true, properties.getBoolean("BOOL_B", false));
		assertEquals((byte) 0xEE, properties.getByte("BYTE", (byte) 0));
		assertEquals(false, properties.getBoolean("BOOL_A", true));
	}

	@Test
	public void testXML() {
		Element elem1 = new Element("ELEM_1");
		Element elem2 = new Element("ELEM_2");
		elem1.setAttribute("NAME", "VALUE");
		elem1.addContent(elem2);
		properties.putXmlElement("XML", elem1);
		Element elem3 = properties.getXmlElement("XML");
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
		properties.putString(greaterThanLessThanKey, stringWithGreaterThanAndLessThan);

		String stringWithLargeHexDigit =
			"The following is a large hex digit: \u0128, \u0132, \307 and \253 \uD835\uDCC8 " +
				"with some trailing text &#xFF;";
		String hexDigitKey = "HEX_DIGIT_KEY";
		properties.putString(hexDigitKey, stringWithLargeHexDigit);

		String stringWithAmpersandApostropheAndQuote = "That is the Jones' \"love & happiness\".";
		String ampersandApostropheQuoteKey = "AMP_APOS_KEY";
		properties.putString(ampersandApostropheQuoteKey, stringWithAmpersandApostropheAndQuote);

		// persist the state
		File saveFileTemp = null;
		Element root = null;
		try {
			saveFileTemp = createTempFile("xmlTest");
			Element element = properties.saveToXml();
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
		GProperties loadedState = new GProperties(root);
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
		assertTrue(properties.isEmpty());
		properties.putBoolean("BOOL", false);
		assertTrue(!properties.isEmpty());
	}

	@Test
	public void testFileInputOutput() throws IOException {
		properties.putBoolean("B1", true);
		properties.putInt("I1", 7);
		properties.putString("S1", "Hey There");
		File file = createTempFile("GPropertiesTest", "xml");
		properties.saveToXmlFile(file);

		GProperties ss2 = new XmlProperties(file);
		assertEquals(true, ss2.getBoolean("B1", false));
		assertEquals(7, ss2.getInt("I1", 1));
		assertEquals("Hey There", ss2.getString("S1", ""));
		file.delete();
	}

	@Test
	public void testJsonStringRoundTrip() {
		properties.putString("foo", "Hey");
		GProperties restored = jsonRoundTrip(properties);
		assertEquals("Hey", restored.getString("foo", "there"));
	}

	@Test
	public void testJsonColorRoundTrip() {
		properties.putColor("foo", Palette.BLUE);
		GProperties restored = jsonRoundTrip(properties);
		assertEquals(Palette.BLUE.getRGB(), restored.getColor("foo", null).getRGB());
	}

	@Test
	public void testJsonDatRoundTrip() throws Exception {
		Date date = GProperties.DATE_FORMAT.parse("2020-12-22T14:20:24-0500");
		properties.putDate("foo", date);
		GProperties restored = jsonRoundTrip(properties);
		assertEquals(date, restored.getDate("foo", null));
	}

	@Test
	public void testJsonFileRoundTrip() throws IOException {
		File file = createTempFile("myFile", "txt");
		properties.putFile("foo", file);
		GProperties restored = jsonRoundTrip(properties);
		assertEquals(file, restored.getFile("foo", null));
		file.deleteOnExit();
	}

	@Test
	public void testJsonKeyStrokRoundTrip() {
		KeyStroke keyStroke = KeyStroke.getKeyStroke("ctrl X");
		assertNotNull(keyStroke);

		properties.putKeyStroke("foo", keyStroke);
		GProperties restored = jsonRoundTrip(properties);
		assertEquals(keyStroke, restored.getKeyStroke("foo", null));
	}

	@Test
	public void testJsonFontRoundTrip() {
		Font font = Font.decode("Dialog-BOLD-12");
		properties.putFont("foo", font);
		GProperties restored = jsonRoundTrip(properties);
		assertEquals(font, restored.getFont("foo", null));
	}

	@Test
	public void testJsonSubGPropertiesRoundTrip() {
		GProperties subState = new GProperties("sub");
		subState.putInt("a", 5);
		subState.putString("foo", "bar");
		properties.putGProperties("foo", subState);
		properties.putString("bar", "xyz");

		GProperties restored = jsonRoundTrip(properties);
		assertEquals("xyz", restored.getString("bar", null));
		GProperties restoredSub = restored.getGProperties("foo");
		assertEquals(2, restoredSub.getNames().length);
		assertEquals(5, restoredSub.getInt("a", 0));
		assertEquals("bar", restoredSub.getString("foo", ""));
	}

	@Test
	public void testJsonByteRoundTrip() {
		properties.putByte("foo", (byte) 42);
		GProperties restored = jsonRoundTrip(properties);
		assertEquals((byte) 42, restored.getByte("foo", (byte) 0));
	}

	@Test
	public void testJsonShortRoundTrip() {
		properties.putShort("foo", (short) 42);
		GProperties restored = jsonRoundTrip(properties);
		assertEquals((short) 42, restored.getShort("foo", (short) 0));
	}

	@Test
	public void testJsonIntRoundTrip() {
		properties.putInt("foo", 123456789);
		GProperties restored = jsonRoundTrip(properties);
		assertEquals(123456789, restored.getInt("foo", 0));
	}

	@Test
	public void testJsonLongRoundTrip() {
		properties.putLong("foo", 12345678901234L);
		GProperties restored = jsonRoundTrip(properties);
		assertEquals(12345678901234L, restored.getLong("foo", 0));
	}

	@Test
	public void testJsonFloatRoundTrip() {
		properties.putFloat("foo", 12.123f);
		GProperties restored = jsonRoundTrip(properties);
		assertEquals(12.123f, restored.getFloat("foo", 0), 0.0001f);
	}

	@Test
	public void testJsonDoubleRoundTrip() {
		properties.putDouble("foo", 12.123456);
		GProperties restored = jsonRoundTrip(properties);
		assertEquals(12.123456, restored.getDouble("foo", 0), 0.00000001);
	}

	@Test
	public void testJsonBooleanRoundTrip() {
		properties.putBoolean("foo", true);
		GProperties restored = jsonRoundTrip(properties);
		assertEquals(true, restored.getBoolean("foo", false));
	}

	@Test
	public void testJsonStringArrayRoundTrip() {
		String[] strings = new String[] { "aaa", "bbb", null, "ccc" };
		String[] after = new String[] { "aaa", "bbb", "ccc" };
		properties.putStrings("foo", strings);
		GProperties restored = jsonRoundTrip(properties);
		assertArrayEquals(after, restored.getStrings("foo", null));
	}

	@Test
	public void testJsonByteArrayRoundTrip() {
		byte[] bytes = new byte[] { (byte) 1, (byte) 2, (byte) 3 };
		properties.putBytes("foo", bytes);
		GProperties restored = jsonRoundTrip(properties);
		assertArrayEquals(bytes, restored.getBytes("foo", null));
	}

	@Test
	public void testJsonShortArrayRoundTrip() {
		short[] shorts = new short[] { (short) 1, (short) 2, (short) 3 };
		properties.putShorts("foo", shorts);
		GProperties restored = jsonRoundTrip(properties);
		assertArrayEquals(shorts, restored.getShorts("foo", null));
	}

	@Test
	public void testJsonIntArrayRoundTrip() {
		int[] ints = new int[] { 1, 2, 3, 4, 5 };
		properties.putInts("foo", ints);
		GProperties restored = jsonRoundTrip(properties);
		assertArrayEquals(ints, restored.getInts("foo", null));
	}

	@Test
	public void testJsonLongArrayRoundTrip() {
		long[] longs = new long[] { 1, 2, 3, 4, 5 };
		properties.putLongs("foo", longs);
		GProperties restored = jsonRoundTrip(properties);
		assertArrayEquals(longs, restored.getLongs("foo", null));
	}

	@Test
	public void testJsonFloatArrayRoundTrip() {
		float[] floats = new float[] { 1.1f, 2.2f, 3.3f, 4.4f, 5.5f };
		properties.putFloats("foo", floats);
		GProperties restored = jsonRoundTrip(properties);
		assertArrayEquals(floats, restored.getFloats("foo", null), .1f);
	}

	@Test
	public void testJsonDoubleArrayRoundTrip() {
		double[] doubles = new double[] { 1.1, 2.2, 3.3, 4.4, 5.5 };
		properties.putDoubles("foo", doubles);
		GProperties restored = jsonRoundTrip(properties);
		assertArrayEquals(doubles, restored.getDoubles("foo", null), .1);
	}

	@Test
	public void testJsonBooleanArrayRoundTrip() {
		boolean[] booleans = new boolean[] { true, false, true, true, false };
		properties.putBooleans("foo", booleans);
		GProperties restored = jsonRoundTrip(properties);
		assertArrayEquals(booleans, restored.getBooleans("foo", null));
	}

	@Test
	public void testJsonEnumRoundTrip() {
		properties.putEnum("foo", AddressType.FUNCTION);
		GProperties restored = jsonRoundTrip(properties);
		assertEquals(AddressType.FUNCTION, restored.getEnum("foo", null));
	}

	@Test
	public void testJsonXmlRoundTrip() {
		Element element = new Element("ABC");
		element.setAttribute("AAA", "aaa");
		element.setAttribute("BBB", "bbb");
		element.setAttribute("CCC", "ccc");
		properties.putXmlElement("Foo", element);
		GProperties restored = jsonRoundTrip(properties);
		Element restoredElement = restored.getXmlElement("Foo");
		assertEquals("aaa", restoredElement.getAttributeValue("AAA"));
		assertEquals("bbb", restoredElement.getAttributeValue("BBB"));
		assertEquals("ccc", restoredElement.getAttributeValue("CCC"));
	}

	private GProperties jsonRoundTrip(GProperties GProperties) {
		JsonObject saveToJason = GProperties.saveToJson();
		return new GProperties(saveToJason);
	}

	@Test
	public void testJsonFullRountTripThoughFile() throws IOException {
		properties.putString("Name", "Bob");
		properties.putBoolean("Retired", true);
		properties.putInt("Age", 65);
		properties.putEnum("Endian", Endian.BIG);
		int[] ints = new int[] { 90, 95, 82, 93 };
		properties.putInts("grades", ints);

		File file = createTempFile("GPropertiesTest", "json");
		properties.saveToJsonFile(file);
		GProperties restoredGProperties = new JSonProperties(file);

		assertEquals("Bob", restoredGProperties.getString("Name", ""));
		assertEquals(true, restoredGProperties.getBoolean("Retired", false));
		assertEquals(65, restoredGProperties.getInt("Age", 0));
		assertEquals(Endian.BIG, restoredGProperties.getEnum("Endian", Endian.LITTLE));
		assertArrayEquals(ints, restoredGProperties.getInts("grades", null));

	}

}
