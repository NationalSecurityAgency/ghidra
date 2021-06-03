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

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.XMLConstants;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParserFactory;

import org.jdom.*;
import org.jdom.input.SAXBuilder;
import org.jdom.output.Format;
import org.jdom.output.XMLOutputter;
import org.xml.sax.*;

import generic.jar.ResourceFile;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;
import util.CollectionUtils;

/**
 * A set of utility methods for working with XML.
 *
 */
public class XmlUtilities {

	private static final String LESS_THAN = "&lt;";
	private static final String GREATER_THAN = "&gt;";
	private static final String APOSTROPHE = "&apos;";
	private static final String QUOTE = "&quot;";
	private static final String AMPERSAND = "&amp;";

	private static final Pattern HEX_DIGIT_PATTERN = Pattern.compile("[&][#][x]([\\da-fA-F]+)[;]");

	public static final String FEATURE_DISALLOW_DTD =
		"http://apache.org/xml/features/disallow-doctype-decl";
	public static final String FEATURE_EXTERNAL_GENERAL_ENTITIES =
		"http://xml.org/sax/features/external-general-entities";
	public static final String FEATURE_EXTERNAL_PARAMETER_ENTITIES =
		"http://xml.org/sax/features/external-parameter-entities";

	/**
	 * Simple {@link ErrorHandler SAX error handler} that re-throws any
	 * {@link SAXParseException}s as a {@link SAXException}.
	 *
	 */
	public static class ThrowingErrorHandler implements ErrorHandler {
		@Override
		public void error(SAXParseException exception) throws SAXException {
			throw new SAXException(exception);
		}

		@Override
		public void fatalError(SAXParseException exception) throws SAXException {
			throw new SAXException(exception);
		}

		@Override
		public void warning(SAXParseException exception) throws SAXException {
			throw new SAXException(exception);
		}
	}

	/**
	 * Converts any special or reserved characters in the specified XML string
	 * into the equivalent Unicode encoding.
	 * 
	 * @param xml the XML string
	 * @return the encoded XML string
	 */
	public static String escapeElementEntities(String xml) {
		StringBuffer buffer = new StringBuffer();
		for (int i = 0; i < xml.length(); i++) {
			char next = xml.charAt(i);
			if ((next < ' ') && (next != 0x09) && (next != 0x0A) && (next != 0x0D)) {
				continue;
			}
			if (next >= 0x7F) {
				buffer.append("&#x");
				buffer.append(Integer.toString(next, 16).toUpperCase());
				buffer.append(";");
				continue;
			}
			switch (next) {
				case '<':
					buffer.append(LESS_THAN);
					break;
				case '>':
					buffer.append(GREATER_THAN);
					break;
				case '\'':
					buffer.append(APOSTROPHE);
					break;
				case '"':
					buffer.append(QUOTE);
					break;
				case '&':
					buffer.append(AMPERSAND);
					break;
// Why was 7F deleted
//				case 0x7F:
//					break;
				default:
					buffer.append(next);
					break;
			}
		}
		return buffer.toString();
	}

	/**
	 * Converts any escaped character entities into their unescaped character
	 * equivalents. This method is designed to be compatible with the output of
	 * {@link #escapeElementEntities(String)}.
	 *
	 * @param escapedXMLString The string with escaped data
	 * @return the unescaped string
	 */
	public static String unEscapeElementEntities(String escapedXMLString) {

		Matcher matcher = HEX_DIGIT_PATTERN.matcher(escapedXMLString);
		StringBuffer buffy = new StringBuffer();
		while (matcher.find()) {
			int intValue = Integer.parseInt(matcher.group(1), 16);
			matcher.appendReplacement(buffy, Character.toString((char) intValue));
		}
		matcher.appendTail(buffy);

		String unescapedStr = buffy.toString();

		unescapedStr = unescapedStr.replaceAll(LESS_THAN, "<");
		unescapedStr = unescapedStr.replaceAll(GREATER_THAN, ">");
		unescapedStr = unescapedStr.replaceAll(APOSTROPHE, "'");
		unescapedStr = unescapedStr.replaceAll(QUOTE, "\"");
		unescapedStr = unescapedStr.replaceAll(AMPERSAND, "&");

		return unescapedStr;
	}

	/**
	 * Converts the specified XML element into a byte array.
	 * 
	 * @param root the root element
	 * @return the byte array translation of the given element
	 */
	public static byte[] xmlToByteArray(Element root) {
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		Document doc = new Document(root);
		XMLOutputter xmlOut = new GenericXMLOutputter();
		try {
			xmlOut.output(doc, os);
			os.close();
			return os.toByteArray();
		}
		catch (IOException e) {
			// can't happen
		}
		return null;
	}

	/**
	 * Converts the specified XML element into a String.
	 * 
	 * @param root the root element
	 * @return String translation of the given element
	 */
	public static String toString(Element root) {
		XMLOutputter outputter = new GenericXMLOutputter();
		return outputter.outputString(root);
	}

	/**
	 * Convert a String into a JDOM {@link Element}.
	 * <p>
	 * 
	 * @param s
	 * @return
	 * @throws JDOMException
	 * @throws IOException
	 */
	public static Element fromString(String s) throws JDOMException, IOException {
		SAXBuilder sax = createSecureSAXBuilder(false, false);

		try (Reader r = new StringReader(s)) {
			Document doc = sax.build(r);
			return doc.getRootElement();
		}
	}

	/**
	 * Writes a JDOM XML {@link Document} to a {@link File}.
	 * <p>
	 * 
	 * @param doc JDOM XML {@link Document} to write.
	 * @param dest {@link File} to write to.
	 * @throws IOException if error when writing file.
	 */
	public static void writeDocToFile(Document doc, File dest) throws IOException {
		XMLOutputter outputter = new XMLOutputter();
		try (FileWriter fw = new FileWriter(dest)) {
			outputter.output(doc, fw);
		}
	}

	/**
	 * Writes a JDOM XML {@link Document} to a {@link File}, with a prettier
	 * format than {@link #writeDocToFile(Document, File)}.
	 * <p>
	 * 
	 * @param doc JDOM XML {@link Document} to write.
	 * @param dest {@link File} to write to.
	 * @throws IOException if error when writing file.
	 */
	public static void writePrettyDocToFile(Document doc, File dest) throws IOException {
		XMLOutputter outputter = new XMLOutputter();
		outputter.setFormat(Format.getPrettyFormat());
		try (FileWriter fw = new FileWriter(dest)) {
			outputter.output(doc, fw);
		}
	}

	/**
	 * Read a File and convert to jdom xml doc.
	 * <p>
	 * 
	 * @param f {@link File} to read
	 * @return JDOM {@link Document}
	 * @throws JDOMException if text in file isn't valid XML
	 * @throws IOException if IO error when reading file.
	 */
	public static Document readDocFromFile(File f) throws JDOMException, IOException {
		SAXBuilder sax = createSecureSAXBuilder(false, false);

		try (Reader r = new FileReader(f)) {
			Document doc = sax.build(r);
			return doc;
		}
	}

	/**
	 * Read a File and convert to jdom xml doc.
	 * <p>
	 * 
	 * @param f {@link ResourceFile} to read
	 * @return JDOM {@link Document}
	 * @throws JDOMException if text in file isn't valid XML
	 * @throws IOException if IO error when reading file.
	 */
	public static Document readDocFromFile(ResourceFile f) throws JDOMException, IOException {
		SAXBuilder sax = createSecureSAXBuilder(false, false);

		try (InputStream is = f.getInputStream()) {
			Reader r = new InputStreamReader(is, StandardCharsets.UTF_8);
			Document doc = sax.build(r);
			return doc;
		}
	}

	/**
	 * Converts the specified byte array into an XML element.
	 * 
	 * @param bytes the XML bytes
	 * @return an XML element
	 */
	public static Element byteArrayToXml(byte[] bytes) {
		ByteArrayInputStream is = new ByteArrayInputStream(bytes);
		SAXBuilder sax = createSecureSAXBuilder(false, false);

		try {
			return sax.build(is).getRootElement();
		}
		catch (Exception e) {
			Msg.error(XmlUtilities.class, "Unexpected Exception: " + e.getMessage(), e);
		}
		return null;
	}

	/**
	 * Parses the overlay name from the specified address string. Returns null
	 * if the address string does appear to represent an overlay.
	 * 
	 * @param addrStr the address string
	 * @return the overlay name or null
	 */
	public static String parseOverlayName(String addrStr) {
		int index = addrStr.indexOf("::");
		if (index > 0) {
			return addrStr.substring(0, index);
		}
		return null;
	}

	/**
	 * Parse the given string as either a hex number (if it starts with 0x) or a
	 * decimal number.
	 * 
	 * @param intStr the string to parse into an integer
	 * @return the parsed integer.
	 * @throws NumberFormatException if the given string does not represent a
	 *             valid integer.
	 */
	public static int parseInt(String intStr) {
		return (int) parseLong(intStr);
	}

	/**
	 * Parses the optional specified string as a decimal number, returning its
	 * integer value.
	 * <p>
	 * 
	 * @param intStr string with integer digits, or empty or null
	 * @param defaultValue value to return if intStr is missing
	 * @return integer value of the intStr
	 * @throws NumberFormatException if intStr could not be parsed or the string
	 *             specifies a value outside the range of a signed 32 bit
	 *             integer.
	 */
	public static int parseInt(String intStr, int defaultValue) throws NumberFormatException {
		return parseOptionalBoundedInt(intStr, defaultValue, Integer.MIN_VALUE, Integer.MAX_VALUE);
	}

	/**
	 * Parses the optional specified string as a decimal number, returning its
	 * integer value, or defaultValue if the string is null.
	 * <p>
	 * 
	 * @param intStr string with integer digits, or null.
	 * @param defaultValue value to return if intStr is null.
	 * @param minValue minimum value allowed (inclusive).
	 * @param maxValue maximum value allowed (inclusive).
	 * @return integer value of the intStr.
	 * @throws NumberFormatException if intStr could not be parsed or is out of
	 *             range.
	 */
	public static int parseOptionalBoundedInt(String intStr, int defaultValue, int minValue,
			int maxValue) throws NumberFormatException {
		if (intStr != null) {
			long tmp = parseLong(intStr);
			if (tmp < minValue || tmp > maxValue) {
				throw new NumberFormatException(
					"Integer value " + tmp + " out of range: [" + minValue + ".." + maxValue + "]");
			}
			return (int) tmp;
		}
		return defaultValue;
	}

	/**
	 * Parses the specified string as a decimal number, returning its integer
	 * value.
	 * <p>
	 * 
	 * @param intStr String with integer digits
	 * @param minValue minimum value allowed (inclusive)
	 * @param maxValue maximum value allowed (inclusive)
	 * @return integer value of the intStr
	 * @throws NumberFormatException if intStr is null or empty or could not be
	 *             parsed or is out of range.
	 */
	public static int parseBoundedInt(String intStr, int minValue, int maxValue)
			throws NumberFormatException {
		if (intStr == null || intStr.isEmpty()) {
			throw new NumberFormatException("Missing value");
		}
		long tmp = parseLong(intStr);
		if (tmp < minValue || tmp > maxValue) {
			throw new NumberFormatException(
				"Integer value " + tmp + " out of range: [" + minValue + ".." + maxValue + "]");
		}
		return (int) tmp;
	}

	/**
	 * Parses the required attribute as a decimal number, returning its integer
	 * value.
	 * <p>
	 * 
	 * @param ele JDom element that contains the attribute
	 * @param attrName the name of the xml attribute to parse
	 * @param minValue minimum value allowed (inclusive)
	 * @param maxValue maximum value allowed (inclusive)
	 * @return integer value of the attribute
	 * @throws NumberFormatException if intStr could not be parsed or is out of
	 *             range.
	 */
	public static int parseBoundedIntAttr(Element ele, String attrName, int minValue, int maxValue)
			throws NumberFormatException {
		try {
			return parseBoundedInt(ele.getAttributeValue(attrName), minValue, maxValue);
		}
		catch (NumberFormatException nfe) {
			throw new NumberFormatException("Attribute '" + attrName + "' bad value: " +
				nfe.getMessage() + " in " + toString(ele));
		}
	}

	/**
	 * Parses an optional attribute as a decimal number, returning its integer
	 * value, or the defaultValue if the attribute is null.
	 * <p>
	 * 
	 * @param ele JDOM element that contains the attribute.
	 * @param attrName the name of the xml attribute to parse.
	 * @param defaultValue the default value to return if attribute is missing.
	 * @param minValue minimum value allowed (inclusive).
	 * @param maxValue maximum value allowed (inclusive).
	 * @return integer value of the attribute.
	 * @throws NumberFormatException if the attribute value could not be parsed
	 *             or is out of range.
	 */
	public static int parseOptionalBoundedIntAttr(Element ele, String attrName, int defaultValue,
			int minValue, int maxValue) throws NumberFormatException {
		String value = ele.getAttributeValue(attrName);
		if (value == null) {
			return defaultValue;
		}
		try {
			return parseBoundedInt(value, minValue, maxValue);
		}
		catch (NumberFormatException nfe) {
			throw new NumberFormatException("Attribute '" + attrName + "' bad value: " +
				nfe.getMessage() + " in " + toString(ele));
		}
	}

	/**
	 * Parse the given string as either a hex number (if it starts with 0x) or a
	 * decimal number.
	 * 
	 * @param longStr the string to parse into an long
	 * @return the parsed long.
	 * @throws NumberFormatException if the given string does not represent a
	 *             valid long.
	 */
	public static long parseLong(String longStr) {
		boolean isNegative = longStr.startsWith("-");
		if (isNegative) {
			longStr = longStr.substring(1);
		}
		int radix = 10;
		if (longStr.startsWith("0x")) {
			longStr = longStr.substring(2);
			radix = 16;
		}
		long val = (radix == 10) ? NumericUtilities.parseLong(longStr)
				: NumericUtilities.parseHexLong(longStr);
		if (isNegative) {
			val *= -1;
		}
		return val;
	}

	/**
	 * Parses the specified string as a decimal number, returning its long
	 * integer value.
	 * <p>
	 * Note, using {@link Long#MIN_VALUE} and/or {@link Long#MAX_VALUE} as lower
	 * and upper bounds is problematic and should be avoided as the range check
	 * will become a NO-OP and always succeed.
	 * <p>
	 * 
	 * @param longStr String with integer digits
	 * @param minValue minimum value allowed (inclusive)
	 * @param maxValue maximum value allowed (inclusive)
	 * @return long integer value of the longStr
	 * @throws NumberFormatException if intStr is null or empty or could not be
	 *             parsed or is out of range.
	 */
	public static long parseBoundedLong(String longStr, long minValue, long maxValue)
			throws NumberFormatException {
		if (longStr == null || longStr.isEmpty()) {
			throw new NumberFormatException("Missing value");
		}
		long tmp = parseLong(longStr);
		if (tmp < minValue || tmp > maxValue) {
			throw new NumberFormatException(
				"Long value " + tmp + " out of range: [" + minValue + ".." + maxValue + "]");
		}
		return tmp;
	}

	/**
	 * Parses the required attribute as a decimal number, returning its long
	 * integer value.
	 * <p>
	 * Note, using {@link Long#MIN_VALUE} and/or {@link Long#MAX_VALUE} as lower
	 * and upper bounds is problematic and should be avoided as the range check
	 * will become a NO-OP and always succeed.
	 * <p>
	 * 
	 * @param ele JDom element that contains the attribute
	 * @param attrName the name of the xml attribute to parse
	 * @param minValue minimum value allowed (inclusive)
	 * @param maxValue maximum value allowed (inclusive)
	 * @return long integer value of the attribute
	 * @throws NumberFormatException if intStr could not be parsed or is out of
	 *             range.
	 */
	public static long parseBoundedLongAttr(Element ele, String attrName, long minValue,
			long maxValue) throws NumberFormatException {
		try {
			return parseBoundedLong(ele.getAttributeValue(attrName), minValue, maxValue);
		}
		catch (NumberFormatException nfe) {
			throw new NumberFormatException("Attribute '" + attrName + "' bad value: " +
				nfe.getMessage() + " in " + toString(ele));
		}
	}

	/**
	 * Parses the required attribute as a decimal number, returning its long
	 * integer value.
	 * <p>
	 * Note, using {@link Long#MIN_VALUE} and/or {@link Long#MAX_VALUE} as lower
	 * and upper bounds is problematic and should be avoided as the range check
	 * will become a NO-OP and always succeed.
	 * <p>
	 * 
	 * @param ele JDom element that contains the attribute.
	 * @param attrName the name of the xml attribute to parse.
	 * @param defaultValue the default value to return if attribute is missing.
	 * @param minValue minimum value allowed (inclusive).
	 * @param maxValue maximum value allowed (inclusive).
	 * @return long integer value of the attribute.
	 * @throws NumberFormatException if intStr could not be parsed or is out of
	 *             range.
	 */
	public static long parseOptionalBoundedLongAttr(Element ele, String attrName, long defaultValue,
			long minValue, long maxValue) throws NumberFormatException {

		String value = ele.getAttributeValue(attrName);
		if (value == null || value.isEmpty()) {
			return defaultValue;
		}
		try {
			return parseBoundedLong(value, minValue, maxValue);
		}
		catch (NumberFormatException nfe) {
			throw new NumberFormatException("Attribute '" + attrName + "' bad value: " +
				nfe.getMessage() + " in " + toString(ele));
		}
	}

	/**
	 * Parses the given string into a boolean value. Acceptable inputs are
	 * y,n,true,fase. A null input string will return false (useful if optional
	 * boolean attribute is false by default)
	 * 
	 * @param boolStr the string to parse into a boolean value
	 * @return the boolean result.
	 * @throws XmlAttributeException if the string in not one of y,n,true,false
	 *             or null.
	 */
	public static boolean parseBoolean(String boolStr) {
		if (boolStr == null) {
			return false;
		}
		if (!boolStr.equalsIgnoreCase("y") && !boolStr.equalsIgnoreCase("n") &&
			!boolStr.equalsIgnoreCase("true") && !boolStr.equalsIgnoreCase("false")) {
			throw new XmlAttributeException(boolStr + " is not a valid boolean (y|n)");
		}
		return "y".equalsIgnoreCase(boolStr) || "true".equalsIgnoreCase(boolStr);
	}

	/**
	 * Parses the optional attribute as a boolean value, returning its value or
	 * the specified defaultValue if missing.
	 *
	 * @param ele JDom element that contains the attribute
	 * @param attrName the name of the xml attribute to parse
	 * @param defaultValue boolean value to return if the attribute is not
	 *            defined
	 * @return boolean equiv of the attribute string value ("y", "true"/"n",
	 *         "false")
	 * @throws IOException if attribute value is not valid boolean string
	 */
	public static boolean parseOptionalBooleanAttr(Element ele, String attrName,
			boolean defaultValue) throws IOException {
		String value = ele.getAttributeValue(attrName);
		try {
			return (value != null) ? parseBoolean(value) : defaultValue;
		}
		catch (XmlAttributeException e) {
			throw new IOException("Attribute '" + attrName + "' bad boolean value: '" + value +
				"' in " + toString(ele));
		}
	}

	/**
	 * Throws an {@link IOException} with a verbose explanation if the requested
	 * attribute is not present or is empty.
	 * <p>
	 * 
	 * @param ele JDOM {@link Element} that contains the attribute
	 * @param attrName the attribute name
	 * @return String value of the attribute (never null or empty)
	 * @throws IOException if attribute is missing or empty
	 */
	public static String requireStringAttr(Element ele, String attrName) throws IOException {
		String value = ele.getAttributeValue(attrName);
		if (value == null || value.isEmpty()) {
			throw new IOException(
				"Missing required attribute: '" + attrName + "' in " + toString(ele));
		}
		return value;
	}

	/**
	 * Sets a string attribute on the specified element.
	 * 
	 * @param ele JDom element
	 * @param attrName name of attribute
	 * @param attrValue value of attribute, null ok
	 */
	public static void setStringAttr(Element ele, String attrName, String attrValue) {
		if (attrValue != null) {
			ele.setAttribute(attrName, attrValue);
		}
	}

	/**
	 * Sets an integer attribute on the specified element.
	 * 
	 * @param ele JDom element
	 * @param attrName name of attribute
	 * @param attrValue value of attribute
	 */
	public static void setIntAttr(Element ele, String attrName, int attrValue) {
		ele.setAttribute(attrName, Integer.toString(attrValue));
	}

	/**
	 * Type-safe way of getting a list of {@link Element}s from JDom.
	 * 
	 * @param ele the parent element
	 * @param childName the name of the children elements to return
	 * @return {@literal List<Element>} of elements
	 */
	public static List<Element> getChildren(Element ele, String childName) {
		return CollectionUtils.asList(ele.getChildren(childName), Element.class);
	}

	/**
	 * Tests a string for characters that would cause a problem if added to an
	 * xml attribute or element.
	 * 
	 * @param s a string
	 * @return boolean true if the string will cause a problem if added to an
	 *         xml attribute or element.
	 */
	public static boolean hasInvalidXMLCharacters(String s) {
		return !s.codePoints().allMatch(Verifier::isXMLCharacter);
	}

	/**
	 * Create a {@link SAXBuilder} that is not susceptible to XXE.
	 * 
	 * This configures the builder to ignore external entities.
	 * 
	 * @param validate indicates whether validation should occur
	 * @param needsDTD false to disable doctype declarations altogether
	 * @return the configured builder
	 */
	public static SAXBuilder createSecureSAXBuilder(boolean validate, boolean needsDTD) {
		final String IMPLNAME = "com.sun.org.apache.xerces.internal.parsers.SAXParser";
		SAXBuilder sax = new SAXBuilder(IMPLNAME, validate);
		sax.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
		// XML Program Import uses DTD
		if (!needsDTD) {
			sax.setFeature(FEATURE_DISALLOW_DTD, true);
		}
		sax.setFeature(FEATURE_EXTERNAL_GENERAL_ENTITIES, false);
		sax.setFeature(FEATURE_EXTERNAL_PARAMETER_ENTITIES, false);
		return sax;
	}

	/**
	 * Create a {@link SAXParserFactory} that is not susceptible to XXE.
	 * 
	 * This configures the factory to ignore external entities.
	 * 
	 * @param needsDTD false to disable doctype declarations altogether
	 * @return the configured factory
	 */
	public static SAXParserFactory createSecureSAXParserFactory(boolean needsDTD) {
		SAXParserFactory factory = SAXParserFactory.newInstance();
		try {
			factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
			// XML Program Import uses DTD
			if (!needsDTD) {
				factory.setFeature(FEATURE_DISALLOW_DTD, true);
			}
			factory.setFeature(FEATURE_EXTERNAL_GENERAL_ENTITIES, false);
			factory.setFeature(FEATURE_EXTERNAL_PARAMETER_ENTITIES, false);
		}
		catch (SAXNotRecognizedException | SAXNotSupportedException
				| ParserConfigurationException e) {
			throw new RuntimeException("Cannot set XML parsing feature for secure processing: ", e);
		}
		return factory;
	}
}
