/* ###
 * IP: Apache License 2.0
 */
package ghidra.file.formats.android.xml;

import ghidra.util.StringUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.io.*;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

import android.content.res.AXmlResourceParser;
import android.util.TypedValue;

/**
 * NOTE: most of this logic was copied form AndroidXmlFileSystem, which had the following
 * note: "most of this code was hijacked from AXMLPrinter.java class!"
 *
 */
public class AndroidXmlConvertor {

	private static final float[] RADIX_MULTS =
		{ 0.00390625F, 3.051758E-05F, 1.192093E-07F, 4.656613E-10F };

	private static final String[] DIMENSION_UNITS = { "px", "dip", "sp", "pt", "in", "mm", "", "" };

	private static final String[] FRACTION_UNITS = { "%", "%p", "", "", "", "", "", "" };

	public static final byte[] ANDROID_BINARY_XML_MAGIC = { 0x03, 0x00, 0x08, 0x00 };
	public static final int ANDROID_BINARY_XML_MAGIC_LEN = 4;

	public static void convert(InputStream is, PrintWriter out, TaskMonitor monitor)
			throws IOException, CancelledException {

		monitor.setMessage("Converting Android Binary XML to Text...");

		AXmlResourceParser parser = new AXmlResourceParser();
		parser.open(is);

		try {
			int indent = -1;
			int type;
			while ((type = parser.next()) != XmlPullParser.END_DOCUMENT) {
				monitor.checkCanceled();

				StringBuffer buffer = new StringBuffer();
				switch (type) {
					case XmlPullParser.START_DOCUMENT:
						buffer.append("<?xml version=\"1.0\" encoding=\"utf-8\"?>");
						buffer.append("\n");
						break;
					case XmlPullParser.START_TAG: {
						++indent;

						buffer.append(StringUtilities.pad("", '\t', indent));
						buffer.append("<");
						buffer.append(getNamespacePrefix(parser.getPrefix()));
						buffer.append(parser.getName());
						buffer.append("\n");

						int namespaceCountBefore = parser.getNamespaceCount(parser.getDepth() - 1);
						int namespaceCount = parser.getNamespaceCount(parser.getDepth());

						++indent;

						for (int i = namespaceCountBefore; i != namespaceCount; ++i) {
							buffer.append(StringUtilities.pad("", '\t', indent));
							buffer.append("xmlns:");
							buffer.append(parser.getNamespacePrefix(i));
							buffer.append("=");
							buffer.append("\"");
							buffer.append(parser.getNamespaceUri(i));
							buffer.append("\"");
							buffer.append("\n");
						}

						for (int i = 0; i < parser.getAttributeCount(); ++i) {
							buffer.append(StringUtilities.pad("", '\t', indent));
							buffer.append(getNamespacePrefix(parser.getAttributePrefix(i)));
							buffer.append(parser.getAttributeName(i));
							buffer.append("=");
							buffer.append("\"");
							buffer.append(getAttributeValue(parser, i));
							buffer.append("\"");
							buffer.append("\n");
						}

						buffer.append(StringUtilities.pad("", '\t', indent));
						buffer.append(">");
						buffer.append("\n");

						--indent;
					}
						break;
					case XmlPullParser.END_TAG: {
						buffer.append(StringUtilities.pad("", '\t', indent));
						buffer.append("<");
						buffer.append("/");
						buffer.append(getNamespacePrefix(parser.getPrefix()));
						buffer.append(parser.getName());
						buffer.append(">");
						buffer.append("\n");
						--indent;
					}
						break;
					case XmlPullParser.TEXT: {
						buffer.append(StringUtilities.pad("", '\t', indent));
						buffer.append(parser.getText());
						buffer.append("\n");
					}
				}

				out.print(buffer.toString());
			}
			out.println();
		}
		catch (XmlPullParserException | ArrayIndexOutOfBoundsException e) {
			throw new IOException("Failed to read AXML file", e);
		}
		finally {
			parser.close();
		}
	}

	private static String getNamespacePrefix(String prefix) {
		if (prefix == null || prefix.length() == 0) {
			return "";
		}
		return prefix + ":";
	}

	private static String getAttributeValue(AXmlResourceParser parser, int index) {
		int type = parser.getAttributeValueType(index);
		int data = parser.getAttributeValueData(index);

		if (type == TypedValue.TYPE_STRING) {
			return parser.getAttributeValue(index);
		}
		if (type == TypedValue.TYPE_ATTRIBUTE) {
			return String.format("?%s%08X", getPackage(data), data);
		}
		if (type == TypedValue.TYPE_REFERENCE) {
			return String.format("@%s%08X", getPackage(data), data);
		}
		if (type == TypedValue.TYPE_FLOAT) {
			return String.valueOf(Float.intBitsToFloat(data));
		}
		if (type == TypedValue.TYPE_INT_HEX) {
			return String.format("0x%08X", data);
		}
		if (type == TypedValue.TYPE_INT_BOOLEAN) {
			return data == 0 ? "false" : "true";
		}
		if (type == TypedValue.TYPE_DIMENSION) {
			return Float.toString(complexToFloat(data)) +
				DIMENSION_UNITS[data & TypedValue.COMPLEX_UNIT_MASK];
		}
		if (type == TypedValue.TYPE_FRACTION) {
			return Float.toString(complexToFloat(data)) +
				FRACTION_UNITS[data & TypedValue.COMPLEX_UNIT_MASK];
		}
		if (type >= TypedValue.TYPE_FIRST_COLOR_INT && type <= TypedValue.TYPE_LAST_COLOR_INT) {
			return String.format("#%08X", data);
		}
		if (type >= TypedValue.TYPE_FIRST_INT && type <= TypedValue.TYPE_LAST_INT) {
			return String.valueOf(data);
		}
		return String.format("<0x%X, type 0x%02X>", data, type);
	}

	private static String getPackage(int id) {
		if (id >>> 24 == 1) {
			return "android:";
		}
		return "";
	}

	private static float complexToFloat(int complex) {
		return (complex & 0xffffff00) * RADIX_MULTS[complex >> 4 & 3];
	}

}
