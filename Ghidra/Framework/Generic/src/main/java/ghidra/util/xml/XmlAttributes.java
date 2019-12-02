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

import ghidra.util.Conv;

import java.math.BigInteger;

/**
 * A container class for creating XML attribute strings.
 * For example, given the following code:
 * <pre>
 * XmlAttributes attrs = new XmlAttributes();
 * attrs.add("FIVE", 32, true);
 * attrs.add("BAR", "foo");
 * attrs.add("PI", 3.14159);
 * </pre><br>
 * The output would be: <code>FIVE="0x20" BAR="foo" PI="3.14159".</code>
 * 
 */
public class XmlAttributes {
	private StringBuffer buffer;

	/**
	 * Constructs a new empty XML attributes.
	 */
	public XmlAttributes() {
		buffer = new StringBuffer();
	}

	/**
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		String s = buffer.toString();
		buffer.setLength(0);
		return s;
	}

	/**
	 * Add a new string attribute.
	 * @param name  the name of the new attribute
	 * @param value the string value
	 */
	public void addAttribute(String name, String value) {
		if (value == null) {
			value = "";
		}
		buffer.append(" " + name + "=\"" + XmlUtilities.escapeElementEntities(value) + "\"");
	}

	/**
	 * Add a new boolean attribute.
	 * @param name  the name of the new attribute
	 * @param value the boolean value
	 */
	public void addAttribute(String name, boolean value) {
		addAttribute(name, value ? "y" : "n");
	}

	/**
	 * Add a new float attribute.
	 * @param name  the name of the new attribute
	 * @param value the float value
	 */
	public void addAttribute(String name, float value) {
		addAttribute(name, Float.toString(value));
	}

	/**
	 * Add a new double attribute.
	 * @param name  the name of the new attribute
	 * @param value the double value
	 */
	public void addAttribute(String name, double value) {
		addAttribute(name, Double.toString(value));
	}

	/**
	 * Add a new byte attribute as decimal.
	 * @param name  the name of the new attribute
	 * @param value the byte value
	 */
	public void addAttribute(String name, byte value) {
		addAttribute(name, value, false);
	}

	/**
	 * Add a new byte attribute.
	 * @param name  the name of the new attribute
	 * @param value the byte value
	 * @param hex   true if value should be written in hex
	 */
	public void addAttribute(String name, byte value, boolean hex) {
		addAttribute(name, hex ? Conv.byteToInt(value) : (int) value, hex);
	}

	/**
	 * Add a new short attribute as decimal.
	 * @param name  the name of the new attribute
	 * @param value the short value
	 */
	public void addAttribute(String name, short value) {
		addAttribute(name, value, false);
	}

	/**
	 * Add a new short attribute.
	 * @param name  the name of the new attribute
	 * @param value the short value
	 * @param hex   true if value should be written in hex
	 */
	public void addAttribute(String name, short value, boolean hex) {
		addAttribute(name, hex ? Conv.shortToInt(value) : (int) value, hex);
	}

	/**
	 * Add a new int attribute as decimal.
	 * @param name  the name of the new attribute
	 * @param value the int value
	 */
	public void addAttribute(String name, int value) {
		addAttribute(name, value, false);
	}

	/**
	 * Add a new int attribute.
	 * @param name  the name of the new attribute
	 * @param value the int value
	 * @param hex   true if value should be written in hex
	 */
	public void addAttribute(String name, int value, boolean hex) {
		/*
		if the value is negative (and in hex) we want
		the negative sign ('-') to appear before the '0x'
		*/
		buffer.append(" " + name + "=\"");
		String valueString = Integer.toString(value, hex ? 16 : 10);
		if (valueString.startsWith("-")) {
			buffer.append("-");
			valueString = valueString.substring(1);
		}
		if (hex) {
			buffer.append("0x");
		}
		buffer.append(valueString);
		buffer.append("\"");
	}

	/**
	 * Add a new long attribute as decimal.
	 * @param name  the name of the new attribute
	 * @param value the long value
	 */
	public void addAttribute(String name, long value) {
		addAttribute(name, value, false);
	}

	/**
	 * Add a new long attribute.
	 * @param name  the name of the new attribute
	 * @param value the long value
	 * @param hex   true if value should be written in hex
	 */
	public void addAttribute(String name, long value, boolean hex) {
		/*
		if the value is negative (and in hex) we want
		the negative sign ('-') to appear before the '0x'
		*/
		buffer.append(" " + name + "=\"");
		String valueString = Long.toString(value, hex ? 16 : 10);
		if (valueString.startsWith("-")) {
			buffer.append("-");
			valueString = valueString.substring(1);
		}
		if (hex) {
			buffer.append("0x");
		}
		buffer.append(valueString);
		buffer.append("\"");
	}

	/**
	 * Add a new big integer attribute.
	 * @param name  the name of the new attribute
	 * @param value the big integer value
	 */
	public void addAttribute(String name, BigInteger value, boolean hex) {
		buffer.append(" " + name + "=\"");
		if (hex) {
			buffer.append("0x");
		}
		buffer.append(value.toString(hex ? 16 : 10));
		buffer.append("\"");
	}

	/**
	 * @return the number of attributes in this
	 */
	public boolean isEmpty() {
		return buffer.length() == 0;
	}
}
