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
package ghidra.util.xml;

import java.math.BigInteger;
import java.util.*;

import org.xml.sax.Attributes;

/**
 * A class to represent the start or end tag from an XML file.
 */
public class XmlParserElement {
	private HashMap<String,Object> attrsMap = new HashMap<String,Object>();
	private boolean isStart;
	private String name;
	private StringBuffer text;
	private int lineNum;

	XmlParserElement(String name, StringBuffer text, int lineNum) {
		isStart = false;
		this.name = name.toUpperCase();
		this.text = text;
		this.lineNum = lineNum;
	}
	XmlParserElement(String name, Attributes attrs, int lineNum) {
		isStart = true;
		this.name = name.toUpperCase();
		int count = attrs.getLength();
		for (int i = 0; i < count; i++) {
			attrsMap.put(attrs.getQName(i), attrs.getValue(i));
		}
		this.lineNum = lineNum;
	}

	@Override
	public boolean equals(Object obj) {
		XmlParserElement that = (XmlParserElement)obj;
		if (this.isStart != that.isStart) {
			return false;
		}
		if (!this.name.equals(that.name)) {
			return false;
		}
		boolean textEquals = (this.text == null && that.text == null) ||
                             (this.text != null && this.text.equals(that.text));
		if (!textEquals) {
			return false;
		}
		Iterator<String> iter = attrsMap.keySet().iterator();
		while (iter.hasNext()) {
			String lname = iter.next();
			Object thisValue = this.attrsMap.get(lname);
			Object thatValue = that.attrsMap.get(lname);
			if (thisValue == null && thatValue != null) {
				return false;
			}
			if (thisValue != null && thatValue == null) {
				return false;
			}
			if (thisValue != null && !thisValue.equals(thatValue)) {
				return false;
			}
		}
		return true;
	}

	@Override
	public String toString() {
		StringBuffer buffer = new StringBuffer(name);
		String [] attrNames = getAttrNames();
		Arrays.sort(attrNames);
		for (int i = 0; i < attrNames.length; i++) {
			if (i == 0) {
				buffer.append(" ");
			}
            buffer.append(attrNames[i]);
			buffer.append("=\"");
			buffer.append(getAttrValue(attrNames[i]));
			buffer.append("\"");
			if (i < attrNames.length - 1) {
				buffer.append(" ");
			}
        }
        buffer.append(isStart ? " ->START":" ->END");
        return buffer.toString();
	}
	/**
	 * Returns true if this element represents a start tag.
	 * @return true if this element represents a start tag
	 */
	public boolean isStart() {
		return isStart;
	}
	/**
	 * Returns true if this element represents an end tag.
	 * @return true if this element represents an end tag
	 */
	public boolean isEnd() {
		return !isStart;
	}
	/**
	 * Returns the name of this element/tag.
	 * @return the name of this element/tag
	 */
	public String getName() {
		return name;
	}
	/**
	 * Returns the line number where this element was defined.
	 * @return the line number where this element was defined
	 */
	public int getLineNum() {
		return lineNum;
	}
	/**
	 * Returns the text of this element. Or, null if no text existed
	 * in the XML.
	 * @return the text of this element
	 */
	public String getText() {
		return text == null ? "" : text.toString();
	}
	StringBuffer getTextBuffer() {
	    return text;
	}
	/**
	 * Returns the value of the specified attribute.
	 * Or, null if no attribute exists with the specified name.
	 * @param attrName the name of the attribute
	 * @return the value of the specified attribute
	 */
	public String getAttrValue(String attrName) {
		return (String)attrsMap.get(attrName);
	}
	/**
	 * Returns the boolean value of the specified attribute.
	 * @param attrName the name of the attribute
	 * @return the boolean value of the specified attribute
	 * @throws XmlAttributeException if no attribute exists with the specified name
	 */
	public boolean getAttrValueAsBool(String attrName) {
		String val = getAttrValue(attrName);
		if (val == null) {
			throw new XmlAttributeException("Element: "+name+": attribute "+attrName+" does not exist.");
		}
		try {
			return XmlUtilities.parseBoolean(val);
		}
		catch (XmlAttributeException e) {
			throw new XmlAttributeException("Element: "+name+": attribute "+attrName+" is not a valid boolean (y|n): "+getAttrValue(attrName));
		}
	}
	/**
	 * Returns the integer value of the specified attribute.
	 * @param attrName the name of the attribute
	 * @return the integer value of the specified attribute
	 * @throws XmlAttributeException if no attribute exists with the specified name
	 */
	public int getAttrValueAsInt(String attrName) {
		try {
			String intStr = getAttrValue(attrName);
			return XmlUtilities.parseInt(intStr);
		}
		catch (NullPointerException e) {
			throw new XmlAttributeException("Element: "+name+": attribute "+attrName+" does not exist.");
		}
		catch (NumberFormatException e) {
			throw new XmlAttributeException("Element: "+name+": attribute "+attrName+" is not a valid integer: "+getAttrValue(attrName));
		}
	}
	/**
	 * Returns the long value of the specified attribute.
	 * @param attrName the name of the attribute
	 * @return the long value of the specified attribute
	 * @throws XmlAttributeException if no attribute exists with the specified name
	 */
	public long getAttrValueAsLong(String attrName) {
		try {
			String longStr = getAttrValue(attrName);
			boolean isNegative = longStr.startsWith("-");
			if (isNegative) {
				longStr = longStr.substring(1);
			}
			int radix = 10;
			if (longStr.startsWith("0x")) {
				longStr = longStr.substring(2);
				radix = 16;
			}
			long longVal = new BigInteger(longStr, radix).longValue();
			if (isNegative) {
				longVal *= -1;
			}
			return longVal;
		}
		catch (NullPointerException e) {
			throw new XmlAttributeException("Element: "+name+": attribute "+attrName+" does not exist.");
		}
		catch (NumberFormatException e) {
			throw new XmlAttributeException("Element: "+name+": attribute "+attrName+" is not a valid long: "+getAttrValue(attrName));
		}
	}
	/**
	 * Returns the double value of the specified attribute.
	 * @param attrName the name of the attribute
	 * @return the double value of the specified attribute
	 * @throws XmlAttributeException if no attribute exists with the specified name
	 */
	public double getAttrValueAsDouble(String attrName) {
		try {
			return Double.parseDouble(getAttrValue(attrName));
		}
		catch (NullPointerException e) {
			throw new XmlAttributeException("Element: "+name+": attribute "+attrName+" does not exist.");
		}
		catch (NumberFormatException e) {
			throw new XmlAttributeException("Element: "+name+": attribute "+attrName+" is not a valid double: "+getAttrValue(attrName));
		}
	}
	/**
	 * Returns an array containing the names of all attributes defined in this element.
	 * @return an array containing the names of all attributes defined in this element
	 */
	public String[] getAttrNames() {
		if (attrsMap == null) {
			return new String[0];
		}
		String[] names = new String[attrsMap.size()];
		attrsMap.keySet().toArray(names);
		return names;
	}
	/**
	 * Returns true if this element contains an attribute with the specified name.
	 * @param attrName the name of the attribute
	 * @return true if this element contains an attribute with the specified name
	 */
	public boolean hasAttr(String attrName) {
		return attrsMap.containsKey(attrName);
	}
	/**
	 * Sets the value of the specified attribute.
	 * @param name   the name of the attribute
	 * @param value  the value of the attribute
	 */
	public void setAttribute(String name, String value) {
		attrsMap.put(name, value);
	}
}
