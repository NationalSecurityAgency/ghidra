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
package generic.constraint;

import ghidra.util.xml.XmlAttributeException;

import java.util.HashMap;
import java.util.Map;

/**
 * Convenience class that converts XML attributes into typed property values.
 */
public class ConstraintData {
	private Map<String, String> map = new HashMap<String, String>();

	public ConstraintData(Map<String, String> mappings) {
		map.putAll(mappings);
	}

	public String getString(String name) {
		return getValue(name, "string");

	}

	public boolean hasValue(String name) {
		return map.containsKey(name);
	}

	public int getInt(String name) {
		String value = getValue(name, "int");
		try {
			return Integer.parseInt(value);
		}
		catch (NumberFormatException e) {
			throw new XmlAttributeException("Expected int value for attribute \"" + name +
				"\", but was \"" + value + "\"");
		}
	}

	public long getLong(String name) {
		String value = getValue(name, "long");
		try {
			return Long.parseLong(value);
		}
		catch (NumberFormatException e) {
			throw new XmlAttributeException("Expected long value for attribute \"" + name +
				"\", but was \"" + value + "\"");
		}
	}

	public boolean getBoolean(String name) {
		String value = getValue(name, "boolean");

		value = value.toLowerCase();
		if (value.equals("true")) {
			return true;
		}
		if (value.equals("false")) {
			return false;
		}
		throw new XmlAttributeException("Expected boolean value for attribute \"" + name +
			"\", but was \"" + value + "\"");
	}

	public float getFloat(String name) {
		String value = getValue(name, "float");

		try {
			return Float.parseFloat(value);
		}
		catch (NumberFormatException e) {
			throw new XmlAttributeException("Expected float value for attribute \"" + name +
				"\", but was \"" + value + "\"");
		}
	}

	public double getDouble(String name) {
		String value = getValue(name, "double");

		try {
			return Double.parseDouble(value);
		}
		catch (NumberFormatException e) {
			throw new XmlAttributeException("Expected double value for attribute \"" + name +
				"\", but was \"" + value + "\"");
		}
	}

	private String getValue(String name, String type) {
		String value = map.get(name);
		if (value == null) {
			throw new XmlAttributeException("Missing " + type + " value for attribute \"" + name +
				"\"");
		}
		return value;
	}
}
