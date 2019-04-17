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

import java.io.*;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.util.*;

import org.jdom.Element;

import ghidra.util.Msg;
import ghidra.util.NumericUtilities;
import ghidra.util.xml.XmlUtilities;
import utilities.util.FileUtilities;

/**
 * Class for saving values in "serializable safe" way.  Classes that want to be
 * able to save their state can do so using the SaveState object.
 * The idea is that each state variable in the class
 * is first saved into a SaveState object via a String key.  Then the SaveState
 * object is written out to an XML element.  When the save state object is
 * to be restored, the saveState object is constructed with an XML Element
 * that contains all of the name/value pairs. Since the "get" methods require
 * a default value, the object that is recovering its state variables
 * will be successfully initialized even if
 * the given key,value pair is not found in the SaveState object.
 * <p> <i>Note: Names for options are assumed to be unique. When a putXXX()
 * method is called, if a value already exists for a name, it will
 * be overwritten.</i>
 */

public class SaveState {
	private HashMap<String, Object> map;
	private String saveStateName;

	/**
	 * Creates a new saveState object.
	 * @param name of the state
	 */
	public SaveState(String name) {
		this.saveStateName = name;
		this.map = new HashMap<>();
	}

	/**
	 * Default Constructor for SaveState; uses "SAVE_STATE" as the
	 * name of the state.
	 * @see java.lang.Object#Object()
	 */
	public SaveState() {
		this("SAVE_STATE");
	}

	/**
	 * Construct a SaveState from a file containing XML from a previously saved SaveState.
	 * @param file the file containing the XML to read.
	 * @throws IOException if the file can't be read or is not formatted properly for a SaveState
	 */
	public SaveState(File file) throws IOException {
		this(getXmlElementFromFile(file));
	}

	/**
	 * Construct a new SaveState object using the given XML element.
	 * @param root XML contents of the save state
	 */
	public SaveState(Element root) {
		map = new HashMap<>();
		saveStateName = root.getName();
		Iterator<?> iter = root.getChildren().iterator();
		while (iter.hasNext()) {
			Element elem = (Element) iter.next();
			String tag = elem.getName();
			String name = elem.getAttributeValue("NAME");
			String type = elem.getAttributeValue("TYPE");
			String value = elem.getAttributeValue("VALUE");
			if (tag.equals("XML")) {
				map.put(name, elem.getChildren().get(0));
			}
			else if (tag.equals("BYTES")) {
				if (value != null) {
					map.put(name, NumericUtilities.convertStringToBytes(value));
				}
			}
			else if (tag.equals("STATE")) {
				try {
					if (type == null) {
						// skip this element
					}
					else if (type.equals("byte")) {
						map.put(name, Byte.valueOf(value));
					}
					else if (type.equals("short")) {
						map.put(name, Short.valueOf(value));
					}
					else if (type.equals("int")) {
						map.put(name, Integer.valueOf(value));
					}
					else if (type.equals("long")) {
						map.put(name, Long.valueOf(value));
					}
					else if (type.equals("float")) {
						map.put(name, Float.valueOf(value));
					}
					else if (type.equals("double")) {
						map.put(name, Double.valueOf(value));
					}
					else if (type.equals("boolean")) {
						map.put(name, Boolean.valueOf(value));
					}
					else if (type.equals("string")) {
						String encodedValue = elem.getAttributeValue("ENCODED_VALUE");
						if (value == null && encodedValue != null) {
							byte[] strBytes = NumericUtilities.convertStringToBytes(encodedValue);
							value = new String(strBytes, StandardCharsets.UTF_8);
						}
						map.put(name, value);
					}
				}
				catch (Exception e) {
					Msg.warn(this, "Error processing primitive value in saveState", e);
				}
			}
			else if (tag.equals("ARRAY")) {
				if (type == null) {
					continue;
				}

				try {
					List<?> list = elem.getChildren("A");
					Iterator<?> it = list.iterator();
					int i = 0;
					if (type.equals("short")) {
						short[] vals = new short[list.size()];
						while (it.hasNext()) {
							Element e = (Element) it.next();
							vals[i++] = Short.parseShort(e.getAttributeValue("VALUE"));
						}
						map.put(name, vals);
					}
					else if (type.equals("int")) {
						int[] vals = new int[list.size()];
						while (it.hasNext()) {
							Element e = (Element) it.next();
							vals[i++] = Integer.parseInt(e.getAttributeValue("VALUE"));
						}
						map.put(name, vals);
					}
					else if (type.equals("long")) {
						long[] vals = new long[list.size()];
						while (it.hasNext()) {
							Element e = (Element) it.next();
							vals[i++] = Long.parseLong(e.getAttributeValue("VALUE"));
						}
						map.put(name, vals);
					}
					else if (type.equals("float")) {
						float[] vals = new float[list.size()];
						while (it.hasNext()) {
							Element e = (Element) it.next();
							vals[i++] = Float.parseFloat(e.getAttributeValue("VALUE"));
						}
						map.put(name, vals);
					}
					else if (type.equals("double")) {
						double[] vals = new double[list.size()];
						while (it.hasNext()) {
							Element e = (Element) it.next();
							vals[i++] = Double.parseDouble(e.getAttributeValue("VALUE"));
						}
						map.put(name, vals);
					}
					else if (type.equals("boolean")) {
						boolean[] vals = new boolean[list.size()];
						while (it.hasNext()) {
							Element e = (Element) it.next();
							vals[i++] =
								Boolean.valueOf(e.getAttributeValue("VALUE")).booleanValue();
						}
						map.put(name, vals);
					}
					else if (type.equals("string")) {
						String[] vals = new String[list.size()];
						while (it.hasNext()) {
							Element e = (Element) it.next();
							vals[i++] = e.getAttributeValue("VALUE");
						}
						map.put(name, vals);
					}
				}
				catch (Exception exc) {
					Msg.warn(this, "Error processing array value in saveState", exc);
				}
			}
			else if (tag.equals("ENUM")) {
				if (type == null) {
					continue;
				}
				if (type.equals("stringenum")) {
					// skip it, string enums are no longer supported
					continue;
				}
				if (type.equals("enum")) {
					String className = elem.getAttributeValue("CLASS");
					try {
						Class<?> enumClass = Class.forName(className).asSubclass(Enum.class);

						Method m = enumClass.getMethod("valueOf", new Class[] { String.class });
						if (m != null) {
							Enum<?> e = (Enum<?>) m.invoke(null, new Object[] { value });
							if (e != null) {
								map.put(name, e);
							}
						}
					}
					catch (Exception e) {
						Msg.warn(this, "Error processing enum class " + className, e);
					}
				}
			}
			else if (tag.equals("NULL")) {
				map.put(name, null);
			}
		}
	}

	/**
	 * Save this object to an XML element.
	 * @return Element XML element containing the state
	 */
	public Element saveToXml() {
		return saveToXml(null);
	}

	private static Element getXmlElementFromFile(File file) throws IOException {
		byte[] bytes = FileUtilities.getBytesFromFile(file);
		return XmlUtilities.byteArrayToXml(bytes);
	}

	/**
	 * Write the saveState to a file as XML
	 * @param file the file to write to.
	 * @throws FileNotFoundException if the file does not represent a valid file path.
	 * @throws IOException if the file could not be written
	 */
	public void saveToFile(File file) throws FileNotFoundException, IOException {
		Element saveToXml = saveToXml(null);
		byte[] bytes = XmlUtilities.xmlToByteArray(saveToXml);
		FileUtilities.writeBytes(file, bytes);
	}

	/**
	 * Save this object to an XML element.
	 * Restrict child elements to the set specified.
	 * @param restrictedSet restricted set of element names or null for all names
	 * @return Element XML element containing the state
	 */
	public Element saveToXml(Set<String> restrictedSet) {
		Element root = new Element(saveStateName);
		Iterator<String> iter = map.keySet().iterator();
		while (iter.hasNext()) {
			String key = iter.next();
			if (restrictedSet != null && !restrictedSet.contains(key)) {
				continue;
			}
			Object value = map.get(key);
			Element elem = null;
			if (value instanceof Element) {
				elem = createElementFromElement(key, (Element) value);
			}
			else if (value instanceof Byte) {
				elem = new Element("STATE");
				elem.setAttribute("NAME", key);
				elem.setAttribute("TYPE", "byte");
				elem.setAttribute("VALUE", ((Byte) value).toString());
			}
			else if (value instanceof Short) {
				elem = new Element("STATE");
				elem.setAttribute("NAME", key);
				elem.setAttribute("TYPE", "short");
				elem.setAttribute("VALUE", ((Short) value).toString());
			}
			else if (value instanceof Integer) {
				elem = new Element("STATE");
				elem.setAttribute("NAME", key);
				elem.setAttribute("TYPE", "int");
				elem.setAttribute("VALUE", ((Integer) value).toString());
			}
			else if (value instanceof Long) {
				elem = new Element("STATE");
				elem.setAttribute("NAME", key);
				elem.setAttribute("TYPE", "long");
				elem.setAttribute("VALUE", ((Long) value).toString());
			}
			else if (value instanceof Float) {
				elem = new Element("STATE");
				elem.setAttribute("NAME", key);
				elem.setAttribute("TYPE", "float");
				elem.setAttribute("VALUE", ((Float) value).toString());
			}
			else if (value instanceof Double) {
				elem = new Element("STATE");
				elem.setAttribute("NAME", key);
				elem.setAttribute("TYPE", "double");
				elem.setAttribute("VALUE", ((Double) value).toString());
			}
			else if (value instanceof Boolean) {
				elem = new Element("STATE");
				elem.setAttribute("NAME", key);
				elem.setAttribute("TYPE", "boolean");
				elem.setAttribute("VALUE", ((Boolean) value).toString());
			}
			else if (value instanceof String) {
				elem = new Element("STATE");
				elem.setAttribute("NAME", key);
				elem.setAttribute("TYPE", "string");
				if (XmlUtilities.hasInvalidXMLCharacters((String) value)) {
					elem.setAttribute("ENCODED_VALUE", NumericUtilities.convertBytesToString(
						((String) value).getBytes(StandardCharsets.UTF_8)));
				}
				else {
					elem.setAttribute("VALUE", (String) value);
				}
			}
			else if (value instanceof byte[]) {
				elem = new Element("BYTES");
				elem.setAttribute("NAME", key);
				elem.setAttribute("VALUE", NumericUtilities.convertBytesToString((byte[]) value));
			}
			else if (value instanceof short[]) {
				elem = new Element("ARRAY");
				elem.setAttribute("NAME", key);
				elem.setAttribute("TYPE", "short");
				short[] arr = (short[]) value;
				for (short element : arr) {
					Element arrElem = new Element("A");
					arrElem.setAttribute("VALUE", "" + element);
					elem.addContent(arrElem);
				}
			}
			else if (value instanceof int[]) {
				elem = new Element("ARRAY");
				elem.setAttribute("NAME", key);
				elem.setAttribute("TYPE", "int");
				int[] arr = (int[]) value;
				for (int element : arr) {
					Element arrElem = new Element("A");
					arrElem.setAttribute("VALUE", "" + element);
					elem.addContent(arrElem);
				}
			}
			else if (value instanceof long[]) {
				elem = new Element("ARRAY");
				elem.setAttribute("NAME", key);
				elem.setAttribute("TYPE", "long");
				long[] arr = (long[]) value;
				for (long element : arr) {
					Element arrElem = new Element("A");
					arrElem.setAttribute("VALUE", "" + element);
					elem.addContent(arrElem);
				}
			}
			else if (value instanceof float[]) {
				elem = new Element("ARRAY");
				elem.setAttribute("NAME", key);
				elem.setAttribute("TYPE", "float");
				float[] arr = (float[]) value;
				for (float element : arr) {
					Element arrElem = new Element("A");
					arrElem.setAttribute("VALUE", "" + element);
					elem.addContent(arrElem);
				}
			}
			else if (value instanceof double[]) {
				elem = new Element("ARRAY");
				elem.setAttribute("NAME", key);
				elem.setAttribute("TYPE", "double");
				double[] arr = (double[]) value;
				for (double element : arr) {
					Element arrElem = new Element("A");
					arrElem.setAttribute("VALUE", "" + element);
					elem.addContent(arrElem);
				}
			}
			else if (value instanceof boolean[]) {
				elem = new Element("ARRAY");
				elem.setAttribute("NAME", key);
				elem.setAttribute("TYPE", "boolean");
				boolean[] arr = (boolean[]) value;
				for (boolean element : arr) {
					Element arrElem = new Element("A");
					arrElem.setAttribute("VALUE", "" + element);
					elem.addContent(arrElem);
				}
			}
			else if (value instanceof String[]) {
				elem = new Element("ARRAY");
				elem.setAttribute("NAME", key);
				elem.setAttribute("TYPE", "string");
				String[] arr = (String[]) value;
				for (String element : arr) {
					Element arrElem = new Element("A");
					if (element != null) {
						arrElem.setAttribute("VALUE", element);
					}
					elem.addContent(arrElem);
				}
			}
			else if (value instanceof Enum) {
				Enum<?> e = (Enum<?>) value;
				elem = new Element("ENUM");
				elem.setAttribute("NAME", key);
				elem.setAttribute("TYPE", "enum");
				elem.setAttribute("CLASS", e.getClass().getName());
				elem.setAttribute("VALUE", e.name());
			}
			else {
				elem = new Element("NULL");
				elem.setAttribute("NAME", key);
			}
			root.addContent(elem);
		}
		return root;
	}

	protected Element createElementFromElement(String internalKey, Element internalElement) {
		Element newElement = new Element("XML");
		newElement.setAttribute("NAME", internalKey);

		Element internalElementClone = (Element) internalElement.clone();
		newElement.addContent(internalElementClone);

		return newElement;
	}

	/**
	 * Return whether anything was added to this save state.
	 */
	public boolean isEmpty() {
		return map.isEmpty();
	}

	/**
	 * Remove the object identified by the given name.
	 */
	public void remove(String name) {
		map.remove(name);
	}

	/**
	 * Clear all objects from the save state.
	 */
	public void clear() {
		map.clear();
	}

	/**
	 * Return the number of objects in the save state.
	 */
	public int size() {
		return map.size();
	}

	/**
	 * Return the names of the objects saved in the state.
	 * @return String[] array will be zero length if the save state
	 * is empty
	 */
	public String[] getNames() {
		String[] names = new String[map.size()];
		int idx = 0;
		Iterator<String> iter = map.keySet().iterator();
		while (iter.hasNext()) {
			names[idx] = iter.next();
			++idx;
		}
		return names;
	}

	//////////////////////////////////////////////////////////////

	void putObject(String name, Object obj) {
		map.put(name, obj);
	}

	Object getObject(String name) {
		return map.get(name);
	}

	//////////////////////////////////////////////////////////////

	/**
	 * Associates an integer value with the given name.
	 * @param name The name in the name,value pair.
	 * @param value The value in the name,value pair.
	 */
	public void putInt(String name, int value) {
		map.put(name, new Integer(value));
	}

	/**
	 * Associates a byte value with the given name.
	 * @param name The name in the name,value pair.
	 * @param value The value in the name,value pair.
	 */
	public void putByte(String name, byte value) {
		map.put(name, new Byte(value));
	}

	/**
	 * Associates a short value with the given name.
	 * @param name The name in the name,value pair.
	 * @param value The value in the name,value pair.
	 */
	public void putShort(String name, short value) {
		map.put(name, new Short(value));
	}

	/**
	 * Associates a long value with the given name.
	 * @param name The name in the name,value pair.
	 * @param value The value in the name,value pair.
	 */
	public void putLong(String name, long value) {
		map.put(name, new Long(value));
	}

	/**
	 * Associates a String value with the given name.
	 * @param name The name in the name,value pair.
	 * @param value The value in the name,value pair.
	 */
	public void putString(String name, String value) {
		map.put(name, value);
	}

	/**
	 * Associates a boolean value with the given name.
	 * @param name The name in the name,value pair.
	 * @param value The value in the name,value pair.
	 */
	public void putBoolean(String name, boolean value) {
		map.put(name, new Boolean(value));
	}

	/**
	 * Associates a float value with the given name.
	 * @param name The name in the name,value pair.
	 * @param value The value in the name,value pair.
	 */
	public void putFloat(String name, float value) {
		map.put(name, new Float(value));
	}

	/**
	 * Associates a double value with the given name.
	 * @param name The name in the name,value pair.
	 * @param value The value in the name,value pair.
	 */
	public void putDouble(String name, double value) {
		map.put(name, new Double(value));
	}

	/**
	 * Gets the int value for the given name.
	 * @param name the name of the pair.
	 * @param defaultValue the default value to be returned if the name does
	 * not exist in the map, or it does not contain the proper object type.
	 * @return the int value associated with the given name or the defaultValue
	 * passed in if the name doesn't exist or is the wrong type.
	 */
	public int getInt(String name, int defaultValue) {
		try {
			Integer val = (Integer) map.get(name);
			if (val != null) {
				return val.intValue();
			}
		}
		catch (Exception e) {
			Msg.debug(this, "Two different types for option name: " + name);
		}
		return defaultValue;
	}

	/**
	 * Gets the byte value for the given name.
	 * @param name the name of the pair.
	 * @param defaultValue the default value to be returned if the name does
	 * not exist in the map, or it does not contain the proper object type.
	 * @return the byte value associated with the given name or the defaultValue
	 * passed in if the name doesn't exist or is the wrong type.
	 */
	public byte getByte(String name, byte defaultValue) {
		try {
			Byte val = (Byte) map.get(name);
			if (val != null) {
				return val.byteValue();
			}
		}
		catch (Exception e) {
			Msg.debug(this, "Two different types for option name: " + name);
		}
		return defaultValue;
	}

	/**
	 * Gets the short value for the given name.
	 * @param name the name of the pair.
	 * @param defaultValue the default value to be returned if the name does
	 * not exist in the map, or it does not contain the proper object type.
	 * @return the short value associated with the given name or the defaultValue
	 * passed in if the name doesn't exist or is the wrong type.
	 */
	public short getShort(String name, short defaultValue) {
		try {
			Short val = (Short) map.get(name);
			if (val != null) {
				return val.shortValue();
			}
		}
		catch (Exception e) {
			Msg.debug(this, "Two different types for option name: " + name);
		}
		return defaultValue;
	}

	/**
	 * Gets the long value for the given name.
	 * @param name the name of the pair.
	 * @param defaultValue the default value to be returned if the name does
	 * not exist in the map, or it does not contain the proper object type.
	 * @return the long value associated with the given name or the defaultValue
	 * passed in if the name doesn't exist or is the wrong type.
	 */
	public long getLong(String name, long defaultValue) {
		try {
			Long val = (Long) map.get(name);
			if (val != null) {
				return val.longValue();
			}
		}
		catch (Exception e) {
			Msg.debug(this, "Two different types for option name: " + name);
		}
		return defaultValue;
	}

	/**
	 * Gets the boolean value for the given name.
	 * @param name the name of the pair.
	 * @param defaultValue the default value to be returned if the name does
	 * not exist in the map, or it does not contain the proper object type.
	 * @return the boolean value associated with the given name or the defaultValue
	 * passed in if the name doesn't exist or is the wrong type.
	 */
	public boolean getBoolean(String name, boolean defaultValue) {
		try {
			Boolean val = (Boolean) map.get(name);
			if (val != null) {
				return val.booleanValue();
			}
		}
		catch (Exception e) {
			Msg.debug(this, "Two different types for option name: " + name);
		}
		return defaultValue;
	}

	/**
	 * Gets the String value for the given name.
	 * @param name the name of the pair.
	 * @param defaultValue the default value to be returned if the name does
	 * not exist in the map, or it does not contain the proper object type.
	 * @return the String value associated with the given name or the defaultValue
	 * passed in if the name doesn't exist or is the wrong type.
	 */
	public String getString(String name, String defaultValue) {
		try {
			return map.containsKey(name) ? (String) map.get(name) : defaultValue;
		}
		catch (Exception e) {
			Msg.debug(this, "Two different types for option name: " + name);
			return defaultValue;
		}
	}

	/**
	 * Gets the float value for the given name.
	 * @param name the name of the pair.
	 * @param defaultValue the default value to be returned if the name does
	 * not exist in the map, or it does not contain the proper object type.
	 * @return the float value associated with the given name or the defaultValue
	 * passed in if the name doesn't exist or is the wrong type.
	 */
	public float getFloat(String name, float defaultValue) {
		try {
			Float val = (Float) map.get(name);
			if (val != null) {
				return val.floatValue();
			}
		}
		catch (Exception e) {
			Msg.debug(this, "Two different types for option name: " + name);
		}
		return defaultValue;
	}

	/**
	 * Gets the double value for the given name.
	 * @param name the name of the pair.
	 * @param defaultValue the default value to be returned if the name does
	 * not exist in the map, or it does not contain the proper object type.
	 * @return the double value associated with the given name or the defaultValue
	 * passed in if the name doesn't exist or is the wrong type.
	 */
	public double getDouble(String name, double defaultValue) {
		try {
			Double val = (Double) map.get(name);
			if (val != null) {
				return val.doubleValue();
			}
		}
		catch (Exception e) {
			Msg.debug(this, "Two different types for option name: " + name);
		}
		return defaultValue;
	}

	/**
	 * Associates an integer array with the given name.
	 * @param name The name in the name,value pair.
	 * @param value The value in the name,value pair.
	 */
	public void putInts(String name, int[] value) {
		map.put(name, value);
	}

	/**
	 * Associates a byte array with the given name.
	 * @param name The name in the name,value pair.
	 * @param value The value in the name,value pair.
	 */
	public void putBytes(String name, byte[] value) {
		map.put(name, value);
	}

	/**
	 * Associates a short array with the given name.
	 * @param name The name in the name,value pair.
	 * @param value The value in the name,value pair.
	 */
	public void putShorts(String name, short[] value) {
		map.put(name, value);
	}

	/**
	 * Associates a long array with the given name.
	 * @param name The name in the name,value pair.
	 * @param value The value in the name,value pair.
	 */
	public void putLongs(String name, long[] value) {
		map.put(name, value);
	}

	/**
	 * Associates a String array with the given name.
	 * @param name The name in the name,value pair.
	 * @param value The value in the name,value pair.
	 */
	public void putStrings(String name, String[] value) {
		map.put(name, value);
	}

	/**
	 * Associates an Enum with the given name.
	 * @param name The name in the name,value pair.
	 * @param value The Enum value in the name,value pair.
	 */
	public void putEnum(String name, Enum<?> value) {
		if ((value.getClass().getModifiers() & Modifier.PUBLIC) == 0) {
			throw new IllegalArgumentException("enum '" + value.name() + "' must be public");
		}
		map.put(name, value);
	}

	/**
	 * Associates a boolean array with the given name.
	 * @param name The name in the name,value pair.
	 * @param value The value in the name,value pair.
	 */
	public void putBooleans(String name, boolean[] value) {
		map.put(name, value);
	}

	/**
	 * Associates a float array with the given name.
	 * @param name The name in the name,value pair.
	 * @param value The value in the name,value pair.
	 */
	public void putFloats(String name, float[] value) {
		map.put(name, value);
	}

	/**
	 * Associates a double value with the given name.
	 * @param name The name in the name,value pair.
	 * @param value The value in the name,value pair.
	 */
	public void putDoubles(String name, double[] value) {
		map.put(name, value);
	}

	/**
	 * Gets the int array for the given name.
	 * @param name the name of the pair.
	 * @param defaultValue the default value to be returned if the name does
	 * not exist in the map, or it does not contain the proper object type.
	 * @return the int array associated with the given name or the defaultValue
	 * passed in if the name doesn't exist or is the wrong type.
	 */
	public int[] getInts(String name, int[] defaultValue) {
		return map.containsKey(name) ? (int[]) map.get(name) : defaultValue;
	}

	/**
	 * Gets the byte array for the given name.
	 * @param name the name of the pair.
	 * @param defaultValue the default value to be returned if the name does
	 * not exist in the map, or it does not contain the proper object type.
	 * @return the byte array associated with the given name or the defaultValue
	 * passed in if the name doesn't exist or is the wrong type.
	 */
	public byte[] getBytes(String name, byte[] defaultValue) {
		return map.containsKey(name) ? (byte[]) map.get(name) : defaultValue;
	}

	/**
	 * Gets the short array for the given name.
	 * @param name the name of the pair.
	 * @param defaultValue the default value to be returned if the name does
	 * not exist in the map, or it does not contain the proper object type.
	 * @return the short array associated with the given name or the defaultValue
	 * passed in if the name doesn't exist or is the wrong type.
	 */
	public short[] getShorts(String name, short[] defaultValue) {
		return map.containsKey(name) ? (short[]) map.get(name) : defaultValue;
	}

	/**
	 * Gets the long array for the given name.
	 * @param name the name of the pair.
	 * @param defaultValue the default value to be returned if the name does
	 * not exist in the map, or it does not contain the proper object type.
	 * @return the long array associated with the given name or the defaultValue
	 * passed in if the name doesn't exist or is the wrong type.
	 */
	public long[] getLongs(String name, long[] defaultValue) {
		return map.containsKey(name) ? (long[]) map.get(name) : defaultValue;
	}

	/**
	 * Gets the boolean array for the given name.
	 * @param name the name of the pair.
	 * @param defaultValue the default value to be returned if the name does
	 * not exist in the map, or it does not contain the proper object type.
	 * @return the boolean array associated with the given name or the defaultValue
	 * passed in if the name doesn't exist or is the wrong type.
	 */
	public boolean[] getBooleans(String name, boolean[] defaultValue) {
		return map.containsKey(name) ? (boolean[]) map.get(name) : defaultValue;
	}

	/**
	 * Gets the String array for the given name.
	 * @param name the name of the pair.
	 * @param defaultValue the default value to be returned if the name does
	 * not exist in the map, or it does not contain the proper object type.
	 * @return the String array associated with the given name or the defaultValue
	 * passed in if the name doesn't exist or is the wrong type.
	 */
	public String[] getStrings(String name, String[] defaultValue) {
		return map.containsKey(name) ? (String[]) map.get(name) : defaultValue;
	}

	/**
	 * Gets the Enum value for the given name.
	 * @param name the name of the pair.
	 * @param defaultValue the default Enum value to be returned if the name does
	 * not exist in the map, or it does not contain the proper object type.
	 * @return the Enum value associated with the given name or the defaultValue
	 * passed in if the name doesn't exist or is the wrong type.
	 */
	@SuppressWarnings("unchecked")
	public <T extends Enum<T>> T getEnum(String name, T defaultValue) {
		if (defaultValue != null &&
			(defaultValue.getClass().getModifiers() & Modifier.PUBLIC) == 0) {
			throw new IllegalArgumentException("enum '" + defaultValue.name() + "' must be public");
		}
		try {
			if (map.containsKey(name)) {
				return (T) map.get(name);
			}
		}
		catch (ClassCastException e) {
			// Facilitate transition from StringEnum to Enum
			map.put(name, defaultValue);
		}
		return defaultValue;
	}

	/**
	 * Gets the float array for the given name.
	 * @param name the name of the pair.
	 * @param defaultValue the default value to be returned if the name does
	 * not exist in the map, or it does not contain the proper object type.
	 * @return the float array associated with the given name or the defaultValue
	 * passed in if the name doesn't exist or is the wrong type.
	 */
	public float[] getFloats(String name, float[] defaultValue) {
		return map.containsKey(name) ? (float[]) map.get(name) : defaultValue;
	}

	/**
	 * Gets the double array for the given name.
	 * @param name the name of the pair.
	 * @param defaultValue the default value to be returned if the name does
	 * not exist in the map, or it does not contain the proper object type.
	 * @return the double array associated with the given name or the defaultValue
	 * passed in if the name doesn't exist or is the wrong type.
	 */
	public double[] getDoubles(String name, double[] defaultValue) {
		return map.containsKey(name) ? (double[]) map.get(name) : defaultValue;
	}

	/**
	 * Returns true if the SaveState object has a value for the given name.
	 */
	public boolean hasValue(String name) {
		return map.containsKey(name);
	}

	/**
	 * Adds an XML element to the
	 * saved state object. Used by plugins that have more
	 * complicated state information that needs to be saved.
	 * @param name the name to associate with the element
	 * @param element XML element which is the root of an
	 * XML sub-tree.
	 */
	public void putXmlElement(String name, Element element) {
		map.put(name, element);
	}

	/**
	 * Returns the root of an XML sub-tree associated with the
	 * given name.
	 * @param name The name associated with the desired Element.
	 * @return The root of an XML sub-tree associated with the
	 * given name.
	 */
	public Element getXmlElement(String name) {
		try {
			return (Element) map.get(name);
		}
		catch (Exception exc) {
			Msg.debug(this, "Two different types for option name: " + name);
		}
		return null;
	}
}
