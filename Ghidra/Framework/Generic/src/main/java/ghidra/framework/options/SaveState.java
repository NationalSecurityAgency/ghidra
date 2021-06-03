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

import java.awt.Color;
import java.awt.Font;
import java.io.*;
import java.lang.reflect.*;
import java.nio.charset.StandardCharsets;
import java.text.*;
import java.util.*;

import javax.swing.KeyStroke;

import org.jdom.Element;
import org.jdom.JDOMException;
import org.jdom.output.XMLOutputter;

import com.google.gson.*;

import ghidra.util.Msg;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.AssertException;
import ghidra.util.xml.XmlUtilities;
import utilities.util.FileUtilities;

/**
 * Class for saving name/value pairs as XML or Json.  Classes that want to be
 * able to save their state can do so using the SaveState object.
 * The idea is that each state variable in the class
 * is first saved into a SaveState object via a String key.  Then the SaveState
 * object is written out as XML or Json.  When the save state object is
 * restored, the SaveState object is constructed with an XML Element or JsonObject
 * that contains all of the name/value pairs. Since the "get" methods require
 * a default value, the object that is recovering its state variables
 * will be successfully initialized even if
 * the given key,value pair is not found in the SaveState object.
 * <p> <i>Note: Names for options are assumed to be unique. When a putXXX()
 * method is called, if a value already exists for a name, it will
 * be overwritten.</i>
 * <P>
 * The SaveState supports the following types:
 * <pre>
 *      java primitives
 *      arrays of java primitives
 *      String
 *      Color
 *      Font
 *      KeyStroke
 *      File
 *      Date
 *      Enum
 *      SaveState (values can be nested SaveStates)
 *  </pre>
 */

public class SaveState {
	private static final String STATE = "STATE";
	private static final String TYPE = "TYPE";
	private static final String NAME = "NAME";
	private static final String VALUE = "VALUE";
	private static final String SAVE_STATE = "SAVE_STATE";
	public static DateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ");
	private static final String ARRAY_ELEMENT_NAME = "A";
	private HashMap<String, Object> map;
	private String saveStateName;

	/**
	 * Creates a SaveState object and populates its values from the given file. The file must 
	 * conform to the format that is created with {@link #saveToJson()}
	 * 
	 * @param file the file to load values from
	 * @return a new SaveState object loaded with values from the given file.
	 * @throws IOException if an error occurs reading the given file.
	 */
	public static SaveState readJsonFile(File file) throws IOException {
		try (Reader reader = new FileReader(file)) {
			JsonElement element = JsonParser.parseReader(reader);
			return new SaveState((JsonObject) element);
		}
	}

	/**
	 * Creates a new SaveState object with a non-default name.  The name serves no real purpose
	 * other than as a hint as to what the SaveState represents
	 * 
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
		this(SAVE_STATE);
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
			String name = elem.getAttributeValue(NAME);
			String type = elem.getAttributeValue(TYPE);
			String value = elem.getAttributeValue(VALUE);
			if (tag.equals("XML")) {
				map.put(name, elem.getChildren().get(0));
			}
			else if (tag.equals("BYTES")) {
				if (value != null) {
					map.put(name, NumericUtilities.convertStringToBytes(value));
				}
			}
			else if (tag.equals(STATE)) {
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
					else if (type.equals("Color")) {
						map.put(name, new Color(Integer.valueOf(value)));
					}
					else if (type.equals("Date")) {
						map.put(name, DATE_FORMAT.parse(value));
					}
					else if (type.equals("File")) {
						map.put(name, new File(value));
					}
					else if (type.equals("KeyStroke")) {
						map.put(name, KeyStroke.getKeyStroke(value));
					}
					else if (type.equals("Font")) {
						map.put(name, Font.decode(value));
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
					List<?> list = elem.getChildren(ARRAY_ELEMENT_NAME);
					Iterator<?> it = list.iterator();
					int i = 0;
					if (type.equals("short")) {
						short[] vals = new short[list.size()];
						while (it.hasNext()) {
							Element e = (Element) it.next();
							vals[i++] = Short.parseShort(e.getAttributeValue(VALUE));
						}
						map.put(name, vals);
					}
					else if (type.equals("int")) {
						int[] vals = new int[list.size()];
						while (it.hasNext()) {
							Element e = (Element) it.next();
							vals[i++] = Integer.parseInt(e.getAttributeValue(VALUE));
						}
						map.put(name, vals);
					}
					else if (type.equals("long")) {
						long[] vals = new long[list.size()];
						while (it.hasNext()) {
							Element e = (Element) it.next();
							vals[i++] = Long.parseLong(e.getAttributeValue(VALUE));
						}
						map.put(name, vals);
					}
					else if (type.equals("float")) {
						float[] vals = new float[list.size()];
						while (it.hasNext()) {
							Element e = (Element) it.next();
							vals[i++] = Float.parseFloat(e.getAttributeValue(VALUE));
						}
						map.put(name, vals);
					}
					else if (type.equals("double")) {
						double[] vals = new double[list.size()];
						while (it.hasNext()) {
							Element e = (Element) it.next();
							vals[i++] = Double.parseDouble(e.getAttributeValue(VALUE));
						}
						map.put(name, vals);
					}
					else if (type.equals("boolean")) {
						boolean[] vals = new boolean[list.size()];
						while (it.hasNext()) {
							Element e = (Element) it.next();
							vals[i++] =
								Boolean.valueOf(e.getAttributeValue(VALUE)).booleanValue();
						}
						map.put(name, vals);
					}
					else if (type.equals("string")) {
						String[] vals = new String[list.size()];
						while (it.hasNext()) {
							Element e = (Element) it.next();
							vals[i++] = e.getAttributeValue(VALUE);
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
					Enum<?> e = getEnumValue(className, value);
					if (e != null) {
						map.put(name, e);
					}
				}
			}
			else if (tag.equals(SAVE_STATE)) {
				Element element = (Element) elem.getChildren().get(0);
				if (element != null) {
					map.put(name, new SaveState(element));
				}
			}
			else if (tag.equals("NULL")) {
				map.put(name, null);
			}
		}
	}

	protected SaveState(JsonObject root) {
		map = new HashMap<>();
		saveStateName = root.get("SAVE_STATE_NAME").getAsString();
		JsonObject values = root.get("VALUES").getAsJsonObject();
		JsonObject types = root.get("TYPES").getAsJsonObject();
		JsonObject enumClasses = root.get("ENUM_CLASSES").getAsJsonObject();

		for (String name : values.keySet()) {
			String type = types.get(name).getAsString();
			JsonElement valueElement = values.get(name);
			JsonElement enumClass = enumClasses.get(name);
			Object value = getObjectFromJson(type, valueElement, enumClass);
			if (value != null) {
				map.put(name, value);
			}
		}
	}

	private Object getObjectFromJson(String type, JsonElement value, JsonElement enumClass) {

		switch (type) {
			case "null":
				return null;
			case "String":
				return value.getAsString();
			case "Color":
				return new Color(value.getAsInt());
			case "Date":
				return parseDate(value.getAsString());
			case "File":
				return new File(value.getAsString());
			case "KeyStroke":
				return KeyStroke.getKeyStroke(value.getAsString());
			case "Font":
				return Font.decode(value.getAsString());
			case "byte":
				return value.getAsByte();
			case "short":
				return value.getAsShort();
			case "int":
				return value.getAsInt();
			case "long":
				return value.getAsLong();
			case "float":
				return value.getAsFloat();
			case "double":
				return value.getAsDouble();
			case "boolean":
				return value.getAsBoolean();
			case "byte[]":
				JsonArray byteArray = value.getAsJsonArray();
				byte[] bytes = new byte[byteArray.size()];
				for (int i = 0; i < bytes.length; i++) {
					bytes[i] = byteArray.get(i).getAsByte();
				}
				return bytes;
			case "short[]":
				JsonArray shortArray = value.getAsJsonArray();
				short[] shorts = new short[shortArray.size()];
				for (int i = 0; i < shorts.length; i++) {
					shorts[i] = shortArray.get(i).getAsShort();
				}
				return shorts;
			case "int[]":
				JsonArray intArray = value.getAsJsonArray();
				int[] ints = new int[intArray.size()];
				for (int i = 0; i < ints.length; i++) {
					ints[i] = intArray.get(i).getAsInt();
				}
				return ints;
			case "long[]":
				JsonArray longArray = value.getAsJsonArray();
				long[] longs = new long[longArray.size()];
				for (int i = 0; i < longs.length; i++) {
					longs[i] = longArray.get(i).getAsLong();
				}
				return longs;
			case "float[]":
				JsonArray floatArray = value.getAsJsonArray();
				float[] floats = new float[floatArray.size()];
				for (int i = 0; i < floats.length; i++) {
					floats[i] = floatArray.get(i).getAsFloat();
				}
				return floats;
			case "double[]":
				JsonArray doubleArray = value.getAsJsonArray();
				double[] doubles = new double[doubleArray.size()];
				for (int i = 0; i < doubles.length; i++) {
					doubles[i] = doubleArray.get(i).getAsDouble();
				}
				return doubles;
			case "boolean[]":
				JsonArray boolArray = value.getAsJsonArray();
				boolean[] booleans = new boolean[boolArray.size()];
				for (int i = 0; i < booleans.length; i++) {
					booleans[i] = boolArray.get(i).getAsBoolean();
				}
				return booleans;
			case "String[]":
				JsonArray stringArray = value.getAsJsonArray();
				String[] strings = new String[stringArray.size()];
				for (int i = 0; i < strings.length; i++) {
					strings[i] = stringArray.get(i).getAsString();
				}
				return strings;
			case "xml":
				try {
					return XmlUtilities.fromString(value.getAsString());
				}
				catch (JDOMException | IOException e) {
					throw new AssertException("Error processing embedded XML");
				}

			case "enum":
				String enumClassName = enumClass.getAsString();
				String enumValue = value.getAsString();
				return getEnumValue(enumClassName, enumValue);

			case "SaveState":
				JsonObject json = (JsonObject) value;
				return new SaveState(json);

			default:
				throw new AssertException("Unknown type: " + type);
		}
	}

	private Date parseDate(String dateString) {
		try {
			return DATE_FORMAT.parse(dateString);
		}
		catch (ParseException e) {
			throw new AssertException("Can't parse date string: " + dateString);
		}
	}

	Enum<?> getEnumValue(String enumClassName, String value) {
		try {
			Class<?> enumClass = Class.forName(enumClassName).asSubclass(Enum.class);

			Method m = enumClass.getMethod("valueOf", new Class[] { String.class });
			if (m != null) {
				return (Enum<?>) m.invoke(null, new Object[] { value });
			}
		}
		catch (Exception e) {
			Msg.warn(this, "Can't find field " + value + " in enum class " + enumClassName, e);
		}
		return null;
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
		Element saveToXml = saveToXml();
		byte[] bytes = XmlUtilities.xmlToByteArray(saveToXml);
		FileUtilities.writeBytes(file, bytes);
	}

	/**
	 * Outputs this SaveState to a file using Json
	 * <P>
	 * For example, a SaveState that is created with:
	 * <pre>
	 *  ss = new SaveState("foo")
	 *	ss.putString("Name", "Bob");
	 *	ss.putBoolean("Retired", true);
	 *	ss.putInt("Age", 65);
	 *	ss.putEnum("Endian", Endian.BIG);
	 *
	 *  would produce a Json file with the following text
	 *
	 * {
	 *  "SAVE STATE NAME": "foo",
	 *  "VALUES": {
	 *    "Name": "Bob"
	 *    "Retired": true,
	 *    "Age": 65,
	 *    "Endian": "BIG",
	 *  },
	 *  "TYPES": {
	 *    "Name": "String"
	 *    "Retired": "boolean",
	 *    "Age": "int",
	 *    "Endian": "enum",
	 *  },	
	 *  "ENUM CLASSES": {
	 *    "Endian": "ghidra.program.model.lang.Endian"
	 *  }
	 *}
	 * </pre>
	 * 
	 * @param file the file to save to
	 * @throws IOException if an error occurs writing to the given file
	 */
	public void saveToJsonFile(File file) throws IOException {
		Gson gson = new GsonBuilder().setPrettyPrinting().create();
		JsonObject saveToJson = saveToJson();
		try (FileWriter writer = new FileWriter(file)) {
			writer.write(gson.toJson(saveToJson));
		}
	}

	/**
	 * Save this object to an XML element.
	 * @return Element XML element containing the state
	 */
	public Element saveToXml() {
		Element root = new Element(saveStateName);
		Iterator<String> iter = map.keySet().iterator();
		while (iter.hasNext()) {
			String key = iter.next();
			Object value = map.get(key);
			Element elem = null;
			if (value instanceof Element) {
				elem = createElementFromElement(key, (Element) value);
			}
			else if (value instanceof Byte) {
				elem = setAttributes(key, "byte", ((Byte) value).toString());
			}
			else if (value instanceof Short) {
				elem = setAttributes(key, "short", ((Short) value).toString());
			}
			else if (value instanceof Integer) {
				elem = setAttributes(key, "int", ((Integer) value).toString());
			}
			else if (value instanceof Long) {
				elem = setAttributes(key, "long", ((Long) value).toString());
			}
			else if (value instanceof Float) {
				elem = setAttributes(key, "float", ((Float) value).toString());
			}
			else if (value instanceof Double) {
				elem = setAttributes(key, "double", ((Double) value).toString());
			}
			else if (value instanceof Boolean) {
				elem = setAttributes(key, "boolean", ((Boolean) value).toString());
			}
			else if (value instanceof String) {
				elem = new Element(STATE);
				elem.setAttribute(NAME, key);
				elem.setAttribute(TYPE, "string");
				if (XmlUtilities.hasInvalidXMLCharacters((String) value)) {
					elem.setAttribute("ENCODED_VALUE", NumericUtilities.convertBytesToString(
						((String) value).getBytes(StandardCharsets.UTF_8)));
				}
				else {
					elem.setAttribute(VALUE, (String) value);
				}
			}
			else if (value instanceof Color) {
				elem = setAttributes(key, "Color", Integer.toString(((Color) value).getRGB()));
			}
			else if (value instanceof Date) {
				elem = setAttributes(key, "Date", DATE_FORMAT.format((Date) value));
			}
			else if (value instanceof File) {
				elem = setAttributes(key, "File", ((File) value).getAbsolutePath());
			}
			else if (value instanceof KeyStroke) {
				elem = setAttributes(key, "KeyStroke", value.toString());
			}
			else if (value instanceof Font) {
				elem =
					setAttributes(key, "Font", OptionType.FONT_TYPE.convertObjectToString(value));
			}
			else if (value instanceof byte[]) {
				elem = new Element("BYTES");
				elem.setAttribute(NAME, key);
				elem.setAttribute(VALUE, NumericUtilities.convertBytesToString((byte[]) value));
			}
			else if (value instanceof short[]) {
				elem = setArrayAttributes(key, "short", value);
			}
			else if (value instanceof int[]) {
				elem = setArrayAttributes(key, "int", value);
			}
			else if (value instanceof long[]) {
				elem = setArrayAttributes(key, "long", value);
			}
			else if (value instanceof float[]) {
				elem = setArrayAttributes(key, "float", value);
			}
			else if (value instanceof double[]) {
				elem = setArrayAttributes(key, "double", value);
			}
			else if (value instanceof boolean[]) {
				elem = setArrayAttributes(key, "boolean", value);
			}
			else if (value instanceof String[]) {
				elem = setArrayAttributes(key, "string", value);
			}
			else if (value instanceof Enum) {
				Enum<?> e = (Enum<?>) value;
				elem = new Element("ENUM");
				elem.setAttribute(NAME, key);
				elem.setAttribute(TYPE, "enum");
				elem.setAttribute("CLASS", e.getClass().getName());
				elem.setAttribute(VALUE, e.name());
			}
			else if (value instanceof SaveState) {
				Element element = ((SaveState) value).saveToXml();
				elem = new Element(SAVE_STATE);
				elem.setAttribute(NAME, key);
				elem.setAttribute(TYPE, "SaveState");
				elem.addContent(element);
			}
			else {
				elem = new Element("NULL");
				elem.setAttribute(NAME, key);
			}
			root.addContent(elem);
		}
		return root;
	}

	private <T> Element setArrayAttributes(String key, String type, Object values) {
		Element elem = new Element("ARRAY");
		elem.setAttribute(NAME, key);
		elem.setAttribute(TYPE, type);
		for (int i = 0; i < Array.getLength(values); i++) {
			Object value = Array.get(values, i);
			if (value != null) {
				Element arrElem = new Element(ARRAY_ELEMENT_NAME);
				arrElem.setAttribute(VALUE, value.toString());
				elem.addContent(arrElem);
			}
		}
		return elem;
	}

	private Element setAttributes(String key, String type, String value) {
		Element elem;
		elem = new Element(STATE);
		elem.setAttribute(NAME, key);
		elem.setAttribute(TYPE, type);
		elem.setAttribute(VALUE, value);
		return elem;
	}

	/**
	 * Save this object to an JsonObject
	 *
	 * @return JsonObject containing the state
	 */
	public JsonObject saveToJson() {
		JsonObject types = new JsonObject();
		JsonObject values = new JsonObject();
		JsonObject enumClasses = new JsonObject();
		Iterator<String> iter = map.keySet().iterator();
		while (iter.hasNext()) {
			String key = iter.next();
			Object value = map.get(key);
			if (value == null) {
				types.addProperty(key, "null");
				values.addProperty(key, "null");
			}
			else if (value instanceof Element) {
				types.addProperty(key, "xml");
				String outputString = new XMLOutputter().outputString((Element) value);
				values.addProperty(key, outputString);
			}
			else if (value instanceof Color) {
				types.addProperty(key, "Color");
				values.addProperty(key, ((Color) value).getRGB());
			}
			else if (value instanceof Date) {
				types.addProperty(key, "Date");
				values.addProperty(key, DATE_FORMAT.format((Date) value));
			}
			else if (value instanceof File) {
				types.addProperty(key, "File");
				values.addProperty(key, ((File) value).getAbsolutePath());
			}
			else if (value instanceof KeyStroke) {
				types.addProperty(key, "KeyStroke");
				values.addProperty(key, value.toString());
			}
			else if (value instanceof Font) {
				types.addProperty(key, "Font");
				values.addProperty(key, OptionType.FONT_TYPE.convertObjectToString(value));
			}
			else if (value instanceof Byte) {
				types.addProperty(key, "byte");
				values.addProperty(key, (Byte) value);
			}
			else if (value instanceof Short) {
				types.addProperty(key, "short");
				values.addProperty(key, (Short) value);
			}
			else if (value instanceof Integer) {
				types.addProperty(key, "int");
				values.addProperty(key, (Integer) value);
			}
			else if (value instanceof Long) {
				types.addProperty(key, "long");
				values.addProperty(key, (Long) value);
			}
			else if (value instanceof Float) {
				types.addProperty(key, "float");
				values.addProperty(key, (Float) value);
			}
			else if (value instanceof Double) {
				types.addProperty(key, "double");
				values.addProperty(key, (Double) value);
			}
			else if (value instanceof Boolean) {
				types.addProperty(key, "boolean");
				values.addProperty(key, (Boolean) value);
			}
			else if (value instanceof String) {
				types.addProperty(key, "String");
				values.addProperty(key, (String) value);
			}
			else if (value instanceof byte[]) {
				JsonArray ja = new JsonArray();
				for (byte b : (byte[]) value) {
					ja.add(b);
				}
				types.addProperty(key, "byte[]");
				values.add(key, ja);
			}
			else if (value instanceof short[]) {
				JsonArray ja = new JsonArray();
				for (short s : (short[]) value) {
					ja.add(s);
				}
				types.addProperty(key, "short[]");
				values.add(key, ja);
			}
			else if (value instanceof int[]) {
				JsonArray ja = new JsonArray();
				for (int i : (int[]) value) {
					ja.add(i);
				}
				types.addProperty(key, "int[]");
				values.add(key, ja);
			}
			else if (value instanceof long[]) {
				JsonArray ja = new JsonArray();
				for (long i : (long[]) value) {
					ja.add(i);
				}
				types.addProperty(key, "long[]");
				values.add(key, ja);
			}
			else if (value instanceof float[]) {
				JsonArray ja = new JsonArray();
				for (float f : (float[]) value) {
					ja.add(f);
				}
				types.addProperty(key, "float[]");
				values.add(key, ja);
			}
			else if (value instanceof double[]) {
				JsonArray ja = new JsonArray();
				for (double f : (double[]) value) {
					ja.add(f);
				}
				types.addProperty(key, "double[]");
				values.add(key, ja);
			}
			else if (value instanceof boolean[]) {
				JsonArray ja = new JsonArray();
				for (boolean b : (boolean[]) value) {
					ja.add(b);
				}
				types.addProperty(key, "boolean[]");
				values.add(key, ja);
			}
			else if (value instanceof String[]) {
				JsonArray ja = new JsonArray();
				for (String s : (String[]) value) {
					if (s != null) {
						ja.add(s);
					}
				}
				types.addProperty(key, "String[]");
				values.add(key, ja);
			}
			else if (value instanceof Enum) {
				Enum<?> e = (Enum<?>) value;
				types.addProperty(key, "enum");
				enumClasses.addProperty(key, e.getClass().getName());
				values.addProperty(key, e.name());
			}
			else if (value instanceof SaveState) {
				types.addProperty(key, "SaveState");
				JsonObject json = ((SaveState) value).saveToJson();
				values.add(key, json);
			}
			else {
				throw new AssertException("found unsupported object type: " + value.getClass());
			}
		}
		JsonObject jsonObject = new JsonObject();
		jsonObject.addProperty("SAVE_STATE_NAME", saveStateName);
		jsonObject.add("VALUES", values);
		jsonObject.add("TYPES", types);
		jsonObject.add("ENUM_CLASSES", enumClasses);
		return jsonObject;
	}

	protected Element createElementFromElement(String internalKey, Element internalElement) {
		Element newElement = new Element("XML");
		newElement.setAttribute(NAME, internalKey);

		Element internalElementClone = (Element) internalElement.clone();
		newElement.addContent(internalElementClone);

		return newElement;
	}

	/**
	 * Returns true if this list contains no elements
	 * @return true if there are no properties in this save  state
	 */
	public boolean isEmpty() {
		return map.isEmpty();
	}

	/**
	 * Remove the object identified by the given name
	 * 
	 * @param name the name of the property to remove
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
	 * Return the number of properties in the save state
	 * @return The number of properties in the save state
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
		map.put(name, Integer.valueOf(value));
	}

	/**
	 * Associates a byte value with the given name.
	 * @param name The name in the name,value pair.
	 * @param value The value in the name,value pair.
	 */
	public void putByte(String name, byte value) {
		map.put(name, Byte.valueOf(value));
	}

	/**
	 * Associates a short value with the given name.
	 * @param name The name in the name,value pair.
	 * @param value The value in the name,value pair.
	 */
	public void putShort(String name, short value) {
		map.put(name, Short.valueOf(value));
	}

	/**
	 * Associates a long value with the given name.
	 * @param name The name in the name,value pair.
	 * @param value The value in the name,value pair.
	 */
	public void putLong(String name, long value) {
		map.put(name, Long.valueOf(value));
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
	 * Associates a Color value with the given name.
	 * @param name The name in the name,value pair.
	 * @param value The value in the name,value pair.
	 */
	public void putColor(String name, Color value) {
		map.put(name, value);
	}

	/**
	 * Associates a Date value with the given name.
	 * @param name The name in the name,value pair.
	 * @param value The value in the name,value pair.
	 */
	public void putDate(String name, Date value) {
		map.put(name, value);
	}

	/**
	 * Associates a File value with the given name.
	 * @param name The name in the name,value pair.
	 * @param value The value in the name,value pair.
	 */
	public void putFile(String name, File value) {
		map.put(name, value);
	}

	/**
	 * Associates a KeyStroke value with the given name.
	 * @param name The name in the name,value pair.
	 * @param value The value in the name,value pair.
	 */
	public void putKeyStroke(String name, KeyStroke value) {
		map.put(name, value);
	}

	/**
	 * Associates a Font value with the given name.
	 * @param name The name in the name,value pair.
	 * @param value The value in the name,value pair.
	 */
	public void putFont(String name, Font value) {
		map.put(name, value);
	}

	/**
	 * Associates a boolean value with the given name.
	 * @param name The name in the name,value pair.
	 * @param value The value in the name,value pair.
	 */
	public void putBoolean(String name, boolean value) {
		map.put(name, Boolean.valueOf(value));
	}

	/**
	 * Associates a float value with the given name.
	 * @param name The name in the name,value pair.
	 * @param value The value in the name,value pair.
	 */
	public void putFloat(String name, float value) {
		map.put(name, Float.valueOf(value));
	}

	/**
	 * Associates a double value with the given name.
	 * @param name The name in the name,value pair.
	 * @param value The value in the name,value pair.
	 */
	public void putDouble(String name, double value) {
		map.put(name, Double.valueOf(value));
	}

	/**
	 * Associates a sub SaveState value with the given name.
	 * @param name The name in the name,value pair.
	 * @param value The value in the name,value pair.
	 */
	public void putSaveState(String name, SaveState value) {
		map.put(name, value);
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
		return getAsType(name, defaultValue, Integer.class);
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
		return getAsType(name, defaultValue, Byte.class);
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
		return getAsType(name, defaultValue, Short.class);
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
		return getAsType(name, defaultValue, Long.class);
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
		return getAsType(name, defaultValue, Boolean.class);
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
		return getAsType(name, defaultValue, String.class);
	}

	/**
	 * Gets the Color value for the given name.
	 * @param name the name of the pair.
	 * @param defaultValue the default value to be returned if the name does
	 * not exist in the map, or it does not contain the proper object type.
	 * @return the Color value associated with the given name or the defaultValue
	 * passed in if the name doesn't exist or is the wrong type.
	 */
	public Color getColor(String name, Color defaultValue) {
		return getAsType(name, defaultValue, Color.class);
	}

	/**
	 * Gets the Date value for the given name.
	 * @param name the name of the pair.
	 * @param defaultValue the default value to be returned if the name does
	 * not exist in the map, or it does not contain the proper object type.
	 * @return the Date value associated with the given name or the defaultValue
	 * passed in if the name doesn't exist or is the wrong type.
	 */
	public Date getDate(String name, Date defaultValue) {
		return getAsType(name, defaultValue, Date.class);
	}

	/**
	 * Gets the File value for the given name.
	 * @param name the name of the pair.
	 * @param defaultValue the default value to be returned if the name does
	 * not exist in the map, or it does not contain the proper object type.
	 * @return the File value associated with the given name or the defaultValue
	 * passed in if the name doesn't exist or is the wrong type.
	 */
	public File getFile(String name, File defaultValue) {
		return getAsType(name, defaultValue, File.class);
	}

	/**
	 * Gets the KeyStroke value for the given name.
	 * @param name the name of the pair.
	 * @param defaultValue the default value to be returned if the name does
	 * not exist in the map, or it does not contain the proper object type.
	 * @return the KeyStroke value associated with the given name or the defaultValue
	 * passed in if the name doesn't exist or is the wrong type.
	 */
	public KeyStroke getKeyStroke(String name, KeyStroke defaultValue) {
		return getAsType(name, defaultValue, KeyStroke.class);
	}

	/**
	 * Gets the Font value for the given name.
	 * @param name the name of the pair.
	 * @param defaultValue the default value to be returned if the name does
	 * not exist in the map, or it does not contain the proper object type.
	 * @return the Font value associated with the given name or the defaultValue
	 * passed in if the name doesn't exist or is the wrong type.
	 */
	public Font getFont(String name, Font defaultValue) {
		return getAsType(name, defaultValue, Font.class);
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
		return getAsType(name, defaultValue, Float.class);
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
		return getAsType(name, defaultValue, Double.class);
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
	 * Returns true if there is a value for the given name
	 * 
	 * @param name true the name of the property to check for a value
	 * @return true if the SaveState object has a value for the given name
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
		return getAsType(name, null, Element.class);
	}

	/**
	 * Returns the sub SaveState associated with the
	 * given name.
	 * @param name The name associated with the desired Element.
	 * @return The SaveState object associated with the
	 * given name.
	 */
	public SaveState getSaveState(String name) {
		return getAsType(name, null, SaveState.class);
	}

	private <T> T getAsType(String name, T defaultValue, Class<T> clazz) {
		if (map.containsKey(name)) {
			Object value = map.get(name);
			if (isExpectedType(name, value, clazz)) {
				return clazz.cast(value);
			}
		}
		return defaultValue;

	}

	private boolean isExpectedType(String name, Object value, Class<?> expectedType) {
		if (value != null && !expectedType.isInstance(value)) {
			Msg.debug(this,
				"Type mismatch on saveState property \"" + name +
					"\". Attempted to retrieve value as a " + expectedType.getName() +
					" but was of type " + value.getClass().getName());
			return false;
		}
		return true;
	}

}
