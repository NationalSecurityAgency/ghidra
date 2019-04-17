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
package ghidra.app.util.xml;

import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.util.*;
import ghidra.util.XmlProgramUtilities;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.*;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

import java.awt.Color;
import java.awt.Font;
import java.io.File;
import java.util.*;

import javax.swing.KeyStroke;

import org.xml.sax.SAXParseException;

class PropertiesXmlMgr {

	private final static String PROPERTY_LIST_CATEGORY_DELIMITER = Options.DELIMITER_STRING;

	private Program program;
	private PropertyMapManager propMapMgr;
	private AddressFactory factory;
	private MessageLog log;

	PropertiesXmlMgr(Program program, MessageLog log) {
		this.program = program;
		this.propMapMgr = program.getUsrPropertyManager();
		this.factory = program.getAddressFactory();
		this.log = log;
	}

	///////////////////////////////////////////////////////////////////////////////////////
	//                            XML READ CURRENT DTD                                   //
	///////////////////////////////////////////////////////////////////////////////////////

	void read(XmlPullParser parser, boolean overwrite, TaskMonitor monitor)
			throws SAXParseException, CancelledException {

		XmlElement element = parser.next();
		if (!element.isStart() || !element.getName().equals("PROPERTIES")) {
			throw new SAXParseException("Expected PROPERTIES start tag", null, null,
				parser.getLineNumber(), parser.getColumnNumber());
		}
		element = parser.next();
		while (element.getName().equals("PROPERTY")) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			processProperty(element, parser, overwrite);
			element = parser.next();
		}
		if (element.isStart() || !element.getName().equals("PROPERTIES")) {
			throw new SAXParseException("Expected PROPERTY element or PROPERTIES end tag", null,
				null, parser.getLineNumber(), parser.getColumnNumber());
		}
	}

	private void processProperty(XmlElement element, XmlPullParser parser, boolean overwrite)
			throws SAXParseException {

		String name = element.getAttribute("NAME");
		if (name == null) {
			throw new SAXParseException("NAME attribute missing for PROPERTY element", null, null,
				parser.getLineNumber(), parser.getColumnNumber());
		}

		String addrStr = element.getAttribute("ADDRESS");
		try {
			if (addrStr != null) {
				Address addr = XmlProgramUtilities.parseAddress(factory, addrStr);
				if (addr == null) {
					throw new AddressFormatException("Incompatible Property [" + name +
						"] Address " + addrStr + " at Line: " + parser.getLineNumber());
				}
				processPropertyMapEntry(addr, name, element, overwrite, parser);
			}
			else {
				processPropertyListEntry(name, element, overwrite);
			}
		}
		catch (Exception e) {
			log.appendException(e);
			parser.discardSubTree(element);
			return;
		}

		element = parser.next();
		if (element.isStart() || !element.getName().equals("PROPERTY")) {
			throw new SAXParseException("Expected PROPERTY end tag", null, null,
				parser.getLineNumber(), parser.getColumnNumber());
		}
	}

	private void processPropertyMapEntry(Address addr, String name, XmlElement element,
			boolean overwrite, XmlPullParser parser) throws Exception {

		String type = element.getAttribute("TYPE");
		if (type != null) {
			type = type.toLowerCase();
		}

		if (!overwrite && !"bookmarks".equals(type)) {
			PropertyMap map = propMapMgr.getPropertyMap(name);
			if (map != null && map.hasProperty(addr)) {
				log.appendMsg("Conflicting '" + name + "' PROPERTY ignored at: " + addr);
				return; // skip - property conflicts
			}
		}

		if (type == null || "void".equals(type)) {
			if (element.getAttribute("VALUE") != null) {
				log.appendMsg("VALUE attribute ignored for void property");
			}
			VoidPropertyMap voidMap = propMapMgr.getVoidPropertyMap(name);
			if (voidMap == null) {
				voidMap = propMapMgr.createVoidPropertyMap(name);
			}
			voidMap.add(addr);
		}
		else if ("int".equals(type)) {
			int value = XmlUtilities.parseInt(element.getAttribute("VALUE"));
			IntPropertyMap intMap = propMapMgr.getIntPropertyMap(name);
			if (intMap == null) {
				intMap = propMapMgr.createIntPropertyMap(name);
			}
			intMap.add(addr, value);
		}
		else if ("long".equals(type)) {
			long value = XmlUtilities.parseLong(element.getAttribute("VALUE"));
			LongPropertyMap longMap = propMapMgr.getLongPropertyMap(name);
			if (longMap == null) {
				longMap = propMapMgr.createLongPropertyMap(name);
			}
			longMap.add(addr, value);
		}
		else if ("string".equals(type)) {
			String str = element.getAttribute("VALUE");
			StringPropertyMap strMap = propMapMgr.getStringPropertyMap(name);
			if (strMap == null) {
				strMap = propMapMgr.createStringPropertyMap(name);
			}
			strMap.add(addr, str);
		}
		else if ("bookmarks".equals(type)) {
			// Must retain for backward compatibility with old Ver-1 Note bookmarks which 
			// were saved as simple properties
			BookmarkManager bmMgr = program.getBookmarkManager();
			if (!overwrite) {
				Bookmark[] bookmarks = bmMgr.getBookmarks(addr, BookmarkType.NOTE);
				if (bookmarks.length != 0) {
					log.appendMsg("Conflicting BOOKMARK ignored at: " + addr);
					return; // skip - bookmark conflicts
				}
			}
			bmMgr.setBookmark(addr, BookmarkType.NOTE, name, element.getAttribute("VALUE"));
		}
		else {
			log.appendMsg("Unsupported PROPERTY usage");
		}
	}

	private String getPropertyList(String path) {
		StringTokenizer st = new StringTokenizer(path, PROPERTY_LIST_CATEGORY_DELIMITER);
		if (st.hasMoreElements()) {
			return st.nextToken();
		}
		return null;
	}

	private String getPropertyName(String path) {
		int ix = path.indexOf(PROPERTY_LIST_CATEGORY_DELIMITER);
		if (ix >= 0) {
			if (path.length() > (ix + 1)) {
				return path.substring(ix + 1);
			}
			return null;
		}
		return path;
	}

	@SuppressWarnings("unchecked")
	private void processPropertyListEntry(String pathname, XmlElement element, boolean overwrite)
			throws Exception {

		String listName = getPropertyList(pathname);
		String name = getPropertyName(pathname);
		if (listName == null || name == null) {
			log.appendMsg("Property NAME attribute must contain both category prefix and property name");
			return;
		}
		Options list = program.getOptions(listName);
		if (!overwrite && list.contains(name)) {
			log.appendMsg("Conflicting PROPERTY ignored: " + pathname);
			return; // skip - property conflicts
		}
		String type = element.getAttribute("TYPE");
		if (type != null) {
			type = type.toLowerCase();
		}
		if (type == null || "void".equals(type)) {
			log.appendMsg("Unsupported PROPERTY usage");
		}
		else if ("int".equals(type)) {
			int value = XmlUtilities.parseInt(element.getAttribute("VALUE"));
			list.setInt(name, value);
		}
		else if ("long".equals(type)) {
			long value = XmlUtilities.parseLong(element.getAttribute("VALUE"));
			list.setLong(name, value);
		}
		else if ("double".equals(type)) {
			double value = Double.parseDouble(element.getAttribute("VALUE"));
			list.setDouble(name, value);
		}
		else if ("float".equals(type)) {
			float value = Float.parseFloat(element.getAttribute("VALUE"));
			list.setFloat(name, value);
		}
		else if ("bool".equals(type)) {
			boolean value = XmlUtilities.parseBoolean(element.getAttribute("VALUE"));
			list.setBoolean(name, value);
		}
		else if ("string".equals(type)) {
			String str = element.getAttribute("VALUE");
			list.setString(name, str);
		}
		else if ("date".equals(type)) {
			long value = XmlUtilities.parseLong(element.getAttribute("VALUE"));
			list.setDate(name, new Date(value));
		}
		else if ("color".equals(type)) {
			Color color = new Color(XmlUtilities.parseInt(element.getAttribute("VALUE")));
			list.setColor(name, color);
		}
		else if ("file".equals(type)) {
			File file = new File(element.getAttribute("VALUE"));
			list.setFile(name, file);
		}
		else if ("enum".equals(type)) {
			String escapedXML = element.getAttribute("VALUE");
			String xmlString = XmlUtilities.unEscapeElementEntities(escapedXML);
			@SuppressWarnings("rawtypes")
			Enum enuum = (Enum) OptionType.ENUM_TYPE.convertStringToObject(xmlString);
			list.setEnum(name, enuum);
		}
		else if ("font".equals(type)) {
			String escapedXML = element.getAttribute("VALUE");
			String xmlString = XmlUtilities.unEscapeElementEntities(escapedXML);
			Font font = (Font) OptionType.FONT_TYPE.convertStringToObject(xmlString);
			list.setFont(name, font);
		}
		else if ("keyStroke".equals(type)) {
			String escapedXML = element.getAttribute("VALUE");
			String xmlString = XmlUtilities.unEscapeElementEntities(escapedXML);
			KeyStroke keyStroke =
				(KeyStroke) OptionType.KEYSTROKE_TYPE.convertStringToObject(xmlString);
			list.setKeyStroke(name, keyStroke);
		}
		else if ("custom".equals(type)) {
			String escapedXML = element.getAttribute("VALUE");
			String xmlString = XmlUtilities.unEscapeElementEntities(escapedXML);
			CustomOption custom =
				(CustomOption) OptionType.CUSTOM_TYPE.convertStringToObject(xmlString);
			list.setCustomOption(name, custom);
		}
		else if ("bytes".equals(type)) {
			String escapedXML = element.getAttribute("VALUE");
			String xmlString = XmlUtilities.unEscapeElementEntities(escapedXML);
			byte[] bytes = (byte[]) OptionType.BYTE_ARRAY_TYPE.convertStringToObject(xmlString);
			list.setByteArray(name, bytes);
		}
		else {
			log.appendMsg("Unsupported PROPERTY usage");
		}
	}

	///////////////////////////////////////////////////////////////////////////////////////
	//							   XML READ VERSION 1 DTD                                //
	///////////////////////////////////////////////////////////////////////////////////////

	void readV1(XmlPullParser parser, boolean overwrite, TaskMonitor monitor)
			throws SAXParseException, CancelledException {
		read(parser, overwrite, monitor);
	}

	///////////////////////////////////////////////////////////////////////////////////////
	//   						 XML WRITE CURRENT DTD                                   //
	///////////////////////////////////////////////////////////////////////////////////////

	void write(XmlWriter writer, AddressSetView set, TaskMonitor monitor) throws CancelledException {
		monitor.setMessage("Writing PROPERTIES ...");
		writer.startElement("PROPERTIES");
		writePropertyMaps(writer, set, monitor);
		writePropertyLists(writer, monitor);
		writer.endElement("PROPERTIES");
	}

	private void writePropertyLists(XmlWriter writer, TaskMonitor monitor)
			throws CancelledException {
		List<String> listNames = program.getOptionsNames();
		Collections.sort(listNames);
		for (int i = 0; i < listNames.size(); i++) {
			Options propList = program.getOptions(listNames.get(i));
			List<String> propNames = propList.getOptionNames();
			Collections.sort(propNames);
			String prefix = listNames.get(i) + PROPERTY_LIST_CATEGORY_DELIMITER;
			for (String name : propNames) {
				if (monitor.isCancelled()) {
					throw new CancelledException();
				}
				if (propList.isAlias(name)) {  // don't write out properties that are just mirrors of some other property
					continue;
				}
				if (propList.isDefaultValue(name)) { // don't write out default properties.
					continue;
				}
				OptionType type = propList.getType(name);
				XmlAttributes attrs = new XmlAttributes();
				attrs.addAttribute("NAME", prefix + name);
				switch (type) {
					case INT_TYPE:
						attrs.addAttribute("TYPE", "int");
						attrs.addAttribute("VALUE", propList.getInt(name, 0), true);
						break;
					case LONG_TYPE:
						attrs.addAttribute("TYPE", "long");
						attrs.addAttribute("VALUE", propList.getLong(name, 0), true);
						break;
					case STRING_TYPE:
						attrs.addAttribute("TYPE", "string");
						attrs.addAttribute("VALUE", propList.getString(name, ""));
						break;
					case BOOLEAN_TYPE:
						attrs.addAttribute("TYPE", "bool");
						attrs.addAttribute("VALUE", propList.getBoolean(name, true));
						break;
					case DOUBLE_TYPE:
						attrs.addAttribute("TYPE", "double");
						attrs.addAttribute("VALUE", propList.getDouble(name, 0));
						break;
					case FLOAT_TYPE:
						attrs.addAttribute("TYPE", "float");
						attrs.addAttribute("VALUE", propList.getFloat(name, 0f));
						break;
					case DATE_TYPE:
						attrs.addAttribute("TYPE", "date");
						Date date = propList.getDate(name, (Date) null);
						long time = date == null ? 0 : date.getTime();
						attrs.addAttribute("VALUE", time, true);
						break;
					case COLOR_TYPE:
						attrs.addAttribute("TYPE", "color");
						Color color = propList.getColor(name, null);
						int rgb = color.getRGB();
						attrs.addAttribute("VALUE", rgb, true);
						break;
					case ENUM_TYPE:
						attrs.addAttribute("TYPE", "enum");
						@SuppressWarnings({ "unchecked", "rawtypes" })
						Enum enuum = propList.getEnum(name, null);
						String xmlString = OptionType.ENUM_TYPE.convertObjectToString(enuum);
						attrs.addAttribute("VALUE", XmlUtilities.escapeElementEntities(xmlString));
						break;
					case FILE_TYPE:
						attrs.addAttribute("TYPE", "file");
						File file = propList.getFile(name, null);
						String path = file.getAbsolutePath();
						attrs.addAttribute("VALUE", path);
						break;
					case FONT_TYPE:
						attrs.addAttribute("TYPE", "font");
						Font font = propList.getFont(name, null);
						xmlString = OptionType.FONT_TYPE.convertObjectToString(font);
						attrs.addAttribute("VALUE", XmlUtilities.escapeElementEntities(xmlString));
						break;
					case KEYSTROKE_TYPE:
						attrs.addAttribute("TYPE", "keyStroke");
						KeyStroke keyStroke = propList.getKeyStroke(name, null);
						xmlString = OptionType.KEYSTROKE_TYPE.convertObjectToString(keyStroke);
						attrs.addAttribute("VALUE", XmlUtilities.escapeElementEntities(xmlString));
						break;
					case CUSTOM_TYPE:
						attrs.addAttribute("TYPE", "custom");
						CustomOption custom = propList.getCustomOption(name, null);
						xmlString = OptionType.KEYSTROKE_TYPE.convertObjectToString(custom);
						attrs.addAttribute("VALUE", XmlUtilities.escapeElementEntities(xmlString));
						break;
					case BYTE_ARRAY_TYPE:
						attrs.addAttribute("TYPE", "bytes");
						byte[] bytes = propList.getByteArray(name, null);
						xmlString = OptionType.BYTE_ARRAY_TYPE.convertObjectToString(bytes);
						attrs.addAttribute("VALUE", XmlUtilities.escapeElementEntities(xmlString));
						break;
					case NO_TYPE:
					default:
						throw new AssertException();
				}
				writer.startElement("PROPERTY", attrs);
				writer.endElement("PROPERTY");
			}
		}
	}

	private void writePropertyMaps(XmlWriter writer, AddressSetView set, TaskMonitor monitor)
			throws CancelledException {
		Iterator<String> mapNames = propMapMgr.propertyManagers();
		while (mapNames.hasNext()) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			String mapName = mapNames.next();
			PropertyMap map = propMapMgr.getPropertyMap(mapName);
			if (map instanceof VoidPropertyMap) {
				writeVoidMap((VoidPropertyMap) map, writer, set, monitor);
			}
			else if (map instanceof IntPropertyMap) {
				writeIntMap((IntPropertyMap) map, writer, set, monitor);
			}
			else if (map instanceof LongPropertyMap) {
				writeLongMap((LongPropertyMap) map, writer, set, monitor);
			}
			else if (map instanceof StringPropertyMap) {
				writeStringMap((StringPropertyMap) map, writer, set, monitor);
			}
		}

	}

	private void writeStringMap(StringPropertyMap map, XmlWriter writer, AddressSetView set,
			TaskMonitor monitor) throws CancelledException {
		AddressIterator iter =
			set != null ? map.getPropertyIterator(set) : map.getPropertyIterator();
		while (iter.hasNext()) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			Address addr = iter.next();
			String value = map.getString(addr);
			XmlAttributes attrs = new XmlAttributes();
			attrs.addAttribute("NAME", map.getName());
			attrs.addAttribute("ADDRESS", XmlProgramUtilities.toString(addr));
			attrs.addAttribute("TYPE", "string");
			attrs.addAttribute("VALUE", value);
			writer.startElement("PROPERTY", attrs);
			writer.endElement("PROPERTY");
		}
	}

	private void writeLongMap(LongPropertyMap map, XmlWriter writer, AddressSetView set,
			TaskMonitor monitor) throws CancelledException {
		AddressIterator iter =
			set != null ? map.getPropertyIterator(set) : map.getPropertyIterator();
		while (iter.hasNext()) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			try {
				Address addr = iter.next();
				long value = map.getLong(addr);
				XmlAttributes attrs = new XmlAttributes();
				attrs.addAttribute("NAME", map.getName());
				attrs.addAttribute("ADDRESS", XmlProgramUtilities.toString(addr));
				attrs.addAttribute("TYPE", "long");
				attrs.addAttribute("VALUE", value, true);
				writer.startElement("PROPERTY", attrs);
				writer.endElement("PROPERTY");
			}
			catch (NoValueException e) {
			}
		}
	}

	private void writeIntMap(IntPropertyMap map, XmlWriter writer, AddressSetView set,
			TaskMonitor monitor) throws CancelledException {
		AddressIterator iter =
			set != null ? map.getPropertyIterator(set) : map.getPropertyIterator();
		while (iter.hasNext()) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			try {
				Address addr = iter.next();
				int value = map.getInt(addr);
				XmlAttributes attrs = new XmlAttributes();
				attrs.addAttribute("NAME", map.getName());
				attrs.addAttribute("ADDRESS", XmlProgramUtilities.toString(addr));
				attrs.addAttribute("TYPE", "int");
				attrs.addAttribute("VALUE", value, true);
				writer.startElement("PROPERTY", attrs);
				writer.endElement("PROPERTY");
			}
			catch (NoValueException e) {
			}
		}
	}

	private void writeVoidMap(VoidPropertyMap map, XmlWriter writer, AddressSetView set,
			TaskMonitor monitor) throws CancelledException {
		AddressIterator iter =
			set != null ? map.getPropertyIterator(set) : map.getPropertyIterator();
		while (iter.hasNext()) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			Address addr = iter.next();
			XmlAttributes attrs = new XmlAttributes();
			attrs.addAttribute("NAME", map.getName());
			attrs.addAttribute("ADDRESS", XmlProgramUtilities.toString(addr));
			attrs.addAttribute("TYPE", "void");
			writer.startElement("PROPERTY", attrs);
			writer.endElement("PROPERTY");
		}
	}

}
