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
package sarif.managers;

import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.List;

import javax.swing.KeyStroke;

import com.google.gson.JsonArray;

import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.util.*;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import sarif.SarifProgramOptions;
import sarif.export.SarifWriterTask;
import sarif.export.props.SarifPropertyListWriter;
import sarif.export.props.SarifPropertyMapWriter;

public class PropertiesSarifMgr extends SarifMgr {

	public static String KEY = "PROPERTIES";
	public static String SUBKEY = "Property";

	private final static String PROPERTY_LIST_CATEGORY_DELIMITER = Options.DELIMITER_STRING;

	private PropertyMapManager propMapMgr;

	PropertiesSarifMgr(Program program, MessageLog log) {
		super(KEY, program, log);
		this.propMapMgr = program.getUsrPropertyManager();
	}

	////////////////////////////
	// SARIF READ CURRENT DTD //
	////////////////////////////

	@Override
	public boolean read(Map<String, Object> result, SarifProgramOptions options,
			TaskMonitor monitor) throws CancelledException {
		processProperty(result, options == null || options.isOverwritePropertyConflicts());
		return true;
	}

	private void processProperty(Map<String, Object> result, boolean overwrite) {

		String name = (String) result.get("name");
		try {
			Address addr = getLocation(result);
			if (addr != null) {
				processPropertyMapEntry(addr, name, result, overwrite);
			}
			else {
				processPropertyListEntry(name, result, overwrite);
			}
		}
		catch (Exception e) {
			log.appendException(e);
		}

	}

	@SuppressWarnings("unchecked")
	private void processPropertyMapEntry(Address addr, String name, Map<String, Object> result,
			boolean overwrite) throws DuplicateNameException {

		String type = (String) result.get("type");
		if (type != null) {
			type = type.toLowerCase();
		}

		if (!overwrite && !"bookmarks".equals(type)) {
			PropertyMap<?> map = propMapMgr.getPropertyMap(name);
			if (map != null && map.hasProperty(addr)) {
				log.appendMsg("Conflicting '" + name + "' PROPERTY ignored at: " + addr);
				return; // skip - property conflicts
			}
		}

		String val = (String) result.get("value");
		if (type == null || "void".equals(type)) {
			if (val != null) {
				log.appendMsg("VALUE attribute ignored for void property");
			}
			VoidPropertyMap voidMap = propMapMgr.getVoidPropertyMap(name);
			if (voidMap == null) {
				voidMap = propMapMgr.createVoidPropertyMap(name);
			}
			voidMap.add(addr);
		}
		else if ("int".equals(type)) {
			int value = Integer.parseInt(val, 16);
			IntPropertyMap intMap = propMapMgr.getIntPropertyMap(name);
			if (intMap == null) {
				intMap = propMapMgr.createIntPropertyMap(name);
			}
			intMap.add(addr, value);
		}
		else if ("long".equals(type)) {
			long value = Long.parseLong(val, 16);
			LongPropertyMap longMap = propMapMgr.getLongPropertyMap(name);
			if (longMap == null) {
				longMap = propMapMgr.createLongPropertyMap(name);
			}
			longMap.add(addr, value);
		}
		else if ("string".equals(type)) {
			String str = val;
			StringPropertyMap strMap = propMapMgr.getStringPropertyMap(name);
			if (strMap == null) {
				strMap = propMapMgr.createStringPropertyMap(name);
			}
			strMap.add(addr, str);
		}
		else if ("color".equals(type)) {
			ObjectPropertyMap<SaveableColor> objMap =
				(ObjectPropertyMap<SaveableColor>) propMapMgr.getObjectPropertyMap(name);
			if (objMap == null) {
				objMap = propMapMgr.createObjectPropertyMap(name, SaveableColor.class);
			}
			objMap.add(addr, new SaveableColor(Color.decode(val)));
		}
		else if ("point".equals(type)) {
			String xstr = val.substring(val.indexOf("[x="), val.indexOf(","));
			String ystr = val.substring(val.indexOf("y="), val.indexOf("]"));
			ObjectPropertyMap<SaveablePoint> objMap =
				(ObjectPropertyMap<SaveablePoint>) propMapMgr.getObjectPropertyMap(name);
			if (objMap == null) {
				objMap = propMapMgr.createObjectPropertyMap(name, SaveablePoint.class);
			}
			objMap.add(addr,
				new SaveablePoint(new Point(Integer.parseInt(xstr), Integer.parseInt(ystr))));
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
			bmMgr.setBookmark(addr, BookmarkType.NOTE, name, val);
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
	private void processPropertyListEntry(String pathname, Map<String, Object> result,
			boolean overwrite) throws Exception {

		String listName = getPropertyList(pathname);
		String name = getPropertyName(pathname);
		if (listName == null || name == null) {
			log.appendMsg(
				"Property NAME attribute must contain both category prefix and property name");
			return;
		}
		Options list = program.getOptions(listName);
		if (!overwrite && list.contains(name)) {
			log.appendMsg("Conflicting PROPERTY ignored: " + pathname);
			return; // skip - property conflicts
		}
		String type = (String) result.get("type");
		if (type != null) {
			type = type.toLowerCase();
		}
		Object val = result.get("value");
		if (type == null || "void".equals(type)) {
			log.appendMsg("Unsupported PROPERTY usage");
		}
		else if ("int".equals(type)) {
			list.setInt(name, Integer.parseInt((String) val, 16));
		}
		else if ("long".equals(type)) {
			list.setLong(name, Long.parseLong((String) val, 16));
		}
		else if ("double".equals(type)) {
			list.setDouble(name, Double.parseDouble((String) val));
		}
		else if ("float".equals(type)) {
			list.setFloat(name, Float.parseFloat((String) val));
		}
		else if ("bool".equals(type)) {
			list.setBoolean(name, Boolean.parseBoolean((String) val));
		}
		else if ("string".equals(type)) {
			list.setString(name, (String) val);
		}
		else if ("date".equals(type)) {
			list.setDate(name, new Date(Long.parseLong((String) val, 16)));
		}
		else if ("color".equals(type)) {
			Color color = ColorUtils.getColor((Integer) val);
			list.setColor(name, color);
		}
		else if ("file".equals(type)) {
			File file = new File((String) val);
			list.setFile(name, file);
		}
		else if ("enum".equals(type)) {
			String sarifString = unEscapeElementEntities((String) val);
			@SuppressWarnings("rawtypes")
			Enum enuum = (Enum) OptionType.ENUM_TYPE.convertStringToObject(sarifString);
			list.setEnum(name, enuum);
		}
		else if ("font".equals(type)) {
			String sarifString = unEscapeElementEntities((String) val);
			Font font = (Font) OptionType.FONT_TYPE.convertStringToObject(sarifString);
			list.setFont(name, font);
		}
		else if ("keyStroke".equals(type)) {
			String sarifString = unEscapeElementEntities((String) val);
			KeyStroke keyStroke =
				(KeyStroke) OptionType.KEYSTROKE_TYPE.convertStringToObject(sarifString);

			ActionTrigger trigger = null;
			if (keyStroke != null) {
				trigger = new ActionTrigger(keyStroke);
			}
			list.setActionTrigger(name, trigger);
		}
		else if ("actionTrigger".equals(type)) {
			String sarifString = unEscapeElementEntities((String) val);
			ActionTrigger actionTrigger =
				(ActionTrigger) OptionType.ACTION_TRIGGER.convertStringToObject(sarifString);
			list.setActionTrigger(name, actionTrigger);
		}
		else if ("custom".equals(type)) {
			String sarifString = unEscapeElementEntities((String) val);
			CustomOption custom =
				(CustomOption) OptionType.CUSTOM_TYPE.convertStringToObject(sarifString);
			list.setCustomOption(name, custom);
		}
		else if ("bytes".equals(type)) {
			String sarifString = unEscapeElementEntities((String) val);
			byte[] bytes = (byte[]) OptionType.BYTE_ARRAY_TYPE.convertStringToObject(sarifString);
			list.setByteArray(name, bytes);
		}
		else {
			log.appendMsg("Unsupported PROPERTY usage");
		}
	}

	/////////////////////////////
	// SARIF WRITE CURRENT DTD //
	/////////////////////////////

	void write(JsonArray results, AddressSetView set, TaskMonitor monitor)
			throws IOException, CancelledException {
		monitor.setMessage("Writing PROPERTIES ...");

		List<String> request = program.getOptionsNames();

		writeAsSARIF(program, request, results);

		List<PropertyMap<?>> mapRequest = new ArrayList<>();
		Iterator<String> mapNames = propMapMgr.propertyManagers();
		while (mapNames.hasNext()) {
			monitor.checkCancelled();
			mapRequest.add(propMapMgr.getPropertyMap(mapNames.next()));
		}

		writeAsSARIF(program, set, mapRequest, results);
	}

	public static void writeAsSARIF(Program program, List<String> request, JsonArray results)
			throws IOException {
		SarifPropertyListWriter writer = new SarifPropertyListWriter(program, request, null);
		new TaskLauncher(new SarifWriterTask(SUBKEY, writer, results), null);
	}

	public static void writeAsSARIF(Program program, AddressSetView set,
			List<PropertyMap<?>> request, JsonArray results) throws IOException {
		SarifPropertyMapWriter writer = new SarifPropertyMapWriter(request, program, set, null);
		new TaskLauncher(new SarifWriterTask(SUBKEY, writer, results), null);
	}

}
