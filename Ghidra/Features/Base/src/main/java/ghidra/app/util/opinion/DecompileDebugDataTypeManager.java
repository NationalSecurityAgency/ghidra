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
/**
 * 
 */
package ghidra.app.util.opinion;

import static ghidra.program.model.pcode.AttributeId.*;

import java.math.BigInteger;
import java.util.Map;
import java.util.TreeMap;

import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.AttributeId;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.*;

/**
 * Manager for parsing and storing data type objects from the XML - identified by 
 * the {@code <coretypes>} and {@code <typegrp>} tags. 
 * 
 * NOTE: In the typegrp subtree, ID is often on a different line from the element's name and 
 * metatype, so we need a way to reference this for use in the map -- String idHolder var 
 * helps with this.
 */
public class DecompileDebugDataTypeManager {

	TaskMonitor monitor;
	Program prog;
	Map<DataTypeKey, DataType> dataTypeMap;
	DataTypeManager programDataManager;
	BuiltInDataTypeManager builtInMngr = BuiltInDataTypeManager.getDataTypeManager();
	private String idHolder;

	/**
	 * @param monitor TaskMonitor
	 * @param prog main program info
	 */
	public DecompileDebugDataTypeManager(TaskMonitor monitor, Program prog) {
		this.monitor = monitor;
		this.prog = prog;
		this.dataTypeMap = new TreeMap<DataTypeKey, DataType>();
		programDataManager = this.prog.getListing().getDataTypeManager();
	}

	/**
	 * Parse Data Type tag, handling types:
	 * <ul>
	 * <li>{@code <type>}</li>
	 * <li>{@code <typeref>}</li>
	 * <li>{@code <def>}</li>
	 * <li>{@code <void>}</li>
	 * </ul>
	 * 
	 * @param parser XmlPullParser
	 * @param log XmlMessageLog
	 * @return retrieved DataType 
	 */
	public DataType parseDataTypeTag(XmlPullParser parser, XmlMessageLog log) {

		String tagName = parser.peek().getName();
		DataType retrieved = null;
		switch (tagName) {
			case "type":
				retrieved = parseType(parser, log);
				break;
			case "typeref":
				retrieved = parseRefType(parser, log);
				break;
			case "def":
				retrieved = parseDef(parser, log);
				break;
			case "void":
				XmlElement voidElement = parser.start("void");
				parser.end(voidElement);
				return new VoidDataType();
			default:
				log.appendMsg(parser.getLineNumber(), "Level " + parser.getCurrentLevel() +
					" tag not currently supported: " + tagName);
				parser.discardSubTree();
		}
		return retrieved;
	}

	/**
	 * Parse the {@code <type>} tag
	 *  
	 * @param parser XmlPullParser
	 * @param log XmlMessageLog
	 */
	private DataType parseType(XmlPullParser parser, XmlMessageLog log) {

		DataType retrieved = null;
		String metatype = parser.peek().getAttribute("metatype");
		if (metatype == null) { // in the typegrp subtree, metatype and name/id are not on the same line
			retrieved = retreiveBaseType(parser, log);
			return retrieved;
		}
		switch (metatype) {
			case "ptr":
				retrieved = parsePointer(parser, log);
				break;
			case "ptrrel":
				retrieved = parsePointerRelative(parser, log);
				break;
			case "array":
				retrieved = parseArray(parser, log);
				break;
			case "struct":
				retrieved = parseStruct(parser, log);
				break;
			case "union":
				retrieved = parseUnion(parser, log);
				break;
			case "enum_int":
			case "enum_uint":
				retrieved = parseEnum(parser, log);
				break;
			default:
				retrieved = retreiveBaseType(parser, log);
		}
		return retrieved;
	}

	/**
	 * TypeDefs ({@cod <def>} tags) are new definitions of types - basically, a re-naming.
	 * 
	 * @param parser XmlPullParser
	 * @param log XmlMessageLog
	 * 
	 * @return retrieved DataType
	 */
	private DataType parseDef(XmlPullParser parser, XmlMessageLog log) {
		XmlElement defElement = parser.start("def");
		DataTypeKey key = new DataTypeKey(defElement);

		if (!dataTypeMap.containsKey(key)) {
			DataType typeDefedType = parseDataTypeTag(parser, log);
			TypedefDataType generatedTypeDef = new TypedefDataType(
				new CategoryPath(CategoryPath.ROOT + key.name()), key.name(), typeDefedType,
				programDataManager);
			DataType resolvedDT = resolveAndMapDataType(key, generatedTypeDef);
			parser.end(defElement);
			return resolvedDT;
		}
		return dataTypeMap.get(key);
	}

	/**
	 * Parse and handle enum types - signed/unsigned
	 * @param parser XmlPullParser
	 * @param log XmlMessageLog 
	 *
	 * @return resolved DataType
	 */
	private DataType parseEnum(XmlPullParser parser, XmlMessageLog log) {
		XmlElement enumElement = parser.start("type");
		DataTypeKey key = new DataTypeKey(enumElement);
		int length = SpecXmlUtils.decodeInt(enumElement.getAttribute(ATTRIB_SIZE.name()));
		Enum enumDT = null;

		if (dataTypeMap.containsKey(key) == false) {
			enumDT = new EnumDataType(new CategoryPath(CategoryPath.ROOT + key.name()), key.name(),
				length,
				programDataManager);
			enumDT =
				(Enum) resolveAndMapDataType(key, enumDT);
		}
		else {
			enumDT = (Enum) dataTypeMap.get(key);
		}

		while (parser.peek().getName().equals(ATTRIB_VAL.name())) {
			XmlElement valElement = parser.start(ATTRIB_VAL.name());

			enumDT.add(valElement.getAttribute(ATTRIB_NAME.name()),
				SpecXmlUtils.decodeInt(valElement.getAttribute(ATTRIB_VALUE.name())), "");
			parser.end(valElement);
		}
		parser.end(enumElement);
		return enumDT;
	}

	/**
	 * Parse and create union types 
	 * @param parser XmlPullParser
	 * @param log XmlMessageLog 
	 * 
	 * @return resolved DataType
	 */
	private DataType parseUnion(XmlPullParser parser, XmlMessageLog log) {
		XmlElement unionElement = parser.start("type");
		DataTypeKey key = new DataTypeKey(unionElement);
		int size = SpecXmlUtils.decodeInt(unionElement.getAttribute(ATTRIB_SIZE.name()));
		Union unionDT = null;

		if (dataTypeMap.containsKey(key) == false) {
			unionDT =
				new UnionDataType(new CategoryPath(CategoryPath.ROOT + key.name()), key.name(),
					programDataManager);
			unionDT = (Union) resolveAndMapDataType(key, unionDT);
		}
		else {
			unionDT = (Union) dataTypeMap.get(key);
		}

		if (unionElement.hasAttribute(ATTRIB_INCOMPLETE.name()) || size == 0) {
			parser.end(unionElement);
			return unionDT;
		}

		while (parser.peek().getName().equals("field")) {
			XmlElement fieldElement = parser.start("field");
			DataType fieldDT = parseDataTypeTag(parser, log);
			unionDT.add(fieldDT, fieldDT.getLength(), key.name(), "");
			parser.end(fieldElement);
		}
		parser.end(unionElement);
		return unionDT;
	}

	/**
	 * Parse and process Array Data Type
	 * @param parser XmlPullParser
	 * @param log XmlMessageLog
	 * 
	 * @return DataType 
	 */
	private DataType parseArray(XmlPullParser parser, XmlMessageLog log) {
		XmlElement arrayElement = parser.start("type");
		int arraySize =
			SpecXmlUtils.decodeInt(arrayElement.getAttribute(AttributeId.ATTRIB_ARRAYSIZE.name()));

		DataType baseType = parseDataTypeTag(parser, log);
		ArrayDataType arrayDT =
			new ArrayDataType(baseType, arraySize, baseType.getLength(), programDataManager);
		DataType resolved = resolveAndMapDataType(
			new DataTypeKey(baseType.getName() + "array", idHolder), arrayDT);
		parser.end(arrayElement);
		return resolved;
	}

	/**
	 * Handle parsing and creating a pointer data type. Add to the programDataManager and the 
	 * DataTypeMap for use later.
	 * @param parser XmlPullParser
	 * @param log XmlMessageLog
	 * @return generated pointer data type
	 */
	private DataType parsePointer(XmlPullParser parser, XmlMessageLog log) {
		XmlElement pointerElement = parser.start("type");
		int size = SpecXmlUtils.decodeInt(pointerElement.getAttribute(ATTRIB_SIZE.name()));

		DataType baseType = parseDataTypeTag(parser, log);
		PointerDataType pointerDT = new PointerDataType(baseType, size, programDataManager);
		DataType resolved =
			resolveAndMapDataType(new DataTypeKey(baseType.getName() + "ptr", idHolder),
				pointerDT);

		parser.end(pointerElement);
		return resolved;
	}

	/**
	 * Parse and handle 'pointer with offset' data types: PointerTypeDef {@PointerTypedef.java line #91}.
	 * These are useful for labeling a variable that points into the interior of a structure, 
	 * but where the compiler still knows it can access the whole structure.
	 * 
	 * @param parser XmlPullParser
	 * @param log XmlMessageLog
	 * @return DataType - PointerTypeDef
	 */
	private DataType parsePointerRelative(XmlPullParser parser, XmlMessageLog log) {
		XmlElement pointerRelElement = parser.start("type");
		int size = SpecXmlUtils.decodeInt(pointerRelElement.getAttribute(ATTRIB_SIZE.name()));
		Long offset = SpecXmlUtils.decodeLong(pointerRelElement.getAttribute(ATTRIB_OFF.name()));

		DataType baseType = parseDataTypeTag(parser, log);
		PointerTypedef relPointerDT =
			new PointerTypedef(baseType.getName(), baseType, size, programDataManager, offset);
		
		DataType resolved = resolveAndMapDataType(new DataTypeKey(baseType.getName()+"relptr", idHolder), relPointerDT);
		parser.end(pointerRelElement);

		return resolved;
	}

	/**
	 * Handle parsing and generating a struct type; populating it with fields.
	 * 
	 * @param parser XmlPullParser
	 * @param log XmlMessageLog
	
	 * @return Structure data type - either an empty one or completed one with fields 
	 */
	private DataType parseStruct(XmlPullParser parser, XmlMessageLog log) {
		XmlElement structElement = parser.start("type");
		DataTypeKey key = new DataTypeKey(structElement);
		int size = SpecXmlUtils.decodeInt(structElement.getAttribute(ATTRIB_SIZE.name()));
		Structure createdStruct = null;

		if (dataTypeMap.containsKey(key) == false) {
			StructureDataType newStruct =
				new StructureDataType(key.name(), size, programDataManager);
			createdStruct = (Structure) resolveAndMapDataType(key, newStruct);
		}
		else {
			createdStruct =
				(Structure) dataTypeMap.get(key);
		}

		if (structElement.hasAttribute(ATTRIB_INCOMPLETE.name()) || size == 0) {
			parser.end(structElement);
			return createdStruct;
		}

		while (parser.peek().getName().equals("field")) {
			XmlElement fieldElement = parser.start("field");
			int fieldOffset =
				SpecXmlUtils.decodeInt(fieldElement.getAttribute(ATTRIB_OFFSET.name()));

			DataType fieldDT = parseDataTypeTag(parser, log);
			createdStruct.replaceAtOffset(fieldOffset, fieldDT, fieldDT.getLength(),
				fieldElement.getAttribute(ATTRIB_NAME.name()), "");
			parser.end(fieldElement);
		}
		parser.end(structElement);

		return createdStruct;

	}

	/**
	 * The type should already exist in the map and in the Program's data type manager. 
	 * If it's not there, this is an error.
	 * 
	 * @param parser XmlPullParser
	 * @param log XmlMessageLog
	 *
	 * @return retrieved DataType or null if it's not actually in the map (this should never happen)
	 */
	private DataType parseRefType(XmlPullParser parser, XmlMessageLog log) {
		XmlElement typeRefElement = parser.start("typeref");
		DataTypeKey key = new DataTypeKey(typeRefElement);
		DataType dt = dataTypeMap.get(key);

		if (dt == null) {
			log.appendMsg("Data Type referenced without first being created.");
		}
		parser.end(typeRefElement);
		return dt;
	}

	/**
	 * Pull the core type from the data type map 
	 * @param parser XmlPullParser
	 * @param log XmlMessageLog
	 * 
	 * @return Retrieved DataType 
	 */
	private DataType retreiveBaseType(XmlPullParser parser, XmlMessageLog log) {
		XmlElement typeElement = parser.start("type");
		DataType retrieved = null;
		DataTypeKey key = new DataTypeKey(typeElement);
		// We need to be able to reference the current ID when building composite DTs
		idHolder = key.id();

		if (dataTypeMap.containsKey(key)) {
			retrieved = dataTypeMap.get(key);
		}
		else {
			retrieved = builtInMngr.getDataType(CategoryPath.ROOT, key.name().toLowerCase()); // there are some cases where the DT name is defined in lowercase and then later referred inconsistently
			if (retrieved != null) {
				retrieved = resolveAndMapDataType(key, retrieved);
			}
			else {
				log.appendMsg("Type tag " + key.name() + " didn't resolve");
			}
		}
		parser.end(typeElement);
		return retrieved;
	}

	/**
	 * Resolve the provided DataType against the Program Manager then add it to the DataTypeMap 
	 * for referencing later.
	 * @param key DataTypeKey consisting of a name and ID for referencing
	 * @param generatedTypeDef DataType identified Data Type for resolving and mapping
	 * 
	 * @return resolved DataType
	 */
	private DataType resolveAndMapDataType(DataTypeKey key, DataType generatedTypeDef) {

		DataType resolvedDT = programDataManager.resolve(generatedTypeDef, dtConflictHandler);
		dataTypeMap.put(key, resolvedDT);
		return resolvedDT;
	}

	public static DataTypeConflictHandler dtConflictHandler = new DataTypeConflictHandler() {

		@Override
		public ConflictResult resolveConflict(DataType addedDataType, DataType existingDataType) {
			return ConflictResult.RENAME_AND_ADD;
		}

		@Override
		public boolean shouldUpdate(DataType sourceDataType, DataType localDataType) {
			return true;
		}

		@Override
		public DataTypeConflictHandler getSubsequentHandler() {
			return DEFAULT_HANDLER;
		}

	};

	/**
	 * Data Types are organized by their name and ID; utilize a combo key structure for this organization
	 *  Name, ID -> DataType
	 * @param name String data type name
	 * @param id String data type id
	 * @param val BigInteger to account for ID's that aren't written in Hex.
	 */
	static record DataTypeKey(String name, String id, BigInteger val)
			implements Comparable<DataTypeKey> {

		public DataTypeKey(XmlElement typeRefElement) {
			this(typeRefElement.getAttribute(ATTRIB_NAME.name()),
				typeRefElement.getAttribute(ATTRIB_ID.name()));
		}

		public DataTypeKey(String name, String id) {
			this(name, id,
				(id.startsWith("0x") ? new BigInteger(id.substring(2), 16)
						: new BigInteger(id, 10)));
		}

		public DataTypeKey(String name, String id, BigInteger val) {
			this.name = name;
			this.id = id;
			this.val = val;
		}

		@Override
		public int compareTo(DataTypeKey other) {
			int nameCompare = this.name.compareTo(other.name);
			if (nameCompare != 0) {
				return nameCompare;
			}
			return (int) (this.val.longValue() - other.val.longValue());
		}
	}

}
