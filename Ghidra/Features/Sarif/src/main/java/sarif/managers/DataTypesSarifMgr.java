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

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.xml.sax.SAXParseException;

import com.google.gson.JsonArray;

import ghidra.app.util.importer.MessageLog;
import ghidra.docking.settings.Settings;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Dynamic;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.LongDoubleDataType;
import ghidra.program.model.data.PascalString255DataType;
import ghidra.program.model.data.PascalStringDataType;
import ghidra.program.model.data.PascalUnicodeDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.data.UnsignedInteger3DataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import sarif.SarifProgramOptions;
import sarif.export.SarifWriterTask;
import sarif.export.data.SarifDataTypeWriter;

/**
 * This manager is responsible for reading and writing datatypes in SARIF.
 */
public class DataTypesSarifMgr extends SarifMgr {

	public static String KEY = "DATATYPE";

	private final static int MAX_PASSES = 10;
	private final static int DEFAULT_SIZE = 1;

	private static Map<String, DataType> foreignTypedefs = Map.of("ascii", CharDataType.dataType, "string1",
			PascalString255DataType.dataType, "string2", PascalStringDataType.dataType,
			// string4 - pascal string with 4-byte length prefix
			"unicode2", PascalUnicodeDataType.dataType,
			// unicode4 - pascal unicode string with 4-byte length prefix
			"tbyte", LongDoubleDataType.dataType, // 10-byte float
			// oword - 16-byte value
			// packed real
			"3byte", UnsignedInteger3DataType.dataType);

	private DataTypeManager dataManager;
	private DtParser dtParser;
	private Map<String, DataType> dataTypes = new HashMap<>();
	private Map<String, Boolean> isPacked = new HashMap<>();
	private Map<String, Integer> packingValue = new HashMap<>();

	/**
	 * Constructs a new root types SARIF manager.
	 * 
	 * @param dataManager the root type manager to read from or write to
	 * @param log         the message log for recording datatype warnings
	 */
	public DataTypesSarifMgr(Program program, MessageLog log) {
		super(KEY, program, log);
		this.dataManager = program.getListing().getDataTypeManager();
	}

	////////////////////////////
	// SARIF READ CURRENT DTD //
	////////////////////////////

	@Override
	protected void readResults(List<Map<String, Object>> list, SarifProgramOptions options, TaskMonitor monitor)
			throws AddressFormatException, CancelledException {
		if (list != null) {
			monitor.setMessage("Processing " + key + "...");
			boolean processedAll;

			int pass = 0;
			do {
				monitor.setMaximum(list.size() * MAX_PASSES);
				monitor.checkCancelled();
				processedAll = true;
				for (Map<String, Object> result : list) {
					if (monitor.isCancelled()) {
						break;
					}
					boolean res = read(result, options, monitor);
					// if (!res) System.err.println(result);
					processedAll &= res;
					monitor.increment();
				}
				pass++;
			} while (!processedAll && pass < MAX_PASSES);
		} else {
			monitor.setMessage("Skipping over " + key + " ...");
		}
	}

	/**
	 * Reads the datatypes encoded in SARIF from the specified SARIF parser and
	 * recreates them in a datatype manager.
	 * 
	 * @param result  the SARIF parser
	 * @param monitor the task monitor
	 * @throws SAXParseException  if an SARIF parse error occurs
	 * @throws CancelledException if the user cancels the read operation
	 */
	@Override
	public boolean read(Map<String, Object> result, SarifProgramOptions options, TaskMonitor monitor)
			throws CancelledException {
		try {
			dtParser = new DtParser(dataManager);
			return process(result);
		} finally {
			dataManager.close();
			dtParser = null;
		}
	}

	private boolean process(Map<String, Object> result) {
		String name = (String) result.get("Message");

		try {
			if (name.equals("DT.Struct")) {
				return processStructure(result);
			}
			if (name.equals("DT.Union")) {
				return processUnion(result);
			}
			if (name.equals("DT.Enum")) {
				return processEnum(result);
			}
			if (name.equals("DT.Typedef")) {
				return processTypeDef(result);
			}
			if (name.equals("DT.TypedObject")) {
				return processTypedObject(result);
			}
			if (name.equals("DT.Builtin")) {
				return processBuiltin(result);
			}
			if (name.equals("DT.Function")) {
				return processFunctionDef(result);
			}
			log.appendMsg("Unrecognized datatype tag: " + name);
		} catch (Exception e) {
			log.appendException(e);
		}
		return true;
	}

	public void addDataType(String key, DataType dt) {
		Boolean packed = isPacked.get(key);
		if (packed != null) {
			Composite composite = (Composite) dt;
			composite.setPackingEnabled(packed);
			Integer packVal = packingValue.get(key);
			if (packVal != null) {
				composite.setExplicitPackingValue(packVal);
			}
		}
		dataTypes.put(key, dt);
		dataManager.addDataType(dt, DataTypeConflictHandler.REPLACE_HANDLER);
	}

	@SuppressWarnings("unchecked")
	private boolean processFunctionDef(Map<String, Object> result) throws InvalidInputException {
		boolean processedAll = true;
		String name = (String) result.get("name");
		CategoryPath path = getCategoryPath(result);
		FunctionDefinition fd = new FunctionDefinitionDataType(path, name, dataManager);
		processSettings(result, fd.getDefaultSettings());
		fd.setVarArgs((boolean) result.get("hasVarArgs"));
		fd.setNoReturn((boolean) result.get("hasNoReturn"));
		fd.setCallingConvention((String) result.get("callingConventionName"));

		dataTypes.put(getPath(fd), fd);

		Map<String, Object> retType = (Map<String, Object>) result.get("retType");
		DataType returnType = findDataType(retType);
		if (returnType != null) {
			fd.setReturnType(returnType);
		}

		List<Map<String, Object>> params = (List<Map<String, Object>>) result.get("params");
		for (Map<String, Object> param : params) {
			processedAll &= processFunctionMembers(param, fd);
		}

		addDataType(getPath(fd), fd);
		return processedAll;
	}

	@SuppressWarnings("unchecked")
	private boolean processEnum(Map<String, Object> result) {
		String name = (String) result.get("name");
		String enuumComment = (String) result.get("comment");
		CategoryPath cp = getCategoryPath(result);
		int size = (int) (double) result.get("size");

		EnumDataType enuum = new EnumDataType(cp, name, size, dataManager);
		processSettings(result, enuum.getDefaultSettings());

		enuum.setDescription(enuumComment);
		Map<String, Object> constants = (Map<String, Object>) result.get("constants");
		for (Entry<String, Object> entry : constants.entrySet()) {
			processEnumMembers(entry, enuum);
		}

		addDataType(getPath(enuum), enuum);
		return true;
	}

	private boolean processTypeDef(Map<String, Object> result) throws InvalidNameException, DuplicateNameException {
		String name = (String) result.get("name");
		// String displayName = (String) result.get("displayName");
		Boolean isAutoNamed = (Boolean) result.get("autoNamed");
		String typeLoc = (String) result.get("typeLocation");
		CategoryPath cp = typeLoc == null ? CategoryPath.ROOT : new CategoryPath(typeLoc);
		DataType dt = findDataType(result);
		if (dt == null) {
			log.appendMsg(name + " NOT FOUND");
			return false;
		}

		int dtSize = dt.getLength();
		int size = (int) (double) result.get("size");
		if (size != -1 && size != dtSize) {
			log.appendMsg("SIZE=" + result.get("size") + " specified on type-def " + name
					+ " does not agree with length of datatype " + dt.getPathName() + " (" + dtSize + ")");
		}

		cp = getCategoryPath(result);
		TypeDef td = new TypedefDataType(cp, name, dt, dataManager);
		processSettings(result, td.getDefaultSettings());
		if (isAutoNamed != null && isAutoNamed) {
			td.enableAutoNaming();
		}
		// if (displayName != null) {
		// td.setName(displayName);
		// }

		try {
			if (name.equals(dt.getPathName()) && dt instanceof TypeDef) {
				td = (TypeDef) dt;
			}
			td.setCategoryPath(cp);
			dt = td;
		} catch (DuplicateNameException e) {
			log.appendMsg("Unable to place typedef '" + name + "' in category '" + cp + "'");
		}

		addDataType(getPath(td), td);
		return true;
	}

	@SuppressWarnings("unchecked")
	private boolean processStructure(Map<String, Object> result) throws InvalidDataTypeException {
		String name = (String) result.get("name");
		CategoryPath path = getCategoryPath(result);
		int size = DEFAULT_SIZE;
		if (result.get("size") != null) {
			size = (int) (double) result.get("size");
		}
		Structure struct = new StructureDataType(path, name, size, dataManager);
		processSettings(result, struct.getDefaultSettings());

		String comment = getRegularComment(result);
		if (comment != null) {
			struct.setDescription(comment);
		}
		Object alignmentMin = result.get("explicitMinimumAlignment");
		if (alignmentMin != null) {
			struct.setExplicitMinimumAlignment((int) (double) alignmentMin);
		}
		
		String packing = (String) result.get("packed");
		if (packing != null) {
			isPacked.put(getPath(struct), Boolean.valueOf(packing));
			// NB: not this - struct.setPackingEnabled(Boolean.valueOf(packing));
			Object epval = result.get("explicitPackingValue");
			if (epval != null) {
				packingValue.put(getPath(struct), (int) (double) epval);
			}
		}

		dataTypes.put(getPath(struct), struct);

		boolean processedAll = true;
		Map<String, Object> fields = (Map<String, Object>) result.get("fields");
		for (Entry<String, Object> entry : fields.entrySet()) {
			processedAll &= processStructMembers(entry, struct);
		}
		if (processedAll) {
			addDataType(getPath(struct), struct);
		} else {
			dataTypes.put(getPath(struct), struct);
		}
		return processedAll;
	}

	@SuppressWarnings("unchecked")
	private boolean processUnion(Map<String, Object> result) throws InvalidDataTypeException {
		String name = (String) result.get("name");
		CategoryPath path = getCategoryPath(result);
		String comment = getRegularComment(result);
		Union union = new UnionDataType(path, name);
		processSettings(result, union.getDefaultSettings());

		if (comment != null) {
			union.setDescription(comment);
		}
		Object alignmentMin = result.get("explicitMinimumAlignment");
		if (alignmentMin != null) {
			union.setExplicitMinimumAlignment((int) (double) alignmentMin);
		}

		String packing = (String) result.get("packed");
		if (packing != null) {
			isPacked.put(getPath(union), Boolean.valueOf(packing));
			// NB: not this - struct.setPackingEnabled(Boolean.valueOf(packing));
			Object epval = result.get("explicitPackingValue");
			if (epval != null) {
				packingValue.put(getPath(union), (int) (double) epval);
			}
		}

		dataTypes.put(getPath(union), union);

		boolean processedAll = true;
		Map<String, Object> fields = (Map<String, Object>) result.get("fields");
		for (Entry<String, Object> entry : fields.entrySet()) {
			processedAll &= processUnionMembers(entry, union);
		}
		if (processedAll) {
			addDataType(getPath(union), union);
		} else {
			dataTypes.put(getPath(union), union);
		}
		return processedAll;
	}

	@SuppressWarnings("unchecked")
	private boolean processTypedObject(Map<String, Object> result) {
		// String name = (String) result.get("name");
		CategoryPath cp = new CategoryPath((String) result.get("typeLocation"));
		String kind = (String) result.get("kind");
		int size = (int) (double) result.get("size");

		Map<String, Object> type = (Map<String, Object>) result.get("type");
		DataType baseType = findDataType(type, cp);
		if (baseType != null) {
			if (kind.equals("pointer")) {
				DataType p = new PointerDataType(baseType, size, dataManager);
				addDataType(getPath(p), p);
				return true;
			}
			throw new RuntimeException("Unexpected baseType kind=" + kind);
		}
		return false;
	}

	private boolean processBuiltin(Map<String, Object> result) {
		String name = (String) result.get("name");
		CategoryPath cp = getCategoryPath(result);
		DataType dt = findDataType(result, cp);
		if (dt != null) {
			addDataType(getPath(cp, name), dt);
			return true;
		}
		return false;
	}

	private String getRegularComment(Map<String, Object> result) {
		return (String) result.get("comment");
	}

	private boolean processFunctionMembers(Map<String, Object> param, FunctionDefinition fn) {
		DataType dt = findDataType(param);
		if (dt != null) {
			int ordinal = (int) (double) param.get("ordinal");
			String name = (String) param.get("name");
			String comment = (String) param.get("comment");
			int size = dt.getLength();
			if (size <= 0) {
				size = (int) (double) param.get("size");
			}
			fn.replaceArgument(ordinal, name, dt, comment, SourceType.USER_DEFINED);
			return true;
		}
		return false;
	}

	private void processEnumMembers(Entry<String, Object> entry, Enum enuum) {
		String entryName = (String) entry.getKey();
		Long entryValue = (long) (double) entry.getValue();
		enuum.add(entryName, entryValue, null);
	}

	@SuppressWarnings("unchecked")
	private boolean processStructMembers(Entry<String, Object> entry, Structure struct)
			throws InvalidDataTypeException {
		boolean processedAll = true;
		Map<String, Object> field = (Map<String, Object>) entry.getValue();
		int offset = (int) (double) field.get("offset");
		Map<String, Object> type = (Map<String, Object>) field.get("type");
		DataType memberDT = findDataType(type);
		if (memberDT != null) {
			processSettings(type, memberDT.getDefaultSettings());
			if (memberDT instanceof Dynamic dynamicDT) {
				if (!dynamicDT.canSpecifyLength()) {
					return false;
				}
			} else if (memberDT.getLength() <= 0) {
				return false;
			}
			String memberName = entry.getKey();
			Boolean noFieldName = (Boolean) field.get("hasNoFieldName");
			if (noFieldName != null && noFieldName) {
				memberName = null;
			}
			String memberComment = (String) field.get("comment");
			int compSize = (int) (double) field.get("length");

			// NOTE: Size consistency checking was removed since some types are filled-out
			// lazily and may not have there ultimate size at this point.

			if (field.get("bitOffset") != null) {
				int bitOffset = (int) (double) field.get("bitOffset");
				int bitSize = (int) (double) field.get("bitSize");
				// NB: we're using "insert" and the team has suggested "add" is a better choice,
				// but, because of the multi-pass approach, I don't think I can guarantee an
				// in-order load.
				DataTypeComponent dtc = struct.insertBitFieldAt(offset, memberDT.getLength(), bitOffset, memberDT,
						bitSize, memberName, memberComment);
				processSettings(field, dtc.getDefaultSettings());
				return processedAll;
			}

			DataTypeComponent dtc;
			if (offset == struct.getLength()) {
				dtc = struct.add(memberDT, compSize, memberName, memberComment);
			} else {
				dtc = struct.replaceAtOffset(offset, memberDT, compSize, memberName, memberComment);
			}

			processSettings(field, dtc.getDefaultSettings());
		} else {
			processedAll = type.get("kind").equals("pointer");
		}
		return processedAll;
	}

	@SuppressWarnings("unchecked")
	private boolean processUnionMembers(Entry<String, Object> entry, Union union) throws InvalidDataTypeException {
		boolean processedAll = true;
		Map<String, Object> member = (Map<String, Object>) entry.getValue();
		String memberName = (String) entry.getKey();
		Boolean noFieldName = (Boolean) member.get("hasNoFieldName");
		if (noFieldName != null && noFieldName) {
			memberName = null;
		}

		Map<String, Object> type = (Map<String, Object>) member.get("type");
		DataType memberDT = findDataType(type);
		if (memberDT != null) {
			processSettings(type, memberDT.getDefaultSettings());
			String memberComment = (String) member.get("comment");
			int dtSize = memberDT.getLength();
			if (member.get("bitSize") != null) {
				int bitSize = (int) (double) member.get("bitSize");
				union.addBitField(memberDT, bitSize, memberName, memberComment);
				return processedAll;
			}
			DataTypeComponent dtc = union.add(memberDT, dtSize, memberName, memberComment);
			processSettings(member, dtc.getDefaultSettings());
		}
		return processedAll;
	}

	private CategoryPath getCategoryPath(Map<String, Object> result) {
		String nameSpace = (String) result.get("location");
		CategoryPath cp = nameSpace == null ? CategoryPath.ROOT : new CategoryPath(nameSpace);
		return cp;
	}

	@SuppressWarnings("unchecked")
	private void processSettings(Map<String, Object> result, Settings defaultSettings) {
		List<Map<String, Object>> settings = (List<Map<String, Object>>) result.get("settings");
		if (settings != null) {
			for (Map<String, Object> map : settings) {
				String settingName = (String) map.get("name");
				String settingValue = (String) map.get("value");
				if (map.get("kind").equals("long")) {
					long val = 0;
					try {
						val = Long.valueOf(settingValue);
					} catch (NumberFormatException nfe) {
						Msg.error(this, nfe);
					}
					if (!settingName.equals("ptr_type")) {
						defaultSettings.setLong(settingName, val);
					}
				} else {
					defaultSettings.setString(settingName, settingValue);
				}
			}
		}
	}

	@SuppressWarnings("unchecked")
	private DataType findDataType(Map<String, Object> type) {
		String loc = (String) type.get("location");
		if (loc == null) {
			Map<String, Object> subtype = (Map<String, Object>) type.get("subtype");
			if (subtype != null) {
				loc = (String) subtype.get("location");
			}
		}
		return findDataType(type, new CategoryPath(loc));
	}

	@SuppressWarnings("unchecked")
	private DataType findDataType(Map<String, Object> type, CategoryPath cp) {
		String kind = (String) type.get("kind");
		String name = (String) type.get("name");
		if (kind == null) {
			return null;
		}
		if (kind.equals("pointer") || (kind.equals("array"))) {
			DataType byName = findExistingDataType(cp, kind, name);
			if (byName != null) {
				if (byName instanceof FunctionDefinition) {
					return new PointerDataType(byName, dataManager);
				}
				return byName;
			}
			Map<String, Object> subtype = (Map<String, Object>) type.get("subtype");
			if (subtype != null) {
				DataType base = findDataType(subtype, cp);
				if (base == null) {
					return null;
					// throw new RuntimeException("Subtype not found: " + subtype);
				}
				if (kind.equals("pointer")) {
					return new PointerDataType(base, dataManager);
				} else {
					int count = (int) (double) type.get("count");
					return new ArrayDataType(base, count, base.getLength(), dataManager);
				}
			}
		}
		if (name == null) {
			return null;
		}
		if (kind.equals("typedef")) {
			Map<String, Object> subtype = (Map<String, Object>) type.get("type");
			String typeName = (String) type.get("typeName");
			if (typeName != null) {
				cp = new CategoryPath((String) type.get("typeLocation"));
				name = typeName;
			} else if (subtype != null) {
				DataType base = findDataType(subtype);
				if (base == null) {
					return null;
				}
				return base;
			}
		}
		if (kind.equals("bitfield")) {
			Map<String, Object> subtype = (Map<String, Object>) type.get("type");
			String typeName = (String) type.get("typeName");
			if (typeName != null) {
				cp = new CategoryPath((String) type.get("typeLocation"));
				name = typeName;
			} else if (subtype != null) {
				DataType base = findDataType(subtype);
				if (base == null) {
					return null;
				}
				return base;
			}
		}
		return findExistingDataType(cp, kind, name);
	}

	private DataType findExistingDataType(CategoryPath cp, String kind, String name) {
		DataType dt = dtParser.parseDataType(name, cp, -1);
		if (dt == null && addForeignTypedefIfNeeded(name)) {
			dt = dtParser.parseDataType(name, cp, -1);
		}
		if (dt != null) {
			return dt;
		}
		dt = dataTypes.get(getPath(cp, name));
		if (dt == null && kind.equals("typedef")) {
			dt = dataTypes.get(cp + "/functions/" + name);
		}
		if (dt != null) {
			return dt;
		}
		return dataTypes.get("/" + name);
	}

	private boolean addForeignTypedefIfNeeded(String dtName) {
		int ptrIndex = dtName.indexOf('*');
		int index = dtName.indexOf('[');
		String baseName = dtName.trim();
		if (index < 0 || index > ptrIndex) {
			index = ptrIndex;
		}
		if (index > 0) {
			baseName = dtName.substring(0, index).trim();
		}
		DataType ourType = foreignTypedefs.get(baseName);
		if (ourType != null && dataManager.getDataType("/" + baseName) == null) {
			TypedefDataType newTypedef = new TypedefDataType(CategoryPath.ROOT, baseName, ourType, dataManager);
			dataManager.resolve(newTypedef, null);
			return true;
		}
		return false;
	}

	private String getPath(DataType dt) {
		String displayName = dt.getPathName();
		String path = dt.getCategoryPath().getPath();
		if (!path.equals("/")) {
			path += "/";
		}
		return path + displayName;
	}

	private String getPath(CategoryPath cp, String displayName) {
		String path = cp.getPath();
		if (!path.equals("/")) {
			path += "/";
		}
		return path + displayName;
	}

	/////////////////////////////
	// SARIF WRITE CURRENT DTD //
	/////////////////////////////

	/**
	 * Writes datatypes into SARIF using the specified SARIF writer.
	 * 
	 * @param results the SARIF writer
	 * @param monitor the task monitor
	 * @throws CancelledException if the user cancels the write operation
	 */
	public void write(JsonArray results, TaskMonitor monitor) throws IOException, CancelledException {
		monitor.setMessage("Writing DATA TYPES ...");

		List<DataType> dataTypeList = new ArrayList<>();
		dataManager.getAllDataTypes(dataTypeList);

		writeAsSARIF(program, dataTypeList, results);
	}

	public static void writeAsSARIF(Program program, List<DataType> dataTypeList, JsonArray results)
			throws IOException {
		SarifDataTypeWriter writer = new SarifDataTypeWriter(program.getDataTypeManager(), dataTypeList, null);
		new TaskLauncher(new SarifWriterTask("DataTypes", writer, results), null);
	}

}
