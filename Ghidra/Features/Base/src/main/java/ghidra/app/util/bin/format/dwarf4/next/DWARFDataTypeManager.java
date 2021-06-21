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
package ghidra.app.util.bin.format.dwarf4.next;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.bin.format.dwarf4.*;
import ghidra.app.util.bin.format.dwarf4.encoding.DWARFEncoding;
import ghidra.app.util.bin.format.dwarf4.encoding.DWARFTag;
import ghidra.app.util.bin.format.dwarf4.expression.DWARFExpressionException;
import ghidra.app.util.bin.format.dwarf4.next.DWARFDataTypeImporter.DWARFDataType;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import utility.function.Dummy;

/**
 * Manages mappings between DWARF DIEs and Ghidra DataTypes.
 */
public class DWARFDataTypeManager {

	private final DataTypeManager dataTypeManager;
	private final DataTypeManager builtInDTM;
	private final DWARFProgram prog;
	private final DWARFImportSummary importSummary;

	/**
	 * Maps DWARF DIE offsets to Ghidra {@link DataType datatypes}, using the
	 * path/name of the datatype instead of live object (to avoid issues with
	 * stale objects)
	 */
	private Map<Long, DataTypePath> offsetToDTP = new HashMap<>();

	private Map<DataTypePath, DWARFSourceInfo> dtpToSourceInfo = new HashMap<>();

	/**
	 * Mapping of base type names to their Ghidra datatype.
	 * <p>
	 * Non-standard base-type names (created on the fly) will have a
	 * {@link #BASETYPE_MANGLE_PREFIX mangling} applied to them to keep them
	 * unique.
	 */
	private Map<String, DataType> baseDataTypes = new HashMap<>();
	private static final String BASETYPE_MANGLE_PREFIX = "__MANGLE__";

	private DataType baseDataTypeVoid;
	private DataType baseDataTypeNullPtr;
	private DataType baseDataTypeBool;
	private DataType baseDataTypeChar;
	private DataType baseDataTypeUchar;
	private DataType baseDataTypeFloats[];
	private DataType baseDataTypeSignedInts[];
	private DataType baseDataTypeUnsignedInts[];
	private DataType baseDataTypeUntyped[];
	private DataType baseDataTypeChars[];
	private DataType baseDataTypeUndefined1;

	/**
	 * Creates a new {@link DWARFDataTypeManager} instance.
	 *
	 * @param prog {@link DWARFProgram} that holds the Ghidra {@link Program} being imported.
	 * @param dataTypeManager {@link DataTypeManager} of the Ghidra Program.
	 * @param builtInDTM {@link DataTypeManager} with built-in data types.
	 * @param importSummary {@link DWARFImportSummary} where summary information will be stored
	 * during the import session.
	 */
	public DWARFDataTypeManager(DWARFProgram prog, DataTypeManager dataTypeManager,
			DataTypeManager builtInDTM, DWARFImportSummary importSummary) {
		this.prog = prog;
		this.dataTypeManager = dataTypeManager;
		this.builtInDTM = builtInDTM;
		this.importSummary = importSummary;
		initBaseDataTypes();
	}

	/**
	 * Creates a {@link DataType} from the DWARF {@link DIEAggregate DIEA}, or returns a
	 * pre-existing {@link DataType} created by the specified DIEA previously.
	 * <p>
	 * Creating a new DataType happens in two stages, where the DataType is created as
	 * an 'impl' DataType first (possibly representing a large graph of referred-to datatypes),
	 * and then it is submitted to the {@link DataTypeManager} to be added to the database and
	 * converted to a 'db' object.
	 * <p>
	 * Mapping from the DIEA's offset to the resultant 'db' DataType object is a two step
	 * process.
	 * <p>
	 * A {@link DataTypeGraphComparator} is used to walk the 'impl' DataType object graph
	 * in lock-step with the resultant 'db' DataType object graph, and the mapping between
	 * the 'impl' object and its creator DIEA (held in {@link DWARFDataType})
	 * is used to create a mapping to the resultant 'db' DataType's path.
	 *
	 * @param diea DWARF {@link DIEAggregate} with datatype information that needs to be converted
	 * to a Ghidra DataType.
	 * @return {@link DataType} that is ready to use.
	 * @throws IOException if problem
	 * @throws DWARFExpressionException if problem
	 */
	public DataType doGetDataType(DIEAggregate diea) throws IOException, DWARFExpressionException {

		// Wait for the swing thread to clear its event queue because we are running into
		// issues with the number of events overwhelming the swing thread.
		// This does slow us down a little bit but this makes the GUI responsive to the user.
		Swing.runNow(Dummy.runnable());

		DWARFDataTypeImporter ddtImporter =
			new DWARFDataTypeImporter(prog, this, prog.getImportOptions());

		// Convert the DWARF DIE record into a Ghidra DataType (probably impls)
		DWARFDataType pre = ddtImporter.getDataType(diea, null);
		if (pre == null) {
			return null;
		}

		// Commit the DataType to the database
		DataType post =
			dataTypeManager.resolve(pre.dataType, DWARFDataTypeConflictHandler.INSTANCE);

		// While walking the pre and post DataType graph in lockstep, use the mapping of
		// pre_impl->offset to cache offset->post_datatype for later re-use.
		DataTypeGraphComparator.compare(pre.dataType, post, (dt1, dt2) -> {

			DWARFDataType currentDDT = ddtImporter.getDDTByInstance(dt1);

			// if we find the pre_datatype metadata, add permanent mapping
			// of offset->db_datatype
			if (currentDDT != null) {
				if (currentDDT.dataType == dt1) {
					for (Long offset : currentDDT.offsets) {
						cacheOffsetToDataTypeMapping(offset, dt2);
					}
				}
				saveDWARFSourceInfo(dt2, currentDDT.dsi);
			}

			return true;
		});

		cacheOffsetToDataTypeMapping(diea.getOffset(), post);
		saveDWARFSourceInfo(post, pre.dsi);

		return post;
	}

	public void addDataType(long offset, DataType dataType, DWARFSourceInfo dsi) {
		cacheOffsetToDataTypeMapping(offset, dataType);
		saveDWARFSourceInfo(dataType, dsi);
	}

	private void saveDWARFSourceInfo(DataType dt, DWARFSourceInfo dsi) {
		if (dsi != null && isGoodDWARFSourceInfo(dsi) &&
			!dtpToSourceInfo.containsKey(dt.getDataTypePath())) {
			dtpToSourceInfo.put(dt.getDataTypePath(), dsi);
		}
	}

	public List<DataTypePath> getImportedTypes() {
		return new ArrayList<>(dtpToSourceInfo.keySet());
	}

	public DWARFSourceInfo getSourceInfo(DataType dataType) {
		return dtpToSourceInfo.get(dataType.getDataTypePath());
	}

	private boolean isGoodDWARFSourceInfo(DWARFSourceInfo dsi) {
		return dsi.getFilename() != null && !dsi.getFilename().isEmpty() &&
			!dsi.getFilename().contains("built-in");
	}

	private void cacheOffsetToDataTypeMapping(long dieOffset, DataType dt) {
		DataTypePath dtp = dt.getDataTypePath();
		DataTypePath prevDTP = offsetToDTP.get(dieOffset);
		if (prevDTP != null) {
			if (prevDTP.equals(dtp)) {
				return;
			}

			importSummary.typeRemappings.add(prevDTP + " -> " + dtp);
		}
		offsetToDTP.put(dieOffset, dtp);
	}

	/**
	 * Returns a Ghidra {@link DataType} corresponding to the specified {@link DIEAggregate},
	 * or the specified defaultValue if the DIEA param is null or does not map to an already
	 * defined datatype (registered with {@link #addDataType(long, DataType, DWARFSourceInfo)}).
	 * <p>
	 * @param diea {@link DIEAggregate} that defines a data type
	 * @param defaultValue Ghidra {@link DataType} to return if the specified DIEA is null
	 * or not already defined.
	 * @return Ghidra {@link DataType}
	 */
	public DataType getDataType(DIEAggregate diea, DataType defaultValue) {
		if (diea == null) {
			return defaultValue;
		}

		DataType result = null;
		DataTypePath dtp = offsetToDTP.get(diea.getOffset());
		if (dtp != null) {
			result = dataTypeManager.getDataType(dtp);
		}
		if (result == null) {
			try {
				result = doGetDataType(diea);
			}
			catch (IOException | DWARFExpressionException e) {
				Msg.error(this, "Problem while retrieving data type in DIE " + diea.getOffset(), e);
				Msg.error(this, "DIE info: " + diea.toString());
			}
		}
		return (result != null) ? result : defaultValue;
	}

	/**
	 * Returns a Ghidra {@link DataType} corresponding to the specified DIE (based on its
	 * offset), or the specified defaultValue if the DIE does not map to a defined
	 * datatype (registered with {@link #addDataType(long, DataType, DWARFSourceInfo)}).
	 * <p>
	 *
	 * @param dieOffset offset of a DIE record that defines a data type
	 * @param defaultValue Ghidra {@link DataType} to return if the specified DIE not already defined.
	 * @return Ghidra {@link DataType}
	 */
	public DataType getDataType(long dieOffset, DataType defaultValue) {
		DataTypePath dtp = offsetToDTP.get(dieOffset);
		DataType result = (dtp != null) ? dataTypeManager.getDataType(dtp) : null;
		return (result != null) ? result : defaultValue;
	}

	public <T extends DataType> T getSpecificDataType(DIEAggregate diea, Class<T> dataTypeClazz) {
		DataType dt = getDataType(diea, null);
		if (dt != null && dataTypeClazz != null && dataTypeClazz.isInstance(dt)) {
			return dataTypeClazz.cast(dt);
		}
		return null;
	}

	/**
	 * Returns a pointer to the specified data type.
	 *
	 * @param dt Ghidra {@link DataType}
	 * @return a {@link Pointer} that points to the specified datatype.
	 */
	public DataType getPtrTo(DataType dt) {
		return dataTypeManager.getPointer(dt);
	}

	/**
	 * Iterate all {@link DataType}s that match the CategoryPath / name given
	 * in the {@link DataTypePath} parameter, including "conflict" datatypes
	 * that have a ".CONFLICTxx" suffix.
	 * @param dtp
	 * @return
	 */
	public Iterable<DataType> forAllConflicts(DataTypePath dtp) {
		Category cat = dataTypeManager.getCategory(dtp.getCategoryPath());
		List<DataType> list = (cat != null)
				? cat.getDataTypesByBaseName(dtp.getDataTypeName())
				: List.of();

		return list;
	}

	private DataType findGhidraType(String name) {
		DataType dt = dataTypeManager.getDataType(CategoryPath.ROOT, name);
		if (dt == null) {
			dt = builtInDTM.getDataType(CategoryPath.ROOT, name);
			if (dt != null) {
				dt = dt.clone(dataTypeManager);
			}
		}
		return dt;
	}

	private DataType findMatchingDataTypeBySize(DataType[] dtList, int size) {
		for (DataType dt : dtList) {
			if (dt.getLength() == size) {
				return dt;
			}
		}
		return null;
	}

	/**
	 * Returns a Ghidra {@link DataType datatype} that corresponds to a type
	 * that can be used to represent an offset.
	 * <p>
	 * @param size
	 * @return
	 */
	public DataType getOffsetType(int size) {
		return findMatchingDataTypeBySize(baseDataTypeUntyped, size);
	}

	/**
	 * Returns the void type.
	 *
	 * @return void {@link DataType}
	 */
	public DataType getVoidType() {
		return baseDataTypeVoid;
	}

	/**
	 * Returns datatype to hold a 1 byte undefined value.
	 *
	 * @return undefined 1 byte {@link DataType}.
	 */
	public DataType getUndefined1Type() {
		return baseDataTypeUndefined1;
	}

	/**
	 * Returns a DWARF base data type based on its name, or null if it does not exist.
	 *
	 * @param name base type name
	 * @return {@link DataType} or null if base type does not exist
	 */
	public DataType getBaseType(String name) {
		DataType dt = baseDataTypes.get(name);
		return dt;
	}

	private boolean isEncodingCompatible(int requestedDwarfEncoding, DataType dt) {
		AbstractIntegerDataType aidt =
			(dt instanceof AbstractIntegerDataType) ? (AbstractIntegerDataType) dt : null;
		switch (requestedDwarfEncoding) {
			case DWARFEncoding.DW_ATE_signed:
				return aidt == null || aidt.isSigned();
			case DWARFEncoding.DW_ATE_unsigned:
				return aidt == null || !aidt.isSigned();
		}
		return true;
	}

	/**
	 * Returns a Ghidra {@link DataType datatype} that corresponds to the DWARF named type.
	 * <p>
	 * If there is no direct matching named Ghidra type, generic types of matching
	 * size will be returned for integer and floating numeric dwarf encoding types, boolean,
	 * and character types.  Failing that, generic storage types of matching size
	 * (word, dword, etc) will be returned, and failing that, an array of the correct size
	 * will be returned.
	 * <p>
	 * If the returned data type is not a direct named match, the returned data type
	 * will be wrapped in a Ghdira typedef using the dwarf type's name.
	 * <p>
	 * Any newly created Ghidra data types will be cached and the same instance will be returned
	 * if the same DWARF named base type is requested again.
	 * <p>
	 * @param name
	 * @param dwarfSize
	 * @param dwarfEncoding
	 * @param isBigEndian
	 * @return
	 */
	public DataType getBaseType(String name, int dwarfSize, int dwarfEncoding,
			boolean isBigEndian) {
		DataType dt = null;
		String mangledName = null;
		if (name != null) {
			dt = baseDataTypes.get(name);
			if (dt != null && dt.getLength() == dwarfSize &&
				isEncodingCompatible(dwarfEncoding, dt)) {
				return dt;
			}
			mangledName = name + mangleDataTypeInfo(dwarfSize, dwarfEncoding);
			dt = baseDataTypes.get(mangledName);
			if (dt != null) {
				return dt;
			}
		}
		switch (dwarfEncoding) {
			case DWARFEncoding.DW_ATE_address:
				// TODO: Check if bytesize != 0 - may want to make a void pointer
				dt = baseDataTypeVoid;
				break;
			case DWARFEncoding.DW_ATE_boolean:
				if (dwarfSize == 1) {
					dt = baseDataTypeBool;
				}
				break;
			case DWARFEncoding.DW_ATE_float:
				dt = findMatchingDataTypeBySize(baseDataTypeFloats, dwarfSize);
				break;
			case DWARFEncoding.DW_ATE_signed:
				dt = findMatchingDataTypeBySize(baseDataTypeSignedInts, dwarfSize);
				break;
			case DWARFEncoding.DW_ATE_unsigned:
				dt = findMatchingDataTypeBySize(baseDataTypeUnsignedInts, dwarfSize);
				break;
			case DWARFEncoding.DW_ATE_signed_char:
				dt = baseDataTypeChar;
				break;
			case DWARFEncoding.DW_ATE_unsigned_char:
				dt = baseDataTypeUchar;
				break;

			case DWARFEncoding.DW_ATE_UTF:
				dt = findMatchingDataTypeBySize(baseDataTypeChars, dwarfSize);
				break;

			// unsupported DWARF encodings
			case DWARFEncoding.DW_ATE_packed_decimal:
			case DWARFEncoding.DW_ATE_numeric_string:
			case DWARFEncoding.DW_ATE_edited:
			case DWARFEncoding.DW_ATE_signed_fixed:
			case DWARFEncoding.DW_ATE_unsigned_fixed:
			case DWARFEncoding.DW_ATE_decimal_float:
			case DWARFEncoding.DW_ATE_complex_float:
			case DWARFEncoding.DW_ATE_imaginary_float:
				break;
		}

		if (dt == null) {
			dt = findMatchingDataTypeBySize(baseDataTypeUntyped, dwarfSize);
		}

		if (dt == null) {
			dt = new ArrayDataType(DataType.DEFAULT, dwarfSize, DataType.DEFAULT.getLength(),
				dataTypeManager);
		}

		if (name != null /* mangledName also will be non-null */) {
			dt = new TypedefDataType(prog.getRootDNI().asCategoryPath(), name, dt, dataTypeManager);

			dt = dataTypeManager.addDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);

			baseDataTypes.put(mangledName, dt);
		}

		return dt;
	}

	/**
	 * Create a string with the data type's size and type info so that
	 * the data type can be stored in the same map as the regular named base types without
	 * conflicting.
	 * <p>
	 * @param dwarfLength
	 * @param dwarfEncoding
	 * @return
	 */
	private String mangleDataTypeInfo(int dwarfLength, int dwarfEncoding) {
		return String.format("%s_%d_%d", BASETYPE_MANGLE_PREFIX, dwarfLength, dwarfEncoding);
	}

	private void initBaseDataTypes() {

		baseDataTypeVoid = findGhidraType("void");
		baseDataTypes.put("void", baseDataTypeVoid);

		baseDataTypeUndefined1 = findGhidraType("undefined1");
		baseDataTypes.put("undefined1", baseDataTypeUndefined1);

		baseDataTypeNullPtr =
			dataTypeManager.resolve(new PointerDataType(baseDataTypeVoid, dataTypeManager),
				DataTypeConflictHandler.DEFAULT_HANDLER);
		baseDataTypes.put("nullptr", baseDataTypeNullPtr);
		baseDataTypes.put("decltype(nullptr)", baseDataTypeNullPtr);

		DataType byteDT = findGhidraType("byte");
		DataType wordDT = findGhidraType("word");
		DataType dwordDT = findGhidraType("dword");
		DataType qwordDT = findGhidraType("qword");
		baseDataTypeUntyped = new DataType[] { baseDataTypeVoid, byteDT, wordDT, dwordDT, qwordDT };

		baseDataTypeChar = findGhidraType("char");
		baseDataTypeUchar = findGhidraType("uchar");
		baseDataTypes.put("char", baseDataTypeChar);
		baseDataTypes.put("signed char", baseDataTypeChar);
		baseDataTypes.put("unsigned char", baseDataTypeUchar);

		baseDataTypeChars = new DataType[] { baseDataTypeChar,
			findGhidraType(WideChar16DataType.dataType.getName()),
			findGhidraType(WideChar32DataType.dataType.getName()) };

		DataType shortDT = findGhidraType("short");
		DataType ushortDT = findGhidraType("ushort");
		DataType intDT = findGhidraType("int");
		DataType uintDT = findGhidraType("uint");
		DataType longDT = findGhidraType("long");
		DataType ulongDT = findGhidraType("ulong");
		DataType longlongDT = findGhidraType("longlong");
		DataType ulonglongDT = findGhidraType("ulonglong");

		baseDataTypeSignedInts = new DataType[] { shortDT, intDT, longDT, longlongDT };
		baseDataTypeUnsignedInts = new DataType[] { ushortDT, uintDT, ulongDT, ulonglongDT };

		baseDataTypes.put("short", shortDT);
		baseDataTypes.put("short int", shortDT);
		baseDataTypes.put("signed short int", shortDT);
		baseDataTypes.put("unsigned short int", ushortDT);
		baseDataTypes.put("short unsigned int", ushortDT);

		baseDataTypes.put("int", intDT);
		baseDataTypes.put("signed int", intDT);
		baseDataTypes.put("unsigned int", uintDT);

		baseDataTypes.put("long", longDT);
		baseDataTypes.put("long int", longDT);
		baseDataTypes.put("signed long int", longDT);
		baseDataTypes.put("unsigned long int", ulongDT);
		baseDataTypes.put("long unsigned int", ulongDT);

		baseDataTypes.put("long long", longlongDT);
		baseDataTypes.put("long long int", longlongDT);
		baseDataTypes.put("signed long long int", longlongDT);
		baseDataTypes.put("unsigned long long int", ulonglongDT);
		baseDataTypes.put("long long unsigned int", ulonglongDT);

		DataType floatDT = findGhidraType("float");
		DataType doubleDT = findGhidraType("double");
		DataType ldoubleDT = findGhidraType("longdouble");
		baseDataTypeFloats = new DataType[] { floatDT, doubleDT, ldoubleDT };
		baseDataTypes.put("double", doubleDT);
		baseDataTypes.put("long double", ldoubleDT);
		baseDataTypes.put("float", floatDT);

		baseDataTypeBool = findGhidraType("bool");
		baseDataTypes.put("bool", baseDataTypeBool);

		baseDataTypes.put("wchar_t", findGhidraType("wchar_t"));
	}

	/**
	 * Does the actual import work.  Updates the {@link #importSummary summary} object
	 * with information about the types imported and errors encountered.
	 *
	 * @param monitor to watch for cancel
	 * @throws IOException if errors are encountered reading data
	 * @throws DWARFException if errors are encountered processing
	 * @throws CancelledException if the {@link TaskMonitor} is canceled by the user.
	 */
	public void importAllDataTypes(TaskMonitor monitor)
			throws IOException, DWARFException, CancelledException {
		int dtCountBefore = dataTypeManager.getDataTypeCount(true);

		for (DIEAggregate diea : DIEAMonitoredIterator.iterable(prog, "DWARF Import Types",
			monitor)) {
			monitor.checkCanceled();

			try {
				if (isDataType(diea)) {
					doGetDataType(diea);
				}
			}
			catch (IllegalArgumentException iae) {
				// squelch full stack trace for data type errors where structure is defined to
				// have itself inside itself.
				Msg.error(this,
					"Failed to process DWARF DIE " + diea.getHexOffset() + ": " + iae.getMessage());
			}
			catch (OutOfMemoryError oom) {
				throw oom;
			}
			catch (Throwable th) {
				// Aggressively catch pretty much everything to allow the import to
				// try to continue with the next compunit.
				Msg.error(this,
					"Error when processing DWARF information for DIE " + diea.getHexOffset(), th);
				Msg.info(this, "DIE info:\n" + diea.toString());
			}
		}

		int dtCountAfter = dataTypeManager.getDataTypeCount(true);

		importSummary.dataTypesAdded = (dtCountAfter - dtCountBefore);

		if (prog.getImportOptions().isCreateFuncSignatures()) {
			importFuncSignatures(monitor);
		}
	}

	private DIEAggregate getFuncDIEA(DIEAggregate diea) {
		switch (diea.getTag()) {
			case DWARFTag.DW_TAG_gnu_call_site:
			case DWARFTag.DW_TAG_call_site:
			case DWARFTag.DW_TAG_inlined_subroutine:
				// these DIEs head elements have a different tag than the rest of the elements
				// in this aggregate, which causes a problem handling this DIEA.  Create
				// a new instance skipping the head element.  No information is typically
				// lost.
				diea = DIEAggregate.createSkipHead(diea);
				// fall-thru:
			case DWARFTag.DW_TAG_subprogram:
				//case DWARFTag.DW_TAG_subroutine_type:
				// Both of these tag types can be converted to Ghidra func definition data types,
				// but dw_tag_subroutine_type was already handled in importAllDataTypes(),
				// so it is being skipped here.
				return diea;
		}
		return null;
	}

	/**
	 * Construct a temporary 'impl' {@link FunctionDefinition} DataType using the information
	 * found in the specified {@link DIEAggregate}.
	 *
	 * @param diea {@link DIEAggregate} of a subprogram, callsite, etc.
	 * @return {@link FunctionDefinition} impl (not saved to the DB) or null if not a valid
	 * DIEA.
	 */
	public FunctionDefinition getFunctionSignature(DIEAggregate diea) {
		diea = getFuncDIEA(diea);
		if (diea != null) {
			DWARFNameInfo dni = prog.getName(diea);
			return createFunctionDefinitionDataType(diea, dni);
		}
		return null;
	}

	private void importFuncSignatures(TaskMonitor monitor) throws CancelledException {

		int dtCountBefore = dataTypeManager.getDataTypeCount(true);

		for (DIEAggregate diea : DIEAMonitoredIterator.iterable(prog,
			"DWARF Import Function Signatures", monitor)) {
			monitor.checkCanceled();
			try {
				diea = getFuncDIEA(diea);
				if (diea != null) {
					DWARFNameInfo dni = prog.getName(diea);
					DataType funcDefDT = createFunctionDefinitionDataType(diea, dni);
					if (funcDefDT != null) {
						// submit the temp 'impl' funcdef datatype to the DTM and get back a permanent
						// db instance.
						funcDefDT = dataTypeManager.addDataType(funcDefDT,
							DataTypeConflictHandler.DEFAULT_HANDLER);

						// Look for the source info in the funcdef die and fall back to its
						// parent's source info (handles auto-generated ctors and such)
						addDataType(diea.getOffset(), funcDefDT,
							DWARFSourceInfo.getSourceInfoWithFallbackToParent(diea));

						Swing.runNow(Dummy.runnable());
					}
				}
			}
			catch (OutOfMemoryError oom) {
				throw oom;
			}
			catch (Throwable th) {
				// Aggressively catch pretty much everything to allow the import to
				// try to continue with the next compunit.
				Msg.error(this,
					"Error when processing DWARF information for DIE " + diea.getHexOffset(), th);
				Msg.info(this, "DIE info:\n" + diea.toString());
			}
		}

		int dtCountAfter = dataTypeManager.getDataTypeCount(true);
		importSummary.funcSignaturesAdded = (dtCountAfter - dtCountBefore);
	}

	private boolean isDataType(DIEAggregate diea) {
		switch (diea.getTag()) {
			case DWARFTag.DW_TAG_base_type:
			case DWARFTag.DW_TAG_array_type:
			case DWARFTag.DW_TAG_typedef:
			case DWARFTag.DW_TAG_class_type:
			case DWARFTag.DW_TAG_interface_type:
			case DWARFTag.DW_TAG_structure_type:
			case DWARFTag.DW_TAG_union_type:
			case DWARFTag.DW_TAG_enumeration_type:
			case DWARFTag.DW_TAG_pointer_type:
			case DWARFTag.DW_TAG_reference_type:
			case DWARFTag.DW_TAG_rvalue_reference_type:
			case DWARFTag.DW_TAG_const_type:
			case DWARFTag.DW_TAG_volatile_type:
			case DWARFTag.DW_TAG_ptr_to_member_type:
			case DWARFTag.DW_TAG_unspecified_type:
			case DWARFTag.DW_TAG_subroutine_type:
				return true;

			default:
				return false;
		}
	}

	/**
	 * Creates a new {@link FunctionDefinitionDataType} from the specified {@link DIEAggregate}
	 * using already known datatypes.
	 * <p>
	 * The logic of this impl is the same as {@link DWARFDataTypeImporter#makeDataTypeForFunctionDefinition(DIEAggregate, boolean)}
	 * but the impls can't be shared without excessive over-engineering.
	 * <p>
	 * This impl uses DataType's that have already been resolved and committed to the DTM, and
	 * a cache mapping entry of the DWARF die -&gt; DataType has been registered via {@link #addDataType(long, DataType, DWARFSourceInfo)}.
	 * <p>
	 * This approach is necessary because of speed issues that arise if the referred datatypes
	 * are created from scratch from the DWARF information and then have to go through a
	 * resolve() before being used in the FunctionDefinition.
	 *
	 *
	 * @param diea DWARF {@link DIEAggregate} that points to a subprogram or subroutine_type.
	 * @param dni DWARF name info for the new function def
	 * @return new {@link FunctionDefinitionDataType}.
	 */
	private FunctionDefinitionDataType createFunctionDefinitionDataType(DIEAggregate diea,
			DWARFNameInfo dni) {
		DataType returnDataType = getDataType(diea.getTypeRef(), baseDataTypeVoid);
		boolean foundThisParam = false;
		List<ParameterDefinition> params = new ArrayList<>();
		for (DebugInfoEntry childEntry : diea.getHeadFragment()
				.getChildren(
					DWARFTag.DW_TAG_formal_parameter)) {
			DIEAggregate childDIEA = prog.getAggregate(childEntry);

			String paramName = childDIEA.getName();
			DataType paramDT = getDataType(childDIEA.getTypeRef(), null);
			if (paramDT == null || paramDT.getLength() <= 0) {
				Msg.error(this,
					"Bad function parameter type for function " + dni.asCategoryPath() +
						", param " + params.size() + " : " + paramDT + ", func die " +
						diea.getHexOffset() + ", param type die: " +
						childDIEA.getTypeRef().getHexOffset());
				return null;
			}

			ParameterDefinition pd = new ParameterDefinitionImpl(paramName, paramDT, null);
			params.add(pd);

			foundThisParam |= DWARFUtil.isThisParam(childDIEA);
		}
		FunctionDefinitionDataType funcDef =
			new FunctionDefinitionDataType(dni.getParentCP(), dni.getName(), dataTypeManager);
		funcDef.setReturnType(returnDataType);
		funcDef.setArguments(params.toArray(new ParameterDefinition[params.size()]));

		if (!diea.getHeadFragment().getChildren(DWARFTag.DW_TAG_unspecified_parameters).isEmpty()) {
			funcDef.setVarArgs(true);
		}
		if (foundThisParam) {
			funcDef.setGenericCallingConvention(GenericCallingConvention.thiscall);
		}

		return funcDef;
	}

}
