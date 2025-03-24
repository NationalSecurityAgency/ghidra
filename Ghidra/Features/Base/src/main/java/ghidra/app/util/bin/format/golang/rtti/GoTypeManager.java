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
package ghidra.app.util.bin.format.golang.rtti;

import static ghidra.app.util.bin.format.golang.GoConstants.*;

import java.io.IOException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.util.bin.format.golang.GoFunctionMultiReturn;
import ghidra.app.util.bin.format.golang.rtti.GoApiSnapshot.*;
import ghidra.app.util.bin.format.golang.rtti.types.*;
import ghidra.app.util.bin.format.golang.structmapping.MarkupSession;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.UnknownProgressWrappingTaskMonitor;

/**
 * Manages all Go RTTI type info, along with their Ghidra data type equivs.
 */
public class GoTypeManager {
	private static final Map<String, String> STATIC_GOTYPE_ALIASES = Map.of(
		"byte", "uint8", // byte->uint8
		"rune", "int32" // rune->int32
	);

	//@formatter:off
	private static final Pattern TYPENAME_SPLITTER_REGEX = Pattern.compile(
		"("+
			"\\*|" +            // leading '*'
			"\\[\\]|" +         // leading slice '[]' 
			"\\[[0-9.]+\\]"+    // sized array '[NN]'
		")" +                   // group=1
		"(.*)"                  // everything else, group=2
	);
	//@formatter:on

	static class TypeRec {
		GoType type;
		String name;
		int conflictCount;
		DataType recoveredDT;
		List<GoItab> interfaces;
	}

	private final GoRttiMapper goBinary;
	private final DataTypeManager dtm;
	private final GoApiSnapshot apiSnapshot;

	private final Map<Long, TypeRec> typeOffsetIndex = new HashMap<>();
	private final Map<String, TypeRec> typeNameIndex = new HashMap<>();

	private Set<String> missingGoTypes = new HashSet<>();

	private Structure defaultClosureType;
	private Structure defaultMethodWrapperType;
	private DataType genericDictDT; // data type of generic dictionary param passed to funcs, w.i.p.
	private DataType voidPtrDT;
	private int ptrSize;

	public GoTypeManager(GoRttiMapper goBinary, GoApiSnapshot apiSnapshot) {
		this.goBinary = goBinary;
		this.apiSnapshot = apiSnapshot;
		this.dtm = goBinary.getDTM();
		this.ptrSize = goBinary.getPtrSize();
		this.voidPtrDT = dtm.getPointer(VoidDataType.dataType);
	}


	/**
	 * Discovers available Go types
	 * 
	 * @param monitor {@link TaskMonitor}
	 * @throws IOException if error reading data or cancelled
	 */
	public void init(TaskMonitor monitor) throws IOException {
		this.genericDictDT = dtm.getPointer(dtm.getPointer(findDataType("uintptr")));

		UnknownProgressWrappingTaskMonitor upwtm = new UnknownProgressWrappingTaskMonitor(monitor);

		Set<Long> discoveredTypes = new HashSet<>();

		for (GoModuledata module : goBinary.getModules()) {

			upwtm.initialize(0, "Iterating Go RTTI types");
			for (Address typeAddr : module.getTypeList()) {
				if (upwtm.isCancelled()) {
					throw new IOException("Failed to init Go type info: cancelled");
				}
				upwtm.setProgress(discoveredTypes.size());

				GoType goType = getTypeUnchecked(typeAddr);
				if (goType != null) {
					goType.discoverGoTypes(discoveredTypes);
				}
				else {
					Msg.warn(this, "Failed to read Go type at " + typeAddr);
				}
			}

			upwtm.initialize(0, "Iterating Go Interfaces");
			for (GoItab itab : module.getItabs()) {
				if (upwtm.isCancelled()) {
					throw new IOException("Failed to init Go type info: cancelled");
				}
				upwtm.setProgress(discoveredTypes.size());

				TypeRec rec = getTypeRec(itab.getType());
				if (rec.interfaces == null) {
					rec.interfaces = new ArrayList<>();
				}
				rec.interfaces.add(itab);
				TypeRec ifaceRec = getTypeRec(itab.getInterfaceType());
				if (ifaceRec.interfaces == null) {
					ifaceRec.interfaces = new ArrayList<>();
				}
				ifaceRec.interfaces.add(itab);

				itab.discoverGoTypes(discoveredTypes);
			}

			findUnindexedClosureStructTypes(monitor);
		}
		Msg.info(this, "Found %d Go types".formatted(typeOffsetIndex.size()));
	}

	public void markupGoTypes(MarkupSession markupSession, TaskMonitor monitor)
			throws CancelledException, IOException {
		// markup all gotype structs.  Most will already be markedup because they
		// were referenced from the firstModule struct
		for (GoType goType : allTypes()) {
			monitor.checkCancelled();
			markupSession.markup(goType, false);
		}
	}

	private long getAlignedEndOfTypeInfo(GoType type, int typeStructAlign) {
		try {
			return NumericUtilities.getUnsignedAlignedValue(type.getEndOfTypeInfo(),
				typeStructAlign);
		}
		catch (IOException e) {
			return type.getTypeOffset();
		}
	}

	record TypeStructRange(long start, long end) {}

	private void findUnindexedClosureStructTypes(TaskMonitor monitor) throws IOException {
		// search for undiscovered Go types that might be lurking in between already discovered
		// Go rtti type structs.  (should only be auto-generated closure context struct types)
		// Most types will be discoverable from the containing gomoduledata's type list, but
		// autogenerated closure context structs are not added to that list.
		int foundCount = 0;
		int typeStructAlign = ptrSize;
		int typeStructMinSize =
			goBinary.getStructureMappingInfo(GoStructType.class).getStructureLength();
		List<TypeStructRange> typeRanges = typeOffsetIndex.entrySet()
				.stream()
				.map(entry -> new TypeStructRange(entry.getKey(),
					getAlignedEndOfTypeInfo(entry.getValue().type, typeStructAlign)))
				.sorted((o1, o2) -> Long.compareUnsigned(o1.start, o2.start))
				.toList();
		monitor.initialize(typeRanges.size(), "Searching for Go unindexed types...");
		for (int i = 1; i < typeRanges.size() - 1; i++) {
			monitor.setProgress(i);
			if (monitor.isCancelled()) {
				throw new IOException("unindexed types cancelled");
			}

			TypeStructRange t1 = typeRanges.get(i);
			TypeStructRange t2 = typeRanges.get(i + 1);

			long gapStart = t1.end;
			while (t2.start - gapStart > typeStructMinSize) {
				GoType goType = readTypeUnchecked(gapStart);
				if (goType == null ||
					!(goType instanceof GoStructType && goType.getSymbolName().isAnonType())) {
					gapStart += typeStructAlign;
					continue;
				}
				@SuppressWarnings("unused")
				TypeRec newTypeRec = getTypeRec(goType); // add to index
				gapStart = getAlignedEndOfTypeInfo(goType, typeStructAlign);
				foundCount++;
			}
		}
		Msg.info(this, "Discovered %d unindexed Go types".formatted(foundCount));
	}

	private TypeRec getTypeRec(GoType goType) {
		long offset = goType.getStructureContext().getStructureStart();
		TypeRec prevRec = typeOffsetIndex.get(offset);
		if (prevRec != null) {
			return prevRec;
		}

		String typeName = goType.getFullyQualifiedName();
		prevRec = typeNameIndex.get(typeName);

		if (prevRec != null && prevRec.recoveredDT != null) {
			prevRec.type = goType;
			typeOffsetIndex.put(offset, prevRec);
			return prevRec;
		}

		if (prevRec != null && prevRec.type != null && !(prevRec.type instanceof GoTypeBridge)) {
			prevRec.conflictCount++;
			typeName = typeName + ".conflict" + prevRec.conflictCount;
		}

		TypeRec newRec = new TypeRec();
		newRec.name = typeName;
		newRec.type = goType;

		typeOffsetIndex.put(offset, newRec);
		typeNameIndex.put(typeName, newRec);

		return newRec;
	}

	private TypeRec getTypeRec(long offset, boolean cacheOnly) throws IOException {
		if (offset == 0) {
			return null;
		}
		TypeRec rec = typeOffsetIndex.get(offset);
		if (rec != null || cacheOnly) {
			return rec;
		}

		GoType goType = readType(offset);
		return getTypeRec(goType);
	}

	public DataTypeManager getDTM() {
		return dtm;
	}

	public int getPtrSize() {
		return ptrSize;
	}

	public List<GoType> allTypes() {
		return typeOffsetIndex.entrySet()
				.stream()
				.sorted((e1, e2) -> Long.compareUnsigned(e1.getKey(), e2.getKey()))
				.map(e -> e.getValue().type)
				.toList();
	}

	private List<TypeRec> sortedTypeRecs() {
		return typeOffsetIndex.entrySet()
				.stream()
				.sorted((e1, e2) -> Long.compareUnsigned(e1.getKey(), e2.getKey()))
				.map(Map.Entry::getValue)
				.toList();
	}

	public List<Long> allTypeOffsets() {
		return typeOffsetIndex.keySet().stream().sorted().toList();
	}

	private GoType readTypeUnchecked(long offset) {
		try {
			return readType(offset);
		}
		catch (IOException e) {
			return null;
		}
	}

	private GoType readType(long offset) throws IOException {
		Class<? extends GoType> typeClass = GoType.getSpecializedTypeClass(goBinary, offset);
		GoType goType = goBinary.readStructure(typeClass, offset);
		return goType;
	}

	public boolean hasGoType(String typeName) {
		TypeRec rec = typeNameIndex.get(typeName);
		return rec != null && rec.type != null;
	}

	/**
	 * Finds a Go type by its go-type name, from the list of discovered Go types.
	 *  
	 * @param typeName name string
	 * @return {@link GoType}, or {@code NULL} if not found
	 * @throws IOException if error
	 */
	public GoType findGoType(String typeName) throws IOException {
		TypeRec result = findTypeRec(typeName);
		if (result == null) {
			missingGoTypes.add(typeName);
		}

		return result != null ? result.type : null;
	}


	/**
	 * Finds a Ghidra data type by its go-type name.
	 * 
	 * @param <T> Ghidra DataType generic type specifier
	 * @param typeName go type name
	 * @param clazz {@link DataType} class reference
	 * @return Ghidra {@link DataType} corresponding to the requested name, coerced into a
	 * specific {@link DataType} subclass, or {@code NULL} if not found
	 * @throws IOException if error
	 */
	public DataType findDataType(GoSymbolName typeName) throws IOException {
		return findDataType(typeName.asString(), DataType.class);
	}

	/**
	 * Finds a Ghidra data type by its go-type name.
	 * 
	 * @param <T> Ghidra DataType generic type specifier
	 * @param typeName go type name
	 * @param clazz {@link DataType} class reference
	 * @return Ghidra {@link DataType} corresponding to the requested name, coerced into a
	 * specific {@link DataType} subclass, or {@code NULL} if not found
	 * @throws IOException if error
	 */
	public <T extends DataType> T findDataType(GoSymbolName typeName, Class<T> clazz)
			throws IOException {
		return findDataType(typeName.asString(), clazz);
	}

	/**
	 * Finds a Ghidra data type by its go-type name.
	 * 
	 * @param typeName go type name
	 * @return Ghidra {@link DataType} corresponding to the requested name, 
	 * or {@code NULL} if not found
	 * @throws IOException if error
	 */
	public DataType findDataType(String typeName) throws IOException {
		TypeRec rec = findTypeRec(typeName);
		return getDataType(rec);
	}

	/**
	 * Finds a Ghidra data type by its go-type name.
	 * 
	 * @param <T> Ghidra DataType generic type specifier
	 * @param typeName go type name
	 * @param clazz {@link DataType} class reference
	 * @return Ghidra {@link DataType} corresponding to the requested name, coerced into a
	 * specific {@link DataType} subclass, or {@code NULL} if not found
	 * @throws IOException if error
	 */
	public <T extends DataType> T findDataType(String typeName, Class<T> clazz)
			throws IOException {
		DataType result = findDataType(typeName);
		return clazz.isInstance(result) ? clazz.cast(result) : null;
	}

	/**
	 * Returns a Ghidra data type by its go-type name.
	 * 
	 * @param typeName go type name
	 * @return Ghidra {@link DataType} corresponding to the requested name, never {@code NULL}
	 * @throws IOException if error or not found
	 */
	public DataType getDataType(String typeName) throws IOException {
		TypeRec result = findTypeRec(typeName);
		if (result == null || result.recoveredDT == null) {
			throw new IOException("Unknown Go data type: " + typeName);
		}
		return result.recoveredDT;
	}

	TypeRec newTypeRecFromDT(String typeName, DataType dt) {
		TypeRec result = new TypeRec();
		//result.type = new GoTypeBridge(typeName, dt, goBinary);
		result.recoveredDT = dt;
		result.name = typeName;

		typeNameIndex.put(typeName, result);

		return result;
	}

	TypeRec findTypeRec(String typeName) throws IOException {
		typeName = STATIC_GOTYPE_ALIASES.getOrDefault(typeName, typeName);
		TypeRec result = typeNameIndex.get(typeName);
		if (result == null) {
			GoSymbolName typeSymbolName = GoSymbolName.parseTypeName(typeName, null);
			String[] typeNameparts = splitTypeName(typeName);
			if (typeNameparts != null) {
				String typePrefix = typeNameparts[0];
				String subTypeName = typeNameparts[1];
				TypeRec subType = null;
				try {
					subType = findTypeRec(subTypeName);
				}
				catch (IOException e) {
					Msg.warn(this,
						"Failed to get subtype '%s' in %s".formatted(subTypeName, typeName));
					// fall thru will null subType
				}
				DataType subDT = subType != null ? subType.recoveredDT : null;

				if (typePrefix.equals("[]")) { // slices, null subDT is ok
					result =
						newTypeRecFromDT(typeName, createSpecializedSlice(typeSymbolName, subDT));
				}
				else if (typePrefix.equals("*")) { // ptr to something, null subDT is ok
					result = newTypeRecFromDT(typeName, dtm.getPointer(subDT));
				}
				else if (typePrefix.startsWith("[") && typePrefix.endsWith("]")) { // sized arrays
					if (subDT != null) { // else result remains null
						int arraySize = extractArraySize(typePrefix);
						DataType arrayDT = new ArrayDataType(subDT, arraySize);
						result = newTypeRecFromDT(typeName, arrayDT);
					}
				}
				else {
					throw new IOException("Unknown type prefix: " + typeName);
				}
			}
			else if (typeName.startsWith("map[")) { // not handled by splitTypeName()
				result = newTypeRecFromDT(typeName, createSpecializedMapDT(typeName));
			}
			else {
				GoKind primitiveTypeKind = GoKind.parseTypename(typeName);
				GoTypeDef typeDef;
				if ( primitiveTypeKind.isPrimitive() ) {
					result = makeBasicType(typeSymbolName, primitiveTypeKind);
				}
				else if ((typeDef = apiSnapshot.getTypeDef(typeName)) != null) {
					result = convertApiTypeDef(typeSymbolName, typeDef);
				}
			}
		}
		return result;
	}

	private int extractArraySize(String arrayStr) throws IOException {
		try {
			int arraySize = Integer.parseInt(arrayStr.substring(1, arrayStr.length() - 1));
			return arraySize;
		}
		catch (NumberFormatException e) {
			throw new IOException("Bad array size: " + arrayStr);
		}

	}

	private TypeRec convertApiTypeDef(GoSymbolName typeName, GoTypeDef typeDef) throws IOException {
		switch (typeDef) {
			case GoBasicDef basic:
				return convertBasicDef(typeName, basic);
			case GoAliasDef alias:
				return convertAliasDef(typeName, alias);
			case GoStructDef struct:
				return convertStructDef(typeName, struct);
			case GoFuncTypeDef func:
				return convertFuncDef(typeName, func);
			default:
				throw new IOException("Go unhandled type definition: " + typeDef.toString());
		}
	}

	private TypeRec convertFuncDef(GoSymbolName typeName, GoFuncTypeDef func) throws IOException {
		CategoryPath cp = getCP(typeName);
		String name = typeName.asString();
		StructureDataType struct = new StructureDataType(cp, name, 0, dtm);
		DataType structPtr = dtm.getPointer(struct);

		FunctionDefinitionDataType funcDef = new FunctionDefinitionDataType(cp, name + "_F", dtm);
		struct.add(dtm.getPointer(funcDef), "F", null);
		struct.add(new ArrayDataType(getDataType("uint8"), 0), "context", null);
		struct.setToDefaultPacking();
		// assert(struct.length == ptrSize)

		// pre-push an partially constructed struct into the cache before reconstructing the
		// data types needed by the arguments to prevent endless recursive loops
		TypeRec result = cacheDataType(name, structPtr);

		List<ParameterDefinition> params = new ArrayList<>();
		params.add(new ParameterDefinitionImpl(GOLANG_CLOSURE_CONTEXT_NAME, structPtr, null));

		for (GoNameTypePair param : func.Params) {
			DataType paramDT = findDataType(param.DataType);
			params.add(new ParameterDefinitionImpl(param.Name, paramDT, null));
		}

		DataType returnDT;
		if (func.Results.isEmpty()) {
			returnDT = VoidDataType.dataType;
		}
		else if (func.Results.size() == 1) {
			returnDT = findDataType(func.Results.get(0).DataType);
		}
		else {
			List<DataType> paramDataTypes = new ArrayList<>();
			for (GoNameTypePair outParam : func.Results) {
				paramDataTypes.add(findDataType(outParam.DataType));
			}
			returnDT = getFuncMultiReturn(paramDataTypes);
		}

		funcDef.setArguments(params.toArray(ParameterDefinition[]::new));
		funcDef.setReturnType(returnDT);

		return result;
	}

	private TypeRec convertBasicDef(GoSymbolName typeName, GoBasicDef basicDef) throws IOException {
		GoKind kind = GoKind.parseTypename(basicDef.DataType);
		if (kind == null) {
			throw new IOException("Bad Go basic typedef " + basicDef.toString());
		}
		return makeBasicType(typeName, kind);
	}

	private TypeRec makeBasicType(GoSymbolName typeName, GoKind kind) throws IOException {
		DataType plainDT = recoverPlainDataType(kind);
		if (plainDT == null) {
			throw new IOException("Bad Go basic type " + kind);
		}
		CategoryPath cp = getCP(typeName);
		String name = typeName.asString();
		if (!plainDT.getCategoryPath().equals(cp) || !plainDT.getName().equals(name)) {
			plainDT = new TypedefDataType(cp, name, plainDT, dtm);
		}
		return newTypeRecFromDT(name, plainDT);
	}

	private TypeRec convertAliasDef(GoSymbolName typeName, GoAliasDef aliasDef) throws IOException {
		DataType targetDT = findDataType(aliasDef.Target);
		if (targetDT == null) {
			throw new IOException("Bad Go type alias " + aliasDef.toString());
		}
		return newTypeRecFromDT(typeName.asString(),
			new TypedefDataType(getCP(typeName), typeName.asString(), targetDT, dtm));

	}

	private TypeRec convertStructDef(GoSymbolName typeName, GoStructDef structDef)
			throws IOException {
		String baseTypeName = typeName.asString();

		LengthAlignment lenInfo = getDataTypeLength(structDef);
		StructureDataType struct =
			new StructureDataType(getCP(typeName), baseTypeName, lenInfo.len, dtm);
		struct.align(lenInfo.align);

		// pre-push an empty (but sized) struct into the cache to prevent endless recursive loops
		TypeRec rec = new TypeRec();
		rec.name = typeName.asString();
		rec.recoveredDT = struct;
		//rec.type = new GoTypeBridge(typeName, struct, goBinary);

		typeNameIndex.put(rec.name, rec);

		StructureDataType packedStruct =
			new StructureDataType(struct.getCategoryPath(), struct.getName(), 0, dtm);
		packedStruct.setToDefaultPacking();

		for (int i = 0; i < structDef.Fields.size(); i++) {
			GoNameTypePair field = structDef.Fields.get(i);
			DataType dtcDT = findDataType(field.DataType);
			if (dtcDT == null) {
				throw new IOException("Failed to get type for field [%d %s: %s] in %s"
						.formatted(i, field.Name, field.DataType, typeName));
			}
			packedStruct.add(dtcDT, field.Name, null);
		}

		if (packedStruct.getLength() != struct.getLength()) {
			throw new IOException("Go type struct definition changed size when packing: %s %d->%d"
					.formatted(rec.name, struct.getLength(), packedStruct.getLength()));
		}
		struct.replaceWith(packedStruct);
		return rec;
	}

	static String[] splitTypeName(String typeName) {
		Matcher m = TYPENAME_SPLITTER_REGEX.matcher(typeName);
		if (m.matches()) {
			return new String[] { m.group(1), m.group(2) };
		}
		return null;
	}

	public List<GoType> getClosureTypes() {
		return typeOffsetIndex.values()
				.stream()
				.filter(rec -> rec.type instanceof GoStructType structType &&
					structType.isClosureContextType())
				.map(rec -> rec.type)
				.toList();
	}

	public List<GoType> getMethodWrapperClosureTypes() {
		return typeOffsetIndex.values()
				.stream()
				.filter(rec -> rec.type instanceof GoStructType structType &&
					structType.isMethodWrapperContextType())
				.map(rec -> rec.type)
				.toList();
	}

	/**
	 * {@return {@link GoType} for the specified offset (example: GoStructType, GoArrayType, etc)}
	 * 
	 * @param offset absolute position of a Go type
	 * @throws IOException if error reading
	 */
	public GoType getType(long offset) throws IOException {
		return getType(offset, false);
	}

	public GoType getType(long offset, boolean cacheOnly) throws IOException {
		TypeRec rec = getTypeRec(offset, cacheOnly);
		return rec != null ? rec.type : null;
	}

	public GoType getTypeUnchecked(Address addr) {
		try {
			return getType(addr.getOffset(), false);
		}
		catch (IOException e) {
			return null;
		}
	}

	public DataType getVoidPtrDT() {
		return voidPtrDT;
	}

	/**
	 * {@return string name, with a fallback if the specified offset was invalid}
	 * 
	 * @param offset offset of the gotype RTTI record
	 */
	public String getTypeName(long offset) {
		try {
			TypeRec rec = getTypeRec(offset, false);
			if (rec != null) {
				return rec.name;
			}
		}
		catch (IOException e) {
			// fall thru
		}
		return "unknown_type_%x".formatted(offset);
	}

	public String getTypeName(GoType type) {
		return getTypeName(type.getStructureContext().getStructureStart());
	}

	/**
	 * {@return list of interfaces that the specified type has implemented}
	 * 
	 * @param type GoType
	 */
	public List<GoItab> getInterfacesImplementedByType(GoType type) {
		TypeRec rec = getTypeRec(type);
		List<GoItab> itabs = rec.interfaces != null ? rec.interfaces : List.of();
		return itabs.stream().filter(itab -> itab._type == type.getTypeOffset()).toList();
	}

	public List<GoItab> getTypesThatImplementInterface(GoInterfaceType iface) {
		TypeRec rec = getTypeRec(iface);
		List<GoItab> itabs = rec.interfaces != null ? rec.interfaces : List.of();
		return itabs.stream().filter(itab -> itab.inter == iface.getTypeOffset()).toList();
	}

	/**
	 * Returns the {@link GoType} corresponding to an offset that is relative to the controlling
	 * GoModuledata's typesOffset.
	 * 
	 * @param ptrInModule the address of the structure that contains the offset that needs to be
	 * calculated.  The containing-structure's address is important because it indicates which
	 * GoModuledata is the 'parent' 
	 * @param off offset
	 * @return {@link GoType}, or {@code NULL} if offset is special value 0 or -1
	 * @throws IOException if error
	 */
	public GoType resolveTypeOff(long ptrInModule, long off) throws IOException {
		if (off == 0 || off == NumericUtilities.MAX_UNSIGNED_INT32_AS_LONG || off == -1) {
			return null;
		}
		GoModuledata module = goBinary.findContainingModule(ptrInModule);
		return getType(module.getTypesOffset() + off, false);
	}

	/**
	 * Inserts a mapping between a {@link GoType Go type} and a 
	 * {@link DataType ghidra data type}.
	 * <p>
	 * Useful to prepopulate the data type mapping before recursing into contained/referenced types
	 * that might be self-referencing.
	 * 
	 * @param typ {@link GoType Go type}
	 * @param dt {@link DataType Ghidra type}
	 * @throws IOException if Go type struct is not a valid struct mapped instance
	 */
	public void cacheRecoveredDataType(GoType typ, DataType dt) throws IOException {
		TypeRec rec = getTypeRec(typ);
		rec.recoveredDT = dt;
	}

	private TypeRec cacheDataType(String typeName, DataType dt) throws IOException {
		TypeRec typeRec = typeNameIndex.get(typeName);
		if (typeRec == null) {
			return newTypeRecFromDT(typeName, dt);
		}
		else {
			throw new IOException("tried to cache data type already exists: " + typeName);
		}
	}

	public void recoverGhidraDataTypes(TaskMonitor monitor) throws IOException, CancelledException {
		monitor.initialize(typeOffsetIndex.size(), "Converting Go types to Ghidra data types");
		for (TypeRec rec : sortedTypeRecs()) {
			monitor.increment();
			if (rec.recoveredDT == null && rec.type != null) {
				rec.recoveredDT = rec.type.recoverDataType();
				if (dtm.getDataType(rec.recoveredDT.getDataTypePath()) == null) {
					dtm.addDataType(rec.recoveredDT, DataTypeConflictHandler.DEFAULT_HANDLER);
				}
			}
		}
	}

	public DataType recoverPlainDataType(GoKind kind) {
		return switch (kind) {
			case Bool -> BooleanDataType.dataType;
			case Float32 -> AbstractFloatDataType.getFloatDataType(32 / 8, null);
			case Float64 -> AbstractFloatDataType.getFloatDataType(64 / 8, null);
			case Int -> AbstractIntegerDataType.getSignedDataType(ptrSize, dtm); // depends on arch
			case Int8 -> AbstractIntegerDataType.getSignedDataType(8 / 8, null);
			case Int16 -> AbstractIntegerDataType.getSignedDataType(16 / 8, null);
			case Int32 -> AbstractIntegerDataType.getSignedDataType(32 / 8, null);
			case Int64 -> AbstractIntegerDataType.getSignedDataType(64 / 8, null);
			case Uint -> AbstractIntegerDataType.getUnsignedDataType(ptrSize, dtm); // depends on arch
			case Uint8 -> AbstractIntegerDataType.getUnsignedDataType(8 / 8, null);
			case Uint16 -> AbstractIntegerDataType.getUnsignedDataType(16 / 8, null);
			case Uint32 -> AbstractIntegerDataType.getUnsignedDataType(32 / 8, null);
			case Uint64 -> AbstractIntegerDataType.getUnsignedDataType(64 / 8, null);
			case Uintptr -> AbstractIntegerDataType.getUnsignedDataType(ptrSize, dtm);  // depends on arch
			case String -> buildStringStruct();
			case Pointer, UnsafePointer -> getVoidPtrDT();  // depends on arch
			default -> null;
		};
	}

	private Structure buildStringStruct() {

		// create a struct that mirrors runtime.stringStruct or runtime.stringStructDWARF

		Structure struct = new StructureDataType(getCP(), "string", 0, dtm);
		struct.setToDefaultPacking();
		// TODO: using char* might cause issues.  Go has stringStruct + stringStructDWARF which
		// use unsafe.Pointer vs. byte*, but imported via dwarf string struct shows (uint8->byte)*
		struct.add(dtm.getPointer(CharDataType.dataType), "str", null);
		struct.add(recoverPlainDataType(GoKind.Int), "len", null);

		return struct;
	}

	/**
	 * Returns a {@link DataType Ghidra data type} that represents the {@link GoType Go type}, 
	 * using a cache of already recovered types to eliminate extra work and self recursion.
	 *  
	 * @param typ the {@link GoType} to convert
	 * @return Ghidra {@link DataType}
	 * @throws IOException if Go type struct is not a valid struct mapped instance
	 */
	public DataType getDataType(GoType typ) throws IOException {
		return getDataType(typ, DataType.class, false);
	}

	public <T extends DataType> T getDataType(GoType typ, Class<T> clazz, boolean cacheOnly)
			throws IOException {
		if (typ == null) {
			return null;
		}
		if (typ instanceof GoTypeBridge typeBridge) {
			DataType dt = typeBridge.recoverDataType();
			return clazz.isInstance(dt) ? clazz.cast(dt) : null;
		}
		TypeRec rec = getTypeRec(typ);
		if (rec.recoveredDT == null && !cacheOnly) {
			rec.recoveredDT = typ.recoverDataType();
		}
		DataType dt = rec.recoveredDT;
		if (clazz.isInstance(dt)) {
			return clazz.cast(dt);
		}
		else if (dt != null) {
			Msg.warn(this, "Failed to get Ghidra data type from Go type: %s[%x]".formatted(
				rec.name, rec.type.getStructureContext().getStructureStart()));
		}
		return null;
	}

	private DataType getDataType(TypeRec rec) throws IOException {
		if (rec == null) {
			return null;
		}
		if (rec.recoveredDT == null) {
			rec.recoveredDT = rec.type.recoverDataType();
		}
		return rec.recoveredDT;
	}


	public CategoryPath getCP() {
		return GOLANG_RECOVERED_TYPES_CATEGORYPATH;
	}

	/**
	 * {@return category path that should be used to place recovered Go types}
	 * @param typ {@link GoType}
	 */
	public CategoryPath getCP(GoType typ) {
		CategoryPath result = GOLANG_RECOVERED_TYPES_CATEGORYPATH;
		try {
			String structNS = typ.getStructureNamespace();
			if (structNS != null && !structNS.isEmpty()) {
				result = result.extend(structNS);
			}
		}
		catch (IOException e) {
			// ignore
		}
		return result;
	}

	/**
	 * {@return {@link CategoryPath} that should be used to place recovered Go types}
	 * @param symbolName {@link GoSymbolName} to convert to a category path 
	 */
	public CategoryPath getCP(GoSymbolName symbolName) {
		CategoryPath result = GOLANG_RECOVERED_TYPES_CATEGORYPATH;
		String packagePath = symbolName.getPackagePath();
		if (packagePath != null && !packagePath.isEmpty()) {
			result = result.extend(packagePath);
		}
		return result;
	}

	public DataType createSpecializedMapDT(String mapTypeName) {
		try {
			GoSymbolName typeSymbolName = GoSymbolName.parseTypeName(mapTypeName);
			Structure hmapStruct = findDataType("runtime.hmap", Structure.class);
			if (hmapStruct != null) {
				return new TypedefDataType(getCP(typeSymbolName), mapTypeName,
					dtm.getPointer(hmapStruct), dtm);
			}
		}
		catch (IOException e) {
			// fall thru
		}
		return voidPtrDT;
	}

	/**
	 * {@return data type that represents a generic Go slice}
	 * @throws IOException 
	 */
	public Structure getGenericSliceDT() throws IllegalArgumentException, IOException {
		GoSymbolName sliceTypeName = GoSymbolName.parseTypeName("runtime.slice");
		Structure sliceDT;
		try {
			sliceDT = findDataType(sliceTypeName, Structure.class);
			if (sliceDT != null) {
				return sliceDT;
			}
		}
		catch (IOException e) {
			// fall thru, manually create struct
		}

		sliceDT = new StructureDataType(getCP(sliceTypeName), sliceTypeName.asString(), 0, dtm);
		sliceDT.setToDefaultPacking();
		sliceDT.add(voidPtrDT, "array", null);
		sliceDT.add(findDataType("int"), "len", null);
		sliceDT.add(findDataType("int"), "cap", null);

		return sliceDT;
	}

	public Structure createSpecializedSlice(GoSymbolName sliceTypeName, DataType element)
			throws IllegalArgumentException, IOException {
		Structure genericSliceDT = getGenericSliceDT();

		StructureDataType sliceDT = new StructureDataType(getCP(sliceTypeName),
			sliceTypeName.asString(), genericSliceDT.getLength(), dtm);

		sliceDT.replaceWith(genericSliceDT);

		int arrayPtrComponentIndex = 0; /* HACK, field ordinal of void* data field in slice type */
		DataTypeComponent arrayDTC = genericSliceDT.getComponent(arrayPtrComponentIndex);
		sliceDT.replace(arrayPtrComponentIndex, dtm.getPointer(element), -1,
			arrayDTC.getFieldName(),
			arrayDTC.getComment());

		return sliceDT;
	}

	public DataType getGenericDictDT() {
		return genericDictDT;
	}

	public Structure getGenericInterfaceDT() {
		return goBinary.getStructureDataType(GoIface.class);
	}

	public Structure getGenericITabDT() {
		return goBinary.getStructureDataType(GoItab.class);
	}

	public DataType getMethodClosureType(String recvType) throws IOException {
		//struct struct { F uintptr; R *atomic.Uint64 }
		GoType closureType = findGoType("struct { F uintptr; R %s }".formatted(recvType));
		return closureType != null ? getDataType(closureType) : null;
	}

	DataType findRecieverType(GoSymbolName symbolName) throws IOException {
		GoSymbolName recvTypeName = symbolName.getReceiverTypeName();
		DataType recvDT = findDataType(recvTypeName);
		if (recvDT == null && symbolName.hasGenerics()) {
			recvTypeName = symbolName.getReceiverTypeName(symbolName.getShapelessGenericsString());
			recvDT = findDataType(recvTypeName);
		}

		return recvDT;
	}

	public DataType getDefaultClosureType() throws IOException {
		if (defaultClosureType == null) {
			StructureDataType closureDT = new StructureDataType(getCP(), ".closure", 0, dtm);
			closureDT.setDescription("Artifical type that represents a Go closure context");

			FunctionDefinitionDataType funcDef =
				new FunctionDefinitionDataType(getCP(), ".closureF", dtm);
			ParameterDefinition[] params = new ParameterDefinition[] { new ParameterDefinitionImpl(
				GOLANG_CLOSURE_CONTEXT_NAME, dtm.getPointer(closureDT), null) };
			funcDef.setArguments(params);

			closureDT.add(dtm.getPointer(funcDef), "F", null);
			closureDT.add(new ArrayDataType(getDataType("uintptr"), 0), "context", null);

			defaultClosureType =
				(Structure) dtm.addDataType(closureDT, DataTypeConflictHandler.DEFAULT_HANDLER);
		}

		return defaultClosureType;
	}

	public Structure getDefaultMethodWrapperClosureType() {
		if (defaultMethodWrapperType == null) {
			StructureDataType closureDT = new StructureDataType(getCP(),
				".methodwrapper", 0, dtm);

			FunctionDefinitionDataType funcDef =
				new FunctionDefinitionDataType(getCP(), ".methodwrapperF", dtm);
			ParameterDefinition[] params = new ParameterDefinition[] { new ParameterDefinitionImpl(
				GOLANG_CLOSURE_CONTEXT_NAME, dtm.getPointer(closureDT), null) };
			funcDef.setArguments(params);

			closureDT.add(dtm.getPointer(funcDef), "F", null);
			closureDT.add(voidPtrDT, "R", "method receiver");

			defaultMethodWrapperType =
				(Structure) dtm.addDataType(closureDT, DataTypeConflictHandler.DEFAULT_HANDLER);
		}

		return defaultMethodWrapperType;
	}

	public Structure getFuncMultiReturn(List<DataType> returnTypes) {
		GoFunctionMultiReturn multiReturn =
			new GoFunctionMultiReturn(getCP(), returnTypes, dtm, goBinary.newStorageAllocator());
		return multiReturn.getStruct();
	}

	public GoType getSubstitutionType(String typeName) throws IOException {
		if (typeName.startsWith("*")) {
			return new GoTypeBridge(typeName, getVoidPtrDT(), goBinary);
		}
		else if (typeName.startsWith("[]") || typeName.equals("runtime.slice")) {
			return new GoTypeBridge(typeName, getGenericSliceDT(), goBinary);
		}
		else if (typeName.startsWith("map[")) {
			return findGoType("*runtime.hmap");
		}
		else if (typeName.startsWith("chan ")) {
			return findGoType("*runtime.hchan");
		}
		else if (typeName.startsWith("func(")) {
			DataType closureType = getDefaultClosureType();
			return new GoTypeBridge(typeName, dtm.getPointer(closureType), goBinary);
		}
		else if (typeName.equals("runtime.iface")) {
			return new GoTypeBridge(typeName, getGenericInterfaceDT(), goBinary);
		}
		return null;
	}

	public Set<String> getMissingGoTypes() {
		return missingGoTypes;
	}

	private LengthAlignment getDataTypeLength(GoBasicDef basicTypeDef) throws IOException {
		return getTypeLength(GoKind.parseTypename(basicTypeDef.DataType));
	}

	private LengthAlignment getTypeLength(GoKind kind) throws IOException {
		return switch (kind) {
			case Bool, Int8, Uint8 -> new LengthAlignment(1, 1);
			case Float32 -> new LengthAlignment(4, align(4));
			case Float64 -> new LengthAlignment(8, align(8));
			case Int16, Uint16 -> new LengthAlignment(2, align(2));
			case Int32, Uint32 -> new LengthAlignment(4, align(4));
			case Int64, Uint64 -> new LengthAlignment(8, align(8));
			case Complex64 -> new LengthAlignment(8, align(8));
			case Complex128 -> new LengthAlignment(16, align(16));
			case Int, Uint -> new LengthAlignment(ptrSize, align(ptrSize));
			case Uintptr -> new LengthAlignment(ptrSize, align(ptrSize));
			case Func -> new LengthAlignment(ptrSize, align(ptrSize));
			case String -> new LengthAlignment(ptrSize * 2, align(ptrSize));
			case Pointer, UnsafePointer -> new LengthAlignment(ptrSize, align(ptrSize));
			default -> throw new IOException();
		};
	}

	record LengthAlignment(int len, int align) {}

	private int align(int size) {
		return dtm.getDataOrganization().getSizeAlignment(size);
	}

	private LengthAlignment getDataTypeLength(String name) throws IOException {
		// recursively calculate the size of a type.  The subtypes of pointers and slices are 
		// not followed, avoiding recursive lookup issues for well-formed data type graphs.
		name = STATIC_GOTYPE_ALIASES.getOrDefault(name, name);
		String[] typeNameParts = GoTypeManager.splitTypeName(name);
		if (typeNameParts != null) {
			String prefix = typeNameParts[0];
			switch (prefix) {
				case "*":
					return new LengthAlignment(ptrSize, align(ptrSize));
				case "[]":
					return new LengthAlignment(ptrSize * 3, align(ptrSize)); // TODO: sizeof(slice)
			}
			if (prefix.startsWith("[") && prefix.endsWith("]")) {
				int arraySize = extractArraySize(prefix);
				LengthAlignment elementInfo = getDataTypeLength(typeNameParts[1]);
				return new LengthAlignment(arraySize * elementInfo.len, elementInfo.align);
			}
			throw new IOException("Unknown type prefix: " + name);
		}
		else if (name.startsWith("map[") || name.startsWith("chan ")) {
			return new LengthAlignment(ptrSize, align(ptrSize));
		}
		else {
			GoKind typeKind = GoKind.parseTypename(name);
			if (typeKind.isPrimitive()) {
				return getTypeLength(typeKind);
			}
			GoTypeDef typeDef = apiSnapshot.getTypeDef(name);
			if (typeDef != null) {
				return switch (typeDef) {
					case GoStructDef x -> getDataTypeLength(x);
					case GoBasicDef x -> getDataTypeLength(x);
					case GoAliasDef x -> getDataTypeLength(x);
					case GoFuncTypeDef x -> getDataTypeLength(x);
					case GoInterfaceDef x -> getDataTypeLength(x);
					default -> throw new IOException(
						"Failed to get size of apisnapshot type: " + name);
				};
			}
		}
		throw new IOException("Failed to get size of type: " + name);
	}

	private LengthAlignment getDataTypeLength(GoAliasDef aliasDef) throws IOException {
		return getDataTypeLength(aliasDef.Target);
	}

	private LengthAlignment getDataTypeLength(GoFuncTypeDef functypeDef) {
		return new LengthAlignment(ptrSize, align(ptrSize));
	}

	private LengthAlignment getDataTypeLength(GoInterfaceDef ifaceDef) {
		return new LengthAlignment(ptrSize * 2, align(ptrSize));
	}

	private LengthAlignment getDataTypeLength(GoStructDef structDef)
			throws IOException {
		int len = 0;
		int align = 1;
		for (GoNameTypePair field : structDef.Fields) {
			LengthAlignment fieldInfo = getDataTypeLength(field.DataType);
			len = (int) NumericUtilities.getUnsignedAlignedValue(len, fieldInfo.align);
			len += fieldInfo.len;
			align = Math.max(align, fieldInfo.align);
		}

		len = (int) NumericUtilities.getUnsignedAlignedValue(len, align);
		return new LengthAlignment(len, align);
	}

	public FunctionDefinitionDataType createFuncDef(List<ParameterDefinition> params,
			List<ParameterDefinition> returnParams, GoSymbolName symbolName, boolean noReturn) {
		DataType returnDT;
		if (returnParams == null) {
			returnDT = null;
		}
		else if (returnParams.size() == 0) {
			returnDT = VoidDataType.dataType;
		}
		else if (returnParams.size() == 1) {
			returnDT = returnParams.get(0).getDataType();
		}
		else {
			List<DataType> paramDTs =
				returnParams.stream().map(ParameterDefinition::getDataType).toList();
			returnDT = getFuncMultiReturn(paramDTs);
		}

		return createFuncDef(params, returnDT, symbolName, noReturn);
	}

	public FunctionDefinitionDataType createFuncDef(List<ParameterDefinition> params,
			DataType returnDT, GoSymbolName symbolName, boolean noReturn) {

		String funcName = SymbolUtilities.replaceInvalidChars(symbolName.asString(), true);

		FunctionDefinitionDataType funcDef =
			new FunctionDefinitionDataType(getCP(symbolName), funcName, dtm);

		funcDef.setArguments(params.toArray(ParameterDefinition[]::new));
		funcDef.setReturnType(returnDT);
		funcDef.setNoReturn(noReturn);

		return funcDef;
	}

}
