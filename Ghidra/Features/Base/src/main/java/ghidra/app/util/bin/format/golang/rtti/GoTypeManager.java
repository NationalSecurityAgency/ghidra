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
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.UnknownProgressWrappingTaskMonitor;

/**
 * Manages all go RTTI type info, along with their Ghidra data type equivs.
 */
public class GoTypeManager {
	private static final Map<String, String> STATIC_GOTYPE_ALIASES = Map.of(
		"byte", "uint8", // byte->uint8
		"rune", "int32", // rune->int32
		"*runtime.funcval", "func()" // alias for closure
	);
	private static final Pattern TYPENAME_SPLITTER_REGEX =
		Pattern.compile("(\\*|\\[\\]|\\[[0-9.]+\\])(.*)");

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

	private GoType mapGoType;
	private GoType mapArgGoType;
	private GoType chanGoType;
	private GoType chanArgGoType;

	private Structure defaultClosureType;
	private Structure defaultMethodWrapperType;
	private DataType genericDictDT; // data type of generic dictionary param passed to funcs, w.i.p.
	private DataType uintptrDT;
	private DataType uintDT;
	private DataType int32DT;
	private DataType uint32DT;
	private DataType uint8DT;
	private DataType voidPtrDT;

	public GoTypeManager(GoRttiMapper goBinary, GoApiSnapshot apiSnapshot) {
		this.goBinary = goBinary;
		this.apiSnapshot = apiSnapshot;
		this.dtm = goBinary.getDTM();
	}

	/**
	 * Discovers available golang types
	 * 
	 * @param monitor {@link TaskMonitor}
	 * @throws IOException if error reading data or cancelled
	 */
	public void init(TaskMonitor monitor) throws IOException {
		this.voidPtrDT = dtm.getPointer(VoidDataType.dataType);
		this.uintptrDT = goBinary.getTypeOrDefault("uintptr", DataType.class,
			AbstractIntegerDataType.getUnsignedDataType(goBinary.getPtrSize(), dtm));
		this.uintDT = goBinary.getTypeOrDefault("uint", DataType.class,
			AbstractIntegerDataType.getUnsignedDataType(dtm.getDataOrganization().getIntegerSize(),
				dtm));
		this.int32DT = goBinary.getTypeOrDefault("int32", DataType.class,
			AbstractIntegerDataType.getSignedDataType(4, null));
		this.uint32DT = goBinary.getTypeOrDefault("uint32", DataType.class,
			AbstractIntegerDataType.getUnsignedDataType(4, null));
		this.uint8DT = goBinary.getTypeOrDefault("uint8", DataType.class,
			AbstractIntegerDataType.getUnsignedDataType(1, null));

		this.genericDictDT = dtm.getPointer(dtm.getPointer(uintptrDT));

		UnknownProgressWrappingTaskMonitor upwtm = new UnknownProgressWrappingTaskMonitor(monitor);
	
		typeOffsetIndex.clear();
		typeNameIndex.clear();
	
		Set<Long> discoveredTypes = new HashSet<>();
	
		for (GoModuledata module : goBinary.getModules()) {
	
			upwtm.initialize(0, "Iterating Golang RTTI types");
			for (Address typeAddr : module.getTypeList()) {
				if (upwtm.isCancelled()) {
					throw new IOException("Failed to init type info: cancelled");
				}
				upwtm.setProgress(discoveredTypes.size());

				GoType goType = getTypeUnchecked(typeAddr);
				if (goType != null) {
					goType.discoverGoTypes(discoveredTypes);
				}
				else {
					Msg.warn(this, "Failed to read type at " + typeAddr);
				}
			}
	
			upwtm.initialize(0, "Iterating Golang Interfaces");
			for (GoItab itab : module.getItabs()) {
				if (upwtm.isCancelled()) {
					throw new IOException("Failed to init type info: cancelled");
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
		Msg.info(this, "Found %d golang types".formatted(typeOffsetIndex.size()));
	
		// these structure types are what golang map and chan types actually point to.
		mapGoType = findGoType("runtime.hmap"); // used when recovering a map[] type
		mapArgGoType = findGoType("*runtime.hmap", "uintptr"); // used when passing an unknown map[] type

		chanGoType = findGoType("runtime.hchan"); // used when recovering a chan type
		chanArgGoType = findGoType("*runtime.hchan", "uintptr"); // used when passing an unknown chan type
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

	private void findUnindexedClosureStructTypes(TaskMonitor monitor) {
		// search for undiscovered go types that might be lurking in between already discovered
		// go rtti type structs.  (should only be auto-generated closure context struct types)
		// Most types will be discoverable from the containing gomoduledata's type list, but
		// autogenerated closure context structs are not added to that list.
		int foundCount = 0;
		int typeStructAlign = goBinary.getPtrSize();
		int typeStructMinSize =
			goBinary.getStructureMappingInfo(GoStructType.class).getStructureLength();
		List<TypeStructRange> typeRanges = typeOffsetIndex.entrySet()
				.stream()
				.map(entry -> new TypeStructRange(entry.getKey(),
					getAlignedEndOfTypeInfo(entry.getValue().type, typeStructAlign)))
				.sorted((o1, o2) -> Long.compareUnsigned(o1.start, o2.start))
				.toList();
		for (int i = 1; i < typeRanges.size()-1; i++) {
			TypeStructRange t1 = typeRanges.get(i);
			TypeStructRange t2 = typeRanges.get(i+1);
			
			long gapStart = t1.end;
			while ( t2.start - gapStart > typeStructMinSize ) {
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
		Msg.info(this, "Discovered %d unindexed rtti types".formatted(foundCount));
	}

	private TypeRec getTypeRec(GoType goType) {
		long offset = goType.getStructureContext().getStructureStart();
		TypeRec prevRec = typeOffsetIndex.get(offset);
		if (prevRec != null) {
			return prevRec;
		}
		String typeName = goType.getFullyQualifiedName();
		prevRec = typeNameIndex.get(typeName);
		if (prevRec != null) {
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

	public List<GoType> allTypes() {
		return typeOffsetIndex.entrySet()
				.stream()
				.sorted((e1, e2) -> Long.compareUnsigned(e1.getKey(), e2.getKey()))
				.map(e -> e.getValue().type)
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

	/**
	 * Finds a go type by its go-type name, from the list of discovered go types.
	 *  
	 * @param typeName name string
	 * @return {@link GoType}, or null if not found
	 */
	public GoType findGoType(String typeName) {
		return findGoType(typeName, null);
	}

	public GoType findGoType(GoSymbolName name) {
		return findGoType(name, null);
	}

	public GoType findGoType(GoSymbolName name, String defaultTypeName) {
		String typeName = name.asString();
		return findGoType(typeName, defaultTypeName);
	}

	public GoType findGoType(String typeName, String defaultTypeName) {
		typeName = resolveTypeNameAliases(typeName);
		TypeRec result = typeNameIndex.get(typeName);
		if (result == null) {
			String[] typeNameparts = splitTypeName(typeName);
			if (typeNameparts != null) {
				String typePrefix = typeNameparts[0];
				String subTypeName = typeNameparts[1];
				GoType subType = findGoType(subTypeName);
				if (subType != null) {
					String subTypeFQN = subType.getFullyQualifiedName();
					if (!subTypeName.equals(subTypeFQN)) {
						return findGoType(typePrefix + subTypeFQN);
					}
				}
			}
		}
		if (result == null) {
			missingGoTypes.add(typeName);
		}
		if (result == null && defaultTypeName != null) {
			typeNameIndex.get(defaultTypeName);
		}

		return result != null ? result.type : null;
	}

	private String[] splitTypeName(String typeName) {
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
	 * Returns the {@link GoType} for the specified offset
	 * 
	 * @param offset absolute position of a go type
	 * @return specialized {@link GoType} (example, GoStructType, GoArrayType, etc)
	 * @throws IOException if error reading
	 */
	public GoType getType(long offset) throws IOException {
		return getType(offset, false);
	}

	public GoType getType(long offset, boolean cacheOnly) throws IOException {
		TypeRec rec = getTypeRec(offset, cacheOnly);
		return rec != null ? rec.type : null;
	}

	/**
	 * Returns a specialized {@link GoType} for the type that is located at the specified location.
	 * 
	 * @param addr location of a go type
	 * @return specialized {@link GoType} (example, GoStructType, GoArrayType, etc)
	 * @throws IOException if error reading
	 */
	public GoType getType(Address addr) throws IOException {
		return getType(addr.getOffset(), false);
	}

	public GoType getTypeUnchecked(Address addr) {
		try {
			return getType(addr.getOffset(), false);
		}
		catch (IOException e) {
			return null;
		}
	}

	private String resolveTypeNameAliases(String typeName) {
		String origTypeName = typeName;

		String result = STATIC_GOTYPE_ALIASES.get(typeName);
		if (result != null) {
			return result;
		}
		if (apiSnapshot != null) {
			int loopCount = 0;
			GoTypeDef snapshotType;
			while (!typeNameIndex.containsKey(typeName) &&
				(snapshotType = apiSnapshot.getTypeDef(typeName)) != null) {
				if (snapshotType instanceof GoAliasDef aliasDef) {
					typeName = aliasDef.Target;
				}
				else if (snapshotType instanceof GoBasicDef basicDef) {
					typeName = basicDef.DataType;
				}
				else {
					break;
				}
				if (loopCount++ > 10) {
					return origTypeName;
				}
			}
		}
		return typeName;
	}

	/**
	 * Returns the go type that represents a golang built-in map RTTI type struct.
	 * 
	 * @return golang map data type
	 */
	public GoType getMapGoType() {
		return mapGoType;
	}

	/**
	 * Returns the go type that represents a generic map argument value.
	 * 
	 * @return {@link GoType} 
	 */
	public GoType getMapArgGoType() {
		return mapArgGoType;
	}

	/**
	 * Returns the go type that represents the built-in golang channel RTTI type struct.
	 * 
	 * @return golang channel type
	 */
	public GoType getChanGoType() {
		return chanGoType;
	}

	/**
	 * Returns the go type that represents a generic chan argument value.
	 * 
	 * @return golang type for chan args
	 */
	public GoType getChanArgGoType() {
		return chanArgGoType;
	}

	public DataType getUint8DT() {
		return uint8DT;
	}

	public DataType getUintDT() {
		return uintDT;
	}

	/**
	 * Returns the data type that represents a golang uintptr
	 * 
	 * @return golang uinptr data type
	 */
	public DataType getUintptrDT() {
		return uintptrDT;
	}

	/**
	 * Returns the data type that represents a golang int32
	 * 
	 * @return golang int32 data type
	 */
	public DataType getInt32DT() {
		return int32DT;
	}

	/**
	 * Returns the data type that represents a golang uint32
	 * 
	 * @return golang uint32 data type
	 */
	public DataType getUint32DT() {
		return uint32DT;
	}

	public DataType getVoidPtrDT() {
		return voidPtrDT;
	}

	/**
	 * Returns the name of a gotype.
	 * 
	 * @param offset offset of the gotype RTTI record
	 * @return string name, with a fallback if the specified offset was invalid
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
	 * Returns a list of interfaces that the specified type has implemented.
	 * 
	 * @param type GoType
	 * @return list of itabs that map a GoType to the interfaces it was found to implement
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
	 * @return {@link GoType}, or null if offset is special value 0 or -1
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
	 * Inserts a mapping between a {@link GoType golang type} and a 
	 * {@link DataType ghidra data type}.
	 * <p>
	 * Useful to prepopulate the data type mapping before recursing into contained/referenced types
	 * that might be self-referencing.
	 * 
	 * @param typ {@link GoType golang type}
	 * @param dt {@link DataType Ghidra type}
	 * @throws IOException if golang type struct is not a valid struct mapped instance
	 */
	public void cacheRecoveredDataType(GoType typ, DataType dt) throws IOException {
		TypeRec rec = getTypeRec(typ);
		rec.recoveredDT = dt;
	}

	/**
	 * Returns a {@link DataType Ghidra data type} that represents the {@link GoType golang type}, 
	 * using a cache of already recovered types to eliminate extra work and self recursion.
	 *  
	 * @param typ the {@link GoType} to convert
	 * @return Ghidra {@link DataType}
	 * @throws IOException if golang type struct is not a valid struct mapped instance
	 */
	public DataType getGhidraDataType(GoType typ) throws IOException {
		return getGhidraDataType(typ, DataType.class, false);
	}

	public <T extends DataType> T getGhidraDataType(GoType typ, Class<T> clazz, boolean cacheOnly)
			throws IOException {
		if (typ == null) {
			return null;
		}
		if (typ instanceof GoTypeBridge typeBridge) {
			DataType dt = typeBridge.recoverDataType(this);
			return clazz.isInstance(dt) ? clazz.cast(dt) : null;
		}
		TypeRec rec = getTypeRec(typ);
		if (rec.recoveredDT == null && !cacheOnly) {
			rec.recoveredDT = typ.recoverDataType(this);
		}
		DataType dt = rec.recoveredDT;
		if (clazz.isInstance(dt)) {
			return clazz.cast(dt);
		}
		else if (dt != null) {
			Msg.warn(this, "Failed to get Ghidra data type from go type: %s[%x]".formatted(
				rec.name, rec.type.getStructureContext().getStructureStart()));
		}
		return null;
	}

	public <T extends DataType> T getGhidraDataType(String goTypeName, Class<T> clazz)
			throws IOException {
		GoType typ = findGoType(goTypeName);
		return typ != null ? getGhidraDataType(typ, clazz, false) : null;
	}

	public CategoryPath getCP() {
		return GOLANG_RECOVERED_TYPES_CATEGORYPATH;
	}

	/**
	 * Returns category path that should be used to place recovered golang types.
	 * @param typ {@link GoType}
	 * @return {@link CategoryPath} to use when creating recovered golang types
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
	 * Returns category path that should be used to place recovered golang types.
	 * @param symbolName {@link GoSymbolName} to convert to a category path 
	 * @return {@link CategoryPath} to use when creating recovered golang types
	 */
	public CategoryPath getCP(GoSymbolName symbolName) {
		CategoryPath result = GOLANG_RECOVERED_TYPES_CATEGORYPATH;
		String packagePath = symbolName.getPackagePath();
		if (packagePath != null && !packagePath.isEmpty()) {
			result = result.extend(packagePath);
		}
		return result;
	}

	/**
	 * Returns the data type that represents a generic golang slice.
	 * 
	 * @return golang generic slice data type
	 */
	public Structure getGenericSliceDT() {
		return goBinary.getStructureDataType(GoSlice.class);
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
		return closureType != null ? getGhidraDataType(closureType) : null;
	}

	GoType findRecieverType(GoSymbolName symbolName) {
		GoSymbolName recvTypeName = symbolName.getReceiverTypeName();
		GoType result = findGoType(recvTypeName);
		if (result == null && symbolName.hasGenerics()) {
			recvTypeName = symbolName.getReceiverTypeName(symbolName.getShapelessGenericsString());
			result = findGoType(recvTypeName);
		}

		return result;
	}

	public DataType getDefaultClosureType() {
		if (defaultClosureType == null) {
			StructureDataType closureDT = new StructureDataType(getCP(), ".closure", 0, dtm);
			closureDT.setDescription("Artifical type that represents a golang closure context");

			FunctionDefinitionDataType funcDef =
				new FunctionDefinitionDataType(getCP(), ".closureF", dtm);
			ParameterDefinition[] params = new ParameterDefinition[] { new ParameterDefinitionImpl(
				GOLANG_CLOSURE_CONTEXT_NAME, dtm.getPointer(closureDT), null) };
			funcDef.setArguments(params);

			closureDT.add(dtm.getPointer(funcDef), "F", null);
			closureDT.add(new ArrayDataType(uint8DT, 0), "context", null);

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

	public GoType getSubstitutionType(String typeName) {
		if (typeName.startsWith("*")) {
			return new GoTypeBridge(typeName, getVoidPtrDT(), goBinary);
		}
		else if (typeName.startsWith("[]") || typeName.equals("runtime.slice")) {
			return new GoTypeBridge(typeName, getGenericSliceDT(), goBinary);
		}
		else if (typeName.startsWith("map[")) {
			return mapArgGoType;
		}
		else if (typeName.startsWith("chan ")) {
			return chanArgGoType;
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

}
