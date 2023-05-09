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

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.datamgr.util.DataTypeArchiveUtility;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf4.next.DWARFProgram;
import ghidra.app.util.bin.format.golang.*;
import ghidra.app.util.bin.format.golang.rtti.types.*;
import ghidra.app.util.bin.format.golang.structmapping.DataTypeMapper;
import ghidra.app.util.bin.format.golang.structmapping.StructureMapping;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.app.util.opinion.PeLoader;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.UnknownProgressWrappingTaskMonitor;

/**
 * {@link DataTypeMapper} for golang binaries. 
 * <p>
 * When bootstrapping golang binaries, the following steps are used:
 * <ul>
 * 	<li>Find the GoBuildInfo struct.  This struct is the easiest to locate, even when the binary
 * 	is stripped.  This gives us the go pointerSize (probably same as ghidra pointer size) and the
 * 	goVersion.  This struct does not rely on StructureMapping, allowing its use before a
 * 	DataTypeMapper is created.
 * 	<li>Create DataTypeMapper
 * 	<li>Find the runtime.firstmoduledata structure.
 * 		<ul>
 *			<li>If there are symbols, just use the symbol or named memory block.
 *			<li>If stripped:
 *				<ul>
 * 					<li>Find the pclntab.  This has a magic signature, a pointerSize, and references
 * 					to a couple of tables that are also referenced in the moduledata structure.
 * 					<li>Search memory for a pointer to the pclntab struct.  This should be the first
 * 					field of the moduledata structure.  The values that are duplicated between the
 * 					two structures can be compared to ensure validity.
 * 					<li>Different binary formats (Elf vs PE) will determine which memory blocks to
 * 					search.
 * 				</ul>  
 * 		</ul>
 * </ul>
 */
public class GoRttiMapper extends DataTypeMapper {

	/**
	 * Returns a new {@link GoRttiMapper} for the specified program, or null if the binary
	 * is not a supported golang binary.
	 * 
	 * @param program {@link Program}
	 * @param log 
	 * @return new {@link GoRttiMapper}, or null if not a golang binary
	 * @throws IOException
	 */
	public static GoRttiMapper getMapperFor(Program program, MessageLog log) throws IOException {
		GoBuildInfo buildInfo = GoBuildInfo.fromProgram(program);
		GoVer goVer;
		if (buildInfo == null || (goVer = buildInfo.getVerEnum()) == GoVer.UNKNOWN) {
			return null;
		}
		ResourceFile gdtFile =
			findGolangBootstrapGDT(goVer, buildInfo.getPointerSize(), getGolangOSString(program));
		if (gdtFile == null) {
			Msg.error(GoRttiMapper.class, "Missing golang gdt archive for " + goVer);
		}

		try {
			return new GoRttiMapper(program, buildInfo.getPointerSize(), buildInfo.getEndian(),
				buildInfo.getVerEnum(), gdtFile);
		}
		catch (IllegalArgumentException e) {
			// user deserves a warning because the binary wasn't supported
			log.appendMsg(e.getMessage());
			return null;
		}
	}

	public static String getGDTFilename(GoVer goVer, int pointerSizeInBytes, String osName) {
		String bitSize = pointerSizeInBytes > 0
				? Integer.toString(pointerSizeInBytes * 8)
				: "any";
		String gdtFilename =
			"golang_%d.%d_%sbit_%s.gdt".formatted(goVer.getMajor(), goVer.getMinor(),
				bitSize, osName);
		return gdtFilename;
	}

	public static String getGolangOSString(Program program) {
		String loaderName = program.getExecutableFormat();
		if (ElfLoader.ELF_NAME.equals(loaderName)) {
			// TODO: this will require additional work to map all Golang OSs to Ghidra loader info
			return "linux";
		}
		else if (PeLoader.PE_NAME.equals(loaderName)) {
			return "win";
		}
		else {
			return null;
		}
	}

	/**
	 * Searches for a golang bootstrap gdt file that matches the specified Go version/size/OS.
	 * <p>
	 * First looks for a gdt with an exact match, then for a gdt with version/size match and
	 * "any" OS, and finally, a gdt that matches the version and "any" size and "any" OS.
	 * 
	 * @param goVer version of Go
	 * @param ptrSize size of pointers
	 * @param osName name of OS
	 * @return
	 */
	public static ResourceFile findGolangBootstrapGDT(GoVer goVer, int ptrSize, String osName) {
		ResourceFile result = null;
		if (osName != null) {
			result = DataTypeArchiveUtility.findArchiveFile(getGDTFilename(goVer, ptrSize, osName));
		}
		if (result == null) {
			result = DataTypeArchiveUtility.findArchiveFile(getGDTFilename(goVer, ptrSize, "any"));
		}
		if (result == null) {
			result =
				DataTypeArchiveUtility.findArchiveFile(getGDTFilename(goVer, -1 /*any*/, "any"));
		}
		return result;
	}

	private static final CategoryPath RECOVERED_TYPES_CP = new CategoryPath("/golang-recovered");
	private static final CategoryPath GOLANG_CP = GoConstants.GOLANG_CATEGORYPATH;
	private static final CategoryPath VARLEN_STRUCTS_CP = GoConstants.GOLANG_CATEGORYPATH;

	/**
	 * List of java classes that are {@link StructureMapping structure mapped}.
	 * <p>
	 * If a class isn't included in this list, it can't be used.
	 */
	private static final List<Class<?>> GOLANG_STRUCTMAPPED_CLASSES =
		List.of(GoModuledata.class, GoName.class, GoVarlenString.class, GoSlice.class,
			GoBaseType.class, GoTypeDetector.class, GoPlainType.class, GoUncommonType.class,
			GoArrayType.class, GoChanType.class, GoFuncType.class, GoInterfaceType.class,
			GoMapType.class, GoPointerType.class, GoSliceType.class, GoIface.class,
			GoStructType.class, GoMethod.class, GoStructField.class, GoIMethod.class,
			GoFunctabEntry.class, GoFuncData.class, GoItab.class, GoString.class, GoPcHeader.class);

	private final BinaryReader reader;
	private final GoVer goVersion;
	private final int ptrSize;
	private final Endian endian;
	private final DataType uintptrDT;
	private final DataType int32DT;
	private final DataType uint32DT;
	private final Map<Long, GoType> goTypes = new HashMap<>();
	private final Map<String, GoType> typeNameIndex = new HashMap<>();
	private final Map<Long, DataType> cachedRecoveredDataTypes = new HashMap<>();
	private final List<GoModuledata> modules = new ArrayList<>();
	private GoType mapGoType;
	private GoType chanGoType;

	public GoRttiMapper(Program program, int ptrSize, Endian endian, GoVer goVersion,
			ResourceFile archiveGDT) throws IOException {
		super(program, archiveGDT);

		this.goVersion = goVersion;
		this.ptrSize = ptrSize;
		this.endian = endian;

		reader = super.createProgramReader();

		addArchiveSearchCategoryPath(CategoryPath.ROOT, GOLANG_CP);
		addProgramSearchCategoryPath(DWARFProgram.DWARF_ROOT_CATPATH, DWARFProgram.UNCAT_CATPATH);

		this.uintptrDT = getTypeOrDefault("uintptr", DataType.class,
			AbstractIntegerDataType.getUnsignedDataType(ptrSize, getDTM()));
		this.int32DT = getTypeOrDefault("int32", DataType.class,
			AbstractIntegerDataType.getSignedDataType(4, null));
		this.uint32DT = getTypeOrDefault("uint32", DataType.class,
			AbstractIntegerDataType.getUnsignedDataType(4, null));

		try {
			registerStructures(GOLANG_STRUCTMAPPED_CLASSES);
		}
		catch (IOException e) {
			if (archiveGDT == null) {
				// a normal'ish situation where there isn't a .gdt for this arch/binary and there
				// isn't any DWARF.
				throw new IllegalArgumentException(
					"Missing golang .gdt archive for %s, no fallback DWARF info, unable to extract golang RTTI info."
							.formatted(goVersion));
			}
			// a bad situation where the data type info is corrupted 
			throw new IOException("Invalid or missing Golang bootstrap GDT file: %s"
					.formatted(archiveGDT.getAbsolutePath()));
		}
	}

	public GoVer getGolangVersion() {
		return goVersion;
	}

	public GoModuledata getFirstModule() {
		return modules.get(0);
	}

	public void addModule(GoModuledata module) {
		modules.add(module);
	}

	public GoModuledata findContainingModule(long offset) {
		for (GoModuledata module : modules) {
			if (module.getTypesOffset() <= offset && offset < module.getTypesEndOffset()) {
				return module;
			}
		}
		return null;
	}

	public GoModuledata findContainingModuleByFuncData(long offset) {
		for (GoModuledata module : modules) {
			if (module.containsFuncDataInstance(offset)) {
				return module;
			}
		}
		return null;
	}

	@Override
	public CategoryPath getDefaultVariableLengthStructCategoryPath() {
		return VARLEN_STRUCTS_CP;
	}

	public DataType getUintptrDT() {
		return uintptrDT;
	}

	public DataType getInt32DT() {
		return int32DT;
	}

	public DataType getUint32DT() {
		return uint32DT;
	}

	public Structure getGenericSliceDT() {
		return getStructureDataType(GoSlice.class);
	}

	public GoType getMapGoType() {
		return mapGoType;
	}

	public GoType getChanGoType() {
		return chanGoType;
	}

	@Override
	protected BinaryReader createProgramReader() {
		return reader.clone();
	}

	public int getPtrSize() {
		return ptrSize;
	}

	public GoName resolveNameOff(long ptrInModule, long off) throws IOException {
		if (off == 0) {
			return null;
		}
		GoModuledata module = findContainingModule(ptrInModule);
		long nameStart = module.getTypesOffset() + off;
		return getGoName(nameStart);
	}

	public GoName getGoName(long offset) throws IOException {
		return offset != 0 ? readStructure(GoName.class, offset) : null;
	}

	public GoType resolveTypeOff(long ptrInModule, long off) throws IOException {
		if (off == 0 || off == NumericUtilities.MAX_UNSIGNED_INT32_AS_LONG || off == -1) {
			return null;
		}
		GoModuledata module = findContainingModule(ptrInModule);
		return getGoType(module.getTypesOffset() + off);
	}

	public GoType getGoType(long offset) throws IOException {
		if (offset == 0) {
			return null;
		}
		GoType goType = goTypes.get(offset);
		if (goType == null) {
			Class<? extends GoType> typeClass = GoType.getSpecializedTypeClass(this, offset);
			goType = readStructure(typeClass, offset);
			goTypes.put(offset, goType);
		}
		return goType;
	}

	public GoType getGoType(Address addr) throws IOException {
		return getGoType(addr.getOffset());
	}

	public GoType findGoType(String typeName) {
		return typeNameIndex.get(typeName);
	}

	public <T extends DataType> T getGhidraDataType(String goTypeName, Class<T> clazz) {
		T dt = getType(goTypeName, clazz);
		if (dt == null) {
			GoType goType = findGoType(goTypeName);
			if (goType != null) {
				try {
					DataType tmpDT = goType.recoverDataType();
					if (clazz.isInstance(tmpDT)) {
						dt = clazz.cast(tmpDT);
					}
				}
				catch (IOException e) {
					Msg.warn(this, "Failed to get Ghidra data type from go type: %s[%x]"
							.formatted(goTypeName,
								goType.getStructureContext().getStructureStart()));
				}
			}
		}
		return dt;
	}

	public Address resolveTextOff(long ptrInModule, long off) {
		if (off == -1 || off == NumericUtilities.MAX_UNSIGNED_INT32_AS_LONG) {
			return null;
		}
		GoModuledata module = findContainingModule(ptrInModule);
		return module != null ? module.getText().add(off) : null;
	}

	/**
	 * Export the currently registered struct mapping types to a gdt file.
	 * <p>
	 * The struct data types will either be from the current program's DWARF data, or
	 * from an earlier golang.gdt (if this binary doesn't have DWARF)
	 * 
	 * @param gdtFile
	 * @throws IOException
	 */
	public void exportTypesToGDT(File gdtFile, TaskMonitor monitor) throws IOException {

		List<DataType> registeredStructDTs = mappingInfo.values()
				.stream()
				.map(smi -> {
					if (smi.getStructureDataType() == null) {
						return null;
					}
					DataType existingDT = findType(smi.getStructureName(),
						List.of(DWARFProgram.DWARF_ROOT_CATPATH, DWARFProgram.UNCAT_CATPATH),
						programDTM);
					if (existingDT == null) {
						existingDT = smi.getStructureDataType();
					}
					if (existingDT == null) {
						Msg.warn(this, "Missing type: " + smi.getDescription());
					}
					return existingDT;
				})
				.filter(Objects::nonNull)
				.collect(Collectors.toList());

		// Copy the data types into a tmp gdt, and then copy them again into the final gdt
		// to avoid traces of the original program name as a deleted source archive link in the
		// gdt data base.  This method only leaves the target gdt filename + ".step1" in the db.
		File tmpGDTFile = new File(gdtFile.getParentFile(), gdtFile.getName() + ".step1.gdt");
		FileDataTypeManager tmpFdtm = FileDataTypeManager.createFileArchive(tmpGDTFile);
		int tx = -1;
		try {
			tx = tmpFdtm.startTransaction("Import");
			tmpFdtm.addDataTypes(registeredStructDTs, DataTypeConflictHandler.DEFAULT_HANDLER,
				monitor);
			moveAllDataTypesTo(tmpFdtm, DWARFProgram.DWARF_ROOT_CATPATH, GOLANG_CP);
			for (SourceArchive sa : tmpFdtm.getSourceArchives()) {
				tmpFdtm.removeSourceArchive(sa);
			}
			tmpFdtm.getRootCategory()
					.removeCategory(DWARFProgram.DWARF_ROOT_CATPATH.getName(), monitor);
			// TODO: could also clear out any description strings on types
		}
		catch (CancelledException | DuplicateNameException e) {
			Msg.error(this, "Error when exporting types to file: %s".formatted(gdtFile), e);
		}
		finally {
			if (tx != -1) {
				tmpFdtm.endTransaction(tx, true);
			}
		}

		tmpFdtm.save();

		FileDataTypeManager fdtm = FileDataTypeManager.createFileArchive(gdtFile);
		tx = -1;
		try {
			tx = fdtm.startTransaction("Import");
			tmpFdtm.getAllDataTypes()
					.forEachRemaining(
						dt -> fdtm.addDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER));
			for (SourceArchive sa : fdtm.getSourceArchives()) {
				fdtm.removeSourceArchive(sa);
			}
		}
		finally {
			if (tx != -1) {
				fdtm.endTransaction(tx, true);
			}
		}

		fdtm.save();

		tmpFdtm.close();
		fdtm.close();

		tmpGDTFile.delete();

	}

	private void moveAllDataTypesTo(DataTypeManager dtm, CategoryPath srcCP, CategoryPath destCP)
			throws DuplicateNameException {
		Category srcCat = dtm.getCategory(srcCP);
		if (srcCat != null) {
			for (DataType dt : srcCat.getDataTypes()) {
				if (dt instanceof Array || dt instanceof Pointer) {
					continue;
				}
				dt.setCategoryPath(destCP);
			}
			for (Category subcat : srcCat.getCategories()) {
				moveAllDataTypesTo(dtm, subcat.getCategoryPath(), destCP); // flatten everything
			}
		}
	}

	public CategoryPath getRecoveredTypesCp() {
		return RECOVERED_TYPES_CP;
	}

	public DataType getRecoveredType(GoType typ) throws IOException {
		long offset = getExistingStructureAddress(typ).getOffset();
		DataType dt = cachedRecoveredDataTypes.get(offset);
		if (dt != null) {
			return dt;
		}
		dt = typ.recoverDataType();
		cachedRecoveredDataTypes.put(offset, dt);
		return dt;
	}

	public void cacheRecoveredDataType(GoType typ, DataType dt) throws IOException {
		long offset = getExistingStructureAddress(typ).getOffset();
		cachedRecoveredDataTypes.put(offset, dt);
	}

	public DataType getCachedRecoveredDataType(GoType typ) throws IOException {
		long offset = getExistingStructureAddress(typ).getOffset();
		return cachedRecoveredDataTypes.get(offset);
	}

	/**
	 * Converts all discovered golang rtti type records to Ghidra data types, placing them
	 * in the program's DTM in /golang-recovered
	 * 
	 * @throws IOException
	 * @throws CancelledException 
	 */
	public void recoverDataTypes(TaskMonitor monitor) throws IOException, CancelledException {
		monitor.setMessage("Converting Golang types to Ghidra data types");
		monitor.initialize(goTypes.size());
		List<Long> typeOffsets = goTypes.keySet().stream().sorted().collect(Collectors.toList());
		for (Long typeOffset : typeOffsets) {
			monitor.checkCancelled();
			monitor.incrementProgress(1);
			GoType typ = getGoType(typeOffset);
			DataType dt = typ.recoverDataType();
			if (programDTM.getDataType(dt.getDataTypePath()) == null) {
				programDTM.addDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
			}
		}
	}

	public void discoverGoTypes(TaskMonitor monitor) throws IOException, CancelledException {
		GoModuledata firstModule = findFirstModuledata(monitor);
		if (firstModule == null) {
			return;
		}
		addModule(firstModule);

		UnknownProgressWrappingTaskMonitor upwtm =
			new UnknownProgressWrappingTaskMonitor(monitor, 50);
		upwtm.setMessage("Iterating Golang RTTI types");
		upwtm.initialize(0);

		goTypes.clear();
		Set<Long> discoveredTypes = new HashSet<>();
		for (Iterator<GoType> it = firstModule.iterateTypes(); it.hasNext();) {
			upwtm.checkCancelled();
			upwtm.setProgress(discoveredTypes.size());

			GoType type = it.next();
			type.discoverGoTypes(discoveredTypes);
		}
		typeNameIndex.clear();
		for (GoType goType : goTypes.values()) {
			String typeName = goType.getBaseType().getNameString();
			typeNameIndex.put(typeName, goType);
		}
		Msg.info(this, "Found %d golang types".formatted(goTypes.size()));
		initHiddenCompilerTypes();
	}

	private void initHiddenCompilerTypes() {
		// these structure types are what golang map and chan types actually point to.
		mapGoType = findGoType("runtime.hmap");
		chanGoType = findGoType("runtime.hchan");
	}

	private GoModuledata findFirstModuledata(TaskMonitor monitor) throws IOException {
		GoModuledata result = GoModuledata.getFirstModuledata(this);
		if (result == null) {
			monitor.setMessage("Searching for Golang pclntab");
			monitor.initialize(0);
			Address pclntabAddress = GoPcHeader.getPclntabAddress(program);
			if (pclntabAddress == null) {
				pclntabAddress =
					GoPcHeader.findPclntabAddress(this, getPclntabSearchRange(), monitor);
			}
			if (pclntabAddress != null) {
				monitor.setMessage("Searching for Golang firstmoduledata");
				monitor.initialize(0);
				GoPcHeader pclntab = readStructure(GoPcHeader.class, pclntabAddress);
				result = GoModuledata.findFirstModule(this, pclntabAddress, pclntab,
					getModuledataSearchRange(), monitor);
			}
		}
		if (result != null && !result.isValid()) {
			throw new IOException("Invalid Golang moduledata at %s"
					.formatted(result.getStructureContext().getStructureAddress()));
		}
		return result;
	}

	private AddressRange getPclntabSearchRange() {
		Memory memory = program.getMemory();
		for (String blockToSearch : List.of(".noptrdata", ".rdata")) {
			MemoryBlock noptrdataBlock = memory.getBlock(blockToSearch);
			if (noptrdataBlock != null) {
				return new AddressRangeImpl(noptrdataBlock.getStart(), noptrdataBlock.getEnd());
			}
		}
		return null;
	}

	private AddressRange getModuledataSearchRange() {
		Memory memory = program.getMemory();
		for (String blockToSearch : List.of(".noptrdata", ".data")) {
			MemoryBlock noptrdataBlock = memory.getBlock(blockToSearch);
			if (noptrdataBlock != null) {
				return new AddressRangeImpl(noptrdataBlock.getStart(), noptrdataBlock.getEnd());
			}
		}
		return null;
	}
}
