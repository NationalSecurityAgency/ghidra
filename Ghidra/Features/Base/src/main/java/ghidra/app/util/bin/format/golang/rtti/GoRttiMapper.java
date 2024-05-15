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

import static java.util.stream.Collectors.*;

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.Map.Entry;

import javax.help.UnsupportedOperationException;

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.TransientProgramProperties;
import ghidra.app.plugin.core.datamgr.util.DataTypeArchiveUtility;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf.DWARFDataTypeConflictHandler;
import ghidra.app.util.bin.format.dwarf.DWARFProgram;
import ghidra.app.util.bin.format.golang.*;
import ghidra.app.util.bin.format.golang.rtti.types.*;
import ghidra.app.util.bin.format.golang.structmapping.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.*;
import ghidra.framework.Platform;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataTypeConflictHandler.ConflictResult;
import ghidra.program.model.data.StandAloneDataTypeManager.LanguageUpdateOption;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.*;
import ghidra.util.exception.*;
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

	private static final String FAILED_FLAG = "FAILED TO FIND GOLANG BINARY";

	/**
	 * Returns a shared {@link GoRttiMapper} for the specified program, or null if the binary
	 * is not a supported golang binary.
	 * <p>
	 * The returned value will be cached and returned in any additional calls to this method, and
	 * automatically {@link #close() closed} when the current analysis session is finished.
	 * <p>
	 * NOTE: Only valid during an analysis session.  If outside of an analysis session, use
	 * {@link #getGoBinary(Program)} to create a new instance if you need to use this outside 
	 * of an analyzer.
	 *   
	 * @param program golang {@link Program} 
	 * @param monitor {@link TaskMonitor}
	 * @return a shared {@link GoRttiMapper go binary} instance, or null if unable to find valid
	 * golang info in the Program
	 * 
	 */
	public static GoRttiMapper getSharedGoBinary(Program program, TaskMonitor monitor) {
		if (TransientProgramProperties.hasProperty(program, FAILED_FLAG)) {
			// don't try to do any work if we've failed earlier
			return null;
		}
		GoRttiMapper goBinary = TransientProgramProperties.getProperty(program, GoRttiMapper.class,
			TransientProgramProperties.SCOPE.ANALYSIS_SESSION, GoRttiMapper.class, () -> {
				// cached instance not found, create new instance
				Msg.info(GoRttiMapper.class, "Reading golang binary info: " + program.getName());
				try {
					GoRttiMapper supplier_result = getGoBinary(program);
					if (supplier_result != null) {
						supplier_result.init(monitor);
						return supplier_result;
					}
				}
				catch (BootstrapInfoException mbie) {
					Msg.warn(GoRttiMapper.class, mbie.getMessage());
					logAnalyzerMsg(program, mbie.getMessage());
				}
				catch (IOException e) {
					// this is a more serious error, and the stack trace should be written
					// to the application log
					Msg.error(GoRttiMapper.class, "Failed to read golang info", e);
					logAnalyzerMsg(program, e.getMessage());
				}

				// this sets the failed flag
				TransientProgramProperties.getProperty(program, FAILED_FLAG,
					TransientProgramProperties.SCOPE.PROGRAM, Boolean.class, () -> true);

				return null;
			});

		return goBinary;
	}

	private static void logAnalyzerMsg(Program program, String msg) {
		AutoAnalysisManager aam = AutoAnalysisManager.getAnalysisManager(program);
		if (aam.isAnalyzing()) {
			// should cause a modal popup at end of analysis that will show the message
			MessageLog log = aam.getMessageLog();
			log.appendMsg(msg);
		}
	}

	/**
	 * Creates a {@link GoRttiMapper} representing the specified program.
	 * 
	 * @param program {@link Program}
	 * @return new {@link GoRttiMapper}, or null if basic golang information is not found in the
	 * binary
	 * @throws BootstrapInfoException if it is a golang binary and has an unsupported or
	 * unparseable version number or if there was a missing golang bootstrap .gdt file
	 * @throws IOException if there was an error in the Ghidra golang rtti reading logic 
	 */
	public static GoRttiMapper getGoBinary(Program program)
			throws BootstrapInfoException, IOException {
		GoBuildInfo buildInfo = GoBuildInfo.fromProgram(program);
		if (buildInfo == null) {
			// probably not a golang binary
			return null;
		}

		GoVer goVer = buildInfo.getVerEnum();
		if (goVer == GoVer.UNKNOWN) {
			throw new BootstrapInfoException(
				"Unsupported Golang version, version info: '%s'".formatted(buildInfo.getVersion()));
		}

		ResourceFile gdtFile =
			findGolangBootstrapGDT(goVer, buildInfo.getPointerSize(), getGolangOSString(program));
		if (gdtFile == null) {
			Msg.error(GoRttiMapper.class, "Missing golang gdt archive for " + goVer);
		}

		return new GoRttiMapper(program, buildInfo.getPointerSize(), buildInfo.getEndian(),
			buildInfo.getVerEnum(), gdtFile);
	}

	/**
	 * Returns the name of the golang bootstrap gdt data type archive, using the specified
	 * version, pointer size and OS name.
	 * 
	 * @param goVer {@link GoVer}
	 * @param pointerSizeInBytes pointer size for this binary, or -1 to use wildcard "any" 
	 * @param osName name of the operating system, or "any"
	 * @return String, "golang_1.18_64bit_any.gdt"
	 */
	public static String getGDTFilename(GoVer goVer, int pointerSizeInBytes, String osName) {
		String bitSize = pointerSizeInBytes > 0 ? Integer.toString(pointerSizeInBytes * 8) : "any";
		String gdtFilename = "golang_%d.%d_%sbit_%s.gdt".formatted(goVer.getMajor(),
			goVer.getMinor(), bitSize, osName);
		return gdtFilename;
	}

	/**
	 * Returns a golang OS string based on the Ghidra program.
	 * 
	 * @param program {@link Program}
	 * @return String golang OS string such as "linux", "win"
	 */
	public static String getGolangOSString(Program program) {
		String loaderName = program.getExecutableFormat();
		if (ElfLoader.ELF_NAME.equals(loaderName)) {
			// TODO: this will require additional work to map all Golang OSs to Ghidra loader info
			return "linux";
		}
		else if (PeLoader.PE_NAME.equals(loaderName)) {
			return "win";
		}
		else if (MachoLoader.MACH_O_NAME.equals(loaderName)) {
			LanguageID languageID = program.getLanguageCompilerSpecPair().getLanguageID();
			if ("AARCH64:LE:64:AppleSilicon".equals(languageID.getIdAsString())) {
				return Platform.MAC_ARM_64.getDirectoryName(); // mac_arm_64
			}
		}
		return null;
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
	 * @return ResourceFile of matching bootstrap gdt, or null if nothing matches
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

	/**
	 * Returns true if the specified Program is marked as "golang".
	 * 
	 * @param program {@link Program}
	 * @return boolean true if program is marked as golang
	 */
	public static boolean isGolangProgram(Program program) {
		return GoConstants.GOLANG_CSPEC_NAME.equals(
			program.getCompilerSpec().getCompilerSpecDescription().getCompilerSpecName());
	}

	public static boolean hasGolangSections(List<String> sectionNames) {
		for (String sectionName : sectionNames) {
			if (sectionName.contains("gopclntab") ||
				sectionName.contains(GoBuildInfo.MACHO_SECTION_NAME) ||
				sectionName.contains(GoBuildInfo.SECTION_NAME)) {
				return true;
			}
		}
		return false;
	}

	private static final List<String> SYMBOL_SEARCH_PREFIXES = List.of("", "_" /* macho symbols */);
	private static final List<String> SECTION_PREFIXES =
		List.of("." /* ELF */, "__" /* macho sections */);

	/**
	 * Returns a matching symbol from the specified program, using golang specific logic.
	 * 
	 * @param program {@link Program}
	 * @param symbolName name of golang symbol
	 * @return {@link Symbol}, or null if not found
	 */
	public static Symbol getGoSymbol(Program program, String symbolName) {
		for (String prefix : SYMBOL_SEARCH_PREFIXES) {
			List<Symbol> symbols = program.getSymbolTable().getSymbols(prefix + symbolName, null);
			if (symbols.size() == 1) {
				return symbols.get(0);
			}
		}
		return null;
	}

	public static MemoryBlock getGoSection(Program program, String sectionName) {
		for (String prefix : SECTION_PREFIXES) {
			MemoryBlock memBlock = program.getMemory().getBlock(prefix + sectionName);
			if (memBlock != null) {
				return memBlock;
			}
		}
		return null;
	}

	public static MemoryBlock getFirstGoSection(Program program, String... blockNames) {
		for (String blockToSearch : blockNames) {
			MemoryBlock memBlock = getGoSection(program, blockToSearch);
			if (memBlock != null) {
				return memBlock;
			}
		}
		return null;
	}

	/**
	 * Return the address of the golang zerobase symbol, or an artificial substitute.
	 * <p>
	 * The zerobase symbol is used as the location of parameters that are zero-length.
	 * 
	 * @param prog {@link Program}
	 * @return {@link Address} of the runtime.zerobase, or artificial substitute
	 */
	public static Address getZerobaseAddress(Program prog) {
		Symbol zerobaseSym = getGoSymbol(prog, "runtime.zerobase");
		Address zerobaseAddr =
			zerobaseSym != null ? zerobaseSym.getAddress() : getArtificalZerobaseAddress(prog);
		if (zerobaseAddr == null) {
			zerobaseAddr = prog.getImageBase().getAddressSpace().getMinAddress();	// ICKY HACK
			Msg.warn(GoFunctionFixup.class,
				"Unable to find Golang runtime.zerobase, using " + zerobaseAddr);
		}
		return zerobaseAddr;
	}

	public final static String ARTIFICIAL_RUNTIME_ZEROBASE_SYMBOLNAME =
		"ARTIFICIAL.runtime.zerobase";

	private static Address getArtificalZerobaseAddress(Program program) {
		Symbol zerobaseSym = getGoSymbol(program, ARTIFICIAL_RUNTIME_ZEROBASE_SYMBOLNAME);
		return zerobaseSym != null ? zerobaseSym.getAddress() : null;
	}

	private static final CategoryPath RECOVERED_TYPES_CP =
		GoConstants.GOLANG_RECOVERED_TYPES_CATEGORYPATH;
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
	private final DataType uint8DT;
	private final DataType stringDT;
	private final Map<Long, GoType> goTypes = new HashMap<>();
	private final Map<String, GoType> typeNameIndex = new HashMap<>();
	private final Map<Long, String> fixedGoTypeNames = new HashMap<>();
	private final Map<Long, DataType> cachedRecoveredDataTypes = new HashMap<>();
	private final List<GoModuledata> modules = new ArrayList<>();
	private Map<Address, GoFuncData> funcdataByAddr = new HashMap<>();
	private Map<String, GoFuncData> funcdataByName = new HashMap<>();
	private Map<Address, List<MethodInfo>> methodsByAddr = new HashMap<>();
	private Map<Long, List<GoItab>> interfacesImplementedByType = new HashMap<>();
	private byte minLC;
	private GoType mapGoType;
	private GoType chanGoType;
	private GoRegisterInfo regInfo;

	/**
	 * Creates a GoRttiMapper using the specified bootstrap information.
	 * 
	 * @param program {@link Program} containing the go binary
	 * @param ptrSize size of pointers
	 * @param endian {@link Endian}
	 * @param goVersion version of go
	 * @param archiveGDT path to the matching golang bootstrap gdt data type file, or null
	 * if not present and types recovered via DWARF should be used instead
	 * @throws IOException if error linking a structure mapped structure to its matching
	 * ghidra structure, which is a programming error or a corrupted bootstrap gdt
	 * @throws BootstrapInfoException if there is no matching bootstrap gdt for this specific
	 * type of golang binary
	 */
	public GoRttiMapper(Program program, int ptrSize, Endian endian, GoVer goVersion,
			ResourceFile archiveGDT) throws IOException, BootstrapInfoException {
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
		this.uint8DT = getTypeOrDefault("uint8", DataType.class,
			AbstractIntegerDataType.getUnsignedDataType(1, null));
		this.stringDT = getTypeOrDefault("string", Structure.class, null);

		try {
			registerStructures(GOLANG_STRUCTMAPPED_CLASSES);
		}
		catch (IOException e) {
			if (archiveGDT == null) {
				// a normal'ish situation where there isn't a .gdt for this arch/binary and there
				// isn't any DWARF.
				throw new BootstrapInfoException(
					"Missing golang .gdt archive for %s, no fallback DWARF info, unable to extract Golang RTTI info."
							.formatted(goVersion));
			}

			// we have a .gdt, but something failed. 
			throw new IOException("Invalid Golang bootstrap GDT file or struct mapping info: %s"
					.formatted(archiveGDT.getAbsolutePath()),
				e);
		}
	}

	/**
	 * Returns the golang version
	 * @return {@link GoVer}
	 */
	public GoVer getGolangVersion() {
		return goVersion;
	}

	/**
	 * Returns a shared {@link GoRegisterInfo} instance
	 * @return {@link GoRegisterInfo}
	 */
	public GoRegisterInfo getRegInfo() {
		return regInfo;
	}

	/**
	 * Finishes making this instance ready to be used.
	 * 
	 * @param monitor {@link TaskMonitor}
	 * @throws IOException if error reading data
	 */
	public void init(TaskMonitor monitor) throws IOException {
		this.regInfo = GoRegisterInfoManager.getInstance()
				.getRegisterInfoForLang(program.getLanguage(), goVersion);

		GoModuledata firstModule = findFirstModuledata(monitor);
		if (firstModule != null) {
			GoPcHeader pcHeader = firstModule.getPcHeader();
			this.minLC = pcHeader.getMinLC();
			if (pcHeader.getPtrSize() != ptrSize) {
				throw new IOException(
					"Mismatched ptrSize: %d vs %d".formatted(pcHeader.getPtrSize(), ptrSize));
			}
			addModule(firstModule);
		}
		initFuncdata();
	}

	private void initFuncdata() throws IOException {
		for (GoModuledata module : modules) {
			for (GoFuncData funcdata : module.getAllFunctionData()) {
				funcdataByAddr.put(funcdata.getFuncAddress(), funcdata);
				funcdataByName.put(funcdata.getName(), funcdata);
			}
		}

	}

	/**
	 * Initializes golang function / method lookup info
	 * 
	 * @throws IOException if error reading data
	 */
	public void initMethodInfoIfNeeded() throws IOException {
		if (methodsByAddr.isEmpty()) {
			initMethodInfo();
		}
	}

	private void initMethodInfo() throws IOException {
		for (GoType goType : goTypes.values()) {
			goType.getMethodInfoList().forEach(this::addMethodInfo);
		}

		for (GoModuledata module : modules) {
			for (GoItab itab : module.getItabs()) {
				itab.getMethodInfoList().forEach(this::addMethodInfo);

				// create index of interfaces that each type implements
				List<GoItab> itabs = interfacesImplementedByType.computeIfAbsent(
					itab.getType().getTypeOffset(), unused -> new ArrayList<>());
				itabs.add(itab);
			}
		}
	}

	private void addMethodInfo(MethodInfo bm) {
		List<MethodInfo> methods =
			methodsByAddr.computeIfAbsent(bm.getAddress(), unused -> new ArrayList<>());
		methods.add(bm);
	}

	/**
	 * Returns the minLC (pcquantum) value found in the pcln header structure
	 * @return minLC value
	 * @throws IOException if value has not been initialized yet
	 */
	public byte getMinLC() throws IOException {
		if (minLC == 0) {
			throw new IOException("Unknown Golang minLC value");
		}
		return minLC;
	}

	/**
	 * Returns the first module data instance
	 * 
	 * @return {@link GoModuledata}
	 */
	public GoModuledata getFirstModule() {
		return !modules.isEmpty() ? modules.get(0) : null;
	}

	/**
	 * Adds a module data instance to the context
	 * 
	 * @param module {@link GoModuledata} to add
	 */
	public void addModule(GoModuledata module) {
		modules.add(module);
	}

	/**
	 * Returns a new param storage allocator instance.
	 * 
	 * @return new {@link GoParamStorageAllocator} instance
	 */
	public GoParamStorageAllocator newStorageAllocator() {
		GoParamStorageAllocator storageAllocator = new GoParamStorageAllocator(program, goVersion);
		return storageAllocator;
	}

	/**
	 * Returns true if the specified function uses the abi0 calling convention.
	 *  
	 * @param func {@link Function} to test
	 * @return boolean true if function uses abi0 calling convention
	 */
	public boolean isGolangAbi0Func(Function func) {
		Address funcAddr = func.getEntryPoint();
		for (Symbol symbol : func.getProgram().getSymbolTable().getSymbolsAsIterator(funcAddr)) {
			if (symbol.getSymbolType() == SymbolType.LABEL) {
				String labelName = symbol.getName();
				if (labelName.endsWith("abi0")) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Returns true if the specified calling convention is defined for the program.
	 * @param ccName calling convention name
	 * @return true if the specified calling convention is defined for the program
	 */
	public boolean hasCallingConvention(String ccName) {
		return program.getFunctionManager().getCallingConvention(ccName) != null;
	}

	@Override
	public MarkupSession createMarkupSession(TaskMonitor monitor) {
		UnknownProgressWrappingTaskMonitor upwtm = new UnknownProgressWrappingTaskMonitor(monitor);
		upwtm.initialize(1, "Marking up Golang RTTI structures");

		return super.createMarkupSession(upwtm);
	}

	/**
	 * Finds the {@link GoModuledata} that contains the specified offset.
	 * <p>
	 * Useful for finding the {@link GoModuledata} to resolve a relative offset of the text,
	 * types or other area.
	 *  
	 * @param offset absolute offset of a structure that a {@link GoModuledata} contains
	 * @return {@link GoModuledata} instance that contains the structure, or null if not found
	 */
	public GoModuledata findContainingModule(long offset) {
		for (GoModuledata module : modules) {
			if (module.getTypesOffset() <= offset && offset < module.getTypesEndOffset()) {
				return module;
			}
		}
		return null;
	}

	/**
	 * Finds the {@link GoModuledata} that contains the specified func data offset.
	 * 
	 * @param offset absolute offset of a func data structure
	 * @return {@link GoModuledata} instance that contains the specified func data, or null if not
	 * found
	 */
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

	/**
	 * Returns the data type that represents a generic golang slice.
	 * 
	 * @return golang generic slice data type
	 */
	public Structure getGenericSliceDT() {
		return getStructureDataType(GoSlice.class);
	}

	/**
	 * Returns the ghidra data type that represents a golang built-in map type.
	 * 
	 * @return golang map data type
	 */
	public GoType getMapGoType() {
		return mapGoType;
	}

	/**
	 * Returns the ghidra data type that represents the built-in golang channel type.
	 * 
	 * @return golang channel type
	 */
	public GoType getChanGoType() {
		return chanGoType;
	}

	@Override
	protected BinaryReader createProgramReader() {
		return reader.clone();
	}

	/**
	 * Returns the size of pointers in this binary.
	 * 
	 * @return pointer size (ex. 4, or 8)
	 */
	public int getPtrSize() {
		return ptrSize;
	}

	/**
	 * Returns a specialized {@link GoType} for the type that is located at the specified location.
	 * 
	 * @param offset absolute position of a go type
	 * @return specialized {@link GoType} (example, GoStructType, GoArrayType, etc)
	 * @throws IOException if error reading
	 */
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

	/**
	 * Returns a previous read and cached GoType, based on its offset.
	 * 
	 * @param offset offset of the GoType
	 * @return GoType, or null if not previously read and cached
	 */
	public GoType getCachedGoType(long offset) {
		GoType goType = goTypes.get(offset);
		return goType;
	}

	/**
	 * Returns a specialized {@link GoType} for the type that is located at the specified location.
	 * 
	 * @param addr location of a go type
	 * @return specialized {@link GoType} (example, GoStructType, GoArrayType, etc)
	 * @throws IOException if error reading
	 */
	public GoType getGoType(Address addr) throws IOException {
		return getGoType(addr.getOffset());
	}

	/**
	 * Finds a go type by its go-type name, from the list of 
	 * {@link #discoverGoTypes(TaskMonitor) discovered} go types.
	 *  
	 * @param typeName name string
	 * @return {@link GoType}, or null if not found
	 */
	public GoType findGoType(String typeName) {
		return typeNameIndex.get(typeName);
	}

	/**
	 * Returns the Ghidra {@link DataType} that is equivalent to the named golang type.
	 * 
	 * @param <T> expected DataType
	 * @param goTypeName golang type name
	 * @param clazz class of expected data type
	 * @return {@link DataType} representing the named golang type, or null if not found
	 */
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
					Msg.warn(this, "Failed to get Ghidra data type from go type: %s[%x]".formatted(
						goTypeName, goType.getStructureContext().getStructureStart()));
				}
			}
		}
		return dt;
	}

	/**
	 * Export the currently registered struct mapping types to a gdt file, producing a bootstrap
	 * GDT archive.
	 * <p>
	 * The struct data types will either be from the current program's DWARF data, or
	 * from an earlier golang.gdt (if this binary doesn't have DWARF)
	 * 
	 * @param gdtFile destination {@link File} to write the bootstrap types to
	 * @param runtimeFuncSnapshot boolean flag, if true include function definitions
	 * @param monitor {@link TaskMonitor}
	 * @throws IOException if error
	 * @throws CancelledException if cancelled
	 */
	public void exportTypesToGDT(File gdtFile, boolean runtimeFuncSnapshot, TaskMonitor monitor)
			throws IOException, CancelledException {

		List<DataType> bootstrapFuncDefs = runtimeFuncSnapshot
				? createBootstrapFuncDefs(program.getDataTypeManager(),
					GoConstants.GOLANG_BOOTSTRAP_FUNCS_CATEGORYPATH, monitor)
				: List.of();

		List<DataType> registeredStructDTs = mappingInfo.values()
				.stream()
				.map(this::structMappingInfoToDataType)
				.filter(Objects::nonNull)
				.toList();

		// Copy the data types into a tmp gdt, and then copy them again into the final gdt
		// to avoid traces of the original program name as a deleted source archive link in the
		// gdt data base.  This method only leaves the target gdt filename + ".step1" in the db.
		File tmpGDTFile = new File(gdtFile.getParentFile(), gdtFile.getName() + ".step1.gdt");
		FileDataTypeManager tmpFdtm = createFileArchive(tmpGDTFile, program.getLanguage(),
			program.getCompilerSpec().getCompilerSpecID(), monitor);
		int tx = -1;
		try {
			tx = tmpFdtm.startTransaction("Import");
			tmpFdtm.addDataTypes(registeredStructDTs, DataTypeConflictHandler.DEFAULT_HANDLER,
				monitor);
			if (runtimeFuncSnapshot) {
				tmpFdtm.addDataTypes(bootstrapFuncDefs, DataTypeConflictHandler.KEEP_HANDLER,
					monitor);
			}
			moveAllDataTypesTo(tmpFdtm, DWARFProgram.DWARF_ROOT_CATPATH, GOLANG_CP);
			for (SourceArchive sa : tmpFdtm.getSourceArchives()) {
				tmpFdtm.removeSourceArchive(sa);
			}
			tmpFdtm.getRootCategory()
					.removeCategory(DWARFProgram.DWARF_ROOT_CATPATH.getName(), monitor);

			// Nuke descriptions in all data types.  Most likely are DWARF debug data, etc that would
			// be specific to the example program.
			for (Iterator<DataType> it = tmpFdtm.getAllDataTypes(); it.hasNext();) {
				DataType dt = it.next();
				if (dt.getDescription() != null) {
					if (dt instanceof Composite &&
						!GoFunctionMultiReturn.isMultiReturnDataType(dt)) {
						// don't nuke the generic warning in the multi-return data type						
						dt.setDescription(null);
					}
				}
				if (dt instanceof FunctionDefinition funcDef) {
					funcDef.setComment(null);
				}
			}
		}
		catch (CancelledException | DuplicateNameException | DataTypeDependencyException
				| InvalidNameException e) {
			Msg.error(this, "Error when exporting types to file: %s".formatted(gdtFile), e);
		}
		finally {
			if (tx != -1) {
				tmpFdtm.endTransaction(tx, true);
			}
		}

		tmpFdtm.save();

		FileDataTypeManager fdtm = createFileArchive(gdtFile, program.getLanguage(),
			program.getCompilerSpec().getCompilerSpecID(), monitor);
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

	private FileDataTypeManager createFileArchive(File gdtFile, Language lang,
			CompilerSpecID compilerId, TaskMonitor monitor) throws IOException {
		try {
			FileDataTypeManager fdtm = FileDataTypeManager.createFileArchive(gdtFile);
			fdtm.setProgramArchitecture(lang, compilerId, LanguageUpdateOption.CLEAR, monitor);
			return fdtm;
		}
		catch (IOException | CancelledException | LockException | UnsupportedOperationException
				| IncompatibleLanguageException e) {
			throw new IOException("Failed to create file data type manager: " + gdtFile, e);
		}
	}

	private DataType structMappingInfoToDataType(StructureMappingInfo<?> smi) {
		if (smi.getStructureDataType() == null) {
			return null;
		}
		DataType existingDT = findType(smi.getStructureName(),
			List.of(DWARFProgram.DWARF_ROOT_CATPATH, DWARFProgram.UNCAT_CATPATH), programDTM);
		if (existingDT == null) {
			existingDT = smi.getStructureDataType();
		}
		if (existingDT == null) {
			Msg.warn(this, "Missing type: " + smi.getDescription());
		}
		return existingDT;
	}


	private List<DataType> createBootstrapFuncDefs(DataTypeManager destDTM, CategoryPath destCP,
			TaskMonitor monitor) throws CancelledException {
		List<Function> funcs = getAllFunctions().stream()
				.filter(funcData -> funcData.getFlags().isEmpty())
				.map(BootstrapFuncInfo::from)
				.filter(Objects::nonNull)
//				.filter(funcInfo -> !GoFunctionMultiReturn
//						.isMultiReturnDataType(funcInfo.func.getReturnType()))
				.filter(BootstrapFuncInfo::isBootstrapFunction)
				.filter(BootstrapFuncInfo::isNotPlatformSpecificSourceFile)
				.map(BootstrapFuncInfo::func)
				.toList();
		monitor.initialize(funcs.size(), "Creating golang bootstrap function defs");
		List<DataType> results = new ArrayList<>();
		for (Function func : funcs) {
			monitor.increment();
			try {
				FunctionDefinitionDataType funcDef =
					new FunctionDefinitionDataType(func.getSignature());
				funcDef.setCategoryPath(destCP);
				funcDef.setCallingConvention(null);
				funcDef.setComment(null);
				DataType newDT = destDTM.addDataType(funcDef, DataTypeConflictHandler.KEEP_HANDLER);
				results.add(newDT);
			}
			catch (InvalidInputException e) {
				// skip
			}
		}
		return results;
	}


	private void moveAllDataTypesTo(DataTypeManager dtm, CategoryPath srcCP, CategoryPath destCP)
			throws DuplicateNameException, DataTypeDependencyException, InvalidNameException {
		Category srcCat = dtm.getCategory(srcCP);
		if (srcCat != null) {
			for (DataType dt : srcCat.getDataTypes()) {
				if (dt instanceof Array || dt instanceof Pointer) {
					continue;
				}
				String destName = dt.getName();
				if (dt instanceof TypeDef td && td.getName().startsWith(".param")) {
					// special case of typedefs called ".paramNNN" (created by go for generic type params)
					// The type name needs to be tweaked to prevent clashes with others
					destName = td.getCategoryPath().getName() + dt.getName();
				}
				DataType existingDT = dtm.getDataType(new DataTypePath(destCP, destName));
				if (existingDT != null) {
					if (DWARFDataTypeConflictHandler.INSTANCE.resolveConflict(dt,
						existingDT) != ConflictResult.USE_EXISTING) {
						throw new DuplicateNameException("Error moving golang type: [%s] to [%s]"
								.formatted(dt.getDataTypePath(), existingDT.getDataTypePath()));
					}
					dtm.replaceDataType(dt, existingDT, false);
					continue;
				}
				dt.setNameAndCategory(destCP, destName);
			}
			for (Category subcat : srcCat.getCategories()) {
				moveAllDataTypesTo(dtm, subcat.getCategoryPath(), destCP); // flatten everything
			}
		}
	}

	/**
	 * Returns category path that should be used to place recovered golang types.
	
	 * @param packagePath optional package path of the type (eg. "utf/utf8", or "runtime")
	 * @return {@link CategoryPath} to use when creating recovered golang types
	 */
	public CategoryPath getRecoveredTypesCp(String packagePath) {
		CategoryPath result = RECOVERED_TYPES_CP;
		if (packagePath != null && !packagePath.isEmpty()) {
			result = result.extend(packagePath);
		}
		return result;
	}

	/**
	 * Returns a {@link DataType Ghidra data type} that represents the {@link GoType golang type}, 
	 * using a cache of already recovered types to eliminate extra work and self recursion.
	 *  
	 * @param typ the {@link GoType} to convert
	 * @return Ghidra {@link DataType}
	 * @throws IOException if error converting type
	 */
	public DataType getRecoveredType(GoType typ) throws IOException {
		Address typeStructAddr = getAddressOfStructure(typ);
		if (typeStructAddr == null) {
			throw new IOException("Unable to get address of a struct mapped instance");
		}
		long offset = typeStructAddr.getOffset();
		DataType dt = cachedRecoveredDataTypes.get(offset);
		if (dt != null) {
			return dt;
		}
		dt = typ.recoverDataType();
		cachedRecoveredDataTypes.put(offset, dt);
		return dt;
	}

	/**
	 * Returns a function definition for a method that is attached to a golang type.
	 * <p>
	 * 
	 * @param methodName name of method
	 * @param methodType golang function def type
	 * @param receiverDT data type of the go type that contains the method
	 * @param allowPartial boolean flag, if true allows returning an artificial funcdef when the
	 * methodType parameter does not point to a function definition
	 * @return new {@link FunctionDefinition} using the function signature specified by the
	 * methodType function definition, with the containing goType's type inserted as the first
	 * parameter, similar to a c++ "this" parameter
	 * @throws IOException if error reading type info
	 */
	public FunctionDefinition getSpecializedMethodSignature(String methodName, GoType methodType,
			DataType receiverDT, boolean allowPartial) throws IOException {
		if ((methodType == null && !allowPartial) || receiverDT == null) {
			return null;
		}
		FunctionDefinition methodFuncDef = methodType != null
				? GoFuncType.unwrapFunctionDefinitionPtrs(getRecoveredType(methodType))
				: new FunctionDefinitionDataType("empty", program.getDataTypeManager());
		if (methodFuncDef == null) {
			return null;
		}
		methodFuncDef = (FunctionDefinition) methodFuncDef.copy(program.getDataTypeManager());
		try {
			methodFuncDef.setNameAndCategory(receiverDT.getCategoryPath(), methodName);
			List<ParameterDefinition> args =
				new ArrayList<>(Arrays.asList(methodFuncDef.getArguments()));
			args.add(0, new ParameterDefinitionImpl(null, receiverDT, null));
			methodFuncDef.setArguments(args.toArray(ParameterDefinition[]::new));

			return methodFuncDef;
		}
		catch (InvalidNameException | DuplicateNameException e) {
			Msg.warn(this, "Error when creating function signature for method", e);
			return null;
		}

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
		Address typeStructAddr = getAddressOfStructure(typ);
		if (typeStructAddr == null) {
			throw new IOException("Unable to get address of a struct mapped instance");
		}
		long offset = typeStructAddr.getOffset();
		cachedRecoveredDataTypes.put(offset, dt);
	}

	/**
	 * Returns a {@link DataType Ghidra data type} that represents the {@link GoType golang type}, 
	 * using a cache of already recovered types to eliminate extra work and self recursion.
	 *  
	 * @param typ the {@link GoType} to convert
	 * @return Ghidra {@link DataType}
	 * @throws IOException if golang type struct is not a valid struct mapped instance
	 */
	public DataType getCachedRecoveredDataType(GoType typ) throws IOException {
		Address typeStructAddr = getAddressOfStructure(typ);
		if (typeStructAddr == null) {
			throw new IOException("Unable to get address of a struct mapped instance");
		}
		long offset = typeStructAddr.getOffset();
		return cachedRecoveredDataTypes.get(offset);
	}

	/**
	 * Converts all discovered golang rtti type records to Ghidra data types, placing them
	 * in the program's DTM in /golang-recovered
	 * 
	 * @param monitor {@link TaskMonitor}
	 * @throws IOException error converting a golang type to a Ghidra type
	 * @throws CancelledException if the user cancelled the import
	 */
	public void recoverDataTypes(TaskMonitor monitor) throws IOException, CancelledException {
		monitor.initialize(goTypes.size(), "Converting Golang types to Ghidra data types");
		List<Long> typeOffsets = goTypes.keySet().stream().sorted().toList();
		for (Long typeOffset : typeOffsets) {
			monitor.increment();
			GoType typ = getGoType(typeOffset);
			DataType dt = typ.recoverDataType();
			if (programDTM.getDataType(dt.getDataTypePath()) == null) {
				programDTM.addDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
			}
		}
	}

	/**
	 * Discovers available golang types if not already done.
	 * 
	 * @param monitor {@link TaskMonitor}
	 * @throws CancelledException if cancelled
	 * @throws IOException if error reading data
	 */
	public void initTypeInfoIfNeeded(TaskMonitor monitor) throws CancelledException, IOException {
		if (goTypes.isEmpty()) {
			discoverGoTypes(monitor);
		}
	}

	/**
	 * Iterates over all golang rtti types listed in the GoModuledata struct, and recurses into
	 * each type to discover any types they reference.
	 * <p>
	 * The found types are accumulated in {@link #goTypes}.
	 * 
	 * @param monitor {@link TaskMonitor}
	 * @throws IOException if error
	 * @throws CancelledException if cancelled
	 */
	public void discoverGoTypes(TaskMonitor monitor) throws IOException, CancelledException {
		UnknownProgressWrappingTaskMonitor upwtm = new UnknownProgressWrappingTaskMonitor(monitor);
		upwtm.setMessage("Iterating Golang RTTI types");

		goTypes.clear();
		typeNameIndex.clear();
		Set<Long> discoveredTypes = new HashSet<>();
		for (GoModuledata module : modules) {
			for (Iterator<GoType> it = module.iterateTypes(); it.hasNext();) {
				upwtm.checkCancelled();
				upwtm.setProgress(discoveredTypes.size());

				GoType type = it.next();
				type.discoverGoTypes(discoveredTypes);
			}
		}

		// Fix non-unique type names, which can happen when types are embedded inside a function,
		// (example: func foo() { type result;... }, in dir1/packageA and in dir2/packageA) 
		Map<String, Integer> typeDupCount = new HashMap<>();
		for (GoType goType : goTypes.values()) {
			String typeName = goType.getNameWithPackageString();
			typeDupCount.merge(typeName, 1, (i1, i2) -> i1 + i2);
		}
		Set<String> dupedTypeNames = typeDupCount.entrySet()
				.stream()
				.filter(entry -> entry.getValue() > 1)
				.map(Entry::getKey)
				.collect(toSet());
		typeDupCount.clear();
		
		for (GoType goType : goTypes.values()) {
			String typeName = goType.getNameWithPackageString();
			if (dupedTypeNames.contains(typeName)) {
				typeName = typeName + "." + typeDupCount.merge(typeName, 1, (i1, i2) -> i1 + i2);
			}
			GoType existingType = typeNameIndex.put(typeName, goType);
			if (existingType != null) {
				Msg.warn(this, "Go type name conflict: " + typeName);
			}
			fixedGoTypeNames.put(goType.getTypeOffset(), typeName);
		}
		Msg.info(this, "Found %d golang types".formatted(goTypes.size()));

		// these structure types are what golang map and chan types actually point to.
		mapGoType = findGoType("runtime.hmap");
		chanGoType = findGoType("runtime.hchan");
	}

	/**
	 * Returns a list of methods (either gotype methods or interface methods) that point
	 * to this function.
	 * 
	 * @param funcAddr function address
	 * @return list of methods
	 */
	public List<MethodInfo> getMethodInfoForFunction(Address funcAddr) {
		List<MethodInfo> result = methodsByAddr.get(funcAddr);
		return result != null ? result : List.of();
	}

	/**
	 * Returns a list of interfaces that the specified type has implemented.
	 * 
	 * @param type GoType
	 * @return list of itabs that map a GoType to the interfaces it was found to implement
	 */
	public List<GoItab> getInterfacesImplementedByType(GoType type) {
		return interfacesImplementedByType.getOrDefault(type.getTypeOffset(), List.of());
	}

	/**
	 * Returns a unique name for the specified go type.
	 * @param goType {@link GoType}
	 * @return unique string name 
	 */
	public String getUniqueGoTypename(GoType goType) {
		String name = fixedGoTypeNames.get(goType.getTypeOffset());
		if (name == null) {
			name = goType.getNameWithPackageString();
		}
		return name;
	}

	public interface GoNameSupplier {
		GoName get() throws IOException;
	}

	/**
	 * An exception handling wrapper around a "getName()" call that could throw an IOException.
	 * <p>
	 * When there is an error fetching the GoName instance via the specified callback, a limited
	 * usage GoName instance will be created and returned that will provide a replacement name
	 * that is built using the calling structure's offset as the identifier.
	 *  
	 * @param <T> struct mapped instance type
	 * @param supplier Supplier callback
	 * @param structInstance reference to the caller's struct-mapped instance 
	 * @param defaultValue string value to return (wrapped in a GoName) if the GoName is simply 
	 * missing
	 * @return GoName, either from the callback, or a limited-functionality instance created to
	 * hold a fallback name string
	 */
	public <T> GoName getSafeName(GoNameSupplier supplier, T structInstance, String defaultValue) {
		try {
			GoName result = supplier.get();
			if (result != null) {
				return result;
			}
			// fall thru, return a fake GoName with defaultValue
		}
		catch (IOException e) {
			// fall thru, return fallback name, but ensure defaultValue isn't used
			defaultValue = null;
		}

		StructureContext<T> structContext = getStructureContextOfInstance(structInstance);
		String fallbackName = defaultValue;
		fallbackName = fallbackName == null && structContext != null
				? "%s_%x".formatted(structContext.getMappingInfo().getStructureName(),
					structContext.getStructureStart())
				: "invalid_object";
		return GoName.createFakeInstance(fallbackName);
	}

	/**
	 * Returns the name of a gotype.
	 * 
	 * @param offset offset of the gotype RTTI record
	 * @return string name, with a fallback if the specified offset was invalid
	 */
	public String getGoTypeName(long offset) {
		try {
			GoType goType = getGoType(offset);
			if (goType != null) {
				return goType.getName();
			}
		}
		catch (IOException e) {
			// fall thru
		}
		return "unknown_type_%x".formatted(offset);
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
		GoModuledata module = findContainingModule(ptrInModule);
		return getGoType(module.getTypesOffset() + off);
	}

	/**
	 * Returns the {@link Address} to an offset that is relative to the controlling
	 * GoModuledata's text value.
	 * 
	 * @param ptrInModule the address of the structure that contains the offset that needs to be
	 * calculated.  The containing-structure's address is important because it indicates which
	 * GoModuledata is the 'parent' 
	 * @param off offset
	 * @return {@link Address}, or null if offset was special value -1
	 */
	public Address resolveTextOff(long ptrInModule, long off) {
		if (off == -1 || off == NumericUtilities.MAX_UNSIGNED_INT32_AS_LONG) {
			return null;
		}
		GoModuledata module = findContainingModule(ptrInModule);
		return module != null ? module.getText().add(off) : null;
	}

	/**
	 * Returns the {@link GoName} corresponding to an offset that is relative to the controlling
	 * GoModuledata's typesOffset.
	 * <p>
	 * 
	 * @param ptrInModule the address of the structure that contains the offset that needs to be
	 * calculated.  The containing-structure's address is important because it indicates which
	 * GoModuledata is the 'parent' 
	 * @param off offset
	 * @return {@link GoName}, or null if offset was special value 0
	 * @throws IOException if error reading name or unable to find containing module
	 */
	public GoName resolveNameOff(long ptrInModule, long off) throws IOException {
		if (off == 0) {
			return null;
		}
		GoModuledata module = findContainingModule(ptrInModule);
		if (module == null) {
			throw new IOException(
				"Unable to find containing module for structure at 0x%x".formatted(ptrInModule));
		}
		long nameStart = module.getTypesOffset() + off;
		return getGoName(nameStart);
	}

	/**
	 * Returns the {@link GoName} instance at the specified offset.
	 * 
	 * @param offset location to read
	 * @return {@link GoName} instance, or null if offset was special value 0
	 * @throws IOException if error reading
	 */
	public GoName getGoName(long offset) throws IOException {
		return offset != 0 ? readStructure(GoName.class, offset) : null;
	}

	/**
	 * Returns metadata about a function
	 * 
	 * @param funcAddr entry point of a function
	 * @return {@link GoFuncData}, or null if function not found in lookup tables
	 */
	public GoFuncData getFunctionData(Address funcAddr) {
		return funcdataByAddr.get(funcAddr);
	}

	/**
	 * Returns a function based on its name
	 * 
	 * @param funcName name of function
	 * @return {@link GoFuncData}, or null if not found
	 */
	public GoFuncData getFunctionByName(String funcName) {
		return funcdataByName.get(funcName);
	}

	/**
	 * Return a list of all functions
	 * 
	 * @return list of all functions contained in the golang func metadata table
	 */
	public List<GoFuncData> getAllFunctions() {
		return new ArrayList<>(funcdataByAddr.values());
	}

	/**
	 * Returns a {@link FunctionDefinition} for a built-in golang runtime function.
	 * 
	 * @param funcName name of function
	 * @return {@link FunctionDefinition}, or null if not found in bootstrap gdt
	 */
	public FunctionDefinition getBootstrapFunctionDefintion(String funcName) {
		if (archiveDTM != null) {
			DataType dt =
				archiveDTM.getDataType(GoConstants.GOLANG_BOOTSTRAP_FUNCS_CATEGORYPATH, funcName);
			return dt instanceof FunctionDefinition funcDef ? funcDef : null;
		}
		return null;
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
		MemoryBlock memBlock = getFirstGoSection(program, "noptrdata", "rdata");
		return memBlock != null
				? new AddressRangeImpl(memBlock.getStart(), memBlock.getEnd())
				: null;
	}

	private AddressRange getModuledataSearchRange() {
		MemoryBlock memBlock = getFirstGoSection(program, "noptrdata", "data");
		return memBlock != null
				? new AddressRangeImpl(memBlock.getStart(), memBlock.getEnd())
				: null;
	}

	/**
	 * Returns the address range that is valid for string structs to be found in.
	 * 
	 * @return {@link AddressSetView} of range that is valid to find string structs in
	 */
	public AddressSetView getStringStructRange() {
		AddressSet result = new AddressSet();
		for (GoModuledata moduledata : modules) {
			result.add(moduledata.getDataRange());
			result.add(moduledata.getRoDataRange());
		}
		return result;
	}

	/**
	 * Returns the address range that is valid for string char[] data to be found in.
	 * 
	 * @return {@link AddressSetView} of range that is valid for string char[] data
	 */
	public AddressSetView getStringDataRange() {
		// TODO: initialized []byte("stringchars") slices can have data in noptrdata section
		AddressSet result = new AddressSet();
		for (GoModuledata moduledata : modules) {
			result.add(moduledata.getRoDataRange());
		}
		return result;
	}

	public AddressSetView getTextAddresses() {
		AddressSet result = new AddressSet();
		for (GoModuledata moduledata : modules) {
			result.add(moduledata.getTextRange());
		}
		return result;
	}


	public Symbol getGoSymbol(String symbolName) {
		return getGoSymbol(program, symbolName);
	}

	public MemoryBlock getGoSection(String sectionName) {
		return getGoSection(program, sectionName);
	}

	//--------------------------------------------------------------------------------------------
	record BootstrapFuncInfo(GoFuncData funcData, Function func) {
		/**
		 * Golang package paths that will be used to decide if a function qualifies as a bootstrap
		 * function and be included in the golang.gdt file.
		 */
		private static final Set<String> BOOTSTRAP_PACKAGE_PATHS = Set.of("archive/tar",
			"archive/zip", "bufio", "bytes", "compress/bzip2", "compress/flate", "compress/gzip",
			"compress/lzw", "compress/zlib", "container/heap", "container/list", "container/ring",
			"context", "crypto", "crypto/aes", "crypto/cipher", "crypto/des", "crypto/dsa",
			"crypto/ecdh", "crypto/ecdsa", "crypto/ed25519", "crypto/elliptic", "crypto/hmac",
			"crypto/md5", "crypto/rand", "crypto/rc4", "crypto/rsa", "crypto/sha1", "crypto/sha256",
			"crypto/sha512", "crypto/subtle", "crypto/tls", "crypto/x509", "database/sql",
			"debug/buildinfo", "debug/elf", "debug/gosym", "errors", "flag", "fmt", "io", "io/fs",
			"io/ioutil", "log", "log/syslog", "math", "math/big", "math/rand", "net", "net/http",
			"net/url", "os", "path", "path/filepath", "plugin", "runtime", "sort", "strconv",
			"strings", "sync", "text/scanner", "text/tabwriter", "text/template", "time", "unicode",
			"unicode/utf16", "unicode/utf8", "unsafe",

			"reflect", "internal/cpu", "internal/fmtsort", "internal/reflectlite");

		/**
		 * Source filename exclusion filters, matched against a function's source filename.
		 */
		private static final Set<String> BOOTSTRAP_SRCFILE_PLATFORM_SPECIFIC =
			Set.of("amd64", "arm" /*arm, arm64*/, "loong64", "ppc64", "386", "mips" /*mips,mips64*/,
				"risc", "s390", "wasm", "aix", "android", "darwin", "dragonfly", "freebsd", "linux",
				"windows", "openbsd", "ios");

		static BootstrapFuncInfo from(GoFuncData funcData) {
			Function func = funcData.getFunction();
			return func != null ? new BootstrapFuncInfo(funcData, func) : null;
		}

		/**
		 * Returns true if the specified function should be included in the bootstrap function defs
		 * that are written to the golang_NNNN.gdt archive.
		 * <p>
		 * @return true if function should be included in golang.gdt bootstrap file
		 */
		public boolean isBootstrapFunction() {
			String packagePath = funcData.getSymbolName().getPackagePath();
			return packagePath != null && BOOTSTRAP_PACKAGE_PATHS.contains(packagePath);
		}

		/**
		 * Returns true if function is a generic function and is not located in a source filename
		 * that has a platform specific substring (eg. "_linux")
		 * 
		 * @return true if function is a generic function and is not located in a platform specific
		 * source file
		 */
		public boolean isNotPlatformSpecificSourceFile() {
			try {
				GoSourceFileInfo sfi = funcData.getSourceFileInfo();
				String sourceFilename = sfi != null ? sfi.getFileName() : null;
				if (sourceFilename != null) {
					for (String sourceFileExclude : BOOTSTRAP_SRCFILE_PLATFORM_SPECIFIC) {
						if (sourceFilename.contains("_" + sourceFileExclude)) {
							return false;
						}
					}
				}
				return true;
			}
			catch (IOException e) {
				return false;
			}
		}

	}
}
