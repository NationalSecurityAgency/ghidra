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
import static ghidra.app.util.bin.format.golang.rtti.GoRttiMapper.FuncDefFlags.*;

import java.io.IOException;
import java.util.*;
import java.util.Map.Entry;
import java.util.regex.Pattern;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.TransientProgramProperties;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.golang.*;
import ghidra.app.util.bin.format.golang.rtti.GoApiSnapshot.*;
import ghidra.app.util.bin.format.golang.rtti.types.*;
import ghidra.app.util.bin.format.golang.rtti.types.GoMethod.GoMethodInfo;
import ghidra.app.util.bin.format.golang.structmapping.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.UnknownProgressWrappingTaskMonitor;

/**
 * {@link DataTypeMapper} for Go binaries. 
 * <p>
 * When bootstrapping Go binaries, the following steps are used:
 * <ul>
 * 	<li>Find the GoBuildInfo struct.  This struct is the easiest to locate, even when the binary
 * 	is stripped.  This gives us the Go pointerSize (probably same as ghidra pointer size) and the
 * 	goVersion.  This struct does not rely on StructureMapping, allowing its use before a
 * 	DataTypeMapper is created.</li>
 * 	<li>Create DataTypeMapper</li>
 * 	<li>Find the runtime.firstmoduledata structure.</li>
 * 	<li>
 *     <ul>
 *			<li>If there are symbols, just use the symbol or named memory block.</li>
 *			<li>If stripped:</li>
 *			<li>
 *				<ul>
 * 					<li>Find the pclntab.  This has a magic signature, a pointerSize, and references
 * 					to a couple of tables that are also referenced in the moduledata structure.</li>
 * 					<li>Search memory for a pointer to the pclntab struct.  This should be the first
 * 					field of the moduledata structure.  The values that are duplicated between the
 * 					two structures can be compared to ensure validity.</li>
 * 					<li>Different binary formats (Elf vs PE) will determine which memory blocks to
 * 					search.</li>
 * 				</ul>
 * 			</li>  
 * 	   </ul>
 *  </li>
 * </ul>
 */
public class GoRttiMapper extends DataTypeMapper implements DataTypeMapperContext {
	public static final GoVerRange SUPPORTED_VERSIONS = GoVerRange.parse("1.15-1.25");

	private static final List<String> SYMBOL_SEARCH_PREFIXES = List.of("", "_" /* macho symbols */);
	private static final List<String> SECTION_PREFIXES =
		List.of("." /* ELF */, "__" /* macho sections */);

	private static final String FAILED_FLAG = "FAILED TO FIND GOLANG BINARY";

	/**
	 * Returns a shared {@link GoRttiMapper} for the specified program, or null if the binary
	 * is not a supported Go binary.
	 * <p>
	 * The returned value will be cached and returned in any additional calls to this method, and
	 * automatically {@link #close() closed} when the current analysis session is finished.
	 * <p>
	 * NOTE: Only valid during an analysis session.  If outside of an analysis session, use
	 * {@link #getGoBinary(Program, TaskMonitor)} to create a new instance if you need to use this 
	 * outside of an analyzer.
	 *   
	 * @param program Go {@link Program} 
	 * @param monitor {@link TaskMonitor}
	 * @return a shared {@link GoRttiMapper Go binary} instance, or null if unable to find valid
	 * Go info in the Program
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
				Msg.info(GoRttiMapper.class, "Reading Go binary info: " + program.getName());
				try {
					GoRttiMapper supplier_result = getGoBinary(program, monitor);
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
					Msg.error(GoRttiMapper.class, "Failed to read Go info", e);
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
	 * @param monitor {@link TaskMonitor}
	 * @return new {@link GoRttiMapper}, or null if basic Go information is not found in the
	 * binary
	 * @throws BootstrapInfoException if it is a Go binary and has an unsupported or
	 * unparseable version number or if there was a missing Go bootstrap .gdt file
	 * @throws IOException if there was an error in the Ghidra Go RTTI reading logic 
	 */
	public static GoRttiMapper getGoBinary(Program program, TaskMonitor monitor)
			throws BootstrapInfoException, IOException {
		GoBuildInfo buildInfo = GoBuildInfo.fromProgram(program);
		if (buildInfo == null) {
			// probably not a Go binary
			return null;
		}

		GoVer goVer = buildInfo.getGoVer();
		if (goVer.isInvalid()) {
			throw new BootstrapInfoException(
				"Invalid Go version string [%s]".formatted(buildInfo.getVersion()));
		}
		if (!SUPPORTED_VERSIONS.contains(goVer) ) {
			Msg.error(GoRttiMapper.class, "Untested Go version [%s]".formatted(goVer));
		}

		GoApiSnapshot apiSnapshot;
		try {
			apiSnapshot = GoApiSnapshot.get(goVer, buildInfo.getGOARCH(program),
				buildInfo.getGOOS(program), monitor);
			if (!apiSnapshot.getVer().isInvalid()) {
				Msg.info(GoRttiMapper.class,
					"Using Go API snapshot for version %s".formatted(apiSnapshot.getVer()));
			}
		}
		catch (CancelledException e) {
			throw new IOException("Error fetching Go API snapshot file: cancelled");
		}

		return new GoRttiMapper(program, buildInfo, buildInfo.getPointerSize(), goVer, apiSnapshot);
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

	/**
	 * Returns a matching symbol from the specified program, using Go specific logic.
	 * 
	 * @param program {@link Program}
	 * @param symbolName name of Go symbol
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
	 * Return the address of the Go zerobase symbol, or an artificial substitute.
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
			Msg.warn(GoRttiMapper.class,
				"Unable to find Go runtime.zerobase, using " + zerobaseAddr);
		}
		return zerobaseAddr;
	}

	public static List<GoVer> getAllSupportedVersions() {
		try {
			return SUPPORTED_VERSIONS.asList();
		}
		catch (IOException e) {
			return List.of();
		}
	}

	public final static String ARTIFICIAL_RUNTIME_ZEROBASE_SYMBOLNAME =
		"ARTIFICIAL.runtime.zerobase";

	private static Address getArtificalZerobaseAddress(Program program) {
		Symbol zerobaseSym = getGoSymbol(program, ARTIFICIAL_RUNTIME_ZEROBASE_SYMBOLNAME);
		return zerobaseSym != null ? zerobaseSym.getAddress() : null;
	}

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
	private final GoBuildInfo buildInfo;
	private final GoVer goVer;
	private final int ptrSize;
	private final GoRegisterInfo regInfo;
	private final String defaultCCName;
	private final List<GoModuledata> modules = new ArrayList<>();
	private Map<Address, GoFuncData> funcdataByAddr = new HashMap<>();
	private Map<String, GoFuncData> funcdataByName = new HashMap<>();
	private Map<Address, List<MethodInfo>> methodsByAddr = new HashMap<>();
	private byte minLC;
	private final GoApiSnapshot apiSnapshot;
	private final GoTypeManager goTypes;

	/**
	 * Creates a GoRttiMapper using the specified bootstrap information.
	 * 
	 * @param program {@link Program} containing the Go binary
	 * @param buildInfo {@link GoBuildInfo}
	 * @param ptrSize size of pointers
	 * @param goVer version of Go
	 * @param apiSnapshot json func signatures and data types 
	 * @throws IOException if error linking a structure mapped structure to its matching
	 * ghidra structure, which is a programming error or a corrupted bootstrap gdt
	 * @throws BootstrapInfoException if there is no matching bootstrap gdt for this specific
	 * type of Go binary
	 */
	public GoRttiMapper(Program program, GoBuildInfo buildInfo, int ptrSize, GoVer goVer,
			GoApiSnapshot apiSnapshot) throws IOException, BootstrapInfoException {
		super(program, null);

		this.regInfo = GoRegisterInfoManager.getInstance()
				.getRegisterInfoForLang(program.getLanguage(), goVer);
		this.apiSnapshot = apiSnapshot;
		this.buildInfo = buildInfo;
		this.goVer = goVer;
		this.ptrSize = ptrSize;
		this.defaultCCName = regInfo.hasAbiInternalParamRegisters() &&
			hasCallingConvention(GOLANG_ABI_INTERNAL_CALLINGCONVENTION_NAME)
					? GOLANG_ABI_INTERNAL_CALLINGCONVENTION_NAME
					: null;

		reader = super.createProgramReader();

		this.goTypes = new GoTypeManager(this, apiSnapshot);

		initStructMappings();
	}

	private void initStructMappings() throws IOException {
		try {
			registerStructures(GOLANG_STRUCTMAPPED_CLASSES, this);
		}
		catch (IOException e) {
			if (apiSnapshot.isInvalid()) {
				// a normal'ish situation where we don't have type info for this arch/binary
				throw new BootstrapInfoException(
					"Missing Go bootstrap type info, unable to extract Go RTTI info."
							.formatted(goVer));
			}

			// we have type info, but something failed in the struct mappings 
			throw new IOException(
				"Invalid Go bootstrap struct mapping info: %s".formatted(goVer), e);
		}
	}

	@Override
	public void close() {
		Set<String> missingGoTypes = goTypes.getMissingGoTypes();
		if (!missingGoTypes.isEmpty()) {
			Msg.info(this, "Go missing type names: " + missingGoTypes.size());
			//missingGoTypes.forEach(s -> Msg.info(this, "  " + s));
		}
		super.close();
	}

	@Override
	public <T extends DataType> T getType(String name, Class<T> clazz) {
		try {
			DataType result = goTypes.findDataType(name);
			if (result == null && GoPcHeader.GO_STRUCTURE_NAME.equals(name) &&
				Structure.class.isAssignableFrom(clazz)) {
				// create an artificial runtime.pcHeader structure for <=1.15 to enable GoModuledata
				// to have references to a GoPcHeader 
				result = clazz.cast(GoPcHeader.createArtificialGoPcHeaderStructure(GOLANG_CP,
					program.getDataTypeManager()));
			}
			return clazz.isInstance(result) ? clazz.cast(result) : null;
		}
		catch (IOException e) {
			Msg.warn(this, "Unable to find Go type %s".formatted(name), e);
			return null;
		}
	}

	@Override
	public boolean isFieldPresent(String presentWhen) {
		presentWhen = presentWhen.strip();
		if (presentWhen.isEmpty()) {
			return true;
		}

		try {
			GoVerSet versions = GoVerSet.parse(presentWhen);
			if (!versions.isEmpty()) {
				return versions.contains(goVer);
			}
			// fall thru, throw error
		}
		catch (IOException e) {
			// fall thru
		}
		throw new IllegalArgumentException(
			"Invalid 'presentWhen' value [%s]".formatted(presentWhen));
	}

	/**
	 * {@return {@link GoVer Go version}}
	 */
	public GoVer getGoVer() {
		return goVer;
	}

	/**
	 * Returns a shared {@link GoRegisterInfo} instance
	 * @return {@link GoRegisterInfo}
	 */
	public GoRegisterInfo getRegInfo() {
		return regInfo;
	}

	public GoBuildInfo getBuildInfo() {
		return buildInfo;
	}

	/**
	 * Finishes making this instance ready to be used.
	 * 
	 * @param monitor {@link TaskMonitor}
	 * @throws IOException if error reading data
	 */
	public void init(TaskMonitor monitor) throws IOException {
		GoModuledata firstModule = findFirstModuledata(monitor);
		if (firstModule != null) {
			GoPcHeader pcHeader = firstModule.getPcHeader();
			if (pcHeader != null) {
				this.minLC = pcHeader.getMinLC();
				if (pcHeader.getPtrSize() != ptrSize) {
					throw new IOException(
						"Mismatched ptrSize: %d vs %d".formatted(pcHeader.getPtrSize(), ptrSize));
				}
				if (pcHeader.getGoVersion().isInvalid()) {
					// we can get here if the firstmoduledata was located via symbolname instead of
					// relying on bootstraping via the pcheader
					Msg.warn(this,
						"Unknown Go pcheader magic value: 0x%x".formatted(pcHeader.getMagic()));
				}
			}
			modules.add(firstModule);
		}
		initFuncdata();
		goTypes.init(monitor);
		initMethodInfo();
	}

	private void initFuncdata() throws IOException {
		for (GoModuledata module : modules) {
			for (GoFuncData funcdata : module.getAllFunctionData()) {
				funcdataByAddr.put(funcdata.getFuncAddress(), funcdata);
				funcdataByName.put(funcdata.getName(), funcdata);
			}
		}
	}

	private void initMethodInfo() throws IOException {
		for (GoType goType : goTypes.allTypes()) {
			goType.getMethodInfoList().forEach(this::addMethodInfo);
		}

		for (GoModuledata module : modules) {
			for (GoItab itab : module.getItabs()) {
				itab.getMethodInfoList().forEach(this::addMethodInfo);
			}
		}
	}

	private void addMethodInfo(MethodInfo bm) {
		List<MethodInfo> methods =
			methodsByAddr.computeIfAbsent(bm.getAddress(), unused -> new ArrayList<>());
		methods.add(bm);
	}

	public GoTypeManager getGoTypes() {
		return goTypes;
	}

	/**
	 * {@return the minLC (pcquantum) value found in the pcln header structure}
	 * @throws IOException if value has not been initialized yet
	 */
	public byte getMinLC() throws IOException {
		if (minLC == 0) {
			throw new IOException("Unknown Go minLC value");
		}
		return minLC;
	}

	/**
	 * {@return the first {@link GoModuledata} module data instance}
	 */
	public GoModuledata getFirstModule() {
		return !modules.isEmpty() ? modules.get(0) : null;
	}

	public List<GoModuledata> getModules() {
		return modules;
	}

	/**
	 * {@return new {@link GoParamStorageAllocator} param storage allocator instance}
	 */
	public GoParamStorageAllocator newStorageAllocator() {
		GoParamStorageAllocator storageAllocator = new GoParamStorageAllocator(program, goVer);
		return storageAllocator;
	}

	/**
	 * Returns true if the specified function uses the abi0 calling convention.
	 *  
	 * @param func {@link Function} to test
	 * @return boolean true if function uses abi0 calling convention
	 */
	public boolean isGolangAbi0Func(Function func) {
		return isAbi0Func(func.getEntryPoint(), program);
	}

	public static boolean isAbi0Func(Address funcEntry, Program program) {
		for (Symbol symbol : program.getSymbolTable().getSymbolsAsIterator(funcEntry)) {
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

	public String getDefaultCallingConventionName() {
		return defaultCCName;
	}

	@Override
	public MarkupSession createMarkupSession(TaskMonitor monitor) {
		UnknownProgressWrappingTaskMonitor upwtm = new UnknownProgressWrappingTaskMonitor(monitor);
		upwtm.initialize(1, "Marking up Go RTTI structures");

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

	public enum FuncDefFlags {
		RECV_MISSING,
		RECV_ARTIFICIAL,
		PARAMS_PARTIAL,
		PARAM_SUBSTITUTION,
		PARAMS_MISSING,
		RETURN_INFO_PARTIAL,
		RESULT_SUBSTITUTION,
		RETURN_INFO_MISSING,
		FROM_RTTI_METHOD,
		FROM_SNAPSHOT,
		FROM_ANALYSIS,
		CLOSURE,
		METHOD_WRAPPER
	}

	public record FuncDefResult(FunctionDefinition funcDef, GoType recvType, Set<FuncDefFlags> flags,
			String funcDefStr, GoSymbolName symbolName) {
	}

	/**
	 * Returns function definition information for a func.
	 * 
	 * @param funcData {@link GoFuncData} representing a Go func
	 * @return {@link FuncDefResult} record, or null if no information could be found or
	 * generated
	 * @throws IOException if error reading type info
	 */
	public FuncDefResult getFuncDefFor(GoFuncData funcData) throws IOException {
		GoSymbolName symbolName = funcData.getSymbolName();

		GoMethodInfo methodInfo = getMethodInfoForFunction(funcData.getFuncAddress());
		if (methodInfo != null) {
			if (symbolName.isNonPtrReceiverCandidate()) {
				GoType recvType = methodInfo.getType(); // never null
				GoSymbolName nonptrRecvName = symbolName.asNonPtrReceiverSymbolName();
				if (nonptrRecvName != null && recvType.getSymbolName()
						.getBaseTypeName()
						.equals(nonptrRecvName.getReceiverString())) {
					symbolName = nonptrRecvName;
				}
			}
			if (methodInfo.getMethodFuncType() != null) {
				return createFuncDefFromMethod(symbolName, methodInfo);
			}
		}

		if (symbolName.getPrefix() != null) {
			String prefix = Objects.requireNonNullElse(symbolName.getTypePrefixSubKeyword(), "");
			switch (prefix) {
				case "eq":
					return createFuncDefForDotEquals(symbolName);
				case "hash":
					return createFuncDefForDotHash(symbolName);
				default:
					return null;
			}
		}

		// TODO: a bit hacky, but the knowledge about how morestack takes a context
		// is not exposed via any function signature info
		if (symbolName.asString().equals("runtime.morestack")) {
			return createFuncDefForClosure(symbolName);
		}

		if (symbolName.isNonPtrReceiverCandidate()) {
			// attempt to reinterpret the symbolname as a non-pointer receiver symbol name
			GoSymbolName nonptrRecvName = symbolName.asNonPtrReceiverSymbolName();
			if (nonptrRecvName != null && goTypes.findRecieverType(nonptrRecvName) != null) {
				symbolName = nonptrRecvName;
			}
		}

		GoType recvType = methodInfo != null ? methodInfo.getType() : null;

		GoSymbolNameType nameType = symbolName.getNameType();
		if (nameType == GoSymbolNameType.METHOD_WRAPPER) {
			return createFuncDefForMethodWrapper(symbolName);
		}
		else if (nameType != null && nameType.isClosure()) {
			return createFuncDefForClosure(symbolName);
		}
		else {
			GoFuncDef snapshotFuncdef =
				apiSnapshot.getFuncdef(symbolName.getStrippedSymbolString());
			if (snapshotFuncdef != null) {
				return createFuncDefFromApiSnapshot(symbolName, recvType, snapshotFuncdef);
			}
		}

		return createFuncDefWithMissingInfo(symbolName, recvType);
	}

	private FuncDefResult createFuncDefForDotEquals(GoSymbolName symbolName) throws IOException {
		GoSymbolName typeName = GoSymbolName.parseTypeName(symbolName.getBaseName(), null);

		// Note: anon structs in older Go vers tend to also have package paths that make them
		// fail to match a simple namelookup, as well as the field names can fail to make because
		// of inconsistent package name inclusion.

		if (typeName.asString().startsWith("[...]")) {
			// strip array initializer string because it causes problems with parsing, and doesn't
			// matter because arrays are converted to element anyways.
			typeName = GoSymbolName.parseTypeName(typeName.asString().substring(5));
		}

		DataType typ = null;
		try {
			typ = goTypes.findDataType(typeName);
			if (typ != null && typ instanceof Array adt) {
				// convert array to its element, which will be turned into ptr-to-element lower down
				typ = adt.getDataType();
			}
		}
		catch (IOException e) {
			// fall thru with null dt
		}
		DataType dt = programDTM.getPointer(typ);
		DataType returnDT = BooleanDataType.dataType;

		List<ParameterDefinition> params = List.of(new ParameterDefinitionImpl("o1", dt, null),
			new ParameterDefinitionImpl("o2", dt, null));

		Set<FuncDefFlags> flags = typ != null
				? Set.of(FuncDefFlags.FROM_ANALYSIS)
				: Set.of(FuncDefFlags.FROM_ANALYSIS, FuncDefFlags.PARAM_SUBSTITUTION);

		FunctionDefinitionDataType funcDef =
			goTypes.createFuncDef(params, returnDT, symbolName, false);
		return new FuncDefResult(funcDef, null, flags, "func(*o1, *o2) bool", symbolName);
	}

	private FuncDefResult createFuncDefForDotHash(GoSymbolName symbolName) throws IOException {
		GoSymbolName typeName = GoSymbolName.parseTypeName(symbolName.getBaseName(), null);
		DataType typ = goTypes.findDataType(typeName);
		DataType dt = programDTM.getPointer(typ);
		DataType returnDT = goTypes.getDataType("uintptr");

		List<ParameterDefinition> params = List.of(new ParameterDefinitionImpl(null, dt, null),
			new ParameterDefinitionImpl("seed", goTypes.getDataType("uintptr"), null));

		Set<FuncDefFlags> flags = typ != null
				? Set.of(FuncDefFlags.FROM_ANALYSIS)
				: Set.of(FuncDefFlags.FROM_ANALYSIS, FuncDefFlags.PARAM_SUBSTITUTION);

		FunctionDefinitionDataType funcDef =
			goTypes.createFuncDef(params, returnDT, symbolName, false);
		return new FuncDefResult(funcDef, null, flags, "func(val*, seed) uintptr", symbolName);
	}

	private FuncDefResult createFuncDefForMethodWrapper(GoSymbolName symbolName)
			throws IOException {

		String s = symbolName.asString();
		String baseMethodName = s.substring(0, s.length() - "-fm".length()); // TODO: hacky
		GoFuncData methodFunc = getFunctionByName(baseMethodName);
		if (methodFunc != null) {
			GoSymbolName recvTypeName = symbolName.getReceiverTypeName();
			DataType closureDT = goTypes.getMethodClosureType(recvTypeName.asString());
			FuncDefResult funcDefResult = getFuncDefFor(methodFunc);
			if (closureDT != null && funcDefResult != null) {
				FunctionDefinition funcDef = funcDefResult.funcDef();
				ParameterDefinition[] args = funcDef.getArguments();
				ParameterDefinition recvArg = args[0];
				recvArg.setName(GOLANG_CLOSURE_CONTEXT_NAME);
				recvArg.setDataType(programDTM.getPointer(closureDT));

				funcDef.setArguments(args); // this is a NO-OP, modifying recvArg directly updates the funcdef

				EnumSet<FuncDefFlags> newFlags = EnumSet.copyOf(funcDefResult.flags());
				newFlags.add(METHOD_WRAPPER);

				return new FuncDefResult(funcDef, funcDefResult.recvType, newFlags,
					funcDefResult.funcDefStr, funcDefResult.symbolName);
			}
		}

		Structure closureDT = goTypes.getDefaultMethodWrapperClosureType();
		FunctionDefinition closureFuncdef = getFuncDefFromContextStruct(closureDT);
		if (closureFuncdef != null) {
			return new FuncDefResult(closureFuncdef, null,
				EnumSet.of(METHOD_WRAPPER, PARAMS_MISSING, RETURN_INFO_MISSING),
				"func-fm(.context, ???) ???", symbolName);
		}

		return null;
	}

	private FunctionDefinition getFuncDefFromContextStruct(Structure struct) {
		DataType ptrF =
			struct.getNumDefinedComponents() > 0 ? struct.getComponent(0).getDataType() : null;
		return ptrF instanceof Pointer ptr &&
			ptr.getDataType() instanceof FunctionDefinition funcdef ? funcdef : null;
	}

	private FuncDefResult createFuncDefForClosure(GoSymbolName symbolName) throws IOException {
		List<ParameterDefinition> closureParams =
			List.of(new ParameterDefinitionImpl(GOLANG_CLOSURE_CONTEXT_NAME,
				programDTM.getPointer(goTypes.getDefaultClosureType()), null));
		EnumSet<FuncDefFlags> flags = EnumSet.of(PARAMS_MISSING, RETURN_INFO_MISSING, CLOSURE);

		FunctionDefinitionDataType funcDef =
			goTypes.createFuncDef(closureParams, (DataType) null, symbolName, false);
		return new FuncDefResult(funcDef, null, flags, "func(.context, ???) ???",
			symbolName);

	}

	private FuncDefResult createFuncDefFromMethod(GoSymbolName symbolName,
			GoMethodInfo methodInfo) throws IOException {
		// This is the 'best' way to get the signature for a function, as all the types
		// should be resolved and present in the binary already
		EnumSet<FuncDefFlags> flags = EnumSet.of(FROM_RTTI_METHOD);

		GoType recvType = methodInfo.getType(); // never null
		GoFuncType methodFuncDefType = methodInfo.getMethodFuncType();

		FunctionDefinition funcdef = methodFuncDefType.getFunctionSignature(goTypes);

		FunctionDefinition funcDT = goTypes.createFuncDef(List.of(funcdef.getArguments()),
			funcdef.getReturnType(), symbolName, false);

		insertArg(funcDT, 0, GOLANG_RECEIVER_PARAM_NAME, goTypes.getDataType(recvType));
		if (symbolName.hasGenerics()) {
			insertArg(funcDT, 1, GOLANG_GENERICS_PARAM_NAME, goTypes.getGenericDictDT());
		}
		return new FuncDefResult(funcDT, recvType, flags, methodInfo.toString(),
			symbolName);
	}

	private FuncDefResult createFuncDefWithMissingInfo(GoSymbolName symbolName, GoType recvType)
			throws IOException {
		String funcdefStr = "";
		EnumSet<FuncDefFlags> flags = EnumSet.of(PARAMS_MISSING, RETURN_INFO_MISSING);
		List<ParameterDefinition> params = new ArrayList<>();

		if (symbolName.hasReceiver()) {
			DataType recvDT = goTypes.getDataType(recvType);
			if ( recvDT == null ) {
				recvDT = goTypes.findRecieverType(symbolName);
			}
			if (recvType == null) {
				recvType = goTypes.getSubstitutionType(symbolName.getReceiverString());
				flags.add(RECV_ARTIFICIAL);
			}
			if (recvType == null) {
				// if we can't get the receiver type, which is the first param in the arg list,
				// we can't construct a useful funcdef
				return null;
			}

			funcdefStr = recvType.getMethodPrototypeString(symbolName.getBaseName(), null);


			params.add(new ParameterDefinitionImpl(GOLANG_RECEIVER_PARAM_NAME,
				goTypes.getDataType(recvType), null));
		}

		if (symbolName.hasGenerics()) {
			params.add(
				new ParameterDefinitionImpl(GOLANG_GENERICS_PARAM_NAME, goTypes.getGenericDictDT(),
					null));
		}

		if (!params.isEmpty()) {
			FunctionDefinitionDataType funcDef =
				goTypes.createFuncDef(params, (DataType) null, symbolName, false);

			return new FuncDefResult(funcDef, recvType, flags, funcdefStr, symbolName);
		}

		return null;
	}

	private FuncDefResult createFuncDefFromApiSnapshot(GoSymbolName symbolName, GoType recvType,
			GoFuncDef snapshotFuncdef) throws IOException {
		EnumSet<FuncDefFlags> flags = EnumSet.of(FROM_SNAPSHOT);
		List<ParameterDefinition> params = new ArrayList<>();
		List<ParameterDefinition> returnParams = new ArrayList<>();
		for (int i =0; i < snapshotFuncdef.Params.size(); i++) {
			GoNameTypePair p = snapshotFuncdef.Params.get(i);
			DataType pDT = goTypes.findDataType(p.DataType);
			if (pDT == null) {
				break;
			}
			if (!goTypes.hasGoType(p.DataType)) {
				flags.add(
					i == 0 && symbolName.hasReceiver() ? RECV_ARTIFICIAL : PARAM_SUBSTITUTION);
			}
			String paramName = (p.Name == null || p.Name.isEmpty()) && i == 0
					? GOLANG_RECEIVER_PARAM_NAME
					: p.Name;
			params.add(new ParameterDefinitionImpl(paramName, pDT, null));
		}
		for (GoNameTypePair p : snapshotFuncdef.Results) {
			DataType pDT = goTypes.findDataType(p.DataType);
			if (pDT == null) {
				break;
			}
			if (!goTypes.hasGoType(p.DataType)) {
				flags.add(RESULT_SUBSTITUTION);
			}
			returnParams.add(new ParameterDefinitionImpl(p.Name, pDT, null));
		}
		
		if ( params.size() < snapshotFuncdef.Params.size() ) {
			flags.add(params.isEmpty() ? PARAMS_MISSING : FuncDefFlags.PARAMS_PARTIAL);
		}
		if ( returnParams.size() < snapshotFuncdef.Results.size() ) {
			if (returnParams.isEmpty()) {
				returnParams = null;
			}
			flags.add(returnParams == null ? RETURN_INFO_MISSING : RETURN_INFO_PARTIAL);
		}
		if ( symbolName.hasGenerics() ) {
			// insert artificial generic dict param, iff recv param was successfully added
			int generics_index = symbolName.hasReceiver() && params.size() > 0 ? 1 : 0;
			if (params.size() >= generics_index) {
				params.add(generics_index,
					new ParameterDefinitionImpl(GOLANG_GENERICS_PARAM_NAME,
						goTypes.getGenericDictDT(), null));
			}
		}
		
		FunctionDefinitionDataType funcDef = goTypes.createFuncDef(params, returnParams, symbolName,
			snapshotFuncdef.getFuncFlags().contains(FuncFlags.NoReturn));
		return new FuncDefResult(funcDef, recvType, flags,
			snapshotFuncdef.getDefinitionString(symbolName), symbolName);

	}
	
	private void insertArg(FunctionDefinition funcDef, int index, String argName, DataType argDT) {
		List<ParameterDefinition> args = new ArrayList<>(Arrays.asList(funcDef.getArguments()));
		args.add(index, new ParameterDefinitionImpl(argName, argDT, null));
		funcDef.setArguments(args.toArray(ParameterDefinition[]::new));
	}
	


	/**
	 * Returns method info about the specified function.
	 * 
	 * @param funcAddr function address
	 * @return {@link GoMethodInfo}, or null
	 */
	public GoMethodInfo getMethodInfoForFunction(Address funcAddr) {
		List<MethodInfo> results = methodsByAddr.getOrDefault(funcAddr, List.of());
		for (MethodInfo mi : results) {
			if (mi instanceof GoMethodInfo gmi && gmi.isTfn(funcAddr)) {
				return gmi;
			}
		}
		return null;
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
		fallbackName =
			fallbackName == null && structContext != null
					? "%s_%x".formatted(structContext.getMappingInfo().getStructureName(),
						structContext.getStructureStart())
					: "invalid_object";
		return GoName.createFakeInstance(fallbackName);
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

	public List<GoFuncData> getFunctionsByNamePattern(Pattern pattern) {
		List<GoFuncData> results = new ArrayList<>();
		for (Entry<String, GoFuncData> entry : funcdataByName.entrySet()) {
			String name = entry.getKey();
			GoFuncData func = entry.getValue();
			if (pattern.matcher(name).matches()) {
				results.add(func);
			}
		}
		return results;
	}

	/**
	 * {@return list of all functions contained in the Go func metadata table}
	 */
	public List<GoFuncData> getAllFunctions() {
		return new ArrayList<>(funcdataByAddr.values());
	}

	private GoModuledata findFirstModuledata(TaskMonitor monitor) throws IOException {
		GoModuledata result = GoModuledata.getFirstModuledata(this);
		Address pcHeaderAddress =
			result != null ? result.getPcHeaderAddress() : GoPcHeader.getPcHeaderAddress(program);
		if (pcHeaderAddress == null) {
			monitor.initialize(0, "Searching for Go pclntab");
			pcHeaderAddress =
				GoPcHeader.findPcHeaderAddress(this, getPclntabSearchRange(), monitor);
		}
		if (result == null && pcHeaderAddress != null) {
			// find the moduledata struct by searching for a pointer to the pclntab/pcHeader,
			// which should be the first field in the moduledata struct.
			monitor.initialize(0, "Searching for Go firstmoduledata");
			GoPcHeader pcHeader = readStructure(GoPcHeader.class, pcHeaderAddress);
			result = GoModuledata.findFirstModule(this, pcHeaderAddress, pcHeader,
				getModuledataSearchRange(), monitor);
		}

		if (result != null && !result.isValid()) {
			throw new IOException("Invalid Go moduledata at %s"
					.formatted(result.getStructureContext().getStructureAddress()));
		}
		return result;
	}

	private AddressRange getPclntabSearchRange() {
		MemoryBlock memBlock = getFirstGoSection(program, "noptrdata", "rdata");
		return memBlock != null ? new AddressRangeImpl(memBlock.getStart(), memBlock.getEnd())
				: null;
	}

	private AddressRange getModuledataSearchRange() {
		MemoryBlock memBlock = getFirstGoSection(program, "noptrdata", "data");
		return memBlock != null ? new AddressRangeImpl(memBlock.getStart(), memBlock.getEnd())
				: null;
	}

	/**
	 * {@return {@link AddressSetView} of range that is valid to find string structs in}
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
	 * {@return {@link AddressSetView} of range that is valid for string char[] data}
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

	public AddressSetView getUninitializedNoPtrDataRange() {
		AddressSet result = new AddressSet();
		for (GoModuledata moduledata : modules) {
			result.add(moduledata.getUninitializedNoPtrDataRange());
		}
		return result;
	}

	public Symbol getGoSymbol(String symbolName) {
		return getGoSymbol(program, symbolName);
	}

	public MemoryBlock getGoSection(String sectionName) {
		return getGoSection(program, sectionName);
	}
}
