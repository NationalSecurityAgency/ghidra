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
package ghidra.app.plugin.core.analysis;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.util.*;

import generic.jar.ResourceFile;
import ghidra.app.services.*;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.format.dwarf4.DWARFUtil;
import ghidra.app.util.bin.format.elf.info.ElfInfoItem.ItemWithAddress;
import ghidra.app.util.bin.format.golang.*;
import ghidra.app.util.bin.format.golang.rtti.*;
import ghidra.app.util.bin.format.golang.structmapping.MarkupSession;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.UnknownProgressWrappingTaskMonitor;
import ghidra.xml.XmlParseException;
import utilities.util.FileUtilities;

/**
 * Analyzes Golang binaries for RTTI and function symbol information.
 */
public class GolangSymbolAnalyzer extends AbstractAnalyzer {

	private final static String NAME = "Golang Symbol";
	private final static String DESCRIPTION = """
			Analyze Golang binaries for RTTI and function symbols.
			'Apply Data Archives' and 'Shared Return Calls' analyzers should be disabled \
			for best results.""";
	private final static String ARTIFICIAL_RUNTIME_ZEROBASE_SYMBOLNAME =
		"ARTIFICIAL.runtime.zerobase";

	private GolangAnalyzerOptions analyzerOptions = new GolangAnalyzerOptions();

	public GolangSymbolAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.FORMAT_ANALYSIS.after().after());
		setDefaultEnablement(true);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		monitor.setMessage("Golang symbol analyzer");

		try (GoRttiMapper goBinary = GoRttiMapper.getMapperFor(program, log)) {
			if (goBinary == null) {
				Msg.error(this, "Golang analyzer error: unable to get GoRttiMapper");
				return false;
			}
			goBinary.init(monitor);
			goBinary.discoverGoTypes(monitor);

			UnknownProgressWrappingTaskMonitor upwtm =
				new UnknownProgressWrappingTaskMonitor(monitor, 100);
			upwtm.initialize(0);
			upwtm.setMessage("Marking up Golang RTTI structures");

			MarkupSession markupSession = goBinary.createMarkupSession(upwtm);
			GoModuledata firstModule = goBinary.getFirstModule();
			if (firstModule != null) {
				markupSession.labelStructure(firstModule, "firstmoduledata");
				markupSession.markup(firstModule, false);
			}

			markupWellknownSymbols(goBinary, markupSession);
			setupProgramContext(goBinary, markupSession);
			goBinary.recoverDataTypes(monitor);
			markupGoFunctions(goBinary, markupSession);
			fixupNoReturnFuncs(program);
			markupMiscInfoStructs(program);

			if (analyzerOptions.createBootstrapDatatypeArchive) {
				createBootstrapGDT(goBinary, program, monitor);
			}
		}
		catch (IOException e) {
			Msg.error(this, "Golang analysis failure", e);
		}

		return true;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(GolangAnalyzerOptions.CREATE_BOOTSTRAP_GDT_OPTIONNAME,
			analyzerOptions.createBootstrapDatatypeArchive, null,
			GolangAnalyzerOptions.CREATE_BOOTSTRAP_GDT_DESC);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		analyzerOptions.createBootstrapDatatypeArchive =
			options.getBoolean(GolangAnalyzerOptions.CREATE_BOOTSTRAP_GDT_OPTIONNAME,
				analyzerOptions.createBootstrapDatatypeArchive);
	}

	private void markupWellknownSymbols(GoRttiMapper goBinary, MarkupSession session)
			throws IOException {
		Program program = goBinary.getProgram();

		Symbol g0 = SymbolUtilities.getUniqueSymbol(program, "runtime.g0");
		Structure gStruct = goBinary.getGhidraDataType("runtime.g", Structure.class);
		if (g0 != null && gStruct != null) {
			session.markupAddressIfUndefined(g0.getAddress(), gStruct);
		}

		Symbol m0 = SymbolUtilities.getUniqueSymbol(program, "runtime.m0");
		Structure mStruct = goBinary.getGhidraDataType("runtime.m", Structure.class);
		if (m0 != null && mStruct != null) {
			session.markupAddressIfUndefined(m0.getAddress(), mStruct);
		}
	}

	private void markupGoFunctions(GoRttiMapper goBinary, MarkupSession markupSession)
			throws IOException {
		for (GoFuncData funcdata : goBinary.getAllFunctions()) {
			String funcname = SymbolUtilities.replaceInvalidChars(funcdata.getName(), true);
			markupSession.createFunctionIfMissing(funcname, funcdata.getFuncAddress());
		}
		try {
			fixDuffFunctions(goBinary, markupSession);
		}
		catch (InvalidInputException | DuplicateNameException e) {
			Msg.error(this, "Error configuring duff functions", e);
		}
	}

	/**
	 * Fixes the function signature of the runtime.duffzero and runtime.duffcopy functions.
	 * <p>
	 * The alternate duff-ified entry points haven't been discovered yet, so the information
	 * set to the main function entry point will be propagated at a later time to the alternate 
	 * entry points by the GolangDuffFixupAnalyzer.
	 * 
	 * @param goBinary the golang binary
	 * @param session {@link MarkupSession}
	 * @throws InvalidInputException if error assigning the function signature
	 * @throws DuplicateNameException if error assigning the function signature
	 */
	private void fixDuffFunctions(GoRttiMapper goBinary, MarkupSession session)
			throws InvalidInputException, DuplicateNameException {
		Program program = goBinary.getProgram();
		GoRegisterInfo regInfo = goBinary.getRegInfo();
		DataType voidPtr = program.getDataTypeManager().getPointer(VoidDataType.dataType);
		DataType uintDT = goBinary.getTypeOrDefault("uint", DataType.class,
			AbstractUnsignedIntegerDataType.getUnsignedDataType(goBinary.getPtrSize(), null));
		
		GoFuncData duffzeroFuncdata = goBinary.getFunctionByName("runtime.duffzero");
		Function duffzeroFunc = duffzeroFuncdata != null
				? program.getFunctionManager().getFunctionAt(duffzeroFuncdata.getFuncAddress())
				: null;
		PrototypeModel duffzeroCC = goBinary.getDuffzeroCallingConvention();
		if (duffzeroFunc != null && duffzeroCC != null) {
			// NOTE: some duffzero funcs need a zero value supplied to them via a register set
			// by the caller.  (depending on the arch)  The duffzero calling convention defined 
			// by the callspec should take care of this by defining that register as the second 
			// storage location. Otherwise, the callspec will only have a single storage 
			// location defined.
			boolean needZeroValueParam = regInfo.getZeroRegister() == null;
			List<Variable> params = new ArrayList<>();
			params.add(new ParameterImpl("dest", voidPtr, program));
			if (needZeroValueParam) {
				params.add(new ParameterImpl("zeroValue", uintDT, program));
			}

			duffzeroFunc.updateFunction(duffzeroCC.getName(),
				new ReturnParameterImpl(VoidDataType.dataType, program), params,
				FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true,
				SourceType.ANALYSIS);

			DWARFUtil.appendComment(program, duffzeroFunc.getEntryPoint(), CodeUnit.PLATE_COMMENT,
				"Golang special function: ", "duffzero", "\n");
		}

		GoFuncData duffcopyFuncdata = goBinary.getFunctionByName("runtime.duffcopy");
		Function duffcopyFunc = duffcopyFuncdata != null
				? program.getFunctionManager().getFunctionAt(duffcopyFuncdata.getFuncAddress())
				: null;
		PrototypeModel duffcopyCC = goBinary.getDuffcopyCallingConvention();
		if (duffcopyFuncdata != null && duffcopyCC != null) {
			List<Variable> params = List.of(
				new ParameterImpl("dest", voidPtr, program),
				new ParameterImpl("src", voidPtr, program));
			duffcopyFunc.updateFunction(duffcopyCC.getName(),
				new ReturnParameterImpl(VoidDataType.dataType, program), params,
				FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);

			DWARFUtil.appendComment(program, duffcopyFunc.getEntryPoint(), CodeUnit.PLATE_COMMENT,
				"Golang special function: ", "duffcopy", "\n");
		}

	}

	private void markupMiscInfoStructs(Program program) {
		// this also adds "golang" info to program properties

		ItemWithAddress<GoBuildInfo> wrappedBuildInfo = GoBuildInfo.findBuildInfo(program);
		if (wrappedBuildInfo != null && program.getListing()
				.isUndefined(wrappedBuildInfo.address(), wrappedBuildInfo.address())) {
			// this will mostly be PE binaries that don't have Elf markup magic stuff
			wrappedBuildInfo.item().markupProgram(program, wrappedBuildInfo.address());
		}
		ItemWithAddress<PEGoBuildId> wrappedPeBuildId = PEGoBuildId.findBuildId(program);
		if (wrappedPeBuildId != null && program.getListing()
				.isUndefined(wrappedPeBuildId.address(), wrappedPeBuildId.address())) {
			// HACK to handle golang hack: check if a function symbol was laid down at the location
			// of the buildId string.  If true, convert it to a plain label
			Symbol[] buildIdSymbols =
				program.getSymbolTable().getSymbols(wrappedPeBuildId.address());
			for (Symbol sym : buildIdSymbols) {
				if (sym.getSymbolType() == SymbolType.FUNCTION) {
					String symName = sym.getName();
					sym.delete();
					try {
						program.getSymbolTable()
								.createLabel(wrappedPeBuildId.address(), symName,
									SourceType.IMPORTED);
					}
					catch (InvalidInputException e) {
						// ignore
					}
					break;
				}
			}
			wrappedPeBuildId.item().markupProgram(program, wrappedPeBuildId.address());
		}
	}

	private void fixupNoReturnFuncs(Program program) {
		Set<String> noreturnFuncnames = new HashSet<>();

		try {
			for (ResourceFile file : NonReturningFunctionNames.findDataFiles(program)) {
				FileUtilities.getLines(file)
						.stream()
						.map(String::trim)
						.filter(s -> !s.isBlank() && !s.startsWith("#"))
						.forEach(noreturnFuncnames::add);
			}
		}
		catch (IOException | XmlParseException e) {
			Msg.error(this, "Failed to read Golang noreturn func data file", e);
		}

		int count = 0;
		SymbolTable symbolTable = program.getSymbolTable();
		for (Symbol symbol : symbolTable.getPrimarySymbolIterator(true)) {
			String name = symbol.getName(false);
			if (symbol.isExternal() /* typically not an issue with golang */
				|| !noreturnFuncnames.contains(name)) {
				continue;
			}

			Function functionAt = program.getFunctionManager().getFunctionAt(symbol.getAddress());
			if (functionAt == null) {
				continue;
			}
			if (!functionAt.hasNoReturn()) {

				functionAt.setNoReturn(true);

				program.getBookmarkManager()
						.setBookmark(symbol.getAddress(), BookmarkType.ANALYSIS,
							"Non-Returning Function", "Non-Returning Golang Function Identified");
				count++;
			}
		}
		Msg.info(this, "Marked %d golang funcs as NoReturn".formatted(count));
	}

	private Address createFakeContextMemory(Program program, long len) {
		long offset_from_eom = 0x100_000;
		Address max = program.getAddressFactory().getDefaultAddressSpace().getMaxAddress();
		Address mbStart = max.subtract(offset_from_eom + len - 1);
		MemoryBlock newMB =
			MemoryBlockUtils.createUninitializedBlock(program, false, "ARTIFICAL_GOLANG_CONTEXT",
				mbStart, len, "Artifical memory block created to hold golang context data types",
				null, true, true, false, null);
		return newMB.getStart();
	}

	private void setupProgramContext(GoRttiMapper goBinary, MarkupSession session)
			throws IOException {
		Program program = goBinary.getProgram();
		GoRegisterInfo goRegInfo = goBinary.getRegInfo();

		MemoryBlock txtMemblock = program.getMemory().getBlock(".text");
		if (txtMemblock != null && goRegInfo.getZeroRegister() != null &&
			!goRegInfo.isZeroRegisterIsBuiltin()) {
			try {
				program.getProgramContext()
						.setValue(goRegInfo.getZeroRegister(), txtMemblock.getStart(),
							txtMemblock.getEnd(), BigInteger.ZERO);
			}
			catch (ContextChangeException e) {
				Msg.error(this, "Unexpected Error", e);
			}
		}

		int alignment = goBinary.getPtrSize();
		long sizeNeeded = 0;

		Symbol zerobase = SymbolUtilities.getUniqueSymbol(program, "runtime.zerobase");
		long zerobaseSymbol = sizeNeeded;
		sizeNeeded += zerobase == null
				? NumericUtilities.getUnsignedAlignedValue(1 /* sizeof(byte) */, alignment)
				: 0;

		long gStructOffset = sizeNeeded;
		Structure gStruct = goBinary.getGhidraDataType("runtime.g", Structure.class);
		sizeNeeded += gStruct != null
				? NumericUtilities.getUnsignedAlignedValue(gStruct.getLength(), alignment)
				: 0;

		long mStructOffset = sizeNeeded;
		Structure mStruct = goBinary.getGhidraDataType("runtime.m", Structure.class);
		sizeNeeded += mStruct != null
				? NumericUtilities.getUnsignedAlignedValue(mStruct.getLength(), alignment)
				: 0;

		Address contextMemoryAddr = sizeNeeded > 0
				? createFakeContextMemory(program, sizeNeeded)
				: null;

		if (zerobase == null) {
			session.labelAddress(contextMemoryAddr.add(zerobaseSymbol),
				ARTIFICIAL_RUNTIME_ZEROBASE_SYMBOLNAME);
		}

		if (gStruct != null) {
			Address gAddr = contextMemoryAddr.add(gStructOffset);
			session.markupAddressIfUndefined(gAddr, gStruct);
			session.labelAddress(gAddr, "CURRENT_G");

			Register currentGoroutineReg = goRegInfo.getCurrentGoroutineRegister();
			if (currentGoroutineReg != null && txtMemblock != null) {
				// currentGoroutineReg is set in a platform's arch-golang.register.info in 
				// the <current_goroutine> element for arch's that have a dedicated processor
				// register that points at G
				try {
					program.getProgramContext()
							.setValue(currentGoroutineReg, txtMemblock.getStart(),
								txtMemblock.getEnd(), gAddr.getOffsetAsBigInteger());
				}
				catch (ContextChangeException e) {
					Msg.error(this, "Unexpected Error", e);
				}
			}
		}
		if (mStruct != null) {
			Address mAddr = contextMemoryAddr.add(mStructOffset);
			session.markupAddressIfUndefined(mAddr, mStruct);
		}
	}

	private void createBootstrapGDT(GoRttiMapper goBinary, Program program,
			TaskMonitor monitor) throws IOException {
		GoVer goVer = goBinary.getGolangVersion();
		String osName = GoRttiMapper.getGolangOSString(program);
		String gdtFilename =
			GoRttiMapper.getGDTFilename(goVer, goBinary.getPtrSize(), osName);
		gdtFilename =
			gdtFilename.replace(".gdt", "_%d.gdt".formatted(System.currentTimeMillis()));
		File gdt = new File(System.getProperty("user.home"), gdtFilename);
		goBinary.exportTypesToGDT(gdt, monitor);
		Msg.info(this, "Golang bootstrap GDT created: " + gdt);
	}

	@Override
	public void analysisEnded(Program program) {
	}

	@Override
	public boolean canAnalyze(Program program) {
		return GoConstants.GOLANG_CSPEC_NAME.equals(
			program.getCompilerSpec().getCompilerSpecDescription().getCompilerSpecName());
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return true;
	}

	private static Address getArtificalZerobaseAddress(Program program) {
		Symbol zerobaseSym =
			SymbolUtilities.getUniqueSymbol(program, ARTIFICIAL_RUNTIME_ZEROBASE_SYMBOLNAME);
		return zerobaseSym != null ? zerobaseSym.getAddress() : null;
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
		Symbol zerobaseSym = SymbolUtilities.getUniqueSymbol(prog, "runtime.zerobase");
		Address zerobaseAddr = zerobaseSym != null
				? zerobaseSym.getAddress()
				: getArtificalZerobaseAddress(prog);
		if (zerobaseAddr == null) {
			zerobaseAddr = prog.getImageBase().getAddressSpace().getMinAddress();	// ICKY HACK
			Msg.warn(GoFunctionFixup.class,
				"Unable to find Golang runtime.zerobase, using " + zerobaseAddr);
		}
		return zerobaseAddr;
	}

	//--------------------------------------------------------------------------------------------
	private static class GolangAnalyzerOptions {
		static final String CREATE_BOOTSTRAP_GDT_OPTIONNAME = "Create Bootstrap GDT";
		static final String CREATE_BOOTSTRAP_GDT_DESC = """
				Creates a Ghidra data type archive that contains just the necessary \
				data types to parse other golang binaries. \
				DWARF data is needed for this to succeed. \
				The new GDT file will be placed in the user's home directory and will \
				be called golang_MajorVer.MinorVer_XXbit_osname.NNNNNNNNN.gdt, where NNNNNN \
				is a timestamp.""";
		boolean createBootstrapDatatypeArchive;
	}
}
