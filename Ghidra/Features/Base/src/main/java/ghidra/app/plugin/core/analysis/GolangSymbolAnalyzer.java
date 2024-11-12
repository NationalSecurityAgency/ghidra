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

import static ghidra.app.util.bin.format.golang.GoConstants.*;
import static java.util.stream.Collectors.*;
import static java.util.stream.StreamSupport.*;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.util.*;
import java.util.Map.Entry;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

import generic.jar.ResourceFile;
import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.services.*;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.format.golang.*;
import ghidra.app.util.bin.format.golang.rtti.*;
import ghidra.app.util.bin.format.golang.rtti.GoRttiMapper.FuncDefFlags;
import ghidra.app.util.bin.format.golang.rtti.GoRttiMapper.FuncDefResult;
import ghidra.app.util.bin.format.golang.rtti.types.GoType;
import ghidra.app.util.bin.format.golang.rtti.types.GoTypeBridge;
import ghidra.app.util.bin.format.golang.structmapping.MarkupSession;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.viewer.field.AddressAnnotatedStringHandler;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.program.util.SymbolicPropogator.Value;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.UnknownProgressWrappingTaskMonitor;
import ghidra.xml.XmlParseException;
import utilities.util.FileUtilities;

/**
 * Analyzes Golang binaries for RTTI and function symbol information by following references from
 * the root GoModuleData instance.
 * 
 */
public class GolangSymbolAnalyzer extends AbstractAnalyzer {
	private static final AnalysisPriority GOLANG_ANALYSIS_PRIORITY =
		AnalysisPriority.FORMAT_ANALYSIS.after().after();
	private static final AnalysisPriority PROP_RTTI_PRIORITY =
		AnalysisPriority.REFERENCE_ANALYSIS.after();
	private static final AnalysisPriority FIX_CLOSURES_PRIORITY = PROP_RTTI_PRIORITY.after();
	static final AnalysisPriority STRINGS_PRIORITY = FIX_CLOSURES_PRIORITY.after();

	private final static String NAME = "Golang Symbols";
	private final static String DESCRIPTION = """
			Analyze Golang binaries for RTTI and function symbols.
			'Apply Data Archives' and 'Shared Return Calls' analyzers should be disabled \
			for best results.""";
	private static final String ANALYZED_FLAG_OPTION_NAME = "Golang Analyzed";

	private GolangAnalyzerOptions analyzerOptions = new GolangAnalyzerOptions();

	private GoRttiMapper goBinary;
	private GoTypeManager goTypes;
	private Program program;
	private MarkupSession markupSession;
	private AutoAnalysisManager aam;
	private long lastTxId = -1;

	public GolangSymbolAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPriority(GOLANG_ANALYSIS_PRIORITY);
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return GoRttiMapper.isGolangProgram(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		long txId = program.getCurrentTransactionInfo().getID();
		if (txId == lastTxId) {
			// Only run once per analysis session - as denoted by being in the same transaction
			return true;
		}
		lastTxId = txId;

		if (isAlreadyAnalyzed(program)) {
			Msg.info(this, "Golang analysis already performed, skipping.");
			return false;
		}

		monitor.setMessage("Golang symbol analyzer");

		this.program = program;
		aam = AutoAnalysisManager.getAnalysisManager(program);

		goBinary = GoRttiMapper.getSharedGoBinary(program, monitor);
		if (goBinary == null) {
			Msg.error(this, "Golang symbol analyzer error: unable to get GoRttiMapper");
			return false;
		}

		goTypes = goBinary.getGoTypes();

		try {
			goBinary.initMethodInfoIfNeeded();

			markupSession = goBinary.createMarkupSession(monitor);
			GoModuledata firstModule = goBinary.getFirstModule();
			if (firstModule != null) {
				markupSession.labelStructure(firstModule, "firstmoduledata", null);
				markupSession.markup(firstModule, false);
			}

			for (GoType goType : goTypes.allTypes()) {
				// markup all gotype structs.  Most will already be markedup because they
				// were referenced from the firstModule struct
				markupSession.markup(goType, false);
			}

			markupWellknownSymbols();
			setupProgramContext();
			recoverDataTypes(monitor);
			markupGoFunctions(monitor);
			if (analyzerOptions.fixupDuffFunctions) {
				fixDuffFunctions();
			}
			if (analyzerOptions.fixupGcWriteBarierFunctions) {
				fixGcWriteBarrierFunctions();
			}

			if (analyzerOptions.propagateRtti) {
				Msg.info(this,
					"Golang symbol analyzer: scheduling RTTI propagation after reference analysis");
				aam.schedule(new PropagateRttiBackgroundCommand(goBinary),
					PROP_RTTI_PRIORITY.priority());
				Msg.info(this,
					"Golang symbol analyzer: scheduling closure function fixup");
				aam.schedule(new FixClosureFuncArgsBackgroundCommand(goBinary),
					FIX_CLOSURES_PRIORITY.priority());
			}

			if (analyzerOptions.createBootstrapDatatypeArchive) {
				createBootstrapGDT(monitor);
			}

			program.getOptions(Program.PROGRAM_INFO).setBoolean(ANALYZED_FLAG_OPTION_NAME, true);
			return true;
		}
		catch (IOException e) {
			Msg.error(this, "Golang analysis failure", e);
		}
		return false;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		analyzerOptions.registerOptions(options, program);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		analyzerOptions.optionsChanged(options, program);
	}

	private void markupWellknownSymbols() throws IOException {
		Symbol g0 = goBinary.getGoSymbol("runtime.g0");
		Structure gStruct = goTypes.getGhidraDataType("runtime.g", Structure.class);
		if (g0 != null && gStruct != null) {
			markupSession.markupAddressIfUndefined(g0.getAddress(), gStruct);
		}

		Symbol m0 = goBinary.getGoSymbol("runtime.m0");
		Structure mStruct = goTypes.getGhidraDataType("runtime.m", Structure.class);
		if (m0 != null && mStruct != null) {
			markupSession.markupAddressIfUndefined(m0.getAddress(), mStruct);
		}
	}

	/**
	 * Converts all discovered golang rtti type records to Ghidra data types, placing them
	 * in the program's DTM in /golang-recovered
	 * 
	 * @param monitor {@link TaskMonitor}
	 * @throws IOException error converting a golang type to a Ghidra type
	 * @throws CancelledException if the user cancelled the import
	 */
	private void recoverDataTypes(TaskMonitor monitor) throws IOException, CancelledException {
		List<Long> typeOffsets = goTypes.allTypeOffsets();
		ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
		monitor.initialize(typeOffsets.size(), "Converting Golang types to Ghidra data types");
		for (Long typeOffset : typeOffsets) {
			monitor.increment();
			GoType typ = goTypes.getType(typeOffset);
			DataType dt = goTypes.getGhidraDataType(typ);
			if (dtm.getDataType(dt.getDataTypePath()) == null) {
				dtm.addDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
			}
		}
	}

	private void markupGoFunctions(TaskMonitor monitor) throws IOException, CancelledException {
		Set<String> noreturnFuncNames = readNoReturnFuncNames();
		int noreturnFuncCount = 0;
		int functionSignatureFromBootstrap = 0;
		int functionSignatureFromMethod = 0;
		String abiIntCCName =
			goBinary.hasCallingConvention(GOLANG_ABI_INTERNAL_CALLINGCONVENTION_NAME)
					? GOLANG_ABI_INTERNAL_CALLINGCONVENTION_NAME
					: null;

		List<GoFuncData> funcs = goBinary.getAllFunctions();

		monitor.initialize(funcs.size(), "Fixing golang function signatures");
		for (GoFuncData funcdata : funcs) {
			monitor.increment();

			Address funcAddr = funcdata.getFuncAddress();
			GoSymbolName funcSymbolNameInfo = funcdata.getSymbolName();
			String funcname =
				SymbolUtilities.replaceInvalidChars(funcSymbolNameInfo.asString(), true);
			Namespace funcns = funcSymbolNameInfo.getSymbolNamespace(program);

			if ("go:buildid".equals(funcSymbolNameInfo.asString())) {
				// this funcdata entry is a bogus element that points to the go buildid string.  skip
				continue;
			}

			Function func = markupSession.createFunctionIfMissing(funcname, funcns, funcAddr);
			if (func == null ||
				func.getSignatureSource().isHigherPriorityThan(SourceType.IMPORTED)) {
				continue;
			}

			boolean prevNoReturnFlag = func.hasNoReturn();

			markupSession.appendComment(func, "Golang function info: ",
				AddressAnnotatedStringHandler.createAddressAnnotationString(
					funcdata.getStructureContext().getStructureAddress(),
					"Flags: %s".formatted(funcdata.getFlags())));

			if (!funcSymbolNameInfo.asString().equals(funcname)) {
				markupSession.appendComment(func, "Golang original name: ",
					funcSymbolNameInfo.asString());
			}

			GoSourceFileInfo sfi = null;
			if (analyzerOptions.outputSourceInfo && (sfi = funcdata.getSourceFileInfo()) != null) {
				markupSession.appendComment(func, "Golang source: ", sfi.getDescription());
				funcdata.markupSourceFileInfo();
			}

			if (funcdata.getFlags().isEmpty() /* dont try to get arg info for ASM funcs*/) {
				markupSession.appendComment(func, null,
					"Golang stacktrace signature: " + funcdata.recoverFunctionSignature());
			}

			// Try to get a function definition signature from:
			// 1) Methods (with full info) attached to a type that point to this func
			// 2) Snapshot json file
			// 3) Partial signature with receiver or closure context info params
			FuncDefResult funcDefResult = goBinary.getFuncDefFor(funcdata);
			if (funcDefResult != null) {
				Set<FuncDefFlags> flags = funcDefResult.flags();
				String flagStr = !flags.isEmpty() ? " " + flags.toString().toLowerCase() : "";
				String snapshotStr = funcDefResult.funcDefStr();
				if (!flagStr.isEmpty() || !snapshotStr.isEmpty()) {
					markupSession.appendComment(func, null,
						"Golang signature%s: %s".formatted(flagStr, snapshotStr));
				}
				if (flags.contains(FuncDefFlags.FROM_SNAPSHOT)) {
					functionSignatureFromBootstrap++;
				}
				if (flags.contains(FuncDefFlags.FROM_RTTI_METHOD)) {
					functionSignatureFromMethod++;
				}

				GoFunctionFixup ff = new GoFunctionFixup(func, funcDefResult.funcDef(),
					goBinary.getCallingConventionFor(funcdata), goBinary.newStorageAllocator());

				try {
					ff.apply();
				}
				catch (DuplicateNameException | InvalidInputException
						| IllegalArgumentException e) {
					MarkupSession.logWarningAt(program, func.getEntryPoint(),
						"Failed to update function signature: " + e.getMessage());
					continue;
				}

				if (funcDefResult.symbolName().hasReceiver()) {
					GoType recvType = funcDefResult.recvType();
					Address typeStructAddr = recvType != null && !(recvType instanceof GoTypeBridge)
							? recvType.getStructureContext().getStructureAddress()
							: null;
					String typeStr = typeStructAddr != null
							? AddressAnnotatedStringHandler.createAddressAnnotationString(
								typeStructAddr,
								recvType.getName())
							: funcDefResult.symbolName().receiverString();
					markupSession.appendComment(func, "",
						"Golang method in type %s".formatted(typeStr));
				}
			}

			if (noreturnFuncNames.contains(funcname)) {
				if (!func.hasNoReturn()) {
					func.setNoReturn(true);
				}
			}

			if (func.hasNoReturn() && func.hasNoReturn() != prevNoReturnFlag) {
				noreturnFuncCount++;
			}
		}

		Msg.info(this, "Marked %d golang funcs as NoReturn".formatted(noreturnFuncCount));
		Msg.info(this, "Fixed %d golang function signatures from runtime snapshot signatures"
				.formatted(functionSignatureFromBootstrap));
		Msg.info(this, "Fixed %d golang function signatures from method info"
				.formatted(functionSignatureFromMethod));
	}

	private void fixGcWriteBarrierFunctions() {
		if (GoConstants.GCWRITE_BUFFERED_VERS.contains(goBinary.getGoVer())) {
			fixGcWriteBarrierBufferedFunctions();
		}
		else if (GoConstants.GCWRITE_BATCH_VERS.contains(goBinary.getGoVer())) {
			fixGcWriteBarrierBatchFunctions();
		}
	}

	private void fixGcWriteBarrierBatchFunctions() {
		// gcWriteBarrier scheme for versions 1.21+
		// Signature is: gcWriteBarrier[1-8]() uintptr
		String ccname = GoConstants.GOLANG_GCWRITE_BATCH_CALLINGCONVENTION_NAME;
		if (!goBinary.hasCallingConvention(ccname)) {
			Msg.warn(this, "Missing " + ccname + " from this arch's .cspec");
			return;
		}
		try {
			ReturnParameterImpl retVal =
				new ReturnParameterImpl(goTypes.getDTM().getPointer(null), program);

			GoFuncData funcData = goBinary.getFunctionByName("gcWriteBarrier");
			Function func = funcData != null ? funcData.getFunction() : null;
			if (func != null) {
				List<ParameterImpl> params = List.of(new ParameterImpl("numbytes",
					goTypes.getUintDT(), program, SourceType.ANALYSIS));

				func.updateFunction(ccname, retVal, params,
					FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);
			}
			for (int i = 1; i <= 8; i++) {
				funcData = goBinary.getFunctionByName("runtime.gcWriteBarrier" + i);
				func = funcData != null ? funcData.getFunction() : null;
				if (func != null) {
					func.updateFunction(ccname, retVal, List.of(),
						FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true,
						SourceType.ANALYSIS);
				}
			}
		}
		catch (InvalidInputException | DuplicateNameException e) {
			Msg.error(this, "Failed to update gcwrite function", e);
		}
	}

	private void fixGcWriteBarrierBufferedFunctions() {
		// gcWriteBarrier scheme for versions up to 1.20
		// Signature is: gcWriteBarrier(val,dest)
		String ccname = GoConstants.GOLANG_GCWRITE_BUFFERED_CALLINGCONVENTION_NAME;
		if (!goBinary.hasCallingConvention(ccname)) {
			Msg.warn(this, "Missing " + ccname + " from this arch's .cspec");
			return;
		}
		try {
			DataType voidPtr = goTypes.getDTM().getPointer(null);
			ReturnParameterImpl retVal = new ReturnParameterImpl(VoidDataType.dataType, program);
			List<ParameterImpl> params =
				List.of(new ParameterImpl("value", voidPtr, program, SourceType.ANALYSIS),
					new ParameterImpl("dest", voidPtr, program, SourceType.ANALYSIS));

			GoFuncData funcData = goBinary.getFunctionByName("runtime.gcWriteBarrier");
			Function func = funcData != null ? funcData.getFunction() : null;
			if (func != null) {
				func.updateFunction(ccname, retVal, params,
					FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);
			}

			if (goBinary.getBuildInfo().getGOARCH(program).equals("amd64")) {
				// fix the amd64 specific variants such as gcWriteBarrierBX, etc
				Language lang = program.getLanguage();
				Register destReg = lang.getRegister("RDI"); // TODO: could also get name from cspec
				for (String regName : GoConstants.GCWRITE_BUFFERED_x86_64_Regs) {
					String gregName = regName.startsWith("R") ? regName : "R" + regName;
					funcData = goBinary.getFunctionByName("runtime.gcWriteBarrier" + regName);
					func = funcData != null ? funcData.getFunction() : null;
					Register reg = lang.getRegister(gregName);
					if (func != null && reg != null) {
						params = List.of(
							new ParameterImpl("value", voidPtr, reg, program, SourceType.ANALYSIS),
							new ParameterImpl("dest", voidPtr, destReg, program,
								SourceType.ANALYSIS));
						func.updateFunction(ccname, retVal, params,
							FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.ANALYSIS);
					}
				}
			}
		}
		catch (InvalidInputException | DuplicateNameException e) {
			Msg.error(this, "Failed to update gcwrite function", e);
		}
	}

	/**
	 * Fixes the function signature of the runtime.duffzero and runtime.duffcopy functions.
	 * <p>
	 * The alternate duff-ified entry points haven't been discovered yet, so the information
	 * set to the main function entry point will be propagated at a later time by the
	 * FixupDuffAlternateEntryPointsBackgroundCommand.
	 */
	private void fixDuffFunctions() {
		FunctionManager funcMgr = program.getFunctionManager();
		GoRegisterInfo regInfo = goBinary.getRegInfo();
		DataType voidPtr = program.getDataTypeManager().getPointer(VoidDataType.dataType);

		GoFuncData duffzeroFuncdata = goBinary.getFunctionByName("runtime.duffzero");
		Function duffzeroFunc = duffzeroFuncdata != null
				? funcMgr.getFunctionAt(duffzeroFuncdata.getFuncAddress())
				: null;
		List<Variable> duffzeroParams = regInfo.getDuffzeroParams(program);
		if (duffzeroFunc != null && !duffzeroParams.isEmpty()) {
			// NOTE: some go archs don't create duffzero functions.  See
			// cmd/compile/internal/ssa/config.go and look for flag noDuffDevice in each arch.
			try {

				// NOTE: even though we are specifying custom storage for the arguments, the
				// calling convention name is still important as it tells the decompiler which
				// registers are unaffected vs killed-by-call

				ReturnParameterImpl voidRet = new ReturnParameterImpl(VoidDataType.dataType,
					VariableStorage.VOID_STORAGE, program);
				duffzeroFunc.updateFunction(GOLANG_DUFFZERO_CALLINGCONVENTION_NAME, voidRet,
					duffzeroParams, FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.ANALYSIS);

				markupSession.appendComment(duffzeroFunc, null,
					"Golang special function: duffzero");

				aam.schedule(new FixupDuffAlternateEntryPointsBackgroundCommand(duffzeroFuncdata,
					duffzeroFunc), PROP_RTTI_PRIORITY.priority());
			}
			catch (InvalidInputException | DuplicateNameException e) {
				Msg.error(this, "Failed to update main duffzero function", e);
			}

			GoFuncData duffcopyFuncdata = goBinary.getFunctionByName("runtime.duffcopy");
			Function duffcopyFunc = duffcopyFuncdata != null
					? funcMgr.getFunctionAt(duffcopyFuncdata.getFuncAddress())
					: null;
			if (duffcopyFuncdata != null &&
				goBinary.hasCallingConvention(GOLANG_DUFFCOPY_CALLINGCONVENTION_NAME)) {
				try {
					List<Variable> params =
						List.of(new ParameterImpl("dest", voidPtr, program),
							new ParameterImpl("src", voidPtr, program));
					duffcopyFunc.updateFunction(GOLANG_DUFFCOPY_CALLINGCONVENTION_NAME,
						new ReturnParameterImpl(VoidDataType.dataType, program), params,
						FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);

					markupSession.appendComment(duffcopyFunc, null,
						"Golang special function: duffcopy");

					aam.schedule(
						new FixupDuffAlternateEntryPointsBackgroundCommand(duffcopyFuncdata,
							duffcopyFunc),
						AnalysisPriority.FUNCTION_ANALYSIS.after().priority());
				}
				catch (InvalidInputException | DuplicateNameException e) {
					Msg.error(this, "Failed to update main duffcopy function", e);
				}
			}
		}

	}

	private Set<String> readNoReturnFuncNames() {
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
		return noreturnFuncnames;
	}

	private Address createFakeContextMemory(long len) {
		long offset_from_eom = 0x100_000;
		Address max = program.getAddressFactory().getDefaultAddressSpace().getMaxAddress();
		Address mbStart = max.subtract(offset_from_eom + len - 1);
		MemoryBlock newMB =
			MemoryBlockUtils.createUninitializedBlock(program, false, "ARTIFICAL_GOLANG_CONTEXT",
				mbStart, len, "Artifical memory block created to hold golang context data types",
				null, true, true, false, null);
		newMB.setArtificial(true);
		return newMB.getStart();
	}

	private void setupProgramContext() throws IOException {
		GoRegisterInfo goRegInfo = goBinary.getRegInfo();

		if (goRegInfo.getZeroRegister() != null && !goRegInfo.isZeroRegisterIsBuiltin()) {
			try {
				for (AddressRange textRange : goBinary.getTextAddresses().getAddressRanges()) {
					program.getProgramContext()
							.setValue(goRegInfo.getZeroRegister(), textRange.getMinAddress(),
								textRange.getMaxAddress(), BigInteger.ZERO);
				}
			}
			catch (ContextChangeException e) {
				Msg.error(this, "Unexpected Error", e);
			}
		}

		int alignment = goBinary.getPtrSize();
		long sizeNeeded = 0;

		Symbol zerobase = goBinary.getGoSymbol("runtime.zerobase");
		long zerobaseSymbol = sizeNeeded;
		sizeNeeded += zerobase == null
				? NumericUtilities.getUnsignedAlignedValue(1 /* sizeof(byte) */, alignment)
				: 0;

		long gStructOffset = sizeNeeded;
		Structure gStruct = goTypes.getGhidraDataType("runtime.g", Structure.class);
		sizeNeeded += gStruct != null
				? NumericUtilities.getUnsignedAlignedValue(gStruct.getLength(), alignment)
				: 0;

		long mStructOffset = sizeNeeded;
		Structure mStruct = goTypes.getGhidraDataType("runtime.m", Structure.class);
		sizeNeeded += mStruct != null
				? NumericUtilities.getUnsignedAlignedValue(mStruct.getLength(), alignment)
				: 0;

		Address contextMemoryAddr = sizeNeeded > 0 ? createFakeContextMemory(sizeNeeded) : null;

		if (zerobase == null) {
			markupSession.labelAddress(contextMemoryAddr.add(zerobaseSymbol),
				GoRttiMapper.ARTIFICIAL_RUNTIME_ZEROBASE_SYMBOLNAME);
		}

		if (gStruct != null) {
			Address gAddr = contextMemoryAddr.add(gStructOffset);
			markupSession.markupAddressIfUndefined(gAddr, gStruct);
			markupSession.labelAddress(gAddr, "CURRENT_G");

			Register currentGoroutineReg = goRegInfo.getCurrentGoroutineRegister();
			if (currentGoroutineReg != null) {
				// currentGoroutineReg is set in a platform's arch-golang.register.info in 
				// the <current_goroutine> element for arch's that have a dedicated processor
				// register that points at G
				try {
					for (AddressRange textRange : goBinary.getTextAddresses().getAddressRanges()) {
						program.getProgramContext()
								.setValue(currentGoroutineReg, textRange.getMinAddress(),
									textRange.getMaxAddress(), gAddr.getOffsetAsBigInteger());
					}
				}
				catch (ContextChangeException e) {
					Msg.error(this, "Unexpected Error", e);
				}
			}
		}
		if (mStruct != null) {
			Address mAddr = contextMemoryAddr.add(mStructOffset);
			markupSession.markupAddressIfUndefined(mAddr, mStruct);
		}
	}

	private void createBootstrapGDT(TaskMonitor monitor) throws IOException, CancelledException {
		GoVer goVer = goBinary.getGoVer();
		String osName = goBinary.getBuildInfo().getGOOS(program);
		String gdtFilename = GoRttiMapper.getGDTFilename(goVer, goBinary.getPtrSize(), osName);
		gdtFilename = gdtFilename.replace(".gdt", "_%d.gdt".formatted(System.currentTimeMillis()));
		File gdt = new File(System.getProperty("user.home"), gdtFilename);
		goBinary.exportTypesToGDT(gdt, analyzerOptions.createRuntimeSnapshotDatatypeArchive,
			monitor);
		Msg.info(this, "Golang bootstrap GDT created: " + gdt);
	}

	//--------------------------------------------------------------------------------------------
	/**
	 * A background command that runs later, it copies the function signature information from the
	 * main entry point of the duff function to any unnamed functions that are within the footprint
	 * of the main function.
	 */
	private static class FixupDuffAlternateEntryPointsBackgroundCommand
			extends BackgroundCommand<Program> {

		private Function duffFunc;
		private GoFuncData funcData;

		public FixupDuffAlternateEntryPointsBackgroundCommand(GoFuncData funcData,
				Function duffFunc) {
			this.funcData = funcData;
			this.duffFunc = duffFunc;
		}

		@Override
		public boolean applyTo(Program program, TaskMonitor monitor) {
			if (!duffFunc.getProgram().equals(program)) {
				throw new AssertionError();
			}
			String ccName = duffFunc.getCallingConventionName();
			Namespace funcNS = duffFunc.getParentNamespace();
			AddressSet funcBody = new AddressSet(funcData.getBody());
			String duffComment = program.getListing()
					.getCodeUnitAt(duffFunc.getEntryPoint())
					.getComment(CommentType.PLATE);

			monitor.setMessage("Fixing alternate duffzero/duffcopy entry points");
			for (FunctionIterator funcIt =
				program.getFunctionManager().getFunctions(funcBody, true); funcIt.hasNext();) {
				Function func = funcIt.next();
				if (!FunctionUtility.isDefaultFunctionName(func)) {
					continue;
				}
				try {
					func.setName(duffFunc.getName() + "_" + func.getEntryPoint(),
						SourceType.ANALYSIS);
					func.setParentNamespace(funcNS);
					FunctionUpdateType fut = duffFunc.hasCustomVariableStorage()
							? FunctionUpdateType.CUSTOM_STORAGE
							: FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS;
					func.updateFunction(ccName, duffFunc.getReturn(),
						Arrays.asList(duffFunc.getParameters()), fut, true, SourceType.ANALYSIS);
					if (duffComment != null && !duffComment.isBlank()) {
						new SetCommentCmd(func.getEntryPoint(), CodeUnit.PLATE_COMMENT, duffComment)
								.applyTo(program);
					}
				}
				catch (DuplicateNameException | InvalidInputException
						| CircularDependencyException e) {
					Msg.error(GolangSymbolAnalyzer.class, "Error updating duff functions", e);
				}
			}
			return true;
		}

	}

	//--------------------------------------------------------------------------------------------
	/**
	 * Partially fixup closure func signatures by matching a closure func (*.func1) with a
	 * closure struct ( struct { F uintptr; X0 blah... } ), and giving the func a context param
	 */
	private static class FixClosureFuncArgsBackgroundCommand extends BackgroundCommand<Program> {
		private GoRttiMapper goBinary;
		private Program program;
		private ReferenceManager refMgr;
		private Register closureContextRegister;
		private GoTypeManager goTypes;
		private int closureTypeCount;
		private int methodWrapperTypeCount;
		private int closureFuncsFixed;
		private int methodWrapperFuncsFixed;

		public FixClosureFuncArgsBackgroundCommand(GoRttiMapper goBinary) {
			this.goBinary = goBinary;
			this.goTypes = goBinary.getGoTypes();
			this.program = goBinary.getProgram();
			this.refMgr = program.getReferenceManager();
			this.closureContextRegister = goBinary.getRegInfo().getClosureContextRegister();
		}

		@Override
		public boolean applyTo(Program obj, TaskMonitor monitor) {

			for (GoType closureType : goTypes.getClosureTypes()) {
				if (monitor.isCancelled()) {
					return false;
				}
				fixupFuncsWithClosureRefsToTypeStruct(closureType, false, monitor);
				closureTypeCount++;
			}

			for (GoType closureType : goTypes.getMethodWrapperClosureTypes()) {
				if (monitor.isCancelled()) {
					return false;
				}
				fixupFuncsWithClosureRefsToTypeStruct(closureType, true, monitor);
				methodWrapperTypeCount++;
			}

			Msg.info(this, "Golang closure/method wrapper types found: %d/%d"
					.formatted(closureTypeCount, methodWrapperTypeCount));
			Msg.info(this, "Golang closure/method wrapper funcs fixed: %d/%d"
					.formatted(closureFuncsFixed, methodWrapperFuncsFixed));

			return true;
		}

		private void fixupFuncsWithClosureRefsToTypeStruct(GoType closureStructType,
				boolean isMethodWrapper, TaskMonitor monitor) {
			Address typStructAddr = closureStructType.getStructureContext().getStructureAddress();
			Set<Address> funcsProcessed = new HashSet<>();

			// TODO: this catches most closure funcs because refs to the func will be closely
			// correlated with refs to the closure struct itself.  However, when a closure instance
			// is reused to call another closure func, this simplistic scheme fails
			stream(refMgr.getReferencesTo(typStructAddr).spliterator(), false) //
					.filter(ref -> !monitor.isCancelled() && ref != null &&
						ref.getReferenceType().isData())
					.map(ref -> getNextClosureFuncRef(ref.getFromAddress(), isMethodWrapper, 50))
					.filter(funcData -> funcData != null &&
						!funcsProcessed.contains(funcData.getFuncAddress()))
					.forEach(funcData -> {
						Address addr = funcData.getFuncAddress();
						funcsProcessed.add(addr);
						Function func = program.getFunctionManager().getFunctionAt(addr);
						if (func != null) {
							if (!isOverwriteableClosureFunc(func)) {
								return;
							}
							if (isMethodWrapper) {
								fixupMethodWrapperClosureFunc(funcData, func, closureStructType);
							}
							else {
								fixupClosureFunc(funcData, func, closureStructType);
							}
						}
					});
		}

		private boolean isOverwriteableClosureFunc(Function func) {
			Parameter[] params = func.getParameters();
			return params.length == 0 ||
				(params.length == 1 && GoFunctionFixup.isClosureContext(params[0]));
		}

		private GoFuncData getNextClosureFuncRef(Address startAddr, boolean isMethodWrapper,
				int maxRange) {
			if (!startAddr.isMemoryAddress()) {
				return null;
			}
			// Returns the function that is being used as the destination of a closure struct{}.F
			// This works off of a pattern of references (no decompilation pcode needed)
			// 1) Refs to closure struct { } rtti type
			// 2) ref is followed by call to runtime.newobject
			// 3) the new closure struct{}.F returned by newobject() is initialized with
			// address of a closure function (as determined by the name of the func: foo.func1)
			// The above steps are matched by the pattern of references, not by pcode or value 
			// propagation.
			Address maxAddr = startAddr.add(maxRange);
			for (Address refAddr : refMgr.getReferenceSourceIterator(startAddr, true)) {
				if (refAddr.compareTo(maxAddr) > 0) {
					break;
				}
				for (Reference ref : refMgr.getReferencesFrom(refAddr)) {
					if (ref.getReferenceType().isData()) {
						Address destAddr = ref.getToAddress();
						GoFuncData funcData = goBinary.getFunctionData(destAddr);
						GoSymbolName funcName = funcData != null ? funcData.getSymbolName() : null;
						if (funcName == null) {
							continue;
						}
						GoSymbolNameType nameType = funcName.getNameType();
						if (isMethodWrapper && nameType == GoSymbolNameType.METHOD_WRAPPER) {
							return funcData;
						}
						if (!isMethodWrapper && nameType != null && nameType.isClosure()) {
							return funcData;
						}
					}
				}
			}
			return null;
		}

		private void fixupClosureFunc(GoFuncData funcData, Function func,
				GoType closureStructType) {
			try {
				DataType closureStructDT = goTypes.getGhidraDataType(closureStructType);

				List<Variable> closureParams =
					List.of(new ParameterImpl(GOLANG_CLOSURE_CONTEXT_NAME,
						goBinary.getDTM().getPointer(closureStructDT), closureContextRegister,
						program, SourceType.ANALYSIS));

				func.updateFunction(null, null, closureParams, FunctionUpdateType.CUSTOM_STORAGE,
					true, SourceType.ANALYSIS);

				closureFuncsFixed++;
			}
			catch (IOException | InvalidInputException | DuplicateNameException e) {
				Msg.error(this, "Failed to update closure func signature %s@%s"
						.formatted(func.getName(), func.getEntryPoint()),
					e);
			}
		}

		private void fixupMethodWrapperClosureFunc(GoFuncData funcData, Function func,
				GoType closureStructType) {
			// method wrappers (funcs that end with "-fm") are closures that take the same args as
			// the same-named method, but instead of taking a recv pointer as first arg, it takes
			// a closure pointer with the typical closure sruct layout, and with the
			// context payload being the expected recvr pointer.
			String methodName = func.getName();
			methodName = methodName.substring(0, methodName.length() - "-fm".length());
			GoFuncData methodFuncData = goBinary.getFunctionByName(methodName);
			if (methodFuncData == null) {
				try {
					DataType closureStructDT = goTypes.getGhidraDataType(closureStructType);
					List<Variable> closureParams =
						List.of(new ParameterImpl(GOLANG_CLOSURE_CONTEXT_NAME,
							goBinary.getDTM().getPointer(closureStructDT), closureContextRegister,
							program, SourceType.ANALYSIS));

					func.updateFunction(null, null, closureParams,
						FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.ANALYSIS);

					methodWrapperFuncsFixed++;

					return;
				}
				catch (InvalidInputException | DuplicateNameException | IOException e) {
					Msg.error(this, "Failed to update closure func signature %s@%s"
							.formatted(func.getName(), func.getEntryPoint()),
						e);
				}
			}

			// If the base method is present in the binary (ie. for foo-fm, foo exists), copy
			// its arguments and replace its receiver param with the closure context struct
			Function methodFunc =
				program.getFunctionManager().getFunctionAt(methodFuncData.getFuncAddress());
			if (methodFunc == null) {
				return;
			}

			try {
				DataType closureStructDT = goTypes.getGhidraDataType(closureStructType);

				Parameter methodReturn = methodFunc.getReturn();
				Parameter[] methodParams = methodFunc.getParameters();
				methodParams[0] = new ParameterImpl(GOLANG_CLOSURE_CONTEXT_NAME,
					goBinary.getDTM().getPointer(closureStructDT), closureContextRegister, program,
					SourceType.ANALYSIS);
				func.updateFunction(null, methodReturn, FunctionUpdateType.CUSTOM_STORAGE, true,
					SourceType.ANALYSIS, methodParams);
				methodWrapperFuncsFixed++;
			}
			catch (IOException | InvalidInputException | DuplicateNameException e) {
				Msg.error(this, "Failed to update closure func signature %s@%s"
						.formatted(func.getName(), func.getEntryPoint()),
					e);
			}
		}
	}

	/**
	 * A background command that runs after reference analysis, it applies functions signature
	 * overrides to callsites that have a RTTI type parameter that return a specialized
	 * type instead of a void*.
	 */
	private static class PropagateRttiBackgroundCommand extends BackgroundCommand<Program> {
		record RttiFuncInfo(GoSymbolName funcName, int rttiParamIndex,
				java.util.function.Function<GoType, DataType> returnTypeMapper) {

			public RttiFuncInfo(String funcName, int rttiParamIndex,
					java.util.function.Function<GoType, DataType> returnTypeMapper) {
				this(GoSymbolName.parse(funcName), rttiParamIndex, returnTypeMapper);
			}
		}

		record CallSiteInfo(Reference ref, Function callingFunc, Function calledFunc,
				Register register,
				java.util.function.Function<GoType, DataType> returnTypeMapper) {}

		private GoRttiMapper goBinary;
		private Program program;
		private MarkupSession markupSession;
		int totalCallsiteCount;
		int fixedCallsiteCount;
		int unfixedCallsiteCount;
		int callingFunctionCount;

		public PropagateRttiBackgroundCommand(GoRttiMapper goBinary) {
			super("Golang RTTI Propagation (deferred)", true, true, false);
			this.goBinary = goBinary;
			this.program = goBinary.getProgram();
		}

		@Override
		public boolean applyTo(Program program, TaskMonitor monitor) {
			if (!goBinary.getRegInfo().hasAbiInternalParamRegisters()) {
				// If abi0 mode, don't even bother because currently only handles rtti passed via
				// register.
				return true;
			}
			try {
				this.markupSession = goBinary.createMarkupSession(monitor);
				Set<Entry<Function, List<CallSiteInfo>>> callsiteInfo =
					getInformationAboutCallsites(monitor);

				monitor.initialize(totalCallsiteCount, "Propagating RTTI from callsites");
				for (Entry<Function, List<CallSiteInfo>> callsite : callsiteInfo) {
					monitor.checkCancelled();
					fixupRttiCallsitesInFunc(callsite.getKey(), callsite.getValue(), monitor);
				}
				Msg.info(this, "Golang RTTI callsite fixup info (total/updated/skipped): %d/%d/%d"
						.formatted(totalCallsiteCount, fixedCallsiteCount, unfixedCallsiteCount));
				return true;
			}
			catch (CancelledException e) {
				return false;
			}

		}

		private void fixupRttiCallsitesInFunc(Function callingFunc, List<CallSiteInfo> callsites,
				TaskMonitor monitor) throws CancelledException {
			monitor.setMessage("Propagating RTTI from callsites in %s@%s"
					.formatted(callingFunc.getName(), callingFunc.getEntryPoint()));

			GoTypeManager goTypes = goBinary.getGoTypes();
			ContextEvaluator eval = new ConstantPropagationContextEvaluator(monitor, true);
			SymbolicPropogator symEval = new SymbolicPropogator(program);
			symEval.flowConstants(callingFunc.getEntryPoint(), callingFunc.getBody(), eval, true,
				monitor);

			monitor.setMessage("Propagating RTTI from callsites in %s@%s"
					.formatted(callingFunc.getName(), callingFunc.getEntryPoint()));

			for (CallSiteInfo callsite : callsites) {
				monitor.increment();

				Value val =
					symEval.getRegisterValue(callsite.ref.getFromAddress(), callsite.register);
				if (val == null || val.isRegisterRelativeValue()) {
					//Msg.warn(this, "Failed to get RTTI param reg value: " + callsite);
					unfixedCallsiteCount++;
					continue;
				}

				long goTypeOffset = val.getValue();
				try {
					GoType goType = goTypes.getType(goTypeOffset, true);
					if (goType == null) {
						// if it was previously not discovered (usually closure anon types), also mark it up
						goType = goTypes.getType(goTypeOffset);
						markupSession.markup(goType, false);
					}
					DataType newReturnType =
						goType != null ? callsite.returnTypeMapper.apply(goType) : null;
					if (newReturnType != null) {
						// Create a funcdef for this call site, where the return value is a
						// specific golang type instead of the void* it was before.
						FunctionDefinitionDataType signature =
							new FunctionDefinitionDataType(callsite.calledFunc, true);
						signature.setReturnType(newReturnType);
						HighFunctionDBUtil.writeOverride(callsite.callingFunc,
							callsite.ref.getFromAddress(), signature);
						fixedCallsiteCount++;
					}
				}
				catch (IOException | InvalidInputException e) {
					markupSession.logWarningAt(callsite.ref.getFromAddress(),
						"Failed to override with RTTI: " + e.getMessage());
					unfixedCallsiteCount++;
				}
			}
		}

		Set<Entry<Function, List<CallSiteInfo>>> getInformationAboutCallsites(TaskMonitor monitor) {
			TaskMonitor upwtm = new UnknownProgressWrappingTaskMonitor(monitor);
			upwtm.initialize(1, "Finding callsites with RTTI");

			BiConsumer<RttiFuncInfo, Consumer<CallSiteInfo>> getReferencesToRttiFuncWithMonitor =
				(rfi, c) -> getReferencesToRttiFunc(rfi, c, upwtm);

			//@formatter:off
			Map<Function, List<CallSiteInfo>> result = List.of(
				new RttiFuncInfo("runtime.newobject", 0, this::getReturnTypeForNewObjectFunc),
				new RttiFuncInfo("runtime.makeslice", 0, this::getReturnTypeForSliceFunc),
				new RttiFuncInfo("runtime.growslice", 4, this::getReturnTypeForSliceFunc), 
				new RttiFuncInfo("runtime.makeslicecopy", 0, this::getReturnTypeForSliceFunc))
					.stream()
					.mapMulti(getReferencesToRttiFuncWithMonitor)
					.collect(groupingBy(csi -> csi.callingFunc));
			//@formatter:on

			callingFunctionCount = result.size();
			return result.entrySet();
		}

		private void getReferencesToRttiFunc(RttiFuncInfo rfi, Consumer<CallSiteInfo> consumer,
				TaskMonitor monitor) {
			FunctionManager funcMgr = program.getFunctionManager();
			ReferenceManager refMgr = program.getReferenceManager();

			Function func = rfi.funcName.getFunction(program);
			if (func != null) {
				// TODO: improve this to handle stack values.  Currently only supports values in
				// registers.
				List<Register> callRegs = getRegistersForParameter(func, rfi.rttiParamIndex);
				if (callRegs == null || callRegs.size() != 1) {
					return;
				}

				Register paramReg = callRegs.get(0);

				stream(refMgr.getReferencesTo(func.getEntryPoint()).spliterator(), false) //
						.filter(ref -> !monitor.isCancelled() && ref != null &&
							ref.getReferenceType().isCall())
						.map(ref -> new CallSiteInfo(ref,
							funcMgr.getFunctionContaining(ref.getFromAddress()), func, paramReg,
							rfi.returnTypeMapper))
						.forEach(consumer.andThen(_unused -> {
							monitor.incrementProgress();
							totalCallsiteCount++;
						}));
			}
		}

		private DataType getReturnTypeForNewObjectFunc(GoType goType) {
			try {
				DataTypeManager dtm = goBinary.getDTM();
				DataType dt = goBinary.getGoTypes().getGhidraDataType(goType);
				return dtm.getPointer(dt);
			}
			catch (IOException e) {
				return null;
			}
		}

		private DataType getReturnTypeForSliceFunc(GoType goType) {
			try {
				GoTypeManager goTypes = goBinary.getGoTypes();
				GoType sliceGoType = goTypes.findGoType("[]" + goTypes.getTypeName(goType));
				DataType dt = sliceGoType != null ? goTypes.getGhidraDataType(sliceGoType) : null;
				return dt;
			}
			catch (IOException e) {
				return null;
			}
		}

		private List<Register> getRegistersForParameter(Function func, int paramIndex) {
			GoParamStorageAllocator storageAllocator = goBinary.newStorageAllocator();
			Parameter[] params = func.getParameters();
			if (params.length == 0 && paramIndex == 0) {
				// TODO: this is a hack to handle lack of func param info for built-in runtime alloc methods
				// This will not be needed once param info for the alloc methods is applied before
				// we get to this step.
				// This only works with the rtti funcs that pass the gotype ref in first param 
				return storageAllocator.getRegistersFor(goBinary.getGoTypes().getUintptrDT());
			}
			for (int i = 0; i < params.length; i++) {
				DataType paramDT = params[i].getDataType();
				List<Register> regs = storageAllocator.getRegistersFor(paramDT);
				if (i == paramIndex) {
					return regs;
				}
			}
			return List.of();
		}

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

		boolean createRuntimeSnapshotDatatypeArchive;

		static final String OUTPUT_SOURCE_INFO_OPTIONNAME = "Output Source Info";
		static final String OUTPUT_SOURCE_INFO_DESC = """
				Add "source_file_name:line_number" information to functions.""";
		boolean outputSourceInfo = true;

		static final String FIXUP_DUFF_FUNCS_OPTIONNAME = "Fixup Duff Functions";
		static final String FIXUP_DUFF_FUNCS_DESC = """
				Copies information from the runtime.duffzero and runtime.duffcopy functions to \
				the alternate duff entry points that are discovered during later analysis.""";
		boolean fixupDuffFunctions = true;

		static final String PROP_RTTI_OPTIONNAME = "Propagate RTTI";
		static final String PROP_RTTI_DESC = """
				Override the function signature of calls to some built-in Golang allocator \
				functions (runtime.newobject(), runtime.makeslice(), etc) that have a constant \
				reference to a Golang type record to have a return type of that specific Golang \
				type.""";
		boolean propagateRtti = true;

		static final String FIXUP_GCWRITEBARRIER_OPTIONNAME = "Fixup gcWriteBarrier Functions";
		static final String FIXUP_GCWRITEBARRIER_FUNCS_DESC = """
				Fixup gcWriteBarrier functions \
				(requires gcwrite calling convention defined for the program's arch)""";

		boolean fixupGcWriteBarierFunctions = true;

		void registerOptions(Options options, Program program) {
			options.registerOption(GolangAnalyzerOptions.CREATE_BOOTSTRAP_GDT_OPTIONNAME,
				createBootstrapDatatypeArchive, null,
				GolangAnalyzerOptions.CREATE_BOOTSTRAP_GDT_DESC);
			options.registerOption(GolangAnalyzerOptions.OUTPUT_SOURCE_INFO_OPTIONNAME,
				outputSourceInfo, null, GolangAnalyzerOptions.OUTPUT_SOURCE_INFO_DESC);
			options.registerOption(GolangAnalyzerOptions.FIXUP_DUFF_FUNCS_OPTIONNAME,
				fixupDuffFunctions, null, GolangAnalyzerOptions.FIXUP_DUFF_FUNCS_DESC);
			options.registerOption(GolangAnalyzerOptions.PROP_RTTI_OPTIONNAME, propagateRtti, null,
				GolangAnalyzerOptions.PROP_RTTI_DESC);
			options.registerOption(GolangAnalyzerOptions.FIXUP_GCWRITEBARRIER_OPTIONNAME,
				fixupGcWriteBarierFunctions, null,
				GolangAnalyzerOptions.FIXUP_GCWRITEBARRIER_FUNCS_DESC);
		}

		void optionsChanged(Options options, Program program) {
			createBootstrapDatatypeArchive =
				options.getBoolean(GolangAnalyzerOptions.CREATE_BOOTSTRAP_GDT_OPTIONNAME,
					createBootstrapDatatypeArchive);
			outputSourceInfo = options.getBoolean(
				GolangAnalyzerOptions.OUTPUT_SOURCE_INFO_OPTIONNAME, outputSourceInfo);

			fixupDuffFunctions = options.getBoolean(
				GolangAnalyzerOptions.FIXUP_DUFF_FUNCS_OPTIONNAME, fixupDuffFunctions);
			propagateRtti =
				options.getBoolean(GolangAnalyzerOptions.PROP_RTTI_OPTIONNAME, propagateRtti);
			fixupGcWriteBarierFunctions = options.getBoolean(
				GolangAnalyzerOptions.FIXUP_GCWRITEBARRIER_OPTIONNAME, fixupGcWriteBarierFunctions);
		}

	}

	/**
	 * Returns true if Golang analysis has already been performed for the specified program.
	 * 
	 * @param program {@link Program} to check
	 * @return true if analysis has already been performed, false if not yet
	 */
	public static boolean isAlreadyAnalyzed(Program program) {
		Options options = program.getOptions(Program.PROGRAM_INFO);
		return options.getBoolean(ANALYZED_FLAG_OPTION_NAME, false);
	}
}
