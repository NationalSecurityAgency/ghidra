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
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.services.*;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.format.golang.*;
import ghidra.app.util.bin.format.golang.rtti.*;
import ghidra.app.util.bin.format.golang.rtti.types.GoMethod.GoMethodInfo;
import ghidra.app.util.bin.format.golang.rtti.types.GoType;
import ghidra.app.util.bin.format.golang.structmapping.MarkupSession;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.viewer.field.AddressAnnotatedStringHandler;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
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
 */
public class GolangSymbolAnalyzer extends AbstractAnalyzer {

	private final static String NAME = "Golang Symbol";
	private final static String DESCRIPTION = """
			Analyze Golang binaries for RTTI and function symbols.
			'Apply Data Archives' and 'Shared Return Calls' analyzers should be disabled \
			for best results.""";
	private static final String ANALYZED_FLAG_OPTION_NAME = "Golang Analyzed";

	private GolangAnalyzerOptions analyzerOptions = new GolangAnalyzerOptions();

	private GoRttiMapper goBinary;
	private MarkupSession markupSession;
	private AutoAnalysisManager aam;
	private long lastTxId = -1;

	public GolangSymbolAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.FORMAT_ANALYSIS.after().after());
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

		aam = AutoAnalysisManager.getAnalysisManager(program);

		goBinary = GoRttiMapper.getSharedGoBinary(program, monitor);
		if (goBinary == null) {
			Msg.error(this, "Golang analyzer error: unable to get GoRttiMapper");
			return false;
		}

		try {
			goBinary.initTypeInfoIfNeeded(monitor);
			goBinary.initMethodInfoIfNeeded();

			markupSession = goBinary.createMarkupSession(monitor);
			GoModuledata firstModule = goBinary.getFirstModule();
			if (firstModule != null) {
				markupSession.labelStructure(firstModule, "firstmoduledata", null);
				markupSession.markup(firstModule, false);
			}

			markupWellknownSymbols();
			setupProgramContext();
			goBinary.recoverDataTypes(monitor);
			markupGoFunctions(monitor);
			if (analyzerOptions.fixupDuffFunctions) {
				fixDuffFunctions();
			}

			if (analyzerOptions.propagateRtti) {
				aam.schedule(new PropagateRttiBackgroundCommand(goBinary),
					AnalysisPriority.REFERENCE_ANALYSIS.after().priority());
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
		options.registerOption(GolangAnalyzerOptions.CREATE_BOOTSTRAP_GDT_OPTIONNAME,
			analyzerOptions.createBootstrapDatatypeArchive, null,
			GolangAnalyzerOptions.CREATE_BOOTSTRAP_GDT_DESC);
		options.registerOption(GolangAnalyzerOptions.OUTPUT_SOURCE_INFO_OPTIONNAME,
			analyzerOptions.outputSourceInfo, null, GolangAnalyzerOptions.OUTPUT_SOURCE_INFO_DESC);
		options.registerOption(GolangAnalyzerOptions.FIXUP_DUFF_FUNCS_OPTIONNAME,
			analyzerOptions.fixupDuffFunctions, null, GolangAnalyzerOptions.FIXUP_DUFF_FUNCS_DESC);
		options.registerOption(GolangAnalyzerOptions.PROP_RTTI_OPTIONNAME,
			analyzerOptions.propagateRtti, null, GolangAnalyzerOptions.PROP_RTTI_DESC);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		analyzerOptions.createBootstrapDatatypeArchive =
			options.getBoolean(GolangAnalyzerOptions.CREATE_BOOTSTRAP_GDT_OPTIONNAME,
				analyzerOptions.createBootstrapDatatypeArchive);
		analyzerOptions.outputSourceInfo = options.getBoolean(
			GolangAnalyzerOptions.OUTPUT_SOURCE_INFO_OPTIONNAME, analyzerOptions.outputSourceInfo);
	}

	private void markupWellknownSymbols() throws IOException {
		Program program = goBinary.getProgram();

		Symbol g0 = SymbolUtilities.getUniqueSymbol(program, "runtime.g0");
		Structure gStruct = goBinary.getGhidraDataType("runtime.g", Structure.class);
		if (g0 != null && gStruct != null) {
			markupSession.markupAddressIfUndefined(g0.getAddress(), gStruct);
		}

		Symbol m0 = SymbolUtilities.getUniqueSymbol(program, "runtime.m0");
		Structure mStruct = goBinary.getGhidraDataType("runtime.m", Structure.class);
		if (m0 != null && mStruct != null) {
			markupSession.markupAddressIfUndefined(m0.getAddress(), mStruct);
		}
	}

	private void markupGoFunctions(TaskMonitor monitor) throws IOException, CancelledException {
		Set<String> noreturnFuncNames = readNoReturnFuncNames();
		int noreturnFuncCount = 0;
		int functionSignatureFromBootstrap = 0;
		int functionSignatureFromMethod = 0;
		int partialFunctionSignatureFromMethod = 0;

		List<GoFuncData> funcs = goBinary.getAllFunctions();
		monitor.initialize(funcs.size(), "Fixing golang function signatures");
		for (GoFuncData funcdata : funcs) {
			monitor.increment();

			Address funcAddr = funcdata.getFuncAddress();
			GoSymbolName funcSymbolNameInfo = funcdata.getSymbolName();
			String funcname =
				SymbolUtilities.replaceInvalidChars(funcSymbolNameInfo.getSymbolName(), true);
			Namespace funcns = funcSymbolNameInfo.getSymbolNamespace(goBinary.getProgram());

			if ("go:buildid".equals(funcSymbolNameInfo.getSymbolName())) {
				// this funcdata entry is a bogus element that points to the go buildid string.  skip
				continue;
			}

			Function func = markupSession.createFunctionIfMissing(funcname, funcns, funcAddr);
			if (func == null) {
				continue;
			}

			boolean existingFuncSignature =
				func.getParameterCount() != 0 || !Undefined.isUndefined(func.getReturnType());

			markupSession.appendComment(func, "Golang function info: ",
				AddressAnnotatedStringHandler.createAddressAnnotationString(
					funcdata.getStructureContext().getStructureAddress(),
					"Flags: %s, ID: %s".formatted(funcdata.getFlags(), funcdata.getFuncIDEnum())));

			if (!funcSymbolNameInfo.getSymbolName().equals(funcname)) {
				markupSession.appendComment(func, "Golang original name: ",
					funcSymbolNameInfo.getSymbolName());
			}

			GoSourceFileInfo sfi = null;
			if (analyzerOptions.outputSourceInfo && (sfi = funcdata.getSourceFileInfo()) != null) {
				markupSession.appendComment(func, "Golang source: ", sfi.getDescription());
			}

			if (funcdata.getFlags().isEmpty() /* dont try to get arg info for ASM funcs*/) {
				markupSession.appendComment(func, null,
					"Golang recovered signature: " + funcdata.recoverFunctionSignature());
			}

			// Try to get a function definition signature from:
			// 1) Methods (with full info) attached to a type that point to this func
			// 2) Signature found in the bootstrap gdt file (matched by name)
			// 3) Artificial partial func signatures constructed from the go type method that points here
			GoMethodInfo boundMethod = funcdata.findMethodInfo();
			FunctionDefinition funcdef = boundMethod != null ? boundMethod.getSignature() : null;
			FunctionDefinition partialFuncdef =
				boundMethod != null && funcdef == null ? boundMethod.getPartialSignature() : null;

			if (funcdef == null) {
				funcdef = goBinary.getBootstrapFunctionDefintion(funcname);
				if (funcdef != null) {
					functionSignatureFromBootstrap++;
				}
			}
			else {
				functionSignatureFromMethod++;
			}
			if (funcdef == null && partialFuncdef != null && !existingFuncSignature) {
				// use partial funcdef that only has a receiver 'this' parameter
				funcdef = partialFuncdef;
				partialFunctionSignatureFromMethod++;
			}
			if (funcdef != null) {
				ApplyFunctionSignatureCmd cmd =
					new ApplyFunctionSignatureCmd(funcAddr, funcdef, SourceType.ANALYSIS);
				cmd.applyTo(goBinary.getProgram());
				try {
					GoFunctionFixup.fixupFunction(func, goBinary.getGolangVersion());
				}
				catch (DuplicateNameException | InvalidInputException e) {
					Msg.error(this, "Failed to fix function custom storage", e);
				}
			}

			if (noreturnFuncNames.contains(funcname)) {
				if (!func.hasNoReturn()) {
					func.setNoReturn(true);
					noreturnFuncCount++;
				}
			}

			if (boundMethod != null) {
				String addrAnnotation = AddressAnnotatedStringHandler.createAddressAnnotationString(
					boundMethod.getType().getStructureContext().getStructureAddress(),
					boundMethod.getType().getName());
				String methodComment = "Golang method in type %s%s: ".formatted(addrAnnotation,
					partialFuncdef != null ? " [partial]" : "");
				markupSession.appendComment(func, "",
					methodComment + (partialFuncdef != null ? partialFuncdef : funcdef));
			}

		}

		Msg.info(this, "Marked %d golang funcs as NoReturn".formatted(noreturnFuncCount));
		Msg.info(this, "Fixed %d golang function signatures from runtime snapshot signatures"
				.formatted(functionSignatureFromBootstrap));
		Msg.info(this, "Fixed %d golang function signatures from method info"
				.formatted(functionSignatureFromMethod));
		Msg.info(this, "Fixed %d golang function signatures from partial method info"
				.formatted(partialFunctionSignatureFromMethod));
	}

	/**
	 * Fixes the function signature of the runtime.duffzero and runtime.duffcopy functions.
	 * <p>
	 * The alternate duff-ified entry points haven't been discovered yet, so the information
	 * set to the main function entry point will be propagated at a later time by the
	 * FixupDuffAlternateEntryPointsBackgroundCommand.
	 */
	private void fixDuffFunctions() {
		Program program = goBinary.getProgram();
		GoRegisterInfo regInfo = goBinary.getRegInfo();
		DataType voidPtr = program.getDataTypeManager().getPointer(VoidDataType.dataType);
		DataType uintDT = goBinary.getTypeOrDefault("uint", DataType.class,
			AbstractIntegerDataType.getUnsignedDataType(goBinary.getPtrSize(), null));

		GoFuncData duffzeroFuncdata = goBinary.getFunctionByName("runtime.duffzero");
		Function duffzeroFunc = duffzeroFuncdata != null
				? program.getFunctionManager().getFunctionAt(duffzeroFuncdata.getFuncAddress())
				: null;
		if (duffzeroFunc != null &&
			goBinary.hasCallingConvention(GOLANG_DUFFZERO_CALLINGCONVENTION_NAME)) {
			try {
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

				duffzeroFunc.updateFunction(GOLANG_DUFFZERO_CALLINGCONVENTION_NAME,
					new ReturnParameterImpl(VoidDataType.dataType, program), params,
					FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);

				markupSession.appendComment(duffzeroFunc, null,
					"Golang special function: duffzero");

				aam.schedule(new FixupDuffAlternateEntryPointsBackgroundCommand(duffzeroFuncdata,
					duffzeroFunc), AnalysisPriority.FUNCTION_ANALYSIS.after().priority());
			}
			catch (InvalidInputException | DuplicateNameException e) {
				Msg.error(this, "Failed to update main duffzero function", e);
			}

			GoFuncData duffcopyFuncdata = goBinary.getFunctionByName("runtime.duffcopy");
			Function duffcopyFunc = duffcopyFuncdata != null
					? program.getFunctionManager().getFunctionAt(duffcopyFuncdata.getFuncAddress())
					: null;
			if (duffcopyFuncdata != null &&
				goBinary.hasCallingConvention(GOLANG_DUFFCOPY_CALLINGCONVENTION_NAME)) {
				try {
					List<Variable> params = List.of(new ParameterImpl("dest", voidPtr, program),
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
		Program program = goBinary.getProgram();
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

	private void setupProgramContext() throws IOException {
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

		Address contextMemoryAddr =
			sizeNeeded > 0 ? createFakeContextMemory(program, sizeNeeded) : null;

		if (zerobase == null) {
			markupSession.labelAddress(contextMemoryAddr.add(zerobaseSymbol),
				GoRttiMapper.ARTIFICIAL_RUNTIME_ZEROBASE_SYMBOLNAME);
		}

		if (gStruct != null) {
			Address gAddr = contextMemoryAddr.add(gStructOffset);
			markupSession.markupAddressIfUndefined(gAddr, gStruct);
			markupSession.labelAddress(gAddr, "CURRENT_G");

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
			markupSession.markupAddressIfUndefined(mAddr, mStruct);
		}
	}

	private void createBootstrapGDT(TaskMonitor monitor) throws IOException, CancelledException {
		Program program = goBinary.getProgram();
		GoVer goVer = goBinary.getGolangVersion();
		String osName = GoRttiMapper.getGolangOSString(program);
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
	private static class FixupDuffAlternateEntryPointsBackgroundCommand extends BackgroundCommand {

		private Function duffFunc;
		private GoFuncData funcData;

		public FixupDuffAlternateEntryPointsBackgroundCommand(GoFuncData funcData,
				Function duffFunc) {
			this.funcData = funcData;
			this.duffFunc = duffFunc;
		}

		@Override
		public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
			String ccName = duffFunc.getCallingConventionName();
			Namespace funcNS = duffFunc.getParentNamespace();
			AddressSet funcBody = new AddressSet(funcData.getBody());
			Program program = duffFunc.getProgram();
			String duffComment = program.getListing()
					.getCodeUnitAt(duffFunc.getEntryPoint())
					.getComment(CodeUnit.PLATE_COMMENT);
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
					func.updateFunction(ccName, duffFunc.getReturn(),
						Arrays.asList(duffFunc.getParameters()),
						FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);
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
	 * A background command that runs after reference analysis, it applies functions signature
	 * overrides to callsites that have a RTTI type parameter that return a specialized
	 * type instead of a void*.
	 */
	private static class PropagateRttiBackgroundCommand extends BackgroundCommand {
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
		private MarkupSession markupSession;
		int totalCallsiteCount;
		int fixedCallsiteCount;
		int unfixedCallsiteCount;
		int callingFunctionCount;

		public PropagateRttiBackgroundCommand(GoRttiMapper goBinary) {
			this.goBinary = goBinary;
		}

		@Override
		public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
			if (goBinary.newStorageAllocator().isAbi0Mode()) {
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
			Program program = goBinary.getProgram();

			monitor.setMessage("Propagating RTTI from callsites in %s@%s"
					.formatted(callingFunc.getName(), callingFunc.getEntryPoint()));

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
					GoType goType = goBinary.getCachedGoType(goTypeOffset);
					if (goType == null) {
						// if it was previously not discovered (usually closure anon types), also mark it up
						goType = goBinary.getGoType(goTypeOffset);
						markupSession.markup(goType, false);
					}
					DataType newReturnType =
						goType != null ? callsite.returnTypeMapper.apply(goType) : null;
					if (newReturnType != null) {
						// Create a funcdef for this call site, where the return value is a
						// specific glang type instead of the void* it was before.
						FunctionDefinitionDataType signature =
							new FunctionDefinitionDataType(callsite.calledFunc, true);
						signature.setReturnType(newReturnType);
						try {
							HighFunctionDBUtil.writeOverride(callsite.callingFunc,
								callsite.ref.getFromAddress(), signature);
						}
						catch (InvalidInputException e) {
							Msg.error(this, "Failed to override call", e);
						}
						fixedCallsiteCount++;
					}
				}
				catch (IOException e) {
					Msg.error(this, "Failed to override call", e);
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
				new RttiFuncInfo("runtime.growslice", 4, this::getReturnTypeForSliceFunc),	// won't work unless func signature for growslice is applied, which is a future "todo" 
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
			Program program = goBinary.getProgram();
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
				DataType dt = goBinary.getRecoveredType(goType);
				return dtm.getPointer(dt);
			}
			catch (IOException e) {
				return null;
			}
		}

		private DataType getReturnTypeForSliceFunc(GoType goType) {
			try {
				GoType sliceGoType = goBinary.findGoType("[]" + goType.getNameWithPackageString());
				DataType dt = sliceGoType != null ? goBinary.getRecoveredType(sliceGoType) : null;
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
				return storageAllocator.getRegistersFor(goBinary.getUintptrDT());
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
