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
package ghidra.program.database;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.*;

import generic.jar.ResourceFile;
import generic.test.AbstractGenericTest;
import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.equate.SetEquateCmd;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.label.AddLabelCmd;
import ghidra.app.cmd.label.CreateNamespacesCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.SymbolPath;
import ghidra.framework.Application;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.data.ProgramDataTypeManager;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.*;
import ghidra.program.util.DefaultLanguageService;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import utility.function.ExceptionalCallback;

// TODO: Move this class into a different package (i.e., ghidra.test.program)
public class ProgramBuilder {

	public static final String _ARM = "ARM:LE:32:v7";
	public static final String _AARCH64 = "AARCH64:LE:64:v8A";
	public static final String _X86 = "x86:LE:32:default";
	public static final String _X86_16_REAL_MODE = "x86:LE:16:Real Mode";
	public static final String _X64 = "x86:LE:64:default";
	public static final String _8051 = "8051:BE:16:default";
	public static final String _SPARC64 = "sparc:BE:64:default";
	public static final String _MIPS = "MIPS:BE:32:default";
	public static final String _MIPS_6432 = "MIPS:BE:64:64-32addr";
	public static final String _PPC_32 = "PowerPC:BE:32:default";
	public static final String _PPC_6432 = "PowerPC:BE:64:64-32addr";
	public static final String _PPC_64 = "PowerPC:BE:64:default";

	public static final String _TOY_BE = "Toy:BE:32:default";
	public static final String _TOY_BE_POSITIVE = "Toy:BE:32:posStack";
	public static final String _TOY_LE = "Toy:LE:32:default";
	public static final String _TOY_WORDSIZE2_BE = "Toy:BE:32:wordSize2";
	public static final String _TOY_WORDSIZE2_LE = "Toy:LE:32:wordSize2";
	public static final String _TOY64_BE = "Toy:BE:64:default";
	public static final String _TOY64_LE = "Toy:LE:64:default";

	public static final String _TOY = _TOY_BE;

	private static final String LANGUAGE_DELIMITER = ":";

	protected static final String _TOY_LANGUAGE_PREFIX = "Toy:";

	private static final Map<String, Language> LANGUAGE_CACHE = new HashMap<>();

	private ProgramDB program;

	private int transactionID;
	private int transactionCount = 0;

	/**
	 * Construct program builder using the big-endian Toy language and default compiler spec.
	 * This builder object will be the program consumer and must be disposed to properly
	 * release the program.
	 * @throws Exception if there is an exception creating the program 
	 */
	public ProgramBuilder() throws Exception {
		this("Test Program", _TOY);
	}

	/**
	 * Construct program builder using specified language and default compiler spec.
	 * This builder object will be the program consumer and must be disposed to properly
	 * release the program.
	 * @param name program name
	 * @param languageName supported language ID (includes all Toy language IDs)
	 * @throws Exception if there is an exception creating the program
	 */
	public ProgramBuilder(String name, String languageName) throws Exception {
		this(name, languageName, null, null);
	}

	/**
	 * Construct program builder using specified language and default compiler spec
	 * @param name program name
	 * @param languageName supported language ID (includes all Toy language IDs)
	 * @param consumer program consumer (if null this builder will be used as consumer and must be disposed to release program)
	 * @throws Exception if there is an exception creating the program
	 */
	public ProgramBuilder(String name, String languageName, Object consumer) throws Exception {
		this(name, languageName, null, consumer);
	}

	/**
	 * Construct program builder using specified language
	 * @param name program name
	 * @param languageName supported language ID (includes all Toy language IDs)
	 * @param compilerSpecID compiler specification ID (if null default spec will be used)
	 * @param consumer program consumer (if null this builder will be used as consumer and must be disposed to release program)
	 * @throws Exception if there is an exception creating the program
	 */
	public ProgramBuilder(String name, String languageName, String compilerSpecID, Object consumer)
			throws Exception {
		Language language = getLanguage(languageName);
		CompilerSpec compilerSpec = compilerSpecID == null ? language.getDefaultCompilerSpec()
				: language.getCompilerSpecByID(new CompilerSpecID(compilerSpecID));
		program = new ProgramDB(name, language, compilerSpec, consumer == null ? this : consumer);
		setAnalyzed(true);
		program.setTemporary(true); // ignore changes
	}

	/**
	 * Perform complete analysis on the built program.
	 * Limited analysis may already have been performed during disassembly - so it may not
	 * be necessary to do complete analysis
	 */
	public void analyze() {
		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);

		tx(() -> {
			mgr.reAnalyzeAll(program.getMemory().getLoadedAndInitializedAddressSet());
			mgr.startAnalysis(TaskMonitor.DUMMY, false);
		});

		PluginTool analysisTool = mgr.getAnalysisTool();
		if (analysisTool != null) {
			AbstractGhidraHeadedIntegrationTest.waitForBusyTool(analysisTool);
		}
	}

	/**
	 * Get the constructed program.  If this builder was not constructed with a consumer,
	 * the caller should dispose the builder after either the program is no longer
	 * in use, or a new consumer has been added to the program (e.g., program opened
	 * in a tool or another consumer explicitly added).
	 * @return constructed program
	 */
	public ProgramDB getProgram() {
		// some tests get odd timing issues if the events generated by building the program
		// are delivered while the test is running, so, fire them now
		program.flushEvents();
		return program;
	}

	public Language getLanguage() {
		return program.getLanguage();
	}

	public CompilerSpec getCompilerSpec() {
		return program.getCompilerSpec();
	}

	public Register getRegister(String regName) {
		return program.getRegister(regName);
	}

	public Address addr(long offset) {
		AddressFactory addressFactory = program.getAddressFactory();
		return addressFactory.getDefaultAddressSpace().getAddress(offset);
	}

	public Address addr(String addressString) {
		AddressFactory addressFactory = program.getAddressFactory();
		Address addr = addressFactory.getAddress(addressString);
		if (addr == null) {
			throw new IllegalArgumentException("Failed to parse address string: " + addressString);
		}
		return addr;
	}

	public void dispose() {
		if (program.isUsedBy(this)) {

			// Make sure any buffered events are processed before we release.  This fixes a timing
			// issue that can  happen when the test thread disposes the program while the Swing
			// thread is processing events.
			flushEvents();
			program.release(this);
		}
	}

	private void flushEvents() {
		program.flushEvents();
		if (!SystemUtilities.isInHeadlessMode()) {
			AbstractGenericTest.waitForSwing();
		}
	}

	public void setName(String name) {
		tx(() -> {
			program.setName(name);
		});
	}

	public void withTransaction(Runnable r) {
		tx(() -> r.run());
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	protected void startTransaction() {
		if (transactionCount++ == 0) {
			transactionID = program.startTransaction("Test Transaction");
		}
	}

	protected void endTransaction() {
		endTransaction(true);
	}

	protected void endTransaction(boolean commit) {
		if (--transactionCount == 0) {
			program.endTransaction(transactionID, true);
		}
	}

	private Language getLanguage(String languageName) throws Exception {
		Language language = LANGUAGE_CACHE.get(languageName);
		if (language != null) {
			return language;
		}

		ResourceFile ldefFile = null;
		if (languageName.contains(LANGUAGE_DELIMITER)) {
			switch (languageName.split(LANGUAGE_DELIMITER)[0]) {
				case "x86":
					ldefFile = Application.getModuleDataFile("x86", "languages/x86.ldefs");
					break;
				case "8051":
					ldefFile = Application.getModuleDataFile("8051", "languages/8051.ldefs");
					break;
				case "sparc":
					ldefFile = Application.getModuleDataFile("Sparc", "languages/SparcV9.ldefs");
					break;
				case "ARM":
					ldefFile = Application.getModuleDataFile("ARM", "languages/ARM.ldefs");
					break;
				case "AARCH64":
					ldefFile = Application.getModuleDataFile("AARCH64", "languages/AARCH64.ldefs");
					break;
				case "MIPS":
					ldefFile = Application.getModuleDataFile("MIPS", "languages/mips.ldefs");
					break;
				case "Toy":
					ldefFile = Application.getModuleDataFile("Toy", "languages/toy.ldefs");
					break;
				case "PowerPC":
					ldefFile = Application.getModuleDataFile("PowerPC", "languages/ppc.ldefs");
					break;
				default:
					break;
			}
		}
		if (ldefFile != null) {
			LanguageService languageService = DefaultLanguageService.getLanguageService(ldefFile);
			try {
				language = languageService.getLanguage(new LanguageID(languageName));
			}
			catch (LanguageNotFoundException e) {
				throw new LanguageNotFoundException("Unsupported test language: " + languageName);
			}
			LANGUAGE_CACHE.put(languageName, language);
			return language;
		}
		throw new LanguageNotFoundException("Unsupported test language: " + languageName);
	}

//==================================================================================================
// Convenience Methods
//==================================================================================================

	public void setRecordChanges(boolean enabled) {
		AbstractGenericTest.setInstanceField("recordChanges", program, Boolean.valueOf(enabled));
	}

	/** 
	 * This prevents the 'ask to analyze' dialog from showing when called with {@code true}
	 * @param analyzed true to mark the program as analyzed
	 */
	public void setAnalyzed(boolean analyzed) {
		GhidraProgramUtilities.setAnalyzedFlag(program, analyzed);
	}

	public MemoryBlock createMemory(String name, String address, int size) {
		return createMemory(name, address, size, null);
	}

	public MemoryBlock createMemory(String name, String address, int size, String comment) {
		return createMemory(name, address, size, comment, (byte) 0);
	}

	public MemoryBlock createMemory(String name, String address, int size, String comment,
			byte initialValue) {

		return tx(() -> {
			Address startAddress = addr(address);
			Memory memory = program.getMemory();
			MemoryBlock block = memory.createInitializedBlock(name, startAddress, size,
				initialValue, TaskMonitor.DUMMY, false);
			block.setComment(comment);
			return block;
		});
	}

	public MemoryBlock createUninitializedMemory(String name, String address, int size) {

		return tx(() -> {
			Address startAddress = addr(address);
			Memory memory = program.getMemory();
			return memory.createUninitializedBlock(name, startAddress, size, false);
		});
	}

	public MemoryBlock createOverlayMemory(String name, String address, int size) {

		return tx(() -> {
			return program.getMemory()
					.createInitializedBlock(name, addr(address), size, (byte) 0,
						TaskMonitor.DUMMY, true);
		});
	}

	/**
	 * Sets the bytes starting at {@code address} to the values encoded in {@code byteString}.
	 * <p>
	 * See {@link #setBytes(String, byte[], boolean)}.
	 * <p>
	 * @param address String containing numeric value, preferably hex encoded: "0x1004000"
	 * @param byteString String containing 2 digit hex values, separated by ' ' space chars
	 * or by comma ',' chars: "12 05 ff".  See {@link NumericUtilities#parseHexLong(String)}.
	 * @throws Exception if there is an exception applying the bytes
	 */
	public void setBytes(String address, String byteString) throws Exception {
		byte[] bytes = NumericUtilities.convertStringToBytes(byteString);
		setBytes(address, bytes, false);
	}

	/**
	 * Sets the bytes starting at {@code address} to the values encoded in {@code byteString}
	 * and then optionally disassembling.
	 * <p>
	 * See {@link #setBytes(String, byte[], boolean)}.
	 * <p>
	 * @param address String containing numeric value, preferably hex encoded: "0x1004000"
	 * @param byteString String containing 2 digit hex values, separated by ' ' space chars
	 * or by comma ',' chars: "12 05 ff".  See {@link NumericUtilities#parseHexLong(String)}.
	 * @param disassemble boolean flag.
	 * @throws Exception if there is an exception applying the bytes
	 */
	public void setBytes(String address, String byteString, boolean disassemble) throws Exception {
		byte[] bytes = NumericUtilities.convertStringToBytes(byteString);
		setBytes(address, bytes, disassemble);
	}

	public void setBytes(String stringAddress, byte[] bytes) throws Exception {
		setBytes(stringAddress, bytes, false);
	}

	/**
	 * Sets the bytes starting at {@code stringAddress} to the byte values in {@code bytes}
	 * and then optionally disassembling.
	 * <p>
	 * @param stringAddress String containing numeric value, preferably hex encoded: "0x1004000"
	 * @param bytes array of bytes to copy into the memory buffer at the addresss.
	 * @param disassemble boolean flag.  See {@link #disassemble(String, int)}
	 * @throws Exception if there is an exception applying the bytes
	 */
	public void setBytes(String stringAddress, byte[] bytes, boolean disassemble) throws Exception {
		Address address = addr(stringAddress);
		tx(() -> {
			MemoryBlock block = program.getMemory().getBlock(address);
			if (block == null) {
				createMemory("Block_" + stringAddress.toString().replace(':', '_'), stringAddress,
					bytes.length);
			}

			Memory memory = program.getMemory();
			memory.setBytes(address, bytes);
		});

		if (disassemble) {
			disassemble(stringAddress, bytes.length);
		}
	}

	public void setRead(MemoryBlock block, boolean r) {
		tx(() -> block.setRead(r));
	}

	public void setWrite(MemoryBlock block, boolean w) {
		tx(() -> block.setWrite(w));
	}

	public void setExecute(MemoryBlock block, boolean e) {
		tx(() -> block.setExecute(e));
	}

	public void disassemble(String addressString, int length) {
		disassemble(addressString, length, true);
	}

	public void disassemble(String addressString, int length, boolean followFlows) {
		tx(() -> {
			Address address = addr(addressString);
			AddressSet addresses = new AddressSet(address, address.add(length - 1));
			DisassembleCommand cmd = new DisassembleCommand(addresses, addresses, followFlows);

			cmd.applyTo(program);
			AutoAnalysisManager.getAnalysisManager(program).startAnalysis(TaskMonitor.DUMMY);
		});
	}

	public void disassemble(AddressSetView set) {
		tx(() -> {
			DisassembleCommand cmd = new DisassembleCommand(set, set, true);
			cmd.applyTo(program);
			AutoAnalysisManager.getAnalysisManager(program).startAnalysis(TaskMonitor.DUMMY);
		});
	}

	public void disassemble(AddressSetView set, boolean followFlows) {
		tx(() -> {
			DisassembleCommand cmd = new DisassembleCommand(set, set, followFlows);
			cmd.applyTo(program);
			AutoAnalysisManager.getAnalysisManager(program).startAnalysis(TaskMonitor.DUMMY);
		});
	}

	public void disassembleArm(String addressString, int length, boolean thumb) {
		tx(() -> {
			Address address = addr(addressString);
			DisassembleCommand cmd = new ArmDisassembleCommand(address,
				new AddressSet(address, address.add(length - 1)), true);
			cmd.applyTo(program);
			AutoAnalysisManager.getAnalysisManager(program).startAnalysis(TaskMonitor.DUMMY);
		});
	}

	public void clearCodeUnits(String startAddressString, String endAddressString,
			boolean clearContext) throws Exception {
		tx(() -> {
			Address startAddress = addr(startAddressString);
			Address endAddress = addr(endAddressString);
			Listing listing = program.getListing();
			listing.clearCodeUnits(startAddress, endAddress, clearContext);
		});
	}

	public Symbol createLabel(String addressString, String name) {
		return tx(() -> {
			Address address = addr(addressString);
			AddLabelCmd cmd = new AddLabelCmd(address, name, SourceType.USER_DEFINED);
			cmd.applyTo(program);
			return cmd.getSymbol();
		});
	}

	public Symbol createLabel(String addressString, String name, String namespace) {
		return tx(() -> {
			Address address = addr(addressString);
			Namespace ns = getNamespace(namespace, address);
			AddLabelCmd cmd = new AddLabelCmd(address, name, ns, SourceType.USER_DEFINED);
			cmd.applyTo(program);
			return cmd.getSymbol();
		});
	}

	/**
	 * Creates a function by examining the instructions to find the body.
	 *
	 * @param addressString the address
	 * @return the function
	 */
	public Function createFunction(String addressString) {
		return tx(() -> {
			Address address = addr(addressString);
			CreateFunctionCmd cmd = new CreateFunctionCmd(address);
			cmd.applyTo(program);
			return cmd.getFunction();
		});
	}

	public void addFunctionVariable(Function f, Variable v)
			throws Exception {
		tx(() -> f.addLocalVariable(v, SourceType.USER_DEFINED));
	}

	public Function createEmptyFunction(String name, String address, int size, DataType returnType,
			Parameter... params) throws Exception, OverlappingFunctionException {

		return createEmptyFunction(name, null, null, false, address, size, returnType, params);
	}

	public Function createEmptyFunction(String name, String address, int size, DataType returnType,
			boolean varargs, boolean inline, boolean noReturn, Parameter... params)
			throws Exception {
		return tx(() -> {
			Function fun =
				createEmptyFunction(name, null, null, false, address, size, returnType, params);
			fun.setVarArgs(varargs);
			fun.setInline(inline);
			fun.setNoReturn(noReturn);
			return fun;
		});

	}

	public Function createEmptyFunction(String name, String namespace, String address, int bodySize,
			DataType returnType, Parameter... params) throws Exception {

		return createEmptyFunction(name, namespace, null, false, address, bodySize, returnType,
			params);
	}

	public Function createEmptyFunction(String name, String namespace, String callingConventionName,
			boolean customStorage, String address, int bodySize, DataType returnType,
			Parameter... params) throws Exception {

		return tx(() -> {
			Address entryPoint = addr(address);
			Address endAddress = entryPoint.add(bodySize - 1);
			AddressSet body = new AddressSet(entryPoint, endAddress);
			FunctionManager functionManager = program.getFunctionManager();

			Function function = null;
			if (namespace == null) {
				function = functionManager.createFunction(
					name, entryPoint, body, SourceType.USER_DEFINED);
			}
			else {
				Namespace ns = getNamespace(namespace);
				function = functionManager.createFunction(
					name, ns, entryPoint, body, SourceType.USER_DEFINED);
			}

			Parameter[] myParams = params;
			if (myParams == null) {
				myParams = new Parameter[0];
			}

			Variable returnVar = returnType != null ? new ReturnParameterImpl(returnType, program)
					: function.getReturn();
			function.updateFunction(callingConventionName, returnVar,
				customStorage ? FunctionUpdateType.CUSTOM_STORAGE
						: FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
				false, SourceType.USER_DEFINED, myParams);

			return function;
		});
	}

	public Function createEmptyFunction(String name, String namespace, String callingConventionName,
			String address, int size, DataType returnType, DataType... paramTypes)
			throws Exception {

		Parameter[] params = new ParameterImpl[paramTypes.length];
		for (int i = 0; i < paramTypes.length; i++) {
			params[i] = new ParameterImpl(null, paramTypes[i], program);
		}
		return createEmptyFunction(name, namespace, callingConventionName, false, address, size,
			returnType, params);
	}

	public Library createLibrary(String libraryName)
			throws DuplicateNameException, InvalidInputException {
		return createLibrary(libraryName, SourceType.USER_DEFINED);
	}

	public Library createLibrary(String libraryName, SourceType type)
			throws DuplicateNameException, InvalidInputException {
		SymbolTable symbolTable = program.getSymbolTable();
		return symbolTable.createExternalLibrary(libraryName, type);
	}

	public Namespace createNamespace(String namespace) {
		return createNamespace(namespace, SourceType.USER_DEFINED);
	}

	public Namespace getNamespace(String namespace) {
		if (namespace == null) {
			return null;
		}

		try {
			return NamespaceUtils.createNamespaceHierarchy(namespace, null, program,
				SourceType.USER_DEFINED);
		}
		catch (InvalidInputException e) {
			throw new RuntimeException(e);
		}
	}

	public Namespace getNamespace(String namespace, Address address) {
		if (namespace == null) {
			return null;
		}

		try {
			return NamespaceUtils.createNamespaceHierarchy(namespace, null, program, address,
				SourceType.USER_DEFINED);
		}
		catch (InvalidInputException e) {
			throw new RuntimeException(e);
		}
	}

	public Namespace createNamespace(String namespace, SourceType type) {
		return createNamespace(namespace, null, type);
	}

	public Namespace createNamespace(String namespace, String parentNamespace, SourceType type) {
		return tx(() -> {
			Namespace ns = getNamespace(parentNamespace);
			CreateNamespacesCmd cmd = new CreateNamespacesCmd(namespace, ns, type);
			cmd.applyTo(program);
			return cmd.getNamespace();
		});
	}

	public Namespace createClassNamespace(String name, String parentNamespace, SourceType type)
			throws Exception {
		return tx(() -> {
			Namespace ns = getNamespace(parentNamespace);
			SymbolTable symbolTable = program.getSymbolTable();
			GhidraClass c = symbolTable.createClass(ns, name, SourceType.USER_DEFINED);
			return c;
		});
	}

	public void applyFixedLengthDataType(String addressString, DataType dt, int length) {
		tx(() -> {
			DataUtilities.createData(program, addr(addressString), dt, length, false,
				ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
		});
	}

	public void applyDataType(String addressString, DataType dt) {
		applyDataType(addressString, dt, 1);
	}

	/**
	 * Creates a data instance at the specified address, repeated {@code N} times.
	 *
	 * @param addressString address.
	 * @param dt {@link DataType} to place at address, {@link Dynamic} length datatype not supported.
	 * @param n repeat count.
	 */
	public void applyDataType(String addressString, DataType dt, int n) {
		tx(() -> {
			Address address = addr(addressString);
			for (int i = 0; i < n; i++) {
				CreateDataCmd cmd = new CreateDataCmd(address, dt);
				if (!cmd.applyTo(program)) {
					throw new AssertException(
						"Could not apply data at address " + address + ". " + cmd.getStatusMsg());
				}
				address = address.add(dt.getLength());// advance address after cmd succeeds
			}
		});
	}

	/**
	 * Creates a sting data type instance at the specified address, repeated {@code N} times.
	 *
	 * @param addressString address.
	 * @param dt {@link AbstractStringDataType} string type to place at address.
	 * @param n repeat count.
	 */
	public void applyStringDataType(String addressString, AbstractStringDataType dt, int n) {

		tx(() -> {

			Address address = addr(addressString);
			int previousDataLength = 0;
			for (int i = 0; i < n; i++) {
				address = address.addNoWrap(previousDataLength);
				Data newStringInstance = DataUtilities.createData(program, address, dt, -1, false,
					ClearDataMode.CLEAR_SINGLE_DATA);
				previousDataLength = newStringInstance.getLength();
			}
		});
	}

	public void deleteReference(Reference reference) {
		tx(() -> {
			ReferenceManager refMgr = program.getReferenceManager();
			refMgr.delete(reference);
		});
	}

	public Reference createMemoryReadReference(String fromAddress, String toAddress) {
		return createMemoryReference(fromAddress, toAddress, RefType.READ, SourceType.USER_DEFINED);
	}

	public Reference createMemoryCallReference(String fromAddress, String toAddress) {
		return createMemoryReference(fromAddress, toAddress, RefType.UNCONDITIONAL_CALL,
			SourceType.USER_DEFINED);
	}

	public Reference createMemoryJumpReference(String fromAddress, String toAddress) {
		return createMemoryReference(fromAddress, toAddress, RefType.UNCONDITIONAL_JUMP,
			SourceType.USER_DEFINED);
	}

	public Reference createMemoryReference(String fromAddress, String toAddress, RefType refType,
			SourceType sourceType) {
		return createMemoryReference(fromAddress, toAddress, refType, sourceType, 0);
	}

	public Reference createMemoryReference(String fromAddress, String toAddress, RefType refType,
			SourceType sourceType, int opIndex) {
		return tx(() -> {
			ReferenceManager refManager = program.getReferenceManager();
			Reference ref = refManager.addMemoryReference(addr(fromAddress), addr(toAddress),
				refType, sourceType, opIndex);
			return ref;
		});
	}

	public Reference createOffsetMemReference(String fromAddress, String toAddress, int offset,
			RefType refType, SourceType sourceType, int opIndex) {
		return tx(() -> {
			ReferenceManager refManager = program.getReferenceManager();
			Reference ref = refManager.addOffsetMemReference(addr(fromAddress), addr(toAddress),
				offset, refType, sourceType, opIndex);
			return ref;
		});
	}

	public Reference createStackReference(String fromAddress, RefType refType, int stackOffset,
			SourceType sourceType, int opIndex) {
		return tx(() -> {
			ReferenceManager refManager = program.getReferenceManager();
			Reference ref = refManager.addStackReference(addr(fromAddress), opIndex, stackOffset,
				refType, sourceType);
			return ref;
		});
	}

	public Reference createRegisterReference(String fromAddress, String registerName, int opIndex) {
		return createRegisterReference(fromAddress, RefType.DATA, registerName,
			SourceType.USER_DEFINED, opIndex);
	}

	public Reference createRegisterReference(String fromAddress, RefType refType,
			String registerName, SourceType sourceType, int opIndex) {
		return tx(() -> {
			ReferenceManager refManager = program.getReferenceManager();
			Register register = program.getRegister(registerName);
			Reference ref = refManager.addRegisterReference(addr(fromAddress), opIndex, register,
				refType, sourceType);
			return ref;
		});
	}

	public Symbol createEntryPoint(String addressString, String name) {
		return tx(() -> {
			SymbolTable symbolTable = program.getSymbolTable();
			symbolTable.addExternalEntryPoint(addr(addressString));
			Symbol[] symbols = symbolTable.getSymbols(addr(addressString));
			symbols[0].setName(name, SourceType.ANALYSIS);
			return symbols[0];
		});
	}

	public Bookmark createBookmark(String address, String bookmarkType, String category,
			String comment) {
		return tx(() -> {
			BookmarkManager bookMgr = program.getBookmarkManager();
			Address addr = addr(address);
			Bookmark bm = bookMgr.setBookmark(addr, bookmarkType, category, comment);
			return bm;
		});
	}

	public void createEncodedString(String address, String string, Charset encoding,
			boolean nullTerminate) throws Exception {
		byte[] bytes = string.getBytes(encoding);

		if (encoding == StandardCharsets.US_ASCII || encoding == StandardCharsets.UTF_8) {
			if (nullTerminate) {
				bytes = Arrays.copyOf(bytes, bytes.length + 1);
			}
			setBytes(address, bytes);
			applyDataType(address, new StringDataType(), 1);
		}
		else if (encoding == StandardCharsets.UTF_16BE || encoding == StandardCharsets.UTF_16LE) {
			if (nullTerminate) {
				bytes = Arrays.copyOf(bytes, bytes.length + 2);
				setBytes(address, bytes);
				applyDataType(address, new TerminatedUnicodeDataType(), 1);
			}
			else {
				setBytes(address, bytes);
			}
		}
		else {
			setBytes(address, bytes);
		}
	}

	public Data createString(String address, String string, Charset charset, boolean nullTerminate,
			DataType dataType) throws Exception {
		if (nullTerminate) {
			string = string + "\0";
		}
		byte[] bytes = string.getBytes(charset);
		return createString(address, bytes, charset, dataType);
	}

	public Data createString(String address, byte[] stringBytes, Charset charset,
			DataType dataType) throws Exception {
		Address addr = addr(address);
		setBytes(address, stringBytes);
		if (dataType != null) {
			startTransaction();
			try {
				Data data = DataUtilities.createData(program, addr, dataType, stringBytes.length,
					false, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
				CharsetSettingsDefinition.CHARSET.setCharset(data, charset.name());
				return data;
			}
			finally {
				endTransaction();
			}
		}
		return null;
	}

	public void setProperty(String name, Object value) {
		tx(() -> {
			Options options = program.getOptions(Program.PROGRAM_INFO);
			options.putObject(name, value);
		});
	}

	public void setAnalysisEnabled(String name, boolean enabled) {
		tx(() -> {
			Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
			options.setBoolean(name, enabled);
		});
	}

	public void addDataType(DataType dt) {
		tx(() -> {
			ProgramDataTypeManager dtm = program.getDataTypeManager();
			dtm.addDataType(dt, DataTypeConflictHandler.REPLACE_HANDLER);
		});
	}

	public void addCategory(CategoryPath path) {
		tx(() -> {
			ProgramDataTypeManager dtm = program.getDataTypeManager();
			dtm.createCategory(path);
		});
	}

	public void createProgramTree(String treeName) throws Exception {
		tx(() -> {
			program.getListing().createRootModule(treeName);
		});
	}

	public void createFragment(String treeName, String modulePath, String fragmentName,
			String startAddr, String endAddr) throws Exception {
		tx(() -> {
			ProgramModule module = getOrCreateModule(treeName, modulePath);
			ProgramFragment fragment = module.createFragment(fragmentName);
			fragment.move(addr(startAddr), addr(endAddr));
		});
	}

	public ProgramModule getOrCreateModule(String treeName, String modulePath) throws Exception {
		startTransaction();
		ProgramModule m;
		try {
			ProgramModule rootModule = program.getListing().getRootModule(treeName);
			if (modulePath == null || modulePath.length() == 0) {
				return rootModule;
			}
			String[] modules = modulePath.split("\\.");
			m = rootModule;
			for (String moduleName : modules) {
				m = getOrCreateChildModule(m, moduleName);
			}
		}
		finally {
			endTransaction();
		}

		return m;
	}

	private ProgramModule getOrCreateChildModule(ProgramModule m, String moduleName)
			throws Exception {
		Group[] children = m.getChildren();
		for (Group group : children) {
			if (group.getName().equals(moduleName)) {
				return (ProgramModule) group;
			}
		}
		return m.createModule(moduleName);
	}

	public Equate createEquate(String address, String name, long value, int opIndex) {
		return tx(() -> {
			SetEquateCmd cmd = new SetEquateCmd(name, addr(address), opIndex, value);
			cmd.applyTo(program);
			return cmd.getEquate();
		});
	}

	public void createComment(String address, String comment, int commentType) {
		tx(() -> {
			Listing listing = program.getListing();
			listing.setComment(addr(address), commentType, comment);
		});
	}

	public void createFunctionComment(String entryPointAddress, String comment) {
		tx(() -> {
			FunctionManager functionManager = program.getFunctionManager();
			Address addr = addr(entryPointAddress);
			Function function = functionManager.getFunctionAt(addr);
			function.setComment(comment);
		});
	}

	public void setFallthrough(String from, String to) {
		tx(() -> {
			Listing listing = program.getListing();
			Instruction inst = listing.getInstructionAt(addr(from));
			inst.setFallThrough(addr(to));
		});
	}

	public void createExternalLibraries(String... libraryNames) throws Exception {
		tx(() -> {
			SymbolTable symbolTable = program.getSymbolTable();
			for (String libraryName : libraryNames) {
				symbolTable.createExternalLibrary(libraryName, SourceType.IMPORTED);
			}
		});
	}

	public void bindExternalLibrary(String libraryName, String pathname) throws Exception {
		tx(() -> {
			program.getExternalManager().setExternalPath(libraryName, pathname, true);
		});
	}

	public void createExternalReference(String fromAddress, String libraryName,
			String externalLabel, int opIndex) throws Exception {
		createExternalReference(fromAddress, libraryName, externalLabel, null, opIndex,
			RefType.DATA, SourceType.IMPORTED);
	}

	public void createExternalReference(String fromAddress, String libraryName,
			String externalLabel, String extAddress, int opIndex) throws Exception {
		createExternalReference(fromAddress, libraryName, externalLabel, extAddress, opIndex,
			RefType.DATA, SourceType.IMPORTED);
	}

	public void createExternalReference(String fromAddress, String libraryName,
			String externalLabel, String extAddress, int opIndex, RefType refType,
			SourceType sourceType) throws Exception {
		tx(() -> {
			ReferenceManager refMgr = program.getReferenceManager();
			Address eAddress = extAddress == null ? null : addr(extAddress);

			SymbolTable symTable = program.getSymbolTable();
			ExternalManager extMgr = program.getExternalManager();
			Namespace namespace = extMgr.addExternalLibraryName(libraryName, sourceType);

			String myExternalLabel = externalLabel;
			if (myExternalLabel != null && myExternalLabel.indexOf(Namespace.DELIMITER) > 0) {
				// External manager API does not yet support creation of namespaces within
				// library so we handle that here
				SymbolPath symPath = new SymbolPath(myExternalLabel);
				myExternalLabel = symPath.getName();
				namespace = NamespaceUtils.createNamespaceHierarchy(symPath.getParentPath(),
					namespace, program, null, sourceType);
			}

			Reference ref = refMgr.addExternalReference(addr(fromAddress), libraryName,
				myExternalLabel, eAddress, sourceType, opIndex, refType);

			if (!(namespace instanceof Library)) {
				Symbol s = symTable.getSymbol(ref);
				s.setNamespace(namespace);
			}
		});
	}

	public ExternalLocation createExternalFunction(String extAddress, String libName,
			String functionName) throws Exception {
		return tx(() -> {
			ExternalManager em = program.getExternalManager();
			Address eAddress = extAddress == null ? null : addr(extAddress);
			return em.addExtFunction(libName, functionName, eAddress, SourceType.IMPORTED);
		});
	}

	public ExternalLocation createExternalFunction(String extAddress, String libName,
			String functionName, String originalName) throws Exception {
		return tx(() -> {
			ExternalManager em = program.getExternalManager();
			Address eAddress = extAddress == null ? null : addr(extAddress);
			ExternalLocation extLoc =
				em.addExtFunction(Library.UNKNOWN, originalName, eAddress, SourceType.IMPORTED);
			Library lib = em.addExternalLibraryName(libName, SourceType.IMPORTED);
			extLoc.setName(lib, functionName, SourceType.IMPORTED);
			return extLoc;
		});
	}

	public void createLocalVariable(Function function, String name, DataType dt, int stackOffset)
			throws Exception {
		tx(() -> {
			Variable variable = new LocalVariableImpl(name, dt, stackOffset, program);
			function.addLocalVariable(variable, SourceType.USER_DEFINED);
		});
	}

	public void setRegisterValue(String registerName, String startAddress, String endAddress,
			long value) throws Exception {
		tx(() -> {
			Register register = program.getRegister(registerName);
			ProgramContext programContext = program.getProgramContext();
			programContext.setValue(register, addr(startAddress), addr(endAddress),
				BigInteger.valueOf(value));
		});

	}

	public void setIntProperty(String address, String propertyName, int value) throws Exception {
		tx(() -> {
			PropertyMapManager pm = program.getUsrPropertyManager();
			IntPropertyMap propertyMap = pm.getIntPropertyMap(propertyName);
			if (propertyMap == null) {
				propertyMap = pm.createIntPropertyMap(propertyName);
			}
			propertyMap.add(addr(address), value);
		});
	}

	public void setStringProperty(String address, String propertyName, String value)
			throws Exception {
		tx(() -> {
			PropertyMapManager pm = program.getUsrPropertyManager();
			StringPropertyMap propertyMap = pm.getStringPropertyMap(propertyName);
			if (propertyMap == null) {
				propertyMap = pm.createStringPropertyMap(propertyName);
			}
			propertyMap.add(addr(address), value);
		});
	}

	public void setObjectProperty(String address, String propertyName, Saveable value)
			throws Exception {

		tx(() -> {
			PropertyMapManager pm = program.getUsrPropertyManager();
			ObjectPropertyMap propertyMap = pm.getObjectPropertyMap(propertyName);
			if (propertyMap == null) {
				propertyMap = pm.createObjectPropertyMap(propertyName, value.getClass());
			}
			propertyMap.add(addr(address), value);
		});
	}

	public void setChanged(boolean changed) {
		program.setChanged(changed);
	}

	private <E extends Exception> void tx(ExceptionalCallback<E> c) {
		startTransaction();
		boolean commit = true;
		try {
			c.call();
		}
		catch (Exception e) {
			commit = false;
			throw new AssertException(e);
		}
		finally {
			endTransaction(commit);
		}
	}

	private <R, E extends Exception> R tx(ExceptionalSupplier<R, E> s) {
		startTransaction();
		boolean commit = true;
		try {
			return s.get();
		}
		catch (Exception e) {
			commit = false;
			throw new AssertException(e);
		}
		finally {
			endTransaction(commit);
		}
	}

	private interface ExceptionalSupplier<R, E extends Exception> {
		public R get() throws E;
	}
}
