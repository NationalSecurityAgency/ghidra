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
package ghidra.app.util.pdb.pdbapplicator;

import java.io.IOException;
import java.math.BigInteger;
import java.util.*;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.StringUtils;

import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.label.SetLabelPrimaryCmd;
import ghidra.app.util.*;
import ghidra.app.util.bin.format.pdb.PdbParserConstants;
import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractMsType;
import ghidra.app.util.bin.format.pe.cli.tables.CliAbstractTableRow;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.pdb.PdbCategories;
import ghidra.framework.options.Options;
import ghidra.program.disassemble.DisassemblerContextImpl;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.CancelOnlyWrappingTaskMonitor;
import ghidra.util.task.TaskMonitor;

/**
 * The main engine for applying an AbstractPdb to Ghidra, whether a Program or DataTypeManager.
 * The class is to be constructed first.
 * <p>
 * The
 * {@link #applyTo(Program, DataTypeManager, Address, PdbApplicatorOptions, MessageLog)} method is
 * then called with the appropriate {@link PdbApplicatorOptions} along with
 * a {@link Program} and/or {@link DataTypeManager}.  Either, but not both can be null.
 * If the Program is not null but the DatatypeManager is null, then the DataTypeManager is gotten
 * from the Program.  If the Program is null, then data types can be applied to a DataTypeManager.
 * The validation logic for the parameters is found in
 * {@link #validateAndSetParameters(Program, DataTypeManager, Address, PdbApplicatorOptions,
 * MessageLog)}.
 * <p>
 * Once the parameters are validated, appropriate classes and storage containers are constructed.
 * Then processing commences, first with data types, followed by symbol-related processing.
 * <p>
 * {@link PdbApplicatorMetrics} are captured during the processing and status and logging is
 * reported to various mechanisms including {@link Msg}, {@link MessageLog}, and {@link PdbLog}.
 */
public class DefaultPdbApplicator implements PdbApplicator {

	private static final String THUNK_NAME_PREFIX = "[thunk]:";

	//==============================================================================================
	/**
	 * Returns integer value of BigInteger or Long.MAX_VALUE if does not fit
	 * @param big BigInteger value to convert
	 * @return the integer value
	 */
	long bigIntegerToLong(BigInteger big) {
		try {
			return big.longValueExact();
		}
		catch (ArithmeticException e) {
			String msg = "BigInteger value greater than max Long: " + big;
			PdbLog.message(msg);
			appendLogMsg(msg);
			return Long.MAX_VALUE;
		}
	}

	/**
	 * Returns integer value of BigInteger or Integer.MAX_VALUE if does not fit
	 * @param big BigInteger value to convert
	 * @return the integer value
	 */
	int bigIntegerToInt(BigInteger big) {
		try {
			return big.intValueExact();
		}
		catch (ArithmeticException e) {
			String msg = "BigInteger value greater than max Integer: " + big;
			PdbLog.message(msg);
			appendLogMsg(msg);
			return Integer.MAX_VALUE;
		}
	}

	//==============================================================================================
	private AbstractPdb pdb;

	private PdbApplicatorMetrics pdbApplicatorMetrics;

	//==============================================================================================
	private Program program;

	private PdbApplicatorOptions applicatorOptions;
	private MessageLog log;
	private CancelOnlyWrappingTaskMonitor cancelOnlyWrappingMonitor;

	//==============================================================================================
	private Address imageBase;
	private int linkerModuleNumber = -1;
	private DataTypeManager dataTypeManager;
	private PdbAddressManager pdbAddressManager;
	private List<SymbolGroup> symbolGroups;

	private PdbPeHeaderInfoManager pdbPeHeaderInfoManager;

	private List<PeCoffSectionMsSymbol> linkerPeCoffSectionSymbols = null;
	private AbstractMsSymbol compileSymbolForLinkerModule = null;
	private boolean processedLinkerModule = false;

	//==============================================================================================
	// If we have symbols and memory with VBTs in them, then a better VbtManager is created.
	VbtManager vbtManager;
	PdbRegisterNameToProgramRegisterMapper registerNameToRegisterMapper;

	//==============================================================================================
	private int resolveCount;
	private PdbCategories categoryUtils;
	private PdbPrimitiveTypeApplicator pdbPrimitiveTypeApplicator;
	private TypeApplierFactory typeApplierParser;
	private Map<Integer, Long> dataTypeIdByMsTypeNum;
	private Map<Integer, DataTypeImpl> dataTypeImplByMsTypeNum;
	private Map<Integer, CppCompositeType> classTypeByMsTypeNum;
	private ComplexTypeMapper complexTypeMapper;
	/**
	 * This namespace map documents as follows:
	 * <PRE>
	 *   false = simple namespace
	 *   true = class namespace
	 *  </PRE>
	 */
	private Map<SymbolPath, Boolean> isClassByNamespace;

	//==============================================================================================
	private SymbolApplierFactory symbolApplierParser;

	// Investigating... might change from String to AbstractSymbolApplier.
	private Map<Address, Set<String>> labelsByAddress;
	// Investigations into source/line info
	private Map<String, Set<RecordNumber>> recordNumbersByFileName;
	private Map<Integer, Set<RecordNumber>> recordNumbersByModuleNumber;

	//==============================================================================================
	// Addresses of locations of functions for disassembly/function-creation.
	AddressSet disassembleAddresses;
	List<DeferrableFunctionSymbolApplier> deferredFunctionWorkAppliers;

	//==============================================================================================
	private int currentModuleNumber = 0;

	//==============================================================================================
	public DefaultPdbApplicator(AbstractPdb pdb) {
		Objects.requireNonNull(pdb, "pdb cannot be null");
		this.pdb = pdb;
	}

	//==============================================================================================
	//==============================================================================================
	/**
	 * Applies the PDB to the {@link Program} or {@link DataTypeManager}. Either, but not both,
	 * can be null
	 * @param programParam the {@link Program} to which to apply the PDB. Can be null in certain
	 * circumstances
	 * @param dataTypeManagerParam the {@link DataTypeManager} to which to apply data types. Can be
	 * null in certain circumstances
	 * @param imageBaseParam address bases from which symbol addresses are based. If null, uses
	 * the image base of the program (both cannot be null)
	 * @param applicatorOptionsParam {@link PdbApplicatorOptions} used for applying the PDB
	 * @param logParam the MessageLog to which to output messages
	 * @throws PdbException if there was a problem processing the data
	 * @throws CancelledException upon user cancellation
	 * @throws IOException on file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes
	 */
	public void applyTo(Program programParam, DataTypeManager dataTypeManagerParam,
			Address imageBaseParam, PdbApplicatorOptions applicatorOptionsParam,
			MessageLog logParam) throws PdbException, CancelledException, IOException {

		// FIXME: should not support use of DataTypeManager-only since it will not have the correct
		// data organization if it corresponds to a data type archive.  Need to evaluate archive
		// use case and determine if a program must always be used.

		initializeApplyTo(programParam, dataTypeManagerParam, imageBaseParam,
			applicatorOptionsParam, logParam);

		switch (applicatorOptions.getProcessingControl()) {
			case DATA_TYPES_ONLY:
				processTypes();
				break;
			case PUBLIC_SYMBOLS_ONLY:
				processPublicSymbols();
				break;
			case ALL:
				processTypes();
				processSymbols();
				break;
			default:
				throw new PdbException("PDB: Invalid Application Control: " +
					applicatorOptions.getProcessingControl());
		}

		if (program != null) {
			doDeferredProgramProcessing();
			// Mark PDB analysis as complete.
			Options options = program.getOptions(Program.PROGRAM_INFO);
			options.setBoolean(PdbParserConstants.PDB_LOADED, true);
		}

		pdbAddressManager.logReport();

		pdbApplicatorMetrics.logReport();

		Msg.info(this, "PDB Terminated Normally");
	}

	//==============================================================================================
	private void doDeferredProgramProcessing() throws CancelledException {
		disassembleFunctions();
		doDeferredFunctionProcessing();
	}

	//==============================================================================================
	/**
	 * Set the context for each function, disassemble them, and then do fix-ups
	 */
	private void disassembleFunctions() throws CancelledException {

		TaskMonitor monitor = getMonitor();
		Listing listing = program.getListing();
		DisassemblerContextImpl seedContext =
			new DisassemblerContextImpl(program.getProgramContext());
		AddressSet revisedSet = new AddressSet();
		long num = disassembleAddresses.getNumAddresses();
		monitor.initialize(num);
		monitor.setMessage("PDB: Determining disassembly context for " + num + " addresses...");
		for (Address address : disassembleAddresses.getAddresses(true)) {
			monitor.checkCancelled();
			address = PseudoDisassembler.setTargetContextForDisassembly(seedContext, address);
			Function myFunction = listing.getFunctionAt(address);
			// If no function or not a full function, add it to set for disassembly.
			if (myFunction == null || myFunction.getBody().getNumAddresses() <= 1) {
				revisedSet.add(address);
			}
			monitor.incrementProgress(1);
		}
		// Do disassembly and ensure functions are created appropriately.
		num = revisedSet.getNumAddresses();
		monitor.setMessage("PDB: Bulk disassembly at " + num + " addresses...");
		DisassembleCommand cmd = new DisassembleCommand(revisedSet, null, true);
		cmd.setSeedContext(seedContext);
		cmd.applyTo(program, monitor);
		monitor.initialize(num);
		monitor.setMessage("PDB: Disassembly fix-up for " + num + " addresses...");
		for (Address address : revisedSet.getAddresses(true)) {
			monitor.checkCancelled();
			Function function = listing.getFunctionAt(address);
			if (function != null) {
				CreateFunctionCmd.fixupFunctionBody(program, function, cancelOnlyWrappingMonitor);
			}
			monitor.incrementProgress(1);
		}
	}

	//==============================================================================================
	/**
	 * Do work, such as create parameters or local variables and scopes
	 * @throws CancelledException upon user cancellation
	 */
	private void doDeferredFunctionProcessing() throws CancelledException {
		for (DeferrableFunctionSymbolApplier applier : deferredFunctionWorkAppliers) {
			cancelOnlyWrappingMonitor.checkCancelled();
			applier.doDeferredProcessing();
		}
	}

	//==============================================================================================
	private void processTypes() throws CancelledException, PdbException {
		TaskMonitor monitor = getMonitor();
		monitor.setMessage("PDB: Applying to DTM " + dataTypeManager.getName() + "...");

		PdbResearch.initBreakPointRecordNumbers(); // for developmental debug

		resolveCount = 0;

//		PdbResearch.childWalk(this, monitor);

//		PdbResearch.studyDataTypeConflicts(this, monitor);
//		PdbResearch.studyCompositeFwdRefDef(pdb, monitor);
//		PdbResearch.study1(pdb, monitor);

		complexTypeMapper.mapTypes(this);

		processSequentially();

//		dumpSourceFileRecordNumbers();

//		PdbResearch.developerDebugOrder(this, monitor);

		Msg.info(this, "resolveCount: " + resolveCount);

		// Currently, defining classes needs to have a program.  When this is no longer true,
		//  then this call can be performed with the data types only work.
		if (program != null) {
			defineClasses();
		}

		// Process typedefs, which are in the symbols.
		processGlobalTypdefSymbols();
	}

	//==============================================================================================
	private void processSymbols() throws CancelledException, PdbException {
//		PdbResearch.studyAggregateSymbols(this, monitor);

		// TODO: not sure if the following will be relevant here, elsewhere, or nowhere.
//		if (!pdbAddressManager.garnerSectionSegmentInformation()) {
//		return;
//	}

		// WANTED TO put the following block in place of the one beneath it, but it would require
		// that we visit all appliers to make sure they have the requisite logic to override
		// primary mangled symbols with the appropriate global symbols that have the data types.
		// See FunctionSymbolApplier for logic used in the "if" case below.

//		// Processing public (mangled) symbols first, but global symbol processing can change
//		// which symbol is marked primary to the global one if that global symbol provided a rich
//		// function definition data type.  Doing this will prevent the mangled symbol from applying
//		// the function signature (unless there is an option set to force the mangled symbol to be
//		// the primary symbol).
//		processPublicSymbols();
//		processGlobalSymbolsNoTypedefs();

		// WANTED TO replace the following block with the one above.  See comment above.

		// Doing globals before publics, as publics are those that can have mangled names.  By
		// applying the non-mangled symbols first, we can get full type information from the
		// underlying type.  Then we can apply the mangled symbols and demangle them without
		// affecting our ability to lay down PDB type information--any type information from
		// the mangled symbols can happen afterward.
		// 20220801: Used to be global followed by public symbols, but adding temporary if/else,
		// switching the order when there are no data types in the PDB so that mangled symbols will
		// become primary, allowing their limited type information to be gleaned.  Future plans are
		// to have more sophisticated processing, per address.
		if (pdb.getTypeProgramInterface()
				.getTypeIndexMaxExclusive() == pdb.getTypeProgramInterface().getTypeIndexMin()) {
			processPublicSymbols();
			processGlobalSymbolsNoTypedefs();
		}
		else {
			processGlobalSymbolsNoTypedefs();
			processPublicSymbols();
		}

		// Seems that we shouldn't do the following, as it could be a buffer of invalid symbols
		//  that hadn't been gone through for garbage collection of sorts.
		//processNonPublicOrGlobalSymbols();

		// Seems that we shouldn't do the following, as the ones that are needed seem to be
		//  referenced from a global symbol using a ReferencedSymbol.  If we process the module
		//  symbols, as below, then collisions can start to appear at addresses.  This has
		//  happened to me when I forgot to clear the results from a previous build, in which
		//  case I could find symbols referring to a location within the old build and within
		//  the latest build at the particular address corresponding to its location within that
		//  build. So a module might have symbols that had not been garbage-collected.
		processModuleSymbols();

		// These are good to process (one particular module for the linker).
//		processLinkerSymbols();

		// Get additional thunks (that old pdb analyzer got).
		processThunkSymbolsFromNonLinkerModules();

		//processAllSymbols();

//		dumpLabels();
	}

	//==============================================================================================
	//==============================================================================================
	/**
	 * Initializes helper classes and data items used for applying the PDB
	 * @throws CancelledException upon user cancellation
	 * @throws PdbException upon error in processing components
	 * @throws IOException on file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes
	 */
	private void initializeApplyTo(Program programParam, DataTypeManager dataTypeManagerParam,
			Address imageBaseParam, PdbApplicatorOptions applicatorOptionsParam,
			MessageLog logParam) throws PdbException, CancelledException, IOException {

		validateAndSetParameters(programParam, dataTypeManagerParam, imageBaseParam,
			applicatorOptionsParam, logParam);

		cancelOnlyWrappingMonitor = new CancelOnlyWrappingTaskMonitor(getMonitor());
		pdbApplicatorMetrics = new PdbApplicatorMetrics();

		pdbPeHeaderInfoManager = new PdbPeHeaderInfoManager(this);

		symbolGroups = createSymbolGroups();
		linkerModuleNumber = findLinkerModuleNumber();

		pdbAddressManager = new PdbAddressManager(this, imageBase);

		categoryUtils = setPdbCatogoryUtils(pdb.getFilename());
		initializePlaceholders();
		pdbPrimitiveTypeApplicator = new PdbPrimitiveTypeApplicator(dataTypeManager);
		dataTypeIdByMsTypeNum = new HashMap<>();
		dataTypeImplByMsTypeNum = new HashMap<>();
		classTypeByMsTypeNum = new HashMap<>();
		complexTypeMapper = new ComplexTypeMapper();
		typeApplierParser = new TypeApplierFactory(this);
		isClassByNamespace = new TreeMap<>();

		symbolApplierParser = new SymbolApplierFactory(this);

		if (program != null) {
			disassembleAddresses = new AddressSet();
			deferredFunctionWorkAppliers = new ArrayList<>();
			// Currently, this must happen after symbolGroups are created.
			PdbVbtManager pdbVbtManager = new PdbVbtManager(this);
			//pdbVbtManager.CreateVirtualBaseTables(); // Depends on symbolGroups
			vbtManager = pdbVbtManager;
			registerNameToRegisterMapper = new PdbRegisterNameToProgramRegisterMapper(program);
		}
		else {
			vbtManager = new VbtManager(getDataTypeManager());
		}

		// Investigations
		labelsByAddress = new HashMap<>();
		// Investigations into source/line info
		recordNumbersByFileName = new HashMap<>();
		recordNumbersByModuleNumber = new HashMap<>();
	}

	private void validateAndSetParameters(Program programParam,
			DataTypeManager dataTypeManagerParam, Address imageBaseParam,
			PdbApplicatorOptions applicatorOptionsParam, MessageLog logParam) throws PdbException {
		applicatorOptions =
			(applicatorOptionsParam != null) ? applicatorOptionsParam : new PdbApplicatorOptions();
		if (programParam == null) {
			if (dataTypeManagerParam == null) {
				throw new PdbException(
					"PDB: programParam and dataTypeManagerParam may not both be null.");
			}
			if (imageBaseParam == null) {
				throw new PdbException(
					"PDB: programParam and imageBaseParam may not both be null.");
			}
			if (applicatorOptions.getProcessingControl() != PdbApplicatorControl.DATA_TYPES_ONLY) {
				throw new PdbException(
					"PDB: programParam may not be null for the chosen Applicator Control: " +
						applicatorOptions.getProcessingControl());
			}
		}
		log = (logParam != null) ? logParam : new MessageLog();
		program = programParam;
		dataTypeManager =
			(dataTypeManagerParam != null) ? dataTypeManagerParam : program.getDataTypeManager();
		imageBase = (imageBaseParam != null) ? imageBaseParam : program.getImageBase();
	}

	private List<SymbolGroup> createSymbolGroups() throws CancelledException, PdbException {
		List<SymbolGroup> mySymbolGroups = new ArrayList<>();
		PdbDebugInfo debugInfo = pdb.getDebugInfo();
		if (debugInfo == null) {
			return mySymbolGroups;
		}

		int num = debugInfo.getNumModules();
		// moduleNumber zero (SymbolGroup.PUBLIC_GLOBAL_MODULE_NUMBER) is our global/public group.
		for (int moduleNumber = 0; moduleNumber <= num; moduleNumber++) {
			checkCancelled();
			// Keeping next two lines until all other calls to them are removed
//			Map<Long, AbstractMsSymbol> symbols = debugInfo.getModuleSymbolsByOffset(moduleNumber);
//			SymbolGroup symbolGroup = new SymbolGroup(symbols, moduleNumber);
			SymbolGroup symbolGroup = new SymbolGroup(pdb, moduleNumber);
			mySymbolGroups.add(symbolGroup);
		}
		return mySymbolGroups;
	}

	//==============================================================================================
	// Basic utility methods.
	//==============================================================================================
	/**
	 * Returns the {@link PdbApplicatorOptions} for this PdbApplicator
	 * @return the {@link PdbApplicatorOptions} for this PdbApplicator
	 */
	PdbApplicatorOptions getPdbApplicatorOptions() {
		return applicatorOptions;
	}

	/**
	 * Check to see if this monitor has been canceled
	 * @throws CancelledException if monitor has been cancelled
	 */
	void checkCancelled() throws CancelledException {
		getMonitor().checkCancelled();
	}

	/**
	 * Sets the message displayed on the task monitor
	 * @param message the message to display
	 */
	void appendLogMsg(String message) {
		log.appendMsg(message);
	}

	/**
	 * Returns the MessageLog
	 * @return the MessageLog
	 */
	MessageLog getMessageLog() {
		return log;
	}

	/**
	 * Puts message to {@link PdbLog} and to Msg.info()
	 * @param originator a Logger instance, "this", or YourClass.class
	 * @param message the message to display
	 */
	void pdbLogAndInfoMessage(Object originator, String message) {
		PdbLog.message(message);
		Msg.info(originator, message);
	}

	/**
	 * Puts error message to {@link PdbLog} and to Msg.error() which will
	 * also log a stack trace if exception is specified.
	 * @param originator a Logger instance, "this", or YourClass.class
	 * @param message the error message to display/log
	 * @param exc exception whose stack trace should be reported or null
	 */
	void pdbLogAndErrorMessage(Object originator, String message, Exception exc) {
		PdbLog.message(message);
		if (exc != null) {
			Msg.error(originator, message);
		}
		else {
			Msg.error(originator, message, exc);
		}
	}

	/**
	 * Returns the TaskMonitor
	 * @return the monitor
	 */
	@Override
	public TaskMonitor getMonitor() {
		return pdb.getMonitor();
	}

	/**
	 * Returns the {@link CancelOnlyWrappingTaskMonitor} to available for this analyzer.  This is
	 * useful for the user to be able to control the monitor progress bar without called commands
	 * changing its progress on smaller tasks
	 * @return the monitor
	 */
	TaskMonitor getCancelOnlyWrappingMonitor() {
		return cancelOnlyWrappingMonitor;
	}

	/**
	 * Returns the {@link PdbApplicatorMetrics} being used for this applicator
	 * @return the {@link PdbApplicatorMetrics}
	 */
	PdbApplicatorMetrics getPdbApplicatorMetrics() {
		return pdbApplicatorMetrics;
	}

	/**
	 * Returns the {@link AbstractPdb} being analyzed
	 * @return {@link AbstractPdb} being analyzed
	 */
	@Override
	public AbstractPdb getPdb() {
		return pdb;
	}

	/**
	 * Returns the {@link Program} for which this analyzer is working
	 * @return {@link Program} for which this analyzer is working
	 */
	@Override
	public Program getProgram() {
		return program;
	}

	//==============================================================================================
	// Information for a putative PdbTypeApplicator:

	/**
	 * Returns the {@link DataTypeManager} associated with this analyzer
	 * @return DataTypeManager which this analyzer is using
	 */
	DataTypeManager getDataTypeManager() {
		return dataTypeManager;
	}

	// for PdbTypeApplicator (new)
	DataOrganization getDataOrganization() {
		return dataTypeManager.getDataOrganization();
	}

	PdbPrimitiveTypeApplicator getPdbPrimitiveTypeApplicator() {
		return pdbPrimitiveTypeApplicator;
	}

	//==============================================================================================
	// CategoryPath-related methods.
	//==============================================================================================
	/**
	 * Get the {@link CategoryPath} associated with the {@link SymbolPath} specified, rooting
	 * it either at the PDB Category
	 * @param symbolPath symbol path to be used to create the CategoryPath. Null represents global
	 * namespace
	 * @return {@link CategoryPath} created for the input
	 */
	CategoryPath getCategory(SymbolPath symbolPath) {
		return categoryUtils.getCategory(symbolPath);
	}

	/**
	 * Returns the {@link CategoryPath} for a typedef with with the give {@link SymbolPath} and
	 * module number; 1 <= moduleNumber <= {@link PdbDebugInfo#getNumModules()}
	 * except that modeleNumber of 0 represents publics/globals
	 * @param moduleNumber module number
	 * @param symbolPath SymbolPath of the symbol
	 * @return the CategoryPath
	 */
	CategoryPath getTypedefsCategory(int moduleNumber, SymbolPath symbolPath) {
		return categoryUtils.getTypedefsCategory(moduleNumber, symbolPath);
	}

	/**
	 * Returns the {@link CategoryPath} for Anonymous Functions Category for the PDB
	 * @return the {@link CategoryPath}
	 */
	CategoryPath getAnonymousFunctionsCategory() {
		return categoryUtils.getAnonymousFunctionsCategory();
	}

	/**
	 * Returns the {@link CategoryPath} for Anonymous Types Category for the PDB
	 * @return the {@link CategoryPath}
	 */
	CategoryPath getAnonymousTypesCategory() {
		return categoryUtils.getAnonymousTypesCategory();
	}

	/**
	 * Returns the {@link CategoryPath} for Placeholder Types Category for the PDB
	 * @return the {@link CategoryPath}
	 */
	CategoryPath getPlaceholderTypesCategory() {
		return categoryUtils.getPlaceholderTypesCategory();
	}

//	/**
//	 * Returns the name of what should be the next Anonymous Function (based on the count of
//	 * the number of anonymous functions) so that there is a unique name for the function.
//	 * @return the name for the next anonymous function.
//	 */
//	String getNextAnonymousFunctionName() {
//		return categoryUtils.getNextAnonymousFunctionName();
//	}

//	/**
//	 * Updates the count of the anonymous functions.  This is a separate call from
//	 * {@link #getNextAnonymousFunctionName()} because the count should only be updated after
//	 * the previous anonymous function has been successfully created/stored.
//	 */
//	void incrementNextAnonymousFunctionName() {
//		categoryUtils.incrementNextAnonymousFunctionName();
//	}

	private PdbCategories setPdbCatogoryUtils(String pdbFilename)
			throws CancelledException, PdbException {

		List<String> categoryNames = new ArrayList<>();

		PdbDebugInfo debugInfo = pdb.getDebugInfo();
		if (debugInfo != null) {

			int num = debugInfo.getNumModules();
			for (int index = 1; index <= num; index++) {
				checkCancelled();
				String moduleName = debugInfo.getModuleInformation(index).getModuleName();
				categoryNames.add(moduleName);
			}
		}

		return new PdbCategories(FilenameUtils.getName(pdbFilename), categoryNames);
	}

	//==============================================================================================
	//==============================================================================================
	//==============================================================================================
	MsTypeApplier getApplierOrNoTypeSpec(RecordNumber recordNumber,
			Class<? extends MsTypeApplier> expected) throws PdbException {
		return typeApplierParser.getApplierOrNoTypeSpec(recordNumber, expected);
	}

	MsTypeApplier getTypeApplier(RecordNumber recordNumber) {
		//PdbResearch.checkBreak(recordNumber.getNumber());
		return typeApplierParser.getTypeApplier(recordNumber);
	}

	MsTypeApplier getTypeApplier(AbstractMsType type) {
		return typeApplierParser.getTypeApplier(type);
	}

	MsTypeApplier getTypeApplier(int pdbId) {
		return typeApplierParser.getTypeApplier(pdbId);
	}

	//==============================================================================================
	//==============================================================================================
	//==============================================================================================

	private Map<Integer, Pointer> placeholderPointers;
	private Set<Long> pointerIDs;
	// Structure used to mock placeholder array.
	private Map<PlaceholderArrayKey, Structure> placeholderArrays;
	private Set<Long> arrayIDs;

	private void initializePlaceholders() {
		placeholderPointers = new HashMap<>();
		pointerIDs = new HashSet<>();
		placeholderArrays = new HashMap<>();
		arrayIDs = new HashSet<>();
	}

	private void cleanUpPlaceholders() throws CancelledException {

		TaskMonitor monitor = getMonitor();
		DataTypeManager dtm = getDataTypeManager();

		// Remove placeholder arrays from DTM and from the Set
		for (long id : arrayIDs) {
			checkCancelled();
			DataType dt = dtm.getDataType(id);
			Collection<DataType> parents = dt.getParents();
			if (parents.size() == 0) {
				dtm.remove(dt, monitor);
			}
			else {
				Msg.warn(this,
					"PDB: Could not eliminate parented placeholder array: " + dt.getName());
			}
		}
		arrayIDs.clear();
		arrayIDs = null;

		// Eliminate array placeholder map
		placeholderArrays.clear();
		placeholderArrays = null;

		// Not removing placeholder pointers from DTM, but we are eliminating them from the Set
		pointerIDs.clear();
		pointerIDs = null;

		// Eliminate pointer placeholder map
		placeholderPointers.clear();
		placeholderPointers = null;
	}

	Pointer getPlaceholderPointer(int size) throws PdbException {
		Pointer pointer = placeholderPointers.get(size);
		if (pointer != null) {
			return pointer;
		}
		DataTypeManager dtm = getDataTypeManager();
		pointer = new PointerDataType(null, size, dtm);
		pointer = (Pointer) resolve(pointer);
		long id = dtm.getID(pointer);
		if (id == -1) {
			throw new PdbException("Could not create placeholder pointer.");
		}
		placeholderPointers.put(size, pointer);
		pointerIDs.add(id);
		return pointer;
	}

	boolean isPlaceholderPointer(DataType pointer) {
		// need this check for unresolved member types (such as primitives or bit-fields)
		if (pointer instanceof DataTypeImpl || pointer instanceof BitFieldDataType) {
			return false;
		}
		long id = getDataTypeManager().getID(pointer);
		return pointerIDs.contains(id);
	}

	private record PlaceholderArrayKey(int arraySize, int alignment) {}

	// Using a structure as a mock array because we can set both size and alignment, which
	//  is what needs to be consistent with the final real array when used in a containing
	//  composite.
	DataType getPlaceholderArray(int arraySize, int alignment) throws PdbException {
		PlaceholderArrayKey key = new PlaceholderArrayKey(arraySize, alignment);
		Structure placeholderArray = placeholderArrays.get(key);
		if (placeholderArray != null) {
			return placeholderArray;
		}

		DataTypeManager dtm = getDataTypeManager();
		String name = String.format("placeholder_array_%08x_%02x", arraySize, alignment);
		placeholderArray =
			new StructureDataType(getPlaceholderTypesCategory(), name, arraySize, dtm);
		placeholderArray.align(alignment);
		if (arraySize == 0) {
			// For the zero-length, we need to enable packing to prevent the placeholder array
			//  (actual structure) from reporting itself as "not yet defined."
			placeholderArray.setPackingEnabled(true);
		}
		placeholderArray = (Structure) resolve(placeholderArray);

		long id = dtm.getID(placeholderArray);
		if (id == -1) {
			throw new PdbException("Could not create array placeholder.");
		}
		placeholderArrays.put(key, placeholderArray);
		arrayIDs.add(id);
		return placeholderArray;
	}

	boolean isPlaceholderArray(DataType array) {
		return array.getCategoryPath().equals(getPlaceholderTypesCategory());
	}

	boolean isPlaceholderType(DataType type) {
		return isPlaceholderPointer(type) || isPlaceholderArray(type);
	}

	//==============================================================================================
	//==============================================================================================
	//==============================================================================================

	/**
	 * Returns the processed Ghidra class type associated with the PDB type record number.  Causes
	 *  the type to be processed if it already has not been.
	 * <p>
	 * This method is intended to be used by "Consumers" that need the type after all type
	 *  creation is complete.
	 * @param recordNumber the record number of the type needed
	 * @return the Ghidra data type
	 * @throws CancelledException upon user cancellation
	 * @throws PdbException upon processing error
	 * @see #getDataType(AbstractMsType)
	 * @see #getDataType(RecordNumber)
	 */
	DataType getCompletedDataType(RecordNumber recordNumber) //************************************************ 5 REFS
			throws CancelledException, PdbException {
		DataType dataType = getDataType(recordNumber);
		if (dataType instanceof DataTypeImpl) {
			if (!(dataType instanceof BuiltInDataType)) {
				AbstractMsType type = getPdb().getTypeRecord(recordNumber);
				Msg.info(this, "Type not resolved for record: " + recordNumber + "; " +
					type.getClass().getSimpleName());
			}
		}
		else if (dataType == null) {
			AbstractMsType type = getPdb().getTypeRecord(recordNumber);
			Msg.info(this, "Type not completed for record: " + recordNumber + "; " +
				type.getClass().getSimpleName());
			FixupContext fixupContext = new FixupContext();
			fixupContext.addStagedRecord(recordNumber.getNumber());
			dataType = getProcessedDataType(recordNumber, fixupContext, false);
		}
		return dataType;
	}

	/**
	 * Stores the Ghidra data type associated with the PDB data type.
	 * This method is intended to be used by appliers that work on this specific type, not by
	 *  appliers that need the data type
	 * @param msType the PdbReader type pertaining to the type
	 * @param dataType the data type to store
	 */
	void putDataType(AbstractMsType msType, DataType dataType) {
		Integer number = getNumber(msType);
		putDataType(number, dataType);
	}

	/**
	 * Stores the Ghidra data type associated with the PDB data type.
	 * This method is intended to be used by appliers that work on this specific type, not by
	 *  appliers that need the data type
	 * @param number number of type record
	 * @param dataType the data type to store
	 */
	void putDataType(Integer number, DataType dataType) {
		DataType existing = getDataType(number); // could be null
		if (existing == dataType) {
			return;
		}
		if (existing != null) {
			if (dataType.isEquivalent(existing)) {
				if (!(existing instanceof DataTypeImpl) || dataType instanceof DataTypeImpl) {
					return;
				}
			}
			else if (isDefinedComposite(existing)) {
				//TODO: Need to investigate how to deal with this.... we are only storing one, so
				// how do we know we have the correct one... we should know by what the fwdref was...
				// record-number-wise.
				if (isDefinedComposite(dataType)) {
					appendLogMsg("Existing and Replacement datatypes are both keepers:\n" +
						existing + "\n" + dataType + "\n");
				}
				return;
			}
		}
		putDataTypeInternal(number, dataType);
	}

	/**
	 * Returns the Ghidra data type associated with the PDB data type.
	 * This method is intended to be used by appliers that work on this specific type, not by
	 *  appliers that need the data type
	 * @param msType the PdbReader type pertaining to the type
	 * @return the Ghidra data type
	 */
	DataType getDataType(AbstractMsType msType) {
		Integer number = getNumber(msType);
		if (number == null) {
			return null;
		}
		return getDataType(number);
	}

	/**
	 * Returns the Ghidra data type associated with the PDB type record number.
	 * <p>
	 * This method is intended to be used by appliers that work on this specific type, not by
	 *  appliers that need the data type
	 * @param recordNumber the record number of the type needed
	 * @return the Ghidra data type
	 * @see #getDataType(AbstractMsType)
	 */
	DataType getDataType(RecordNumber recordNumber) {
		if (recordNumber.getCategory() != RecordCategory.TYPE) {
			return null;
		}
		return getDataType(recordNumber.getNumber());
	}

	/**
	 * Returns the Ghidra data type associated with the PDB data type number.
	 * This method is intended to be used by appliers that work on this specific type, not by
	 *  appliers that need the data type
	 * @param number the PDB type record number
	 * @return the Ghidra data type
	 */
	DataType getDataType(Integer number) {
		Integer mappedNumber = getMappedComplexType(number);
		Long ID = dataTypeIdByMsTypeNum.get(mappedNumber);
		if (ID == null) {
			return dataTypeImplByMsTypeNum.get(mappedNumber);
		}
		return dataTypeManager.getDataType(ID);
	}

	private boolean isDefinedComposite(DataType dt) {
		return (dt instanceof Composite comp && comp.getNumDefinedComponents() > 0);
	}

	private void putDataTypeInternal(Integer number, DataType dataType) {
		Integer mappedNumber = getMappedComplexType(number);
		if (dataType instanceof DataTypeImpl impl) {
			if (!(dataType instanceof BuiltInDataType)) {
				Msg.warn(this, "PDB: Unexpected Impl storage: " + impl.getClass().getSimpleName());
			}
			dataTypeImplByMsTypeNum.put(mappedNumber, impl);
		}
		else {
			long dataTypeID = dataTypeManager.getID(dataType);
			if (dataTypeID == -1) {
				// Error, such as DataType is not DB version
				return;
			}
			dataTypeIdByMsTypeNum.put(mappedNumber, dataTypeID);
		}
	}

	//==============================================================================================
	/**
	 * Stores the Ghidra class type associated with the PDB data type.
	 * This method is intended to be used by appliers that work on this specific type, not by
	 *  appliers that need the data type
	 * @param msType the PdbReader type pertaining to the type
	 * @param classType the class to store
	 */
	void putClassType(AbstractMsType msType, CppCompositeType classType) {
		Integer number = getNumber(msType);
		CppCompositeType existing = getClassType(number);
		if (existing == classType) {
			return;
		}
		if (existing != null) {
			appendLogMsg(
				"Existing class type; not replacing:\n" + existing + "\n" + classType + "\n");
			return;
		}
		putClassType(number, classType);
	}

	/**
	 * Returns the Ghidra class type associated with the PDB class type.
	 * <p>
	 * This method is intended to be used by appliers that work on this specific type, not by
	 *  appliers that need the data type
	 * @param msType the PdbReader type pertaining to the type
	 * @return the Ghidra class type
	 * @see #getDataType(RecordNumber)
	 */
	CppCompositeType getClassType(AbstractMsType msType) {
		Integer number = getNumber(msType);
		return getClassType(number);
	}

	private CppCompositeType getClassType(Integer number) {
		return classTypeByMsTypeNum.get(getMappedComplexType(number));
	}

	private void putClassType(Integer number, CppCompositeType classType) {
		Integer mappedNumber = getMappedComplexType(number);
		classTypeByMsTypeNum.put(mappedNumber, classType);
	}

	//==============================================================================================
	// Might change this to private if removed use from CompositeTypeApplier
	Integer getNumber(AbstractMsType msType) {
		if (msType == null) {
			return null;
		}
		RecordNumber recordNumber = msType.getRecordNumber();
		if (recordNumber == null || recordNumber.getCategory() != RecordCategory.TYPE) {
			return null;
		}
		return recordNumber.getNumber();
	}

	// Might change this to private if removed use from CompositeTypeApplier
	Integer getMappedComplexType(Integer input) {
		return complexTypeMapper.getMapped(input);
	}

	//==============================================================================================
	//==============================================================================================
	//==============================================================================================
	int findModuleNumberBySectionOffsetContribution(int section, long offset) throws PdbException {
		PdbDebugInfo debugInfo = pdb.getDebugInfo();
		if (debugInfo == null) {
			throw new PdbException("PDB: DebugInfo is null");
		}

		for (SectionContribution sectionContribution : debugInfo.getSectionContributionList()) {
			int sectionContributionOffset = sectionContribution.getOffset();
			int maxSectionContributionOffset =
				sectionContributionOffset + sectionContribution.getLength();
			if (offset >= sectionContributionOffset && offset < maxSectionContributionOffset) {
				return sectionContribution.getModule();
			}
		}
		throw new PdbException("PDB: Module not found for section/offset");
	}

	//==============================================================================================
	private void processAndResolveDataTypesSequentially() throws CancelledException, PdbException {
		TypeProgramInterface tpi = pdb.getTypeProgramInterface();
		if (tpi == null) {
			return;
		}
		int num = tpi.getTypeIndexMaxExclusive() - tpi.getTypeIndexMin();
		TaskMonitor monitor = getMonitor();
		monitor.initialize(num);
		monitor.setMessage("PDB: Processing " + num + " data type components...");
		for (int indexNumber = tpi.getTypeIndexMin(); indexNumber < tpi
				.getTypeIndexMaxExclusive(); indexNumber++) {
			monitor.checkCancelled();
			processAndResolve(indexNumber);
			monitor.incrementProgress(1);
		}

		// Might need to do this later (after typedefs and symbols)... TODO: figure this out
		cleanUpPlaceholders();
	}

	private void processAndResolve(int indexNumber) throws CancelledException, PdbException {
		DataType dt = getDataType(indexNumber);
		if (dt != null && !(dt instanceof DataTypeImpl)) {
			return;
		}
		RecordNumber recordNumber = RecordNumber.typeRecordNumber(indexNumber);
		AbstractMsType msType = pdb.getTypeRecord(recordNumber);
		MsTypeApplier applier = getTypeApplier(recordNumber);
		if (applier instanceof CompositeTypeApplier) {
			FixupContext fixupContext = new FixupContext();
			int mappedNumber = getMappedComplexType(indexNumber);
			fixupContext.moveToHeadProcessRecord(mappedNumber);
			DataType dataType = applier.apply(msType, fixupContext, false);
			fixupContext.moveProcessToFixupsRecord(mappedNumber, dataType);
			fixUpTypes(fixupContext);
		}
		else {
			DataType dataType = applier.apply(msType, null, true);
		}
	}

	DataType getProcessedDataType(RecordNumber recordNumber, FixupContext fixupContext,
			boolean breakCycle) throws CancelledException, PdbException {
		int mappedNumber = getMappedComplexType(recordNumber.getNumber());
		AbstractMsType type = pdb.getTypeRecord(RecordNumber.typeRecordNumber(mappedNumber));
		MsTypeApplier applier = getTypeApplier(recordNumber);

		if (fixupContext == null) {
			return applier.apply(type, fixupContext, breakCycle);
		}

		if (!(applier instanceof CompositeTypeApplier) &&
			!(applier instanceof ModifierTypeApplier)) {
			return applier.apply(type, fixupContext, breakCycle);
		}

		DataType dataType = getDataType(mappedNumber);
		if (dataType != null) {
			return dataType;
		}
		dataType = fixupContext.getFixupDataType(mappedNumber);
		if (dataType != null) {
			return dataType;
		}

		fixupContext.ensureInContext(mappedNumber);
		if (breakCycle) {
			return null;
		}

		fixupContext.moveToHeadProcessRecord(mappedNumber);
		dataType = applier.apply(type, fixupContext, breakCycle);
		fixupContext.moveProcessToFixupsRecord(mappedNumber, dataType);

		return dataType;
	}

	private void fixUpTypes(FixupContext fixupContext) throws PdbException, CancelledException {

		Integer recordToProcess;
		while ((recordToProcess = fixupContext.peekStagedRecord()) != null) {
			checkCancelled();
			RecordNumber recordNumber = RecordNumber.typeRecordNumber(recordToProcess);
			AbstractMsType msType = pdb.getTypeRecord(recordNumber);
			MsTypeApplier applier = getTypeApplier(recordNumber);
			fixupContext.moveFromStagedToProcessRecord();
			DataType dataType = applier.apply(msType, fixupContext, false);
			fixupContext.moveProcessToFixupsRecord(recordToProcess, dataType);
		}

		while ((recordToProcess = fixupContext.peekFixupsRecord()) != null) {
			checkCancelled();
			RecordNumber recordNumber = RecordNumber.typeRecordNumber(recordToProcess);
			AbstractMsType msType = pdb.getTypeRecord(recordNumber);
			MsTypeApplier applier = getTypeApplier(recordNumber);
			if (applier instanceof CompositeTypeApplier fixupApplier) {
				DataType dataType = applier.apply(msType, fixupContext, false);
				if (dataType instanceof DataTypeImpl) {
					appendLogMsg("Unexpected resolve for: " + dataType.getClass().getSimpleName());
					dataType = resolve(dataType);
				}
				fixupApplier.fixUp(fixupContext);
			}
			fixupContext.popFixupsRecord();
		}
	}

	//==============================================================================================
	//==============================================================================================
	//==============================================================================================
	// Investigations into source/line info
	void putRecordNumberByFileName(RecordNumber recordNumber, String filename) {
		Set<RecordNumber> recordNumbers = recordNumbersByFileName.get(filename);
		if (recordNumbers == null) {
			recordNumbers = new HashSet<>();
			recordNumbersByFileName.put(filename, recordNumbers);
		}
		recordNumbers.add(recordNumber);
	}

	//==============================================================================================
	void putRecordNumberByModuleNumber(RecordNumber recordNumber, int moduleNumber) {
		Set<RecordNumber> recordNumbers = recordNumbersByModuleNumber.get(moduleNumber);
		if (recordNumbers == null) {
			recordNumbers = new HashSet<>();
			recordNumbersByModuleNumber.put(moduleNumber, recordNumbers);
		}
		recordNumbers.add(recordNumber);
	}

	//==============================================================================================
	void dumpSourceFileRecordNumbers() {
		PdbLog.message("RecordNumbersByFileName");
		for (Map.Entry<String, Set<RecordNumber>> entry : recordNumbersByFileName.entrySet()) {
			String filename = entry.getKey();
			PdbLog.message("FileName: " + filename);
			for (RecordNumber recordNumber : entry.getValue()) {
				AbstractMsType msType = pdb.getTypeRecord(recordNumber);
				PdbLog.message(recordNumber.toString() + "\n" + msType);
			}
		}
		PdbLog.message("RecordNumbersByModuleNumber");
		for (Map.Entry<Integer, Set<RecordNumber>> entry : recordNumbersByModuleNumber.entrySet()) {
			int moduleNumber = entry.getKey();
			PdbLog.message("ModuleNumber: " + moduleNumber);
			for (RecordNumber recordNumber : entry.getValue()) {
				AbstractMsType msType = pdb.getTypeRecord(recordNumber);
				PdbLog.message(recordNumber.toString() + "\n" + msType);
			}
		}
	}

	//==============================================================================================
	//==============================================================================================
	//==============================================================================================
	private void processItemTypesSequentially() throws CancelledException, PdbException {
		TypeProgramInterface ipi = pdb.getItemProgramInterface();
		if (ipi == null) {
			return;
		}
		int num = ipi.getTypeIndexMaxExclusive() - ipi.getTypeIndexMin();
		TaskMonitor monitor = getMonitor();
		monitor.initialize(num);
		monitor.setMessage("PDB: Processing " + num + " item type components...");
		for (int indexNumber = ipi.getTypeIndexMin(); indexNumber < ipi
				.getTypeIndexMaxExclusive(); indexNumber++) {
			monitor.checkCancelled();
			RecordNumber recordNumber = RecordNumber.itemRecordNumber(indexNumber);
			AbstractMsType msType = pdb.getTypeRecord(recordNumber);
			MsTypeApplier applier = getTypeApplier(recordNumber);
			FixupContext fixupContext = new FixupContext();
			fixupContext.addStagedRecord(indexNumber);
			applier.apply(msType, fixupContext, false); // fixupContext and breakCycle meaningless here?
			monitor.incrementProgress(1);
		}
	}

	//==============================================================================================
	private void processSequentially() throws CancelledException, PdbException {
		processAndResolveDataTypesSequentially();
		processItemTypesSequentially();
	}

	//==============================================================================================
	//==============================================================================================
	//==============================================================================================
	DataType resolve(DataType dataType) {
		if (!(dataType instanceof DataTypeImpl)) {
			return dataType;
		}
		DataType resolved = getDataTypeManager().resolve(dataType,
			DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER);
		resolveCount++;
		return resolved;
	}

	//==============================================================================================
	//==============================================================================================
	//==============================================================================================
	//==============================================================================================
	Function getExistingOrCreateOneByteFunction(Address address) {
		if (program == null) {
			return null;
		}

		// Get normalized address for function creation
		Address normalizedAddress =
			PseudoDisassembler.getNormalizedDisassemblyAddress(program, address);

		// Does function already exist?
		Function myFunction = program.getListing().getFunctionAt(normalizedAddress);
		if (myFunction != null) {
			return myFunction;
		}

		CreateFunctionCmd funCmd = new CreateFunctionCmd(null, normalizedAddress,
			new AddressSet(normalizedAddress, normalizedAddress), SourceType.DEFAULT);
		if (!funCmd.applyTo(program, cancelOnlyWrappingMonitor)) {
			appendLogMsg("Failed to apply function at address " + address.toString() +
				"; attempting to use possible existing function");
			return program.getListing().getFunctionAt(normalizedAddress);
		}
		myFunction = funCmd.getFunction();

		return myFunction;
	}

	//==============================================================================================
	void scheduleDeferredFunctionWork(DeferrableFunctionSymbolApplier applier) {
		// Not using normalized address is OK, as we should have already set the context and
		//  used the normalized address when creating the one-byte function
		disassembleAddresses.add(applier.getAddress());
		//deferredFunctionWorkAppliers.add(applier);
	}

	//==============================================================================================
	// SymbolGroup-related methods.
	//==============================================================================================
	SymbolGroup getSymbolGroup() {
		return getSymbolGroupForModule(0);
	}

	SymbolGroup getSymbolGroupForModule(int moduleNumber) {
		if (moduleNumber < 0 || moduleNumber >= symbolGroups.size()) {
			return null;
		}
		return symbolGroups.get(moduleNumber);
	}

//	public AbstractMsSymbol getSymbolForModuleAndOffset(int moduleNumber, long offset)
//			throws PdbException {
//		return pdb.getDebugInfo().getSymbolForModuleAndOffsetOfRecord(moduleNumber, offset);
//	}

	//==============================================================================================
	// Address-related methods.
	//==============================================================================================
	/**
	 * Returns true if the {@link Address} is an invalid address for continuing application of
	 * information to the program.  Will report Error or message for an invalid address and will
	 * report a "External address" message for the name when the address is external
	 * @param address the address to test
	 * @param name name associated with the address used for reporting error/info situations
	 * @return {@code true} if the address should be processed
	 */
	boolean isInvalidAddress(Address address, String name) {
		if (address == PdbAddressManager.BAD_ADDRESS) {
			appendLogMsg("Invalid address encountered for: " + name);
			return true;
		}
		if (address == PdbAddressManager.ZERO_ADDRESS) {
			// Symbol OMAP resulted in 0 RVA - Discard silently
			return true;
		}
		if (address == PdbAddressManager.EXTERNAL_ADDRESS) {
			//Msg.info(this, "External address not known for: " + name);
			return true;
		}
		return false;
	}

	/**
	 * Returns the image base Address being used by the applicator.
	 * @return The Address
	 */
	Address getImageBase() {
		return imageBase;
	}

	/**
	 * Returns the Address for the given section and offset
	 * @param symbol the {@link AddressMsSymbol}
	 * @return the Address, which can be {@code Address.NO_ADDRESS} if invalid or
	 * {@code Address.EXTERNAL_ADDRESS} if the address is external to the program
	 */
	Address getAddress(AddressMsSymbol symbol) {
		return pdbAddressManager.getAddress(symbol);
	}

	/**
	 * Returns the Address for the given section and offset
	 * @param segment the segment
	 * @param offset the offset
	 * @return the Address
	 */
	Address getAddress(int segment, long offset) {
		return pdbAddressManager.getRawAddress(segment, offset);
	}

	/**
	 * Returns the Address for the given section and offset
	 * @param symbol The {@link AddressMsSymbol}
	 * @return the Address, which can be {@code Address.NO_ADDRESS} if invalid or
	 * {@code Address.EXTERNAL_ADDRESS} if the address is external to the program
	 */
	Address getRawAddress(AddressMsSymbol symbol) {
		return pdbAddressManager.getRawAddress(symbol);
	}

	/**
	 * Indicate to the {@link PdbAddressManager} that a new symbol with the given name has the
	 * associated address.  This allows the PdbAddressManager to create and organize the
	 * re-mapped address and supply them.  Also returns the address of the pre-existing symbol
	 * of the same name if the name was unique, otherwise null if it didn't exist or wasn't
	 * unique
	 * @param name the symbol name
	 * @param address its associated address
	 * @return the {@link Address} of existing symbol or null
	 */
	Address witnessSymbolNameAtAddress(String name, Address address) {
		return pdbAddressManager.witnessSymbolNameAtAddress(name, address);
	}

	/**
	 * Returns the Address of an existing symbol for the query address, where the mapping is
	 * derived by using a the address of a PDB symbol as the key and finding the address of
	 * a symbol in the program of the same "unique" name. This is accomplished using public
	 * mangled symbols.  If the program symbol came from the PDB, then it maps to itself
	 * @param address the query address
	 * @return the remapAddress
	 */
	Address getRemapAddressByAddress(Address address) {
		return pdbAddressManager.getRemapAddressByAddress(address);
	}

	/**
	 * Method for callee to add a Memory Group symbol to the Memory Group list.
	 * @param symbol the symbol.
	 */
	void addMemoryGroupRefinement(PeCoffGroupMsSymbol symbol) {
		pdbAddressManager.addMemoryGroupRefinement(symbol);
	}

	/**
	 * Method for callee to add a Memory Section symbol to the Memory Section list.
	 * @param symbol the symbol.
	 */
	void addMemorySectionRefinement(PeCoffSectionMsSymbol symbol) {
		pdbAddressManager.addMemorySectionRefinement(symbol);
	}

	//==============================================================================================
	// PdbPeHeaderInfoManager access methods.
	//==============================================================================================

	boolean isDll() {
		return pdbPeHeaderInfoManager.isDll();
	}

	boolean isAslr() {
		return pdbPeHeaderInfoManager.isAslr();
	}

	@Override
	public long getOriginalImageBase() {
		// TODO: If/when this becomes a program property, then get it from the program.
		return pdbPeHeaderInfoManager.getOriginalImageBase();
	}

	/**
	 * Get CLI metadata for specified tableNum and rowNum within the CLI metadata stream
	 * @param tableNum CLI metadata stream table index
	 * @param rowNum table row number
	 * @return CLI metadata or null if specified tableNum not found
	 * @throws PdbException if CLI metadata stream is not found in program file bytes
	 * @throws IndexOutOfBoundsException if specified rowNum is invalid
	 */
	CliAbstractTableRow getCliTableRow(int tableNum, int rowNum) throws PdbException {
		return pdbPeHeaderInfoManager.getCliTableRow(tableNum, rowNum);
	}

	//==============================================================================================
	// Virtual-Base-Table-related methods.
	//==============================================================================================
	VbtManager getVbtManager() {
		return vbtManager;
	}

	//==============================================================================================
	//
	//==============================================================================================
	Register getRegister(String pdbRegisterName) {
		return registerNameToRegisterMapper.getRegister(pdbRegisterName);
	}

	//==============================================================================================
	//==============================================================================================
	@SuppressWarnings("unused") // for method not being called.
	/**
	 * Process all symbols.  User should not then call other methods:
	 * {@link #processGlobalSymbolsNoTypedefs()}, (@link #processPublicSymbols()}, and
	 * {@link #processNonPublicOrGlobalSymbols()}
	 * @throws CancelledException upon user cancellation
	 * @throws PdbException upon issue processing the request
	 */
	private void processAllSymbols() throws CancelledException, PdbException {
		processMainSymbols();
		processModuleSymbols();
	}

	//==============================================================================================
	@SuppressWarnings("unused") // for method not being called.
	private void processMainSymbols() throws CancelledException, PdbException {
		// Get a count
		SymbolGroup symbolGroup = getSymbolGroup();
		if (symbolGroup == null) {
			return;
		}
		int totalCount = symbolGroup.size();
		TaskMonitor monitor = getMonitor();
		monitor.setMessage("PDB: Applying " + totalCount + " main symbol components...");
		monitor.initialize(totalCount);
		MsSymbolIterator iter = symbolGroup.getSymbolIterator();
		processSymbolGroup(0, iter);
	}

	//==============================================================================================
	int getCurrentModuleNumber() {
		return currentModuleNumber;
	}

	private void setCurrentModuleNumber(int moduleNumber) {
		currentModuleNumber = moduleNumber;
	}

	private void processModuleSymbols() throws CancelledException, PdbException {
		PdbDebugInfo debugInfo = pdb.getDebugInfo();
		if (debugInfo == null) {
			return;
		}

		int totalCount = 0;
		int num = debugInfo.getNumModules();
		TaskMonitor monitor = getMonitor();
		for (int moduleNumber = 1; moduleNumber <= num; moduleNumber++) {
			monitor.checkCancelled();
			SymbolGroup symbolGroup = getSymbolGroupForModule(moduleNumber);
			if (symbolGroup == null) {
				continue; // should not happen
			}
			totalCount++;
			//totalCount += symbolGroup.size();
		}
		monitor.setMessage("PDB: Applying module symbol components...");
		//monitor.setMessage("PDB: Applying " + totalCount + " module symbol components...");
		monitor.initialize(totalCount);

		// Process symbols list for each module
		for (int moduleNumber = 1; moduleNumber <= num; moduleNumber++) {
			monitor.checkCancelled();
			setCurrentModuleNumber(moduleNumber);
			// Process module symbols list
			SymbolGroup symbolGroup = getSymbolGroupForModule(moduleNumber);
			if (symbolGroup == null) {
				continue; // should not happen
			}
			MsSymbolIterator iter = symbolGroup.getSymbolIterator();
			processSymbolGroup(moduleNumber, iter);
			monitor.increment();
//			catelogSymbols(index, symbolGroup);
			// do not call monitor.incrementProgress(1) here, as it is updated inside of
			//  processSymbolGroup.
		}
	}

//	private Set<Class<? extends AbstractMsSymbol>> moduleSymbols = new HashSet<>();
//
//	private void catelogSymbols(int moduleNumber, SymbolGroup symbolGroup)
//			throws CancelledException {
//		symbolGroup.initGet();
//		while (symbolGroup.hasNext()) {
//			monitor.checkCancelled();
//			AbstractMsSymbol symbol = symbolGroup.peek();
//			moduleSymbols.add(symbol.getClass());
//			symbolGroup.next();
//		}
//	}
//
	//==============================================================================================
	private void processSymbolGroup(int moduleNumber, MsSymbolIterator iter)
			throws CancelledException {
		iter.initGet();
		TaskMonitor monitor = getMonitor();
		while (iter.hasNext()) {
			monitor.checkCancelled();
			procSym(iter);
			monitor.incrementProgress(1);
		}
	}

	//==============================================================================================
	/**
	 * Process public symbols.  User should not then call {@link #processAllSymbols()}; but
	 * has these other methods available to supplement this one:
	 * {@link #processGlobalSymbolsNoTypedefs()} and {@link #processNonPublicOrGlobalSymbols()}
	 * @throws CancelledException upon user cancellation
	 * @throws PdbException upon issue processing the request
	 */
	private void processPublicSymbols() throws CancelledException, PdbException {

		PdbDebugInfo debugInfo = pdb.getDebugInfo();
		if (debugInfo == null) {
			return;
		}

		SymbolGroup symbolGroup = getSymbolGroup();
		if (symbolGroup == null) {
			return;
		}

		PublicSymbolInformation publicSymbolInformation = debugInfo.getPublicSymbolInformation();
		TaskMonitor monitor = getMonitor();
		monitor.setMessage("PDB: Applying public symbols...");
		MsSymbolIterator iter = symbolGroup.getSymbolIterator();

		List<Long> offsets = publicSymbolInformation.getModifiedHashRecordSymbolOffsets();
		monitor.initialize(offsets.size());
		for (long offset : offsets) {
			monitor.checkCancelled();
			iter.initGetByOffset(offset);
			if (!iter.hasNext()) {
				break;
			}
			pdbApplicatorMetrics.witnessPublicSymbolType(iter.peek());
			procSym(iter);
			monitor.incrementProgress(1);
		}

//		AbstractSymbolInformation.ModifiedOffsetIterator publicsIter =
//			publicSymbolInformation.iterator();
//		monitor.initialize(100L);
//		long percentDone = 0;
//		while (publicsIter.hasNext()) {
//			monitor.checkCancelled();
//			Long offset = publicsIter.next();
//			iter.initGetByOffset(offset);
//			if (!iter.hasNext()) {
//				break;
//			}
//			pdbApplicatorMetrics.witnessPublicSymbolType(iter.peek());
//			procSym(iter);
//			// Increment progress
//			long delta = publicsIter.getPercentageDone() - percentDone;
//			monitor.incrementProgress(delta);
//			percentDone += delta;
//		}
//
	}

	/**
	 * Process global symbols--no typedef.  User should not then call {@link #processAllSymbols()};
	 * but has these other methods available to supplement this one: (@link #processPublicSymbols()}
	 * and {@link #processNonPublicOrGlobalSymbols()}
	 * @throws CancelledException upon user cancellation
	 * @throws PdbException upon issue processing the request
	 */
	private void processGlobalSymbolsNoTypedefs() throws CancelledException, PdbException {

		PdbDebugInfo debugInfo = pdb.getDebugInfo();
		if (debugInfo == null) {
			return;
		}

		SymbolGroup symbolGroup = getSymbolGroup();
		if (symbolGroup == null) {
			return;
		}

		TaskMonitor monitor = getMonitor();
		monitor.setMessage("PDB: Applying global symbols...");
		GlobalSymbolInformation globalSymbolInformation = debugInfo.getGlobalSymbolInformation();
		MsSymbolIterator iter = symbolGroup.getSymbolIterator();

		List<Long> offsets = globalSymbolInformation.getModifiedHashRecordSymbolOffsets();
		monitor.initialize(offsets.size());
		for (long offset : offsets) {
			monitor.checkCancelled();
			iter.initGetByOffset(offset);
			if (!iter.hasNext()) {
				break;
			}
			AbstractMsSymbol symbol = iter.peek();
			pdbApplicatorMetrics.witnessGlobalSymbolType(symbol);
			if (!(symbol instanceof AbstractUserDefinedTypeMsSymbol)) { // Not doing typedefs here
				procSym(iter);
			}
			monitor.incrementProgress(1);
		}

//		AbstractSymbolInformation.ModifiedOffsetIterator globalsIter =
//			globalSymbolInformation.iterator();
//		monitor.initialize(100L);
//		long percentDone = 0;
//		while (globalsIter.hasNext()) {
//			monitor.checkCancelled();
//			Long offset = globalsIter.next();
//			iter.initGetByOffset(offset);
//			if (!iter.hasNext()) {
//				break;
//			}
//			AbstractMsSymbol symbol = iter.peek();
//			pdbApplicatorMetrics.witnessGlobalSymbolType(symbol);
//			if (!(symbol instanceof AbstractUserDefinedTypeMsSymbol)) { // Not doing typedefs here
//				procSym(iter);
//			}
//			// Increment progress
//			long delta = globalsIter.getPercentageDone() - percentDone;
//			monitor.incrementProgress(delta);
//			percentDone += delta;
//		}
	}

	/**
	 * Process global typdef symbols
	 * @throws CancelledException upon user cancellation
	 * @throws PdbException upon issue processing the request
	 */
	private void processGlobalTypdefSymbols() throws CancelledException, PdbException {

		PdbDebugInfo debugInfo = pdb.getDebugInfo();
		if (debugInfo == null) {
			return;
		}

		SymbolGroup symbolGroup = getSymbolGroup();
		if (symbolGroup == null) {
			return;
		}

		TaskMonitor monitor = getMonitor();
		monitor.setMessage("PDB: Applying typedefs...");
		GlobalSymbolInformation globalSymbolInformation = debugInfo.getGlobalSymbolInformation();
		MsSymbolIterator iter = symbolGroup.getSymbolIterator();

		List<Long> offsets = globalSymbolInformation.getModifiedHashRecordSymbolOffsets();
		monitor.initialize(offsets.size());
		for (long offset : offsets) {
			monitor.checkCancelled();
			iter.initGetByOffset(offset);
			if (!iter.hasNext()) {
				break;
			}
			AbstractMsSymbol symbol = iter.peek();
			if (symbol instanceof AbstractUserDefinedTypeMsSymbol) { // Doing typedefs here
				procSym(iter);
			}
			monitor.incrementProgress(1);
		}

//		AbstractSymbolInformation.ModifiedOffsetIterator globalsIter =
//			globalSymbolInformation.iterator();
//		monitor.initialize(100L);
//		long percentDone = 0;
//		while (globalsIter.hasNext()) {
//			monitor.checkCancelled();
//			Long offset = globalsIter.next();
//			iter.initGetByOffset(offset);
//			if (!iter.hasNext()) {
//				break;
//			}
//			AbstractMsSymbol symbol = iter.peek();
//			pdbApplicatorMetrics.witnessGlobalSymbolType(symbol);
//			if (symbol instanceof AbstractUserDefinedTypeMsSymbol) { // Doing typedefs here
//				procSym(iter);
//			}
//			// Increment progress
//			long delta = globalsIter.getPercentageDone() - percentDone;
//			monitor.incrementProgress(delta);
//			percentDone += delta;
//		}
	}

	/**
	 * Processing non-public, non-global symbols.  User should not then call
	 * {@link #processAllSymbols()}; but has these other methods available to supplement this one:
	 * {@link #processGlobalSymbolsNoTypedefs()} and (@link #processPublicSymbols()}
	 * @throws CancelledException upon user cancellation
	 * @throws PdbException upon issue processing the request
	 */
	@SuppressWarnings("unused") // for method not being called.
	private void processNonPublicOrGlobalSymbols() throws CancelledException, PdbException {
		PdbDebugInfo debugInfo = pdb.getDebugInfo();
		if (debugInfo == null) {
			return;
		}

		SymbolGroup symbolGroup = getSymbolGroup();
		if (symbolGroup == null) {
			return;
		}

		TaskMonitor monitor = getMonitor();
		Set<Long> offsetsRemaining = symbolGroup.getOffsets();
		for (long off : debugInfo.getPublicSymbolInformation()
				.getModifiedHashRecordSymbolOffsets()) {
			monitor.checkCancelled();
			offsetsRemaining.remove(off);
		}
		for (long off : debugInfo.getGlobalSymbolInformation()
				.getModifiedHashRecordSymbolOffsets()) {
			monitor.checkCancelled();
			offsetsRemaining.remove(off);
		}

		monitor.setMessage(
			"PDB: Applying " + offsetsRemaining.size() + " other symbol components...");
		monitor.initialize(offsetsRemaining.size());
		//getCategoryUtils().setModuleTypedefsCategory(null);

		MsSymbolIterator iter = symbolGroup.getSymbolIterator();
		for (long offset : offsetsRemaining) {
			monitor.checkCancelled();
			iter.initGetByOffset(offset);
			AbstractMsSymbol symbol = iter.peek();
			procSym(iter);
			monitor.incrementProgress(1);
		}
	}

	//==============================================================================================
	int getLinkerModuleNumber() {
		return linkerModuleNumber;
	}

	private int findLinkerModuleNumber() {
		PdbDebugInfo debugInfo = pdb.getDebugInfo();
		if (debugInfo != null) {
			int num = 1;
			for (ModuleInformation module : debugInfo.getModuleInformationList()) {
				if (isLinkerModule(module.getModuleName())) {
					return num;
				}
				num++;
			}
		}
		pdbLogAndInfoMessage(this, "Not processing linker symbols because linker module not found");
		return -1;
	}

	private boolean isLinkerModule(String name) {
		return "* Linker *".equals(name);
	}

	//==============================================================================================
	@SuppressWarnings("unused") // for method not being called.
	private boolean processLinkerSymbols() throws CancelledException, PdbException {

		SymbolGroup symbolGroup = getSymbolGroupForModule(linkerModuleNumber);
		if (symbolGroup == null) {
			Msg.info(this, "No symbols to process from linker module.");
			return false;
		}

		TaskMonitor monitor = getMonitor();
		monitor.setMessage("PDB: Applying " + symbolGroup.size() + " linker symbol components...");
		monitor.initialize(symbolGroup.size());

		MsSymbolIterator iter = symbolGroup.getSymbolIterator();
		while (iter.hasNext()) {
			monitor.checkCancelled();
			pdbApplicatorMetrics.witnessLinkerSymbolType(iter.peek());
			procSym(iter);
			monitor.incrementProgress(1);
		}
		return true;
	}

	//==============================================================================================
	@Override
	public List<PeCoffSectionMsSymbol> getLinkerPeCoffSectionSymbols()
			throws CancelledException, PdbException {
		processLinkerModuleSpecialInformation();
		return linkerPeCoffSectionSymbols;
	}

	//==============================================================================================
	@Override
	public AbstractMsSymbol getLinkerModuleCompileSymbol() throws CancelledException, PdbException {
		processLinkerModuleSpecialInformation();
		return compileSymbolForLinkerModule;
	}

	//==============================================================================================
	private void processLinkerModuleSpecialInformation() throws CancelledException, PdbException {

		if (processedLinkerModule) {
			return;
		}

		List<PeCoffSectionMsSymbol> symbols = new ArrayList<>();
		AbstractMsSymbol compileSymbol = null;

		SymbolGroup symbolGroup = getSymbolGroupForModule(linkerModuleNumber);
		if (symbolGroup != null) {

			TaskMonitor monitor = getMonitor();
			monitor.initialize(symbolGroup.size());
			MsSymbolIterator iter = symbolGroup.getSymbolIterator();
			int numCompileSymbols = 0;
			int compileSymbolNumForCoffSymbols = -1;
			while (iter.hasNext()) {
				monitor.checkCancelled();
				AbstractMsSymbol symbol = iter.next();
				getPdbApplicatorMetrics().witnessLinkerSymbolType(symbol);
				if (symbol instanceof PeCoffSectionMsSymbol) {
					symbols.add((PeCoffSectionMsSymbol) symbol);
					// Putting this test and log information here if our processing hypothesis is
					// in correct in regard to theory that PE COFF symbols will be found after a
					// COMPILE symbol for those COFF symbols.
					if (numCompileSymbols == 0) {
						Msg.info(this, "PE COFF symbol found before linker compile symbol");
					}
					if (compileSymbolNumForCoffSymbols == -1) {
						compileSymbolNumForCoffSymbols = numCompileSymbols;
					}
					else if (compileSymbolNumForCoffSymbols != numCompileSymbols) {
						Msg.info(this, "Linker COFF symbols found under multiple compiler symbols");
					}
				}
				else if (symbol instanceof Compile3MsSymbol ||
					symbol instanceof AbstractCompile2MsSymbol) {
					numCompileSymbols++;
					// Doing this check because we do not know if there can be more than one
					// compile symbol.  If there is more than one, we want the one that
					// immediately precedes the PE COFF symbols,  However, there are multiple
					// compile symbols that have PE COFF symbols following them, then we
					// would probably have to change this code and the code that uses this
					// information,
					if (symbols.isEmpty()) {
						compileSymbol = symbol;
					}
				}
				monitor.incrementProgress(1);
			}
		}

		// Deferring assignment because above loop can be canceled.
		linkerPeCoffSectionSymbols = symbols;
		compileSymbolForLinkerModule = compileSymbol;
		processedLinkerModule = true;
	}

	//==============================================================================================
	private void processThunkSymbolsFromNonLinkerModules() throws CancelledException, PdbException {

		PdbDebugInfo debugInfo = pdb.getDebugInfo();
		if (debugInfo == null) {
			return;
		}

		int totalCount = 0;
		int num = debugInfo.getNumModules();
		TaskMonitor monitor = getMonitor();
		for (int index = 1; index <= num; index++) {
			monitor.checkCancelled();
			if (index == linkerModuleNumber) {
				continue;
			}
			SymbolGroup symbolGroup = getSymbolGroupForModule(index);
			if (symbolGroup == null) {
				continue; // should not happen
			}
			//totalCount += symbolGroup.size();
			totalCount++;
		}
		monitor.setMessage("PDB: Processing module thunks...");
		monitor.initialize(totalCount);

		// Process symbols list for each module
		for (int index = 1; index <= num; index++) {
			monitor.checkCancelled();
			if (index == linkerModuleNumber) {
				continue;
			}
			SymbolGroup symbolGroup = getSymbolGroupForModule(index);
			if (symbolGroup == null) {
				continue; // should not happen
			}
			MsSymbolIterator iter = symbolGroup.getSymbolIterator();
			while (iter.hasNext()) {
				monitor.checkCancelled();
				AbstractMsSymbol symbol = iter.peek();
				if (symbol instanceof AbstractThunkMsSymbol) {
					procSym(iter);
				}
				else {
					iter.next();
				}
				//monitor.incrementProgress(1);
			}
			monitor.incrementProgress(1);
		}

	}

	//==============================================================================================
	//==============================================================================================
	//==============================================================================================
	MsSymbolApplier getSymbolApplier(MsSymbolIterator iter) throws CancelledException {
		return symbolApplierParser.getSymbolApplier(iter);
	}

	//==============================================================================================
	void procSym(MsSymbolIterator iter) throws CancelledException {
		try {
			MsSymbolApplier applier = getSymbolApplier(iter);
			applier.apply();
		}
		catch (PdbException e) {
			// skipping symbol
			Msg.info(this, "Error applying symbol to program: " + e.toString());
		}
	}

	//==============================================================================================
	//==============================================================================================
	//==============================================================================================
	boolean isClass(SymbolPath path) {
		return isClassByNamespace.get(path);
	}

	//==============================================================================================
	void predefineClass(SymbolPath classPath) {
		isClassByNamespace.put(classPath, true);
		for (SymbolPath path = classPath.getParent(); path != null; path = path.getParent()) {
			if (!isClassByNamespace.containsKey(path)) {
				isClassByNamespace.put(path, false); // path is simple namespace
			}
		}
	}

	//==============================================================================================
	private void defineClasses() throws CancelledException {
		// create namespace and classes in an ordered fashion use tree map
		TaskMonitor monitor = getMonitor();
		monitor.initialize(isClassByNamespace.size());
		monitor.setMessage("PDB: Defining classes...");
		for (Map.Entry<SymbolPath, Boolean> entry : isClassByNamespace.entrySet()) {
			monitor.checkCancelled();
			SymbolPath path = entry.getKey();
			boolean isClass = entry.getValue();
			Namespace parentNamespace =
				NamespaceUtils.getNonFunctionNamespace(program, path.getParent());
			if (parentNamespace == null) {
				String type = isClass ? "class" : "namespace";
				log.appendMsg(
					"PDB Warning: Because parent namespace does not exist, failed to define " +
						type + ": " + path);
				monitor.incrementProgress(1);
				continue;
			}
			defineNamespace(parentNamespace, path.getName(), isClass);
			monitor.incrementProgress(1);

		}
	}

	//==============================================================================================
	private void defineNamespace(Namespace parentNamespace, String name, boolean isClass) {

		try {
			SymbolTable symbolTable = program.getSymbolTable();
			Namespace namespace = symbolTable.getNamespace(name, parentNamespace);
			if (namespace != null) {
				if (isClass) {
					if (namespace instanceof GhidraClass) {
						return;
					}
					if (isSimpleNamespaceSymbol(namespace)) {
						NamespaceUtils.convertNamespaceToClass(namespace);
						return;
					}
				}
				else if (namespace.getSymbol().getSymbolType() == SymbolType.NAMESPACE) {
					return;
				}
				log.appendMsg(
					"PDB Warning: Unable to create class namespace due to conflicting symbol: " +
						namespace.getName(true));
			}
			else if (isClass) {
				symbolTable.createClass(parentNamespace, name, SourceType.IMPORTED);
			}
			else {
				symbolTable.createNameSpace(parentNamespace, name, SourceType.IMPORTED);
			}
		}
		catch (InvalidInputException | DuplicateNameException e) {
			log.appendMsg(
				"PDB Warning: Unable to create class namespace due to exception: " + e.toString() +
					"; Namespace: " + parentNamespace.getName(true) + Namespace.DELIMITER + name);
		}
	}

	//==============================================================================================
	private boolean isSimpleNamespaceSymbol(Namespace namespace) {
		Symbol s = namespace.getSymbol();
		if (s.getSymbolType() != SymbolType.NAMESPACE) {
			return false;
		}
		Namespace n = namespace;
		while (n != null) {
			if (n instanceof Function) {
				return false;
			}
			n = n.getParentNamespace();
		}
		return true;
	}

	//==============================================================================================
	//==============================================================================================
	//==============================================================================================
	@SuppressWarnings("unused") // for method not being called.
	private void storeLabelByAddress(Address address, String label) {
		Set<String> labels = labelsByAddress.get(address);
		if (labels == null) {
			labels = new TreeSet<>();
			labelsByAddress.put(address, labels);
		}
		if (labels.contains(label)) {
			// TODO investigate why we would see it again.
		}
		labels.add(label);
	}

	@SuppressWarnings("unused") // for method not being called.
	private void dumpLabels() {
		for (Map.Entry<Address, Set<String>> entry : labelsByAddress.entrySet()) {
			Address address = entry.getKey();
			Set<String> labels = entry.getValue();
			System.out.println("\nAddress: " + address);
			for (String label : labels) {
				System.out.println(label);
			}
		}
	}

	//==============================================================================================
	boolean shouldForcePrimarySymbol(Address address, boolean forceIfMangled) {
		Symbol primarySymbol = program.getSymbolTable().getPrimarySymbol(address);
		if (primarySymbol != null) {

			if (primarySymbol.getName().startsWith("?") && forceIfMangled &&
				applicatorOptions.allowDemotePrimaryMangledSymbols()) {
				return true;
			}

			SourceType primarySymbolSource = primarySymbol.getSource();

			if (!SourceType.ANALYSIS.isHigherPriorityThan(primarySymbolSource)) {
				return true;
			}
		}
		return false;
	}

	//==============================================================================================
	@SuppressWarnings("unused") // For method not being called. In process of removing this version
	boolean createSymbolOld(Address address, String symbolPathString, boolean forcePrimary) {

//		storeLabelByAddress(address, symbolPathString);

		try {
			Namespace namespace = program.getGlobalNamespace();
			if (symbolPathString.startsWith(THUNK_NAME_PREFIX)) {
				symbolPathString = symbolPathString.substring(THUNK_NAME_PREFIX.length(),
					symbolPathString.length());
			}
			SymbolPath symbolPath = new SymbolPath(symbolPathString);
			symbolPath = symbolPath.replaceInvalidChars();
			String name = symbolPath.getName();
			String namespacePath = symbolPath.getParentPath();
			if (namespacePath != null) {
				namespace = NamespaceUtils.createNamespaceHierarchy(namespacePath, namespace,
					program, address, SourceType.IMPORTED);
			}

			Symbol s = SymbolUtilities.createPreferredLabelOrFunctionSymbol(program, address,
				namespace, name, SourceType.IMPORTED);
			if (s != null && forcePrimary) {
				// PDB contains both mangled, namespace names, and global names
				// If mangled name does not remain primary it will not get demamgled
				// and we may not get signature information applied
				SetLabelPrimaryCmd cmd =
					new SetLabelPrimaryCmd(address, s.getName(), s.getParentNamespace());
				cmd.applyTo(program);
			}
			return true;
		}
		catch (InvalidInputException e) {
			log.appendMsg("PDB Warning: Unable to create symbol: " + e.getMessage());
		}
		return false;
	}

	//==============================================================================================
	private static class PrimarySymbolInfo {
		private Symbol symbol;
		private boolean isNewSymbol;

		private PrimarySymbolInfo(Symbol symbol, boolean isNewSymbol) {
			this.symbol = symbol;
			this.isNewSymbol = isNewSymbol;
		}

		private boolean canBePrimaryForceOverriddenBy(String newName) {
			if (getSource().isLowerPriorityThan(SourceType.IMPORTED)) {
				return true;
			}
			if (isMangled() && !DefaultPdbApplicator.isMangled(newName)) {
				return true;
			}
			if (isNewSymbol()) {
				return false;
			}
			return false;
		}

		private SourceType getSource() {
			return symbol.getSource();
		}

		private boolean isMangled() {
			return symbol.getName().startsWith("?");
		}

		private boolean isNewSymbol() {
			return isNewSymbol;
		}
	}

	private Map<Address, PrimarySymbolInfo> primarySymbolInfoByAddress = new HashMap<>();

	//==============================================================================================
	Symbol createSymbol(Address address, String symbolPathString,
			boolean forcePrimaryIfExistingIsMangled) {
		return createSymbol(address, symbolPathString, forcePrimaryIfExistingIsMangled, null);
	}

	Symbol createSymbol(Address address, String symbolPathString,
			boolean forcePrimaryIfExistingIsMangled, String plateAddition) {

		// Must get existing info before creating new symbol, as we do not want "existing"
		//  to include the new one
		PrimarySymbolInfo existingPrimarySymbolInfo = getExistingPrimarySymbolInfo(address);
		Symbol newSymbol = createSymbol(address, symbolPathString);
		if (newSymbol == null) {
			return null;
		}

		boolean forcePrimary = false;
		if (existingPrimarySymbolInfo != null) {
			if (existingPrimarySymbolInfo.canBePrimaryForceOverriddenBy(symbolPathString) &&
				forcePrimaryIfExistingIsMangled &&
				applicatorOptions.allowDemotePrimaryMangledSymbols()) {
				forcePrimary = true;
			}
		}

		boolean forcePrimarySucceeded = false;
		if (forcePrimary) {
			SetLabelPrimaryCmd cmd = new SetLabelPrimaryCmd(address, newSymbol.getName(),
				newSymbol.getParentNamespace());
			if (cmd.applyTo(program)) {
				forcePrimarySucceeded = true;
			}
		}

		if (existingPrimarySymbolInfo == null || forcePrimarySucceeded) {
			PrimarySymbolInfo primarySymbolInfo = new PrimarySymbolInfo(newSymbol, true);
			setExistingPrimarySymbolInfo(address, primarySymbolInfo);
		}

		addToPlateUnique(address, plateAddition);

		return newSymbol;
	}

	private boolean addToPlateUnique(Address address, String comment) {
		if (StringUtils.isBlank(comment)) {
			return false;
		}
		String plate = program.getListing().getComment(CodeUnit.PLATE_COMMENT, address);
		if (plate == null) {
			plate = "";
		}
		else if (plate.contains(comment)) {
			return true;
		}
		else if (!plate.endsWith("\n")) {
			plate += '\n';
		}
		plate += comment;
		SetCommentCmd.createComment(program, address, comment, CodeUnit.PLATE_COMMENT);
		return true;
	}

	private static boolean isMangled(String name) {
		return name.startsWith("?");
	}

	private void setExistingPrimarySymbolInfo(Address address, PrimarySymbolInfo info) {
		primarySymbolInfoByAddress.put(address, info);
	}

	private PrimarySymbolInfo getExistingPrimarySymbolInfo(Address address) {
		PrimarySymbolInfo info = primarySymbolInfoByAddress.get(address);
		if (info != null) {
			return info;
		}
		Symbol primarySymbol = pdbAddressManager.getPrimarySymbol(address);
		if (primarySymbol == null ||
			primarySymbol.getSource().isLowerPriorityThan(SourceType.IMPORTED)) {
			return null;
		}
		info = new PrimarySymbolInfo(primarySymbol, false);
		primarySymbolInfoByAddress.put(address, info);
		return info;
	}

	private Symbol createSymbol(Address address, String symbolPathString) {
		Symbol symbol = null;
		try {
			Namespace namespace = program.getGlobalNamespace();
			if (symbolPathString.startsWith(THUNK_NAME_PREFIX)) {
				symbolPathString = symbolPathString.substring(THUNK_NAME_PREFIX.length(),
					symbolPathString.length());
			}
			SymbolPath symbolPath = new SymbolPath(symbolPathString);
			symbolPath = symbolPath.replaceInvalidChars();
			String name = symbolPath.getName();
			String namespacePath = symbolPath.getParentPath();
			if (namespacePath != null) {
				namespace = NamespaceUtils.createNamespaceHierarchy(namespacePath, namespace,
					program, address, SourceType.IMPORTED);
			}

			symbol =
				program.getSymbolTable().createLabel(address, name, namespace, SourceType.IMPORTED);
		}
		catch (InvalidInputException e) {
			log.appendMsg("PDB Warning: Unable to create symbol at " + address +
				" due to exception: " + e.toString() + "; symbolPathName: " + symbolPathString);
		}
		return symbol;
	}

}
