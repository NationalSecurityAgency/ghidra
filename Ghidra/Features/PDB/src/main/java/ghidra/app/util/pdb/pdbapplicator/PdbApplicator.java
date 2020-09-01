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

import java.math.BigInteger;
import java.util.*;

import ghidra.app.cmd.label.SetLabelPrimaryCmd;
import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.SymbolPath;
import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractMsType;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.pdb.PdbCategoryUtils;
import ghidra.app.util.pdb.pdbapplicator.SymbolGroup.AbstractMsSymbolIterator;
import ghidra.graph.*;
import ghidra.graph.algo.GraphNavigator;
import ghidra.graph.jung.JungDirectedGraph;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.CancelOnlyWrappingTaskMonitor;
import ghidra.util.task.TaskMonitor;

public class PdbApplicator {

	/**
	 * Returns integer value of BigInteger or Integer.MAX_VALUE if does not fit.
	 * @param myApplicator PdbApplicator for which we are working.
	 * @param big BigInteger value to convert.
	 * @return the integer value.
	 */
	public static long bigIntegerToLong(PdbApplicator myApplicator, BigInteger big) {
		try {
			return big.longValueExact();
		}
		catch (ArithmeticException e) {
			String msg = "BigInteger value greater than max Long: " + big;
			PdbLog.message(msg);
			myApplicator.appendLogMsg(msg);
			return Long.MAX_VALUE;
		}
	}

	/**
	 * Returns integer value of BigInteger or Integer.MAX_VALUE if does not fit.
	 * @param myApplicator PdbApplicator for which we are working.
	 * @param big BigInteger value to convert.
	 * @return the integer value.
	 */
	public static int bigIntegerToInt(PdbApplicator myApplicator, BigInteger big) {
		try {
			return big.intValueExact();
		}
		catch (ArithmeticException e) {
			String msg = "BigInteger value greater than max Integer: " + big;
			PdbLog.message(msg);
			myApplicator.appendLogMsg(msg);
			return Integer.MAX_VALUE;
		}
	}

	//==============================================================================================
	private String pdbFilename;
	private AbstractPdb pdb;

	private PdbApplicatorMetrics pdbApplicatorMetrics;

	//==============================================================================================
	private Program program;

	private PdbApplicatorOptions applicatorOptions;
	private MessageLog log;
	private TaskMonitor monitor;
	private CancelOnlyWrappingTaskMonitor cancelOnlyWrappingMonitor;

	//==============================================================================================
	private Address imageBase;
	private DataTypeManager dataTypeManager;
	private PdbAddressManager pdbAddressManager;
	private List<SymbolGroup> symbolGroups;

	//==============================================================================================
	// If we have symbols and memory with VBTs in them, then a better VbtManager is created.
	VbtManager vbtManager;
	PdbRegisterNameToProgramRegisterMapper registerNameToRegisterMapper;

	//==============================================================================================
	private int resolveCount;
	private PdbCategoryUtils categoryUtils;
	private PdbPrimitiveTypeApplicator pdbPrimitiveTypeApplicator;
	private TypeApplierParser typeApplierParser;
	private ComplexTypeApplierMapper complexApplierMapper;
	private JungDirectedGraph<AbstractMsTypeApplier, GEdge<AbstractMsTypeApplier>> applierDependencyGraph;
	/**
	 * This namespace map documents as follows:
	 * <PRE>
	 *   false = simple namespace
	 *   true = class namespace
	 *  </PRE> 
	 */
	private Map<SymbolPath, Boolean> isClassByNamespace;

	//==============================================================================================
	private SymbolApplierParser symbolApplierParser;

	// Investigating... might change from String to AbstractSymbolApplier.
	private Map<Address, Set<String>> labelsByAddress;
	// Investigations into source/line info
	private Map<String, Set<RecordNumber>> recordNumbersByFileName;
	private Map<Integer, Set<RecordNumber>> recordNumbersByModuleNumber;

	//==============================================================================================
	// TODO: eventually put access methods on AbstractPdb to get filename from it (deep down).
	public PdbApplicator(String pdbFilename, AbstractPdb pdb) {
		Objects.requireNonNull(pdbFilename, "pdbFilename cannot be null");
		Objects.requireNonNull(pdb, "pdb cannot be null");
		this.pdbFilename = pdbFilename;
		this.pdb = pdb;
	}

	//==============================================================================================
	//==============================================================================================
	/**
	 * Applies the PDB to the {@link Program} or {@link DataTypeManager}. Either, but not both,
	 *  can be null.
	 * @param programParam The {@link Program} to which to apply the PDB. Can be null in certain
	 *  circumstances.
	 * @param dataTypeManagerParam The {@link DataTypeManager} to which to apply data types. Can be
	 *  null in certain circumstances.
	 * @param imageBaseParam Address bases from which symbol addresses are based. If null, uses
	 *  the image base of the program (both cannot be null).
	 * @param applicatorOptionsParam {@link PdbApplicatorOptions} used for applying the PDB.
	 * @param monitorParam TaskMonitor uses for watching progress and cancellation notices.
	 * @param logParam The MessageLog to which to output messages.
	 * @throws PdbException if there was a problem processing the data.
	 * @throws CancelledException Upon user cancellation
	 */
	public void applyTo(Program programParam, DataTypeManager dataTypeManagerParam,
			Address imageBaseParam, PdbApplicatorOptions applicatorOptionsParam,
			TaskMonitor monitorParam, MessageLog logParam) throws PdbException, CancelledException {

		initializeApplyTo(programParam, dataTypeManagerParam, imageBaseParam,
			applicatorOptionsParam, monitorParam, logParam);

		if (!applicatorOptions.applyPublicSymbolsOnly()) {
			processTypes();
		}

		if (program != null && !applicatorOptions.applyDataTypesOnly()) {
			if (applicatorOptions.applyPublicSymbolsOnly()) {
				processPublicSymbols();
			}
			else {
				processSymbols();
			}
		}

		pdbAddressManager.logReport();

		String applicatorMetrics = pdbApplicatorMetrics.getPostProcessingReport();
		Msg.info(this, applicatorMetrics);
		PdbLog.message(applicatorMetrics);
		Msg.info(this, "PDB Terminated Normally");
	}

	//==============================================================================================
	private void processTypes() throws CancelledException, PdbException {
		setMonitorMessage("PDB: Applying to DTM " + dataTypeManager.getName() + "...");

		PdbResearch.initCheckBreak(); // for developmental debug

		resolveCount = 0;

//		PdbResearch.childWalk(this, monitor);

//		PdbResearch.studyDataTypeConflicts(this, monitor);
//		PdbResearch.studyCompositeFwdRefDef(pdb, monitor);
//		PdbResearch.study1(pdb, monitor);

		complexApplierMapper.mapAppliers(monitor);

		processSequentially();

//		dumpSourceFileRecordNumbers();

//		PdbResearch.developerDebugOrder(this, monitor);

		processDeferred();

		resolveSequentially();

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

		// Doing globals before publics, as publics are those that can have mangled names.  By
		// applying the non-mangled symbols first, we can get full type information from the
		// underlying type.  Then we can apply the mangled symbols and demangle them without
		// affecting our ability to lay down PDB type information--any type information from
		// the mangled symbols can happen afterward.
		processGlobalSymbolsNoTypedefs();
		processPublicSymbols();

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
	private void initializeApplyTo(Program programParam, DataTypeManager dataTypeManagerParam,
			Address imageBaseParam, PdbApplicatorOptions applicatorOptionsParam,
			TaskMonitor monitorParam, MessageLog logParam) throws PdbException, CancelledException {

		validateAndSetParameters(programParam, dataTypeManagerParam, imageBaseParam,
			applicatorOptionsParam, monitorParam, logParam);

		cancelOnlyWrappingMonitor = new CancelOnlyWrappingTaskMonitor(monitor);
		pdbApplicatorMetrics = new PdbApplicatorMetrics();

		pdbAddressManager = new PdbAddressManager(this, imageBase);
		symbolGroups = createSymbolGroups();

		categoryUtils = setPdbCatogoryUtils(pdbFilename);
		pdbPrimitiveTypeApplicator = new PdbPrimitiveTypeApplicator(dataTypeManager);
		typeApplierParser = new TypeApplierParser(this);
		complexApplierMapper = new ComplexTypeApplierMapper(this);
		applierDependencyGraph = new JungDirectedGraph<>();
		isClassByNamespace = new TreeMap<>();
		if (program != null) {
			// Currently, this must happen after symbolGroups are created.
			PdbVbtManager pdbVbtManager = new PdbVbtManager(this);
			//pdbVbtManager.CreateVirtualBaseTables(); // Depends on symbolGroups
			vbtManager = pdbVbtManager;
			registerNameToRegisterMapper = new PdbRegisterNameToProgramRegisterMapper(program);
		}
		else {
			vbtManager = new VbtManager(getDataTypeManager());
		}

		symbolApplierParser = new SymbolApplierParser(this);

		// Investigations
		labelsByAddress = new HashMap<>();
		// Investigations into source/line info
		recordNumbersByFileName = new HashMap<>();
		recordNumbersByModuleNumber = new HashMap<>();
	}

	private void validateAndSetParameters(Program programParam,
			DataTypeManager dataTypeManagerParam, Address imageBaseParam,
			PdbApplicatorOptions applicatorOptionsParam, TaskMonitor monitorParam,
			MessageLog logParam) throws PdbException {
		if (programParam == null) {
			if (dataTypeManagerParam == null) {
				throw new PdbException(
					"programParam and dataTypeManagerParam may not both be null.");
			}
			if (imageBaseParam == null) {
				throw new PdbException("programParam and imageBaseParam may not both be null.");
			}
		}
		applicatorOptions =
			(applicatorOptionsParam != null) ? applicatorOptionsParam : new PdbApplicatorOptions();
		if (applicatorOptions.applyDataTypesOnly() && applicatorOptions.applyPublicSymbolsOnly()) {
			throw new PdbException("Cannot have both: applyDataTypesOnly, applyPublicSymbolOnly.");
		}
		monitor = (monitorParam != null) ? monitorParam : TaskMonitor.DUMMY;
		log = (logParam != null) ? logParam : new MessageLog();
		program = programParam;
		dataTypeManager =
			(dataTypeManagerParam != null) ? dataTypeManagerParam : program.getDataTypeManager();
		imageBase = (imageBaseParam != null) ? imageBaseParam : program.getImageBase();
	}

	private List<SymbolGroup> createSymbolGroups() throws CancelledException, PdbException {
		List<SymbolGroup> mySymbolGroups = new ArrayList<>();
		int num = pdb.getDatabaseInterface().getNumModules();
		// moduleNumber zero is our global/public group.
		for (int moduleNumber = 0; moduleNumber <= num; moduleNumber++) {
			monitor.checkCanceled();
			Map<Long, AbstractMsSymbol> symbols =
				pdb.getDatabaseInterface().getModuleSymbolsByOffset(moduleNumber);
			SymbolGroup symbolGroup = new SymbolGroup(symbols, moduleNumber);
			mySymbolGroups.add(symbolGroup);
		}
		return mySymbolGroups;
	}

	//==============================================================================================
	// Basic utility methods.
	//==============================================================================================
	/**
	 * Returns the {@link PdbApplicatorOptions} for this PdbApplicator.
	 * @return the {@link PdbApplicatorOptions} for this PdbApplicator.
	 */
	PdbApplicatorOptions getPdbApplicatorOptions() {
		return applicatorOptions;
	}

	/**
	 * Check to see if this monitor has been canceled
	 * @throws CancelledException if monitor has been cancelled
	 */
	void checkCanceled() throws CancelledException {
		monitor.checkCanceled();
	}

	/**
	 * Sets the message displayed on the task monitor
	 * @param message the message to display
	 */
	void setMonitorMessage(String message) {
		monitor.setMessage(message);
	}

	/**
	 * Sets the message displayed on the task monitor
	 * @param message the message to display
	 */
	void appendLogMsg(String message) {
		log.appendMsg(message);
	}

	/**
	 * Returns the {@link TaskMonitor} to available for this analyzer.
	 * @return the monitor.
	 */
	TaskMonitor getMonitor() {
		return monitor;
	}

	/**
	 * Returns the {@link CancelOnlyWrappingTaskMonitor} to available for this analyzer.
	 * @return the monitor.
	 */
	TaskMonitor getCancelOnlyWrappingMonitor() {
		return cancelOnlyWrappingMonitor;
	}

	/**
	 * Returns the {@link PdbApplicatorMetrics} being used for this applicator.
	 * @return the {@link PdbApplicatorMetrics}.
	 */
	PdbApplicatorMetrics getPdbApplicatorMetrics() {
		return pdbApplicatorMetrics;
	}

	/**
	 * Returns the {@link AbstractPdb} being analyzed.
	 * @return {@link AbstractPdb} being analyzed.
	 */
	AbstractPdb getPdb() {
		return pdb;
	}

	/**
	 * Returns the {@link Program} for which this analyzer is working.
	 * @return {@link Program} for which this analyzer is working.
	 */
	Program getProgram() {
		return program;
	}

	//==============================================================================================
	// Information for a putative PdbTypeApplicator:

	/**
	 * Returns the {@link DataTypeManager} associated with this analyzer. 
	 * @return DataTypeManager which this analyzer is using.
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
	 *  it either at the PDB Category.
	 * @param symbolPath Symbol path to be used to create the CategoryPath. Null represents global
	 *  namespace.
	 * @return {@link CategoryPath} created for the input.
	 */
	CategoryPath getCategory(SymbolPath symbolPath) {
		return categoryUtils.getCategory(symbolPath);
	}

	/**
	 * Returns the {@link CategoryPath} for a typedef with with the give {@link SymbolPath} and
	 * module number; 1 <= moduleNumber <= {@link AbstractDatabaseInterface#getNumModules()}, 
	 * except that modeleNumber of 0 represents publics/globals. 
	 * @param moduleNumber module number
	 * @param symbolPath SymbolPath of the symbol
	 * @return the CategoryPath
	 */
	CategoryPath getTypedefsCategory(int moduleNumber, SymbolPath symbolPath) {
		return categoryUtils.getTypedefsCategory(moduleNumber, symbolPath);
	}

	/**
	 * Returns the {@link CategoryPath} for Anonymous Functions Category for the PDB.
	 * @return the {@link CategoryPath}
	 */
	CategoryPath getAnonymousFunctionsCategory() {
		return categoryUtils.getAnonymousFunctionsCategory();
	}

	/**
	 * Returns the {@link CategoryPath} for Anonymous Types Category for the PDB.
	 * @return the {@link CategoryPath}
	 */
	public CategoryPath getAnonymousTypesCategory() {
		return categoryUtils.getAnonymousTypesCategory();
	}

	/**
	 * Returns the name of what should be the next Anonymous Function (based on the count of
	 * the number of anonymous functions) so that there is a unique name for the function.
	 * @return the name for the next anonymous function.
	 */
	String getNextAnonymousFunctionName() {
		return categoryUtils.getNextAnonymousFunctionName();
	}

	/**
	 * Updates the count of the anonymous functions.  This is a separate call from
	 * {@link #getNextAnonymousFunctionName()} because the count should only be updated after
	 * the previous anonymous function has been successfully created/stored.
	 */
	void incrementNextAnonymousFunctionName() {
		categoryUtils.incrementNextAnonymousFunctionName();
	}

	private PdbCategoryUtils setPdbCatogoryUtils(String pdbFilename)
			throws CancelledException, PdbException {

		List<String> categoryNames = new ArrayList<>();
		int num = pdb.getDatabaseInterface().getNumModules();
		for (int index = 1; index <= num; index++) {
			monitor.checkCanceled();
			String moduleName =
				pdb.getDatabaseInterface().getModuleInformation(index).getModuleName();
			categoryNames.add(moduleName);
		}

		int index = pdbFilename.lastIndexOf("\\");
		if (index == -1) {
			index = pdbFilename.lastIndexOf("/");
		}
		return new PdbCategoryUtils(pdbFilename.substring(index + 1), categoryNames);
	}

	//==============================================================================================
	// Applier-based-DataType-dependency-related methods.
	//==============================================================================================
	void addApplierDependency(AbstractMsTypeApplier depender) {
		Objects.requireNonNull(depender);
		applierDependencyGraph.addVertex(depender.getDependencyApplier());
	}

	void addApplierDependency(AbstractMsTypeApplier depender, AbstractMsTypeApplier dependee) {
		Objects.requireNonNull(depender);
		Objects.requireNonNull(dependee);
		// TODO: Possibly do checks on dependee and depender types for actual creation
		//  of dependency--making this the one-stop-shop of this logic.  Then make calls to
		//  this method from all possibly places.  (Perhaps, for example, if depender is a
		//  pointer, then the logic would say "no.")
		//
		// Examples of where dependency should possibly be created (by not doing it, we are
		//  getting .conflict data types) include:
		//  structure or enum as a function return type or argument type.
		//
		applierDependencyGraph.addEdge(
			new DefaultGEdge<>(depender.getDependencyApplier(), dependee.getDependencyApplier()));
	}

	List<AbstractMsTypeApplier> getVerticesInPostOrder() {
		setMonitorMessage("PDB: Determining data type dependency order...");
		return GraphAlgorithms.getVerticesInPostOrder(applierDependencyGraph,
			GraphNavigator.topDownNavigator());
	}

	//==============================================================================================
	//==============================================================================================
	//==============================================================================================
	AbstractMsTypeApplier getApplierSpec(RecordNumber recordNumber,
			Class<? extends AbstractMsTypeApplier> expected) throws PdbException {
		return typeApplierParser.getApplierSpec(recordNumber, expected);
	}

	AbstractMsTypeApplier getApplierOrNoTypeSpec(RecordNumber recordNumber,
			Class<? extends AbstractMsTypeApplier> expected) throws PdbException {
		return typeApplierParser.getApplierOrNoTypeSpec(recordNumber, expected);
	}

	AbstractMsTypeApplier getTypeApplier(RecordNumber recordNumber) {
		return typeApplierParser.getTypeApplier(recordNumber);
	}

	AbstractMsTypeApplier getTypeApplier(AbstractMsType type) {
		return typeApplierParser.getTypeApplier(type);
	}

	//==============================================================================================
	//==============================================================================================
	//==============================================================================================
	public int findModuleNumberBySectionOffsetContribution(int section, long offset)
			throws PdbException {
		for (AbstractSectionContribution sectionContribution : pdb.getDatabaseInterface().getSectionContributionList()) {
			int sectionContributionOffset = sectionContribution.getOffset();
			int maxSectionContributionOffset =
				sectionContributionOffset + sectionContribution.getLength();
			if (offset >= sectionContributionOffset && offset < maxSectionContributionOffset) {
				return sectionContribution.getModule();
			}
		}
		throw new PdbException("Module not found for section/offset");
	}

	//==============================================================================================
	private void processDataTypesSequentially() throws CancelledException, PdbException {
		AbstractTypeProgramInterface tpi = pdb.getTypeProgramInterface();
		int num = tpi.getTypeIndexMaxExclusive() - tpi.getTypeIndexMin();
		monitor.initialize(num);
		setMonitorMessage("PDB: Processing " + num + " data type components...");
		for (int indexNumber =
			tpi.getTypeIndexMin(); indexNumber < tpi.getTypeIndexMaxExclusive(); indexNumber++) {
			monitor.checkCanceled();
			PdbResearch.checkBreak(indexNumber);
			AbstractMsTypeApplier applier =
				getTypeApplier(RecordNumber.typeRecordNumber(indexNumber));
			//PdbResearch.checkBreak(indexNumber, applier);
			applier.apply();
			monitor.incrementProgress(1);
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
		AbstractTypeProgramInterface ipi = pdb.getItemProgramInterface();
		int num = ipi.getTypeIndexMaxExclusive() - ipi.getTypeIndexMin();
		monitor.initialize(num);
		setMonitorMessage("PDB: Processing " + num + " item type components...");
		for (int indexNumber = ipi.getTypeIndexMin(); indexNumber < num; indexNumber++) {
			monitor.checkCanceled();
			AbstractMsTypeApplier applier =
				getTypeApplier(RecordNumber.itemRecordNumber(indexNumber));
			applier.apply();
			monitor.incrementProgress(1);
		}
	}

	//==============================================================================================
	private void processSequentially() throws CancelledException, PdbException {
		processDataTypesSequentially();
		processItemTypesSequentially();
	}

	//==============================================================================================
	private void processDeferred() throws CancelledException, PdbException {
		List<AbstractMsTypeApplier> verticesInPostOrder = getVerticesInPostOrder();
		monitor.initialize(verticesInPostOrder.size());
		setMonitorMessage("PDB: Processing " + verticesInPostOrder.size() +
			" deferred data type dependencies...");
		for (AbstractMsTypeApplier applier : verticesInPostOrder) {
			monitor.checkCanceled();
			PdbResearch.checkBreak(applier.index);
			//checkBreak(applier.index, applier);
			if (applier.isDeferred()) {
				applier.deferredApply();
			}
			monitor.incrementProgress(1);
		}
	}

	//==============================================================================================
	private void resolveSequentially() throws CancelledException {
		AbstractTypeProgramInterface tpi = pdb.getTypeProgramInterface();
		int num = tpi.getTypeIndexMaxExclusive() - tpi.getTypeIndexMin();
		monitor.initialize(num);
		setMonitorMessage("PDB: Resolving " + num + " data type components...");
		Date start = new Date();
		long longStart = start.getTime();
		for (int indexNumber =
			tpi.getTypeIndexMin(); indexNumber < tpi.getTypeIndexMaxExclusive(); indexNumber++) {
			monitor.checkCanceled();
			PdbResearch.checkBreak(indexNumber);
			AbstractMsTypeApplier applier =
				getTypeApplier(RecordNumber.typeRecordNumber(indexNumber));
			PdbResearch.checkBreak(indexNumber, applier);
			applier.resolve();
			monitor.incrementProgress(1);
		}
		Date stop = new Date();
		long longStop = stop.getTime();
		long timeDiff = longStop - longStart;
		Msg.info(this, "Resolve time: " + timeDiff + " mS");
	}

	//==============================================================================================
	//==============================================================================================
	//==============================================================================================
	DataType resolve(DataType dataType) {
		if ("Cr_z_internal_state".equals(dataType.getName())) {
			int a = 1;
			a = a + 1;
		}
		if ("z_stream_s".equals(dataType.getName())) {
			int a = 1;
			a = a + 1;
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
	// SymbolGroup-related methods.
	//==============================================================================================
	SymbolGroup getSymbolGroup() {
		return getSymbolGroupForModule(0);
	}

	SymbolGroup getSymbolGroupForModule(int moduleNumber) {
		return symbolGroups.get(moduleNumber);
	}

//	public AbstractMsSymbol getSymbolForModuleAndOffset(int moduleNumber, long offset)
//			throws PdbException {
//		return pdb.getDatabaseInterface().getSymbolForModuleAndOffsetOfRecord(moduleNumber, offset);
//	}

	//==============================================================================================
	// Address-related methods.
	//==============================================================================================
	/**
	 * Returns the Address for the given section and offset.
	 * @param symbol The {@link AddressMsSymbol}
	 * @return The Address
	 */
	Address reladdr(AddressMsSymbol symbol) {
		return pdbAddressManager.reladdr(symbol);
	}

	/**
	 * Returns the Address for the given section and offset.
	 * @param segment The segment
	 * @param offset The offset
	 * @return The Address
	 */
	Address reladdr(int segment, long offset) {
		return pdbAddressManager.reladdr(segment, offset);
	}

	/**
	 * Write the mapped address for a query address, where where the mapping is
	 *  derived by using a the address of a PDB symbol as the key and finding the address of
	 *  a symbol in the program of the same "unique" name. This is accomplished using public
	 *  mangled symbols.  If the program symbol came from the PDB, then it maps to itself.
	 * @param address the query address
	 * @param remapAddress the mapped address
	 */
	void putRemapAddressByAddress(Address address, Address remapAddress) {
		pdbAddressManager.putRemapAddressByAddress(address, remapAddress);
	}

	/**
	 * Returns the Address of an existing symbol for the query address, where the mapping is
	 *  derived by using a the address of a PDB symbol as the key and finding the address of
	 *  a symbol in the program of the same "unique" name. This is accomplished using public
	 *  mangled symbols.  If the program symbol came from the PDB, then it maps to itself.
	 * @param address the query address
	 * @return the remapAddress
	 */
	Address getRemapAddressByAddress(Address address) {
		return pdbAddressManager.getRemapAddressByAddress(address);
	}

	/**
	 * Method for callee to set the real address for the section.
	 * @param sectionNum the section number
	 * @param realAddress The Address
	 */
	void putRealAddressesBySection(int sectionNum, long realAddress) {
		pdbAddressManager.putRealAddressesBySection(sectionNum, realAddress);
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
	 * {@link #processGlobalSymbols()}, (@link #processPublicSymbols()}, and
	 * {@link #processNonPublicOrGlobalSymbols()}.
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
		int totalCount = symbolGroup.size();
		setMonitorMessage("PDB: Applying " + totalCount + " main symbol components...");
		monitor.initialize(totalCount);
		AbstractMsSymbolIterator iter = symbolGroup.iterator();
		processSymbolGroup(0, iter);
	}

	//==============================================================================================
	private void processModuleSymbols() throws CancelledException {
		int totalCount = 0;
		int num = pdb.getDatabaseInterface().getNumModules();
		for (int moduleNumber = 1; moduleNumber <= num; moduleNumber++) {
			monitor.checkCanceled();
			SymbolGroup symbolGroup = getSymbolGroupForModule(moduleNumber);
			totalCount += symbolGroup.size();
		}
		setMonitorMessage("PDB: Applying " + totalCount + " module symbol components...");
		monitor.initialize(totalCount);

		// Process symbols list for each module
		for (int moduleNumber = 1; moduleNumber <= num; moduleNumber++) {
			monitor.checkCanceled();
			// Process module symbols list
			SymbolGroup symbolGroup = getSymbolGroupForModule(moduleNumber);
			AbstractMsSymbolIterator iter = symbolGroup.iterator();
			processSymbolGroup(moduleNumber, iter);
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
//			monitor.checkCanceled();
//			AbstractMsSymbol symbol = symbolGroup.peek();
//			moduleSymbols.add(symbol.getClass());
//			symbolGroup.next();
//		}
//	}
//
	//==============================================================================================
	private void processSymbolGroup(int moduleNumber, AbstractMsSymbolIterator iter)
			throws CancelledException {
		iter.initGet();
		while (iter.hasNext()) {
			monitor.checkCanceled();
			procSym(iter);
			monitor.incrementProgress(1);
		}
	}

	//==============================================================================================
	/**
	 * Process public symbols.  User should not then call {@link #processAllSymbols()}; but
	 * has these other methods available to supplement this one: {@link #processGlobalSymbolsNoTypedefs()}
	 * and {@link #processNonPublicOrGlobalSymbols()}.
	 * @throws CancelledException upon user cancellation
	 * @throws PdbException upon issue processing the request
	 */
	private void processPublicSymbols() throws CancelledException, PdbException {

		SymbolGroup symbolGroup = getSymbolGroup();

		PublicSymbolInformation publicSymbolInformation =
			pdb.getDatabaseInterface().getPublicSymbolInformation();
		List<Long> offsets = publicSymbolInformation.getModifiedHashRecordSymbolOffsets();
		setMonitorMessage("PDB: Applying " + offsets.size() + " public symbol components...");
		monitor.initialize(offsets.size());

		AbstractMsSymbolIterator iter = symbolGroup.iterator();
		for (long offset : offsets) {
			monitor.checkCanceled();
			iter.initGetByOffset(offset);
			if (!iter.hasNext()) {
				break;
			}
			pdbApplicatorMetrics.witnessPublicSymbolType(iter.peek());
			procSym(iter);
			monitor.incrementProgress(1);
		}
	}

	/**
	 * Process global symbols--no typedef.  User should not then call {@link #processAllSymbols()};
	 * but has these other methods available to supplement this one: (@link #processPublicSymbols()}
	 * and {@link #processNonPublicOrGlobalSymbols()}.
	 * @throws CancelledException upon user cancellation
	 * @throws PdbException upon issue processing the request
	 */
	private void processGlobalSymbolsNoTypedefs() throws CancelledException, PdbException {

		SymbolGroup symbolGroup = getSymbolGroup();

		GlobalSymbolInformation globalSymbolInformation =
			pdb.getDatabaseInterface().getGlobalSymbolInformation();
		List<Long> offsets = globalSymbolInformation.getModifiedHashRecordSymbolOffsets();
		setMonitorMessage("PDB: Applying global symbols...");
		monitor.initialize(offsets.size());

		AbstractMsSymbolIterator iter = symbolGroup.iterator();
		for (long offset : offsets) {
			monitor.checkCanceled();
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
	}

	/**
	 * Process global typdef symbols.
	 * @throws CancelledException upon user cancellation
	 * @throws PdbException upon issue processing the request
	 */
	private void processGlobalTypdefSymbols() throws CancelledException, PdbException {

		SymbolGroup symbolGroup = getSymbolGroup();

		GlobalSymbolInformation globalSymbolInformation =
			pdb.getDatabaseInterface().getGlobalSymbolInformation();
		List<Long> offsets = globalSymbolInformation.getModifiedHashRecordSymbolOffsets();
		setMonitorMessage("PDB: Applying typedefs...");
		monitor.initialize(offsets.size());

		AbstractMsSymbolIterator iter = symbolGroup.iterator();
		for (long offset : offsets) {
			monitor.checkCanceled();
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
	}

	/**
	 * Processing non-public, non-global symbols.  User should not then call
	 * {@link #processAllSymbols()}; but has these other methods available to supplement this one:
	 * {@link #processGlobalSymbolsNoTypedefs()} and (@link #processPublicSymbols()}.
	 * @throws CancelledException upon user cancellation
	 * @throws PdbException upon issue processing the request
	 */
	@SuppressWarnings("unused") // for method not being called.
	private void processNonPublicOrGlobalSymbols() throws CancelledException, PdbException {
		Set<Long> offsetsRemaining = getSymbolGroup().getOffsets();
		for (long off : pdb.getDatabaseInterface().getPublicSymbolInformation().getModifiedHashRecordSymbolOffsets()) {
			monitor.checkCanceled();
			offsetsRemaining.remove(off);
		}
		for (long off : pdb.getDatabaseInterface().getGlobalSymbolInformation().getModifiedHashRecordSymbolOffsets()) {
			monitor.checkCanceled();
			offsetsRemaining.remove(off);
		}

		setMonitorMessage(
			"PDB: Applying " + offsetsRemaining.size() + " other symbol components...");
		monitor.initialize(offsetsRemaining.size());
		//getCategoryUtils().setModuleTypedefsCategory(null);

		SymbolGroup symbolGroup = getSymbolGroup();
		AbstractMsSymbolIterator iter = symbolGroup.iterator();
		for (long offset : offsetsRemaining) {
			monitor.checkCanceled();
			iter.initGetByOffset(offset);
			AbstractMsSymbol symbol = iter.peek();
			procSym(iter);
			monitor.incrementProgress(1);
		}
	}

	//==============================================================================================
	private int findLinkerModuleNumber() {
		if (pdb.getDatabaseInterface() != null) {
			int num = 1;
			for (AbstractModuleInformation module : pdb.getDatabaseInterface().getModuleInformationList()) {
				if (isLinkerModule(module.getModuleName())) {
					return num;
				}
				num++;
			}
		}
		appendLogMsg("Not processing linker symbols because linker module not found");
		return -1;
	}

	private boolean isLinkerModule(String name) {
		return "* Linker *".equals(name);
	}

	//==============================================================================================
	@SuppressWarnings("unused") // for method not being called.
	private boolean processLinkerSymbols() throws CancelledException {

		int linkerModuleNumber = findLinkerModuleNumber();
		if (linkerModuleNumber == -1) {
			return false;
		}

		SymbolGroup symbolGroup = getSymbolGroupForModule(linkerModuleNumber);
		if (symbolGroup == null) {
			Msg.info(this, "No symbols to process from linker module.");
			return false;
		}

		setMonitorMessage("PDB: Applying " + symbolGroup.size() + " linker symbol components...");
		monitor.initialize(symbolGroup.size());

		AbstractMsSymbolIterator iter = symbolGroup.iterator();
		while (iter.hasNext()) {
			checkCanceled();
			pdbApplicatorMetrics.witnessLinkerSymbolType(iter.peek());
			procSym(iter);
			monitor.incrementProgress(1);
		}
		return true;
	}

	//==============================================================================================
	private void processThunkSymbolsFromNonLinkerModules() throws CancelledException {

		int linkerModuleNumber = findLinkerModuleNumber();

		int totalCount = 0;
		int num = pdb.getDatabaseInterface().getNumModules();
		for (int index = 1; index <= num; index++) {
			monitor.checkCanceled();
			if (index == linkerModuleNumber) {
				continue;
			}
			SymbolGroup symbolGroup = getSymbolGroupForModule(index);
			totalCount += symbolGroup.size();
		}
		setMonitorMessage("PDB: Processing module thunks...");
		monitor.initialize(totalCount);

		// Process symbols list for each module
		for (int index = 1; index <= num; index++) {
			monitor.checkCanceled();
			if (index == linkerModuleNumber) {
				continue;
			}
			SymbolGroup symbolGroup = getSymbolGroupForModule(index);
			AbstractMsSymbolIterator iter = symbolGroup.iterator();
			while (iter.hasNext()) {
				monitor.checkCanceled();
				AbstractMsSymbol symbol = iter.peek();
				if (symbol instanceof AbstractThunkMsSymbol) {
					procSym(iter);
				}
				else {
					iter.next();
				}
				monitor.incrementProgress(1);
			}
		}

	}

	//==============================================================================================
	//==============================================================================================
	//==============================================================================================
	AbstractMsSymbolApplier getSymbolApplier(AbstractMsSymbolIterator iter)
			throws CancelledException, NoSuchElementException {
		return symbolApplierParser.getSymbolApplier(iter);
	}

	//==============================================================================================
	void procSym(AbstractMsSymbolIterator iter) throws CancelledException {
		try {
			AbstractMsSymbolApplier applier = getSymbolApplier(iter);
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
		monitor.initialize(isClassByNamespace.size());
		setMonitorMessage("PDB: Defining classes...");
		for (Map.Entry<SymbolPath, Boolean> entry : isClassByNamespace.entrySet()) {
			monitor.checkCanceled();
			SymbolPath path = entry.getKey();
			boolean isClass = entry.getValue();
			Namespace parentNamespace =
				NamespaceUtils.getNonFunctionNamespace(program, path.getParent());
			if (parentNamespace == null) {
				String type = isClass ? "class" : "namespace";
				log.appendMsg("Error: failed to define " + type + ": " + path);
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
				log.appendMsg("Unable to create class namespace due to conflicting symbol: " +
					namespace.getName(true));
			}
			else if (isClass) {
				symbolTable.createClass(parentNamespace, name, SourceType.IMPORTED);
			}
			else {
				symbolTable.createNameSpace(parentNamespace, name, SourceType.IMPORTED);
			}
		}
		catch (Exception e) {
			log.appendMsg("Unable to create class namespace: " + parentNamespace.getName(true) +
				Namespace.DELIMITER + name + " due to exception: " + e.toString());
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
				applicatorOptions.allowDemotePrimaryMangledSymbol()) {
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
	private static final String THUNK_NAME_PREFIX = "[thunk]:";

	boolean createSymbol(Address address, String symbolPathString, boolean forcePrimary) {

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
			log.appendMsg("Unable to create symbol: " + e.getMessage());
		}
		return false;
	}

}
