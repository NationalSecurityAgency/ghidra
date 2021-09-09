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
package ghidra.app.util.bin.format.pdb;

import java.io.*;
import java.util.*;

import org.xml.sax.SAXException;

import docking.widgets.OptionDialog;
import ghidra.app.cmd.label.SetLabelPrimaryCmd;
import ghidra.app.plugin.core.datamgr.archive.DuplicateIdException;
import ghidra.app.plugin.core.datamgr.util.DataTypeArchiveUtility;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.SymbolPath;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.pdb.PdbProgramAttributes;
import ghidra.framework.*;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.XmlUtilities;
import ghidra.xml.*;

/**
 * Contains methods for finding .pdb files and parsing them.
 */
public class PdbParser {

	private static final String PDB_EXE = "pdb.exe";
	private static final String README_FILENAME =
		Application.getInstallationDirectory() + "\\docs\\README_PDB.html";

	static final String STRUCTURE_KIND = "Structure";
	static final String UNION_KIND = "Union";

	public final static boolean onWindows =
		(Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.WINDOWS);

	public enum PdbFileType {
		PDB, XML;

		@Override
		public String toString() {
			return "." + name().toLowerCase();
		}
	}

	private TaskMonitor monitor;

	private final boolean forceAnalysis;
	private final File pdbFile;
	private final boolean isXML;
	private final Program program;
	private DataTypeManager dataMgr;
	private final DataTypeManagerService service;
	private final PdbProgramAttributes programAttributes;
	private Process process;
	private XmlPullParser parser;
	private PdbErrorHandler errHandler;
	private PdbErrorReaderThread thread;
	private boolean parsed = false;
	private boolean allowNonExactMatch;

	private CategoryPath pdbCategory;

	/**
	 * Note that the current implementation relies on having all types which are defined
	 * by the PDB to be available within the dataTypeCache using namespace-based type
	 * names.
	 */
	private PdbDataTypeParser dataTypeParser;
	private Map<SymbolPath, Boolean> namespaceMap = new TreeMap<>(); // false: simple namespace, true: class namespace

	/**
	 * Creates a PdbParser instance.
	 * 
	 * @param pdbFile the pdb file to parse, either .pdb or .pdb.xml
	 * @param program the {@link Program} to modify
	 * @param service {@link DataTypeManagerService}
	 * @param forceAnalysis boolean flag, currently always true, needs to be refactored out 
	 * @param allowNonExactMatch boolean flag, if true skips warning user about mismatch
	 * between the program's PDB guid/id/age and the specified PDB file's guid/id/age, which
	 * can terminate the pdb import in headless  
	 * @param monitor {@link TaskMonitor}, null ok
	 */
	public PdbParser(File pdbFile, Program program, DataTypeManagerService service,
			boolean forceAnalysis, boolean allowNonExactMatch, TaskMonitor monitor) {
		this(pdbFile, program, service, getPdbAttributes(program), forceAnalysis,
			allowNonExactMatch, monitor);
	}

	/**
	 * Creates a PdbParser instance.
	 * 
	 * @param pdbFile the pdb file to parse, either .pdb or .pdb.xml
	 * @param program the {@link Program} to modify
	 * @param service {@link DataTypeManagerService}
	 * @param programAttributes the PDB information specified by the program
	 * @param forceAnalysis boolean flag, currently always true, needs to be refactored out 
	 * @param allowNonExactMatch boolean flag, if true skips warning user about mismatch
	 * between the program's PDB guid/id/age and the specified PDB file's guid/id/age, which
	 * can terminate the pdb import in headless  
	 * @param monitor {@link TaskMonitor}, null ok
	 */
	public PdbParser(File pdbFile, Program program, DataTypeManagerService service,
			PdbProgramAttributes programAttributes, boolean forceAnalysis,
			boolean allowNonExactMatch, TaskMonitor monitor) {
		this.pdbFile = pdbFile;
		this.pdbCategory = new CategoryPath(CategoryPath.ROOT, pdbFile.getName());
		this.program = program;
		this.dataMgr = program.getDataTypeManager();
		this.service = service;
		this.forceAnalysis = forceAnalysis;
		this.monitor = monitor != null ? monitor : TaskMonitor.DUMMY;
		this.isXML = pdbFile.getName().toLowerCase().endsWith(PdbFileType.XML.toString());
		this.programAttributes = programAttributes;
		this.allowNonExactMatch = allowNonExactMatch;
	}

	/**
	 * Get the program's data type manager
	 * @return data type manager
	 */
	DataTypeManager getProgramDataTypeManager() {
		return dataMgr;
	}

	/**
	 * Get the program associated with this parser
	 * @return program
	 */
	Program getProgram() {
		return program;
	}

	/**
	 * Parse the PDB file, enforcing pre-conditions and post-conditions.
	 *
	 * @throws IOException If an I/O error occurs
	 * @throws PdbException  if there was a problem during processing
	 */
	public void parse() throws IOException, PdbException {

		checkPdbLoaded();
		checkFileType();
		checkOSCompatibility();

		if (!forceAnalysis && !programAttributes.isProgramAnalyzed()) {
			throw new PdbException("Before loading a PDB, you must first analyze the program.");
		}

		processPdbContents(false);

		// The below code only applies when we are processing .pdb (not .pdb.xml) files
		if (!isXML) {

			try {//give thread sometime to spin up...
				Thread.sleep(1000);
			}
			catch (Exception e) {
				// don't care
			}

			if (hasErrors()) {
				throw new PdbException(getErrorAndWarningMessages());
			}

			if (hasWarnings()) {
				if (SystemUtilities.isInHeadlessMode()) {
					throw new PdbException(
						getErrorAndWarningMessages() + "..  Skipping PDB processing.");
				}
				int option = OptionDialog.showYesNoDialog(null, "Continue Loading PDB?",
					getErrorAndWarningMessages() + "\n " + "\nContinue anyway?" + "\n " +
						"\nPlease note: Invalid disassembly may be produced!");
				if (option == OptionDialog.OPTION_ONE) {
					cleanup();
					processPdbContents(true);//attempt without validation...
				}
				else {
					throw new PdbException(getErrorAndWarningMessages());
				}
			}
		}
		else { // only for .pdb.xml files.
			verifyPdbSignature();
		}
		parsed = true;
	}

	private void checkFileType() throws PdbException {
		String pdbFilename = pdbFile.getName().toLowerCase();

		if (!pdbFilename.endsWith(PdbFileType.PDB.toString()) &&
			!pdbFilename.endsWith(PdbFileType.XML.toString())) {
			throw new PdbException(
				"\nInvalid file type (expecting .pdb or .pdb.xml): '" + pdbFile.getName() + "'");
		}
	}

	private void checkOSCompatibility() throws PdbException {
		if (!isXML && !onWindows) {
			throw new PdbException(
				"\n.pdb files may only be loaded when running Windows. To load PDBs\n" +
					"on other platforms, use Windows to pre-dump the .pdb file to .pdb.xml\n" +
					"using 'CreatePdbXmlFilesScript.java' or 'createPdbXmlFiles.bat'.");
		}

		if (onWindows && isXML) {
			Msg.warn(this,
				"Could not find .pdb file in the classpath or the given Symbol Repository" +
					" Directory. Using " + pdbFile.getAbsolutePath() + ", instead.");
		}
	}

	private void checkPdbLoaded() throws PdbException {
		if (isPdbLoaded()) {
			throw new PdbException("PDB file has already been loaded.");
		}
	}

	private boolean hasErrors() {
		return thread != null && thread.hasErrors();
	}

	private boolean hasWarnings() {
		return thread != null && thread.hasWarnings();
	}

	private String getErrorAndWarningMessages() {
		return thread == null ? "" : thread.getErrorAndWarningMessages();
	}

	/**
	 * Open Windows Data Type Archives
	 * @throws IOException  if an i/o error occurs opening the data type archive
	 * @throws DuplicateIdException  unexpected archive error
	 */
	public void openDataTypeArchives() throws IOException, DuplicateIdException {

		if (program != null) {
			List<String> archiveList = DataTypeArchiveUtility.getArchiveList(program);
			for (String string : archiveList) {
				service.openDataTypeArchive(string);
			}
		}
		// CLIB .gdt is now part of windows archive
		// NTDDK has not been parsed
	}

	/**
	 * Configures the set of command line arguments for the pdb.exe process
	 * @param noValidation do not ask for GUID/Signature, Age validation
	 * @return the array of arguments for the command line
	 * @throws PdbException if the appropriate set of GUID/Signature, Age values is not available
	 */
	private String[] getCommandLineArray(boolean noValidation) throws PdbException {

		File pdbExeFile;
		String pdbExe = null;
		try {
			pdbExeFile = Application.getOSFile(PDB_EXE);
			pdbExe = pdbExeFile.getAbsolutePath();
		}
		catch (OSFileNotFoundException e) {
			throw new PdbException(e.getMessage());
		}

		if (noValidation) {
			return new String[] { pdbExe, pdbFile.getAbsolutePath() };
		}

		String pdbAge = programAttributes.getPdbAge();
		String pdbGuid = programAttributes.getPdbGuid();
		String pdbSignature = programAttributes.getPdbSignature();
		if (pdbAge != null && pdbGuid != null) {
			return new String[] { pdbExe, pdbFile.getAbsolutePath(), pdbGuid, pdbAge };
		}
		if (pdbAge != null && pdbSignature != null) {
			return new String[] { pdbExe, pdbFile.getAbsolutePath(), pdbSignature, pdbAge };
		}
		throw new PdbException("Unable to determine PDB GUID/Signature or Age. " +
			"Please re-import the executable and try again.");
	}

	private void completeDefferedTypeParsing(ApplyDataTypes applyDataTypes,
			ApplyTypeDefs applyTypeDefs, MessageLog log) throws CancelledException {

		defineClasses(log);

		if (applyDataTypes != null) {
			applyDataTypes.buildDataTypes(monitor);
		}

		if (applyTypeDefs != null) {
			applyTypeDefs.buildTypeDefs(monitor); // TODO: no dependencies exist on TypeDefs (use single pass)
		}

		// Ensure that all data types are resolved
		if (dataTypeParser != null) {
			dataTypeParser.flushDataTypeCache();
		}
	}

	/**
	 * Apply PDB debug information to the current program
	 *
	 * @param log  MessageLog used to record errors
	 * @throws IOException  if an error occurs during parsing
	 * @throws PdbException  if PDB file has already been loaded
	 * @throws CancelledException  if user cancels the current action
	 */
	public void applyTo(MessageLog log) throws IOException, PdbException, CancelledException {
		if (!parsed) {
			throw new IOException("PDB: parse() must be called before applyTo()");
		}

		checkPdbLoaded();

		errHandler.setMessageLog(log);
		Msg.debug(this, "Found PDB for " + program.getName() + ": " + pdbFile);
		try {

			ApplyDataTypes applyDataTypes = null;
			ApplyTypeDefs applyTypeDefs = null;

			boolean typesFlushed = false;

			while (parser.hasNext()) {
				if (hasErrors()) {
					throw new IOException(getErrorAndWarningMessages());
				}
				monitor.checkCanceled();
				XmlElement element = parser.next();
				if (!element.isStart()) {
					continue;
				}
//				long start = System.currentTimeMillis();
				if (element.getName().equals("pdb")) {
					/*
					String exe = element.getAttribute("exe");
					exe = (exe == null ? "" : exe.toLowerCase());
					File exeFile = new File(program.getExecutablePath());
					if (!exeFile.getName().toLowerCase().startsWith(exe)) {
						throw new RuntimeException("'"+pdbFile.getName()+"' not valid for '"+exeFile.getName()+"'");
					}
					*/
				}
				else if (element.getName().equals("enums")) {
					// apply enums - no data type dependencies
					ApplyEnums.applyTo(parser, this, monitor, log);
				}
				else if (element.getName().equals("datatypes")) {
					if (applyDataTypes == null) {
						applyDataTypes = new ApplyDataTypes(this, log);
					}
					applyDataTypes.preProcessDataTypeList(parser, false, monitor);
				}
				else if (element.getName().equals("classes")) {
					if (applyDataTypes == null) {
						applyDataTypes = new ApplyDataTypes(this, log);
					}
					applyDataTypes.preProcessDataTypeList(parser, true, monitor);
				}
				else if (element.getName().equals("typedefs")) {
					applyTypeDefs = new ApplyTypeDefs(this, parser, monitor, log);
				}
				else if (element.getName().equals("functions")) {
					// apply functions (must occur within XML after all type sections)
					if (!typesFlushed) {
						completeDefferedTypeParsing(applyDataTypes, applyTypeDefs, log);
						typesFlushed = true;
					}
					ApplyFunctions.applyTo(this, parser, monitor, log);
				}
				else if (element.getName().equals("tables")) {
					// apply tables (must occur within XML after all other sections)
					if (!typesFlushed) {
						completeDefferedTypeParsing(applyDataTypes, applyTypeDefs, log);
						typesFlushed = true;
					}
					ApplyTables.applyTo(this, parser, monitor, log);
				}
//				Msg.debug(this,
//					element.getName().toUpperCase() + ": " + (System.currentTimeMillis() - start) +
//						" ms");
			}

			if (!typesFlushed) {
				completeDefferedTypeParsing(applyDataTypes, applyTypeDefs, log);
			}

			Options options = program.getOptions(Program.PROGRAM_INFO);
			options.setBoolean(PdbParserConstants.PDB_LOADED, true);

			if (dataTypeParser != null && dataTypeParser.hasMissingBitOffsetError()) {
				log.appendMsg("PDB",
					"One or more bitfields were specified without bit-offset data.\nThe use of old pdb.xml data could be the cause.");
			}
		}
		catch (CancelledException e) {
			throw e;
		}
		catch (Exception e) {
			// Exception could occur if a symbol element is missing an important attribute such
			// as address or length
			String message = e.getMessage();
			if (message == null) {
				message = e.getClass().getSimpleName();
			}
			message = "Problem parsing or applying PDB information: " + message;

			Msg.error(this, message, e);
			throw new IOException(message, e);
		}
		finally {
			cleanup();
		}
		if (hasErrors()) {
			throw new IOException(getErrorAndWarningMessages());
		}
	}

	void predefineClass(String classname) {
		SymbolPath classPath = new SymbolPath(classname);
		namespaceMap.put(classPath, true);
		for (SymbolPath path = classPath.getParent(); path != null; path = path.getParent()) {
			if (!namespaceMap.containsKey(path)) {
				namespaceMap.put(path, false); // path is simple namespace
			}
		}
	}

	private void defineClasses(MessageLog log) throws CancelledException {
		// create namespace and classes in an ordered fashion use tree map
		monitor.setMessage("Define classes...");
		monitor.initialize(namespaceMap.size());
		for (SymbolPath path : namespaceMap.keySet()) {
			monitor.checkCanceled();
			boolean isClass = namespaceMap.get(path);
			Namespace parentNamespace =
				NamespaceUtils.getNonFunctionNamespace(program, path.getParent());
			if (parentNamespace == null) {
				String type = isClass ? "class" : "namespace";
				log.appendMsg("PDB", "Failed to define " + type + ": " + path);
				continue;
			}
			defineNamespace(parentNamespace, path.getName(), isClass, log);
			monitor.incrementProgress(1);
		}
		monitor.initialize(100);
	}

	private void defineNamespace(Namespace parentNamespace, String name, boolean isClass,
			MessageLog log) {

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
				log.appendMsg("PDB",
					"Unable to create class namespace due to conflicting symbol: " +
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
			log.appendMsg("PDB", "Unable to create class namespace: " +
				parentNamespace.getName(true) + Namespace.DELIMITER + name);
		}
	}

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

	/**
	 * If it's a *.pdb file, pass it to the pdb.exe executable and get the stream storing
	 * the XML output.
	 *
	 * If it's a *.xml file, read the file into a stream and verify that the XML GUID/Signature and
	 * age match the program's GUID/Signature and age.
	 *
	 * @param skipValidation true if we should skip checking that GUID/Signature and age match
	 * @throws PdbException If issue running the pdb.exe process
	 * @throws IOException If an I/O error occurs
	 */
	private void processPdbContents(boolean skipValidation) throws PdbException, IOException {
		InputStream in = null;

		if (!isXML) {
			String[] cmd = getCommandLineArray(skipValidation);
			Runtime runtime = Runtime.getRuntime();
			try {

				// Note: we can't use process.waitFor() here, because the result of
				// 'process.getInputStream()' is passed around and manipulated by
				// the parser. In order for .waitFor() to work, the stream needs to
				// be taken care of immediately so that the process can return. Currently,
				// with the process' input stream getting passed around, the call to
				// .waitFor() creates a deadlock condition.

				process = runtime.exec(cmd);
			}
			catch (IOException e) {
				if (e.getMessage().endsWith("14001")) {//missing runtime dlls, probably
					throw new PdbException("Missing runtime libraries. " + "Please refer to " +
						README_FILENAME + " and follow instructions.");
				}
				throw e;
			}

			in = process.getInputStream();

			InputStream err = process.getErrorStream();

			thread = new PdbErrorReaderThread(err);
			thread.start();
		}
		else {
			in = new FileInputStream(pdbFile);
		}

		errHandler = new PdbErrorHandler();

		try {
			parser = XmlPullParserFactory.create(in, pdbFile.getName(), errHandler, false);
		}
		catch (SAXException e) {
			throw new IOException(e.getMessage());
		}
	}

	/**
	 * Check to see if GUID and age in XML file matches GUID/Signature and age of binary
	 *
	 * @throws IOException If an I/O error occurs
	 * @throws PdbException If error parsing the PDB.XML data
	 */
	private void verifyPdbSignature() throws IOException, PdbException {

		XmlElement xmlelem;

		try {
			xmlelem = parser.peek();
		}
		catch (Exception e) {
			if (!isXML) {
				if (hasErrors()) {
					throw new PdbException(getErrorAndWarningMessages());
				}
				throw new PdbException("PDB Execution failure of " + PDB_EXE + ".\n" +
					"This was likely caused by severe execution failure which can occur if executed\n" +
					"on an unsupported platform. It may be necessary to rebuild the PDB executable\n" +
					"for your platform (see Ghidra/Features/PDB/src).");
			}
			throw new PdbException("PDB parsing problem: " + e.getMessage());
		}

		if (!"pdb".equals(xmlelem.getName())) {
			throw new PdbException("Unexpected PDB XML element: " + xmlelem.getName());
		}

		String xmlGuid = xmlelem.getAttribute("guid");
		String xmlAge = xmlelem.getAttribute("age");

		String warning = "";
		String pdbGuid = programAttributes.getPdbGuid();

		if (pdbGuid == null) {
			String pdbSignature = programAttributes.getPdbSignature();
			if (pdbSignature != null) {
				pdbGuid = reformatSignatureToGuidForm(pdbSignature);
			}
		}

		String pdbAge = programAttributes.getPdbAge();

		if ((xmlGuid == null) || (pdbGuid == null)) {

			if (xmlGuid == null) {
				warning += "No GUID was listed in the XML file.";
			}

			if (pdbGuid == null) {
				warning += " Could not find a PDB GUID for the binary.";
			}

			warning += " Could not complete verification of matching PDB signatures.";
		}
		else {
			// Reformat PDB GUID so that it matches the way GUIDs are stored in XML
			pdbGuid = pdbGuid.toUpperCase();
			pdbGuid = "{" + pdbGuid + "}";

			if (!allowNonExactMatch) {
				if (!xmlGuid.equals(pdbGuid)) {
					warning = "PDB signature does not match.\n" + "Program GUID: " + pdbGuid +
						"\nXML GUID: " + xmlGuid;
				}
				else {
					// Also check that PDB ages match, if they are both available
					if ((xmlAge != null) && (pdbAge != null)) {

						int pdbAgeDecimal = Integer.parseInt(pdbAge, 16);
						int xmlAgeDecimal = Integer.parseInt(xmlAge);

						if (xmlAgeDecimal != pdbAgeDecimal) {
							warning = "PDB ages do not match.";
						}
					}
				}
			}
		}

		if (warning.length() > 0) {
			if (SystemUtilities.isInHeadlessMode()) {
				throw new PdbException(warning + ".. Skipping PDB processing.");
			}
			int option = OptionDialog.showYesNoDialog(null, "Continue Loading PDB?",
				warning + "\n " + "\nContinue anyway?" + "\n " +
					"\nPlease note: Invalid disassembly may be produced!");
			if (option != OptionDialog.OPTION_ONE) {
				throw new PdbException(warning);
			}
		}
	}

	/**
	 * Translate signature to GUID form. A signature is usually 8 characters long. A GUID
	 * has 32 characters and its subparts are separated by '-' characters.
	 *
	 * @param pdbSignature signature for conversion
	 * @return reformatted String
	 */
	private String reformatSignatureToGuidForm(String pdbSignature) {
		// GUID structure (32 total hex chars):
		//  {8 hex}-{4 hex}-{4 hex}-{4 hex}-{12 hex}
		//
		// If PDB signature is less than 32 chars, make up the rest in 0's.
		// If > 32 chars (which it should never be), just truncate to 32 chars
		if (pdbSignature.length() > 32) {
			pdbSignature = pdbSignature.substring(0, 32);
		}

		StringBuilder builder = new StringBuilder(pdbSignature);
		for (int i = pdbSignature.length(); i < 32; i++) {
			builder = builder.append('0');
		}

		// Insert '-' characters at the right boundaries
		builder = builder.insert(8, '-').insert(13, '-').insert(18, '-').insert(23, '-');
		return builder.toString();
	}

	/**
	 * Checks if PDB has been loaded in the program
	 *
	 * @return whether PDB has been loaded or not
	 */
	public boolean isPdbLoaded() {
		return programAttributes.isPdbLoaded();
	}

	// TODO: verify this method is necessary
	private void cleanup() {
		if (process != null) {
			process.destroy();
			process = null;
		}
		if (parser != null) {
			parser.dispose();
			parser = null;
		}
		//errHandler = null;
		//thread = null;
		if (dataTypeParser != null) {
			dataTypeParser.clear();
		}
	}

	boolean isCorrectKind(DataType dt, PdbKind kind) {
		if (kind == PdbKind.STRUCTURE) {
			return (dt instanceof Structure);
		}
		else if (kind == PdbKind.UNION) {
			return (dt instanceof Union);
		}
		return false;
	}

	Composite createComposite(PdbKind kind, String name) {
		if (kind == PdbKind.STRUCTURE) {
			return createStructure(name, 0);
		}
		else if (kind == PdbKind.UNION) {
			return createUnion(name);
		}
		throw new IllegalArgumentException("unsupported kind: " + kind);
	}

	Structure createStructure(String name, int length) {
		SymbolPath path = new SymbolPath(name);
		return new StructureDataType(getCategory(path.getParent(), true), path.getName(), length,
			dataMgr);
	}

	Union createUnion(String name) {
		SymbolPath path = new SymbolPath(name);
		return new UnionDataType(getCategory(path.getParent(), true), path.getName(), dataMgr);
	}

	TypedefDataType createTypeDef(String name, DataType baseDataType) {
		SymbolPath path = new SymbolPath(name);
		return new TypedefDataType(getCategory(path.getParent(), true), path.getName(),
			baseDataType, dataMgr);
	}

	EnumDataType createEnum(String name, int length) {
		SymbolPath path = new SymbolPath(name);
		// Ghidra does not like size of zero.
		length = Integer.max(length, 1);
		return new EnumDataType(getCategory(path.getParent(), true), path.getName(), length,
			dataMgr);
	}

	void createString(boolean isUnicode, Address address, MessageLog log) {
		DataType dataType = isUnicode ? new UnicodeDataType() : new StringDataType();
		createData(address, dataType, log);
	}

	void createData(Address address, String datatype, MessageLog log) throws CancelledException {
		WrappedDataType wrappedDt = getDataTypeParser().findDataType(datatype);
		if (wrappedDt == null) {
			log.appendMsg("PDB", "Failed to resolve datatype " + datatype + " at " + address);
		}
		else if (wrappedDt.isZeroLengthArray()) {
			Msg.debug(this, "Did not apply zero length array data " + datatype + " at " + address);
		}
		else {
			createData(address, wrappedDt.getDataType(), log);
		}
	}

	void createData(Address address, DataType dataType, MessageLog log) {
		DumbMemBufferImpl memBuffer = new DumbMemBufferImpl(program.getMemory(), address);
		DataTypeInstance dti = DataTypeInstance.getDataTypeInstance(dataType, memBuffer);
		if (dti == null) {
			log.appendMsg("PDB",
				"Failed to apply datatype " + dataType.getName() + " at " + address);
		}
		else {
			createData(address, dti.getDataType(), dti.getLength(), log);
		}
	}

	private void createData(Address address, DataType dataType, int dataTypeLength,
			MessageLog log) {

		// Ensure that we do not clear previously established code and data
		Data existingData = null;
		CodeUnit cu = program.getListing().getCodeUnitContaining(address);
		if (cu != null) {
			if ((cu instanceof Instruction) || !address.equals(cu.getAddress())) {
				log.appendMsg("PDB", "Did not create data type \"" + dataType.getDisplayName() +
					"\" at address " + address + " due to conflict");
				return;
			}
			Data d = (Data) cu;
			if (d.isDefined()) {
				existingData = d;
			}
		}

		if (dataType == null) {
			return;
		}
		if (dataType.getLength() <= 0 && dataTypeLength <= 0) {
			log.appendMsg("PDB", "Unknown dataTypeLength specified at address " + address +
				" for " + dataType.getName());
			return;
		}

		// TODO: This is really bad logic and should be refactored
		// All conflicting data, not just the one containing address,
		// needs to be considered and not blindly cleared.

		if (existingData != null) {
			DataType existingDataType = existingData.getDataType();
			if (isEquivalent(existingData, existingData.getLength(), dataType)) {
				return;
			}
			if (isEquivalent2(existingDataType, dataType)) {
				return;
			}
			if (existingDataType.isEquivalent(dataType)) {
				return;
			}
		}
		Listing listing = program.getListing();
		if (existingData == null) {
			try {
				listing.clearCodeUnits(address, address.add(dataTypeLength - 1), false);
				if (dataType.getLength() == -1) {
					listing.createData(address, dataType, dataTypeLength);
				}
				else {
					listing.createData(address, dataType);
				}
			}
			catch (Exception e) {
				log.appendMsg("PDB", "Unable to create " + dataType.getDisplayName() + " at 0x" +
					address + ": " + e.getMessage());
			}
		}
		else if (isDataReplaceable(existingData)) {
			try {
				listing.clearCodeUnits(address, address.add(dataTypeLength - 1), false);
				listing.createData(address, dataType, dataTypeLength);
			}
			catch (Exception e) {
				log.appendMsg("PDB", "Unable to replace " + dataType.getDisplayName() + " at 0x" +
					address + ": " + e.getMessage());
			}
		}
		else {
			DataType existingDataType = existingData.getDataType();
			String existingDataTypeString =
				existingDataType == null ? "null" : existingDataType.getDisplayName();
			log.appendMsg("PDB",
				"Did not create data type \"" + dataType.getDisplayName() + "\" at address " +
					address + ".  Preferring existing datatype \"" + existingDataTypeString + "\"");
		}
	}

	private boolean isDataReplaceable(Data data) {
		DataType dataType = data.getDataType();
		if (dataType instanceof Pointer) {
			Pointer pointer = (Pointer) dataType;
			DataType pointerDataType = pointer.getDataType();
			if (pointerDataType == null || pointerDataType.isEquivalent(DataType.DEFAULT)) {
				return true;
			}
		}
		else if (dataType instanceof Array) {
			Array array = (Array) dataType;
			DataType arrayDataType = array.getDataType();
			if (arrayDataType == null || arrayDataType.isEquivalent(DataType.DEFAULT)) {
				return true;
			}
		}

		// All forms of Undefined data are replaceable
		// TODO: maybe it should check the length of the data type before putting it down.
		if (Undefined.isUndefined(dataType)) {
			return true;
		}
		return false;
	}

	private boolean isEquivalent(Data existingData, int existingDataTypeLength,
			DataType newDataType) {
		if (existingData.hasStringValue()) {
			if (newDataType instanceof ArrayDataType) {
				Array array = (Array) newDataType;
				DataType arrayDataType = array.getDataType();
				if (arrayDataType instanceof ArrayStringable) {
					if (array.getLength() == existingDataTypeLength) {
						return true;
					}
				}
			}
		}
		return false;
	}

	/**
	 * "char[12] *"   "char * *"
	 *
	 * "ioinfo * *"   "ioinfo[64] *"
	 */
	private boolean isEquivalent2(DataType datatype1, DataType datatype2) {

		if (datatype1 == datatype2) {
			return true;
		}

		if (datatype1 == null || datatype2 == null) {
			return false;
		}

		if (datatype1 instanceof Array) {
			Array array1 = (Array) datatype1;
			if (datatype2 instanceof Array) {
				Array array2 = (Array) datatype2;
				return isEquivalent2(array1.getDataType(), array2.getDataType());
			}
		}
		else if (datatype1 instanceof Pointer) {
			Pointer pointer1 = (Pointer) datatype1;
			if (datatype2 instanceof Array) {
				Array array2 = (Array) datatype2;
				return isEquivalent2(pointer1.getDataType(), array2.getDataType());
			}
		}
		return datatype1.isEquivalent(datatype2);
	}

	boolean createSymbol(Address address, String symbolPathString, boolean forcePrimary,
			MessageLog log) {

		try {
			Namespace namespace = program.getGlobalNamespace();
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
			log.appendMsg("PDB", "Unable to create symbol at " + address + ": " + e.getMessage());
		}
		return false;
	}

//	DataType createPointer(DataType dt) {
//		return PointerDataType.getPointer(dt, program.getDataTypeManager());
//	}

//	DataType getCachedDataType(String key) {
//		return dataTypeCache.get(key);
//	}
//
//	void cacheDataType(String key, DataType dataType) {
//		dataTypeCache.put(key, dataType);
//	}

	/**
	 * Get the PDB root category path
	 * @return PDB root category path
	 */
	CategoryPath getCategory() {
		return pdbCategory;
	}

	/**
	 * Get the name with any namespace stripped
	 * @param name name with optional namespace prefix
	 * @return name without namespace prefix
	 */
	String stripNamespace(String name) {
		int index = name.lastIndexOf(Namespace.DELIMITER);
		if (index <= 0) {
			return name;
		}
		return name.substring(index + Namespace.DELIMITER.length());
	}

	/**
	 * Get the category path associated with the namespace qualified data type name
	 * @param namespaceQualifiedDataTypeName data type name
	 * @param addPdbRoot true if PDB root category should be used, otherwise it will be omitted
	 * @return the category path
	 */
	CategoryPath getCategory(String namespaceQualifiedDataTypeName, boolean addPdbRoot) {
		String[] names = namespaceQualifiedDataTypeName.split(Namespace.DELIMITER);
		CategoryPath category = addPdbRoot ? pdbCategory : CategoryPath.ROOT;
		if (names.length > 1) {
			String[] categoryNames = new String[names.length - 1];
			System.arraycopy(names, 0, categoryNames, 0, categoryNames.length);
			for (String c : categoryNames) {
				category = new CategoryPath(category, c);
			}
		}
		return category;
	}

	/**
	 * Get the {@link CategoryPath} associated with the namespace specified by the
	 * {@link SymbolPath}, rooting it either at the Category Path root or the PDB Category.
	 * @param symbolPath the {@link SymbolPath} input; can be null if no depth in path.
	 * @param addPdbRoot True if PDB root category should be used, otherwise it will be omitted.
	 * @return {@link CategoryPath} created for the input.
	 */
	CategoryPath getCategory(SymbolPath symbolPath, boolean addPdbRoot) {
		CategoryPath category = addPdbRoot ? pdbCategory : CategoryPath.ROOT;
		if (symbolPath != null) {
			List<String> names = symbolPath.asList();
			for (String name : names) {
				category = new CategoryPath(category, name);
			}
		}
		return category;
	}

	/********************************************************************/
	/*   STATIC METHODS                                                 */
	/********************************************************************/

	/**
	 * Get the object that stores PDB-related attributes for the program.
	 *
	 * @param program  program for which to find a matching PDB
	 * @return PDBProgramAttributes object associated with the program
	 */
	public static PdbProgramAttributes getPdbAttributes(Program program) {
		return new PdbProgramAttributes(program);
	}

	/**
	 * Determine if the PDB has previously been loaded for the specified program.
	 * @param program  program for which to find a matching PDB
	 * @return true if PDB has already been loaded
	 */
	public static boolean isAlreadyLoaded(Program program) {
		return getPdbAttributes(program).isPdbLoaded();
	}

	PdbDataTypeParser getDataTypeParser() {
		if (program == null) {
			throw new AssertException("Parser was not constructed with program");
		}
		if (dataTypeParser == null) {
			dataTypeParser = new PdbDataTypeParser(program.getDataTypeManager(), service, monitor);
		}
		return dataTypeParser;
	}

	void cacheDataType(String name, DataType dataType) {
		getDataTypeParser().cacheDataType(name, dataType);
	}

	DataType getCachedDataType(String name) {
		return getDataTypeParser().getCachedDataType(name);
	}

	WrappedDataType findDataType(String dataTypeName) throws CancelledException {
		return getDataTypeParser().findDataType(dataTypeName);
	}

	public PdbMember getPdbXmlMember(XmlTreeNode node) {
		return new PdbXmlMember(node);
	}

	public PdbXmlMember getPdbXmlMember(XmlElement element) {
		return new PdbXmlMember(element);
	}

	class PdbXmlMember extends DefaultPdbMember {

		PdbXmlMember(XmlTreeNode node) {
			this(node.getStartElement());
		}

		PdbXmlMember(XmlElement element) {
			super(SymbolUtilities.replaceInvalidChars(element.getAttribute("name"), false),
				SymbolUtilities.replaceInvalidChars(element.getAttribute("datatype"), false),
				XmlUtilities.parseInt(element.getAttribute("offset")),
				PdbKind.parse(element.getAttribute("kind")), getDataTypeParser());
		}
	}

}
