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
package ghidra.app.util.pdb;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.*;

import docking.widgets.OptionDialog;
import ghidra.app.util.bin.format.pdb.PdbParserConstants;
import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.app.util.datatype.microsoft.GUID;
import ghidra.app.util.importer.LibrarySearchPathManager;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.OperatingSystem;
import ghidra.framework.Platform;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Searches for and presents PDB path information in order specified by
 * <a href="https://docs.microsoft.com/en-us/windows/desktop/debug/symbol-paths">
 * Symbol Paths</a>.
 * <P>
 * Gist is: TODO.
 * <PRE>
 * Our design:
 *   Looking for files with extension .pdb or .PDB using an ordered set of paths and resources. 
 *   
 *   TODO:
 *   Option to look exclusively for the above, exclusively for something else, or inclusive of
 *    other extensions with a preference order.  So if we want to inclusively look for .pdb
 *    and .pdb.xml with a preference of .pdb, and if we have a path search order of path A,
 *    then path B, the question is whether we would choose a .pdb file in path B before a .pdb.xml
 *    in path A.  Same question for other extensions such as .dbg.
 *    
 *   Could do similar to SymSetSearchPath() with semicolon-separated paths.
 *   
 *   Could have an configuration list that gives the search order for all resources to be searched.
 *    For instance: path of the loaded executable, path specified in header of loaded executable,
 *    local symbol paths, symbol servers at specified URLs.
 *    -> Could allow any of these to not be active; could require optional user interaction ("are
 *       you sure") for the path specified in the header of the loaded executable, option of read
 *       and/or write to local symbol cache.
 *   
 *   Depending on whether is or used to be supported by MSFT, allow (with option?) the 2-tier
 *    symbol server directory structure.
 *    
 *   Should we allow different or use different structures for local paths vs. symbol server paths?
 *    For instance, the extension-tier (if *.dll, search an appropriate set of paths that have a
 *    "dll" component). 
 *   
 * </PRE>
 */
public class PdbLocator {

	public static final boolean onWindows =
		(Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.WINDOWS);

	private static final File USER_HOME = new File(System.getProperty("user.home"));
	public static final File DEFAULT_SYMBOLS_DIR =
		onWindows ? new File("C:\\Symbols") : new File(USER_HOME, "Symbols");
	public final static File WINDOWS_SYMBOLS_DIR =
		onWindows ? new File("C:/WINDOWS/Symbols") : null;

	public final static String PDB_SYMBOLS_DIR_PREFERENCE = "PDB Storage Directory";

	private File symbolsRepositoryDir;
	/**
	 * Only holds identifies in PDBs up until a matching one was found--nothing beyond that.
	 */
	private Map<String, PdbIdentifiers> identifiersByFilePath = new HashMap<>();

	public PdbLocator(File symbolsRepositoryDir) {
		this.symbolsRepositoryDir = symbolsRepositoryDir;
	}

	//==============================================================================================
	// TODO: Ideas for future.
//	public SymbolPathSearcher(String message) {
//	}

	// Search order preference:
	//   EXTENSION_PREFERENCE_ORDER(pdb, pdb.xml, dbg)--at least one; no duplicates
	//      e.g., {PDB, PDB_XML, DBG} means *.pdb before *.pdb.xml before *.dbg
	//   PATH_BEFORE_EXTENSION or EXTENSION_BEFORE_PATH
	//      e.g.,
	//        PATH_BEFORE_EXTENSION means: (assuming EXTENION_PREFERENCE_ORDER is {PDB, PDB_XML}),
	//          at first path in list look for *.pdb, then *.pdb.xml, then if failed to
	//          find at the first path, try the same tWO ordered searches at the second path in
	//          the path list, etc.
	//        EXTENSION_BEFORE_PATH means: (assuming EXTENION_PREFERENCE_ORDER is {PDB, PDB_XML}),
	//          at first path in list look for *.pdb, then search for *.pdb at the second path, etc.
	//          If after the last path a *.pdb is not found, then repeat with list of paths, now
	//          looking for *.pdb.xml

	// Use a list of enums to specify search order?
	// queryUser true if can interact with user (non-headless)

	// need paths for symbol server vs. paths for local cache?

	// specify filetype (pdb, pdb.xml, dbg, other?)

	// upper/lower case conversion

//	public void find(boolean includePeSpecifiedPdbPath, boolean queryUser) {
//	}

	//==============================================================================================
	/*
	 * TODO 20190403: Need to consider documentation at 
	 * <a href="https://docs.microsoft.com/en-us/windows/desktop/debug/symbol-paths">
	 * Symbol Paths</a>.
	 * <P>
	 * Says order:
	 * <li>C:\MySymbols
	 * <li>C:\MySymbols\ext, where ext is extension of binary (e.g., dll, exe, sys)
	 * <li>C:\MySymbols\symbols\ext
	 * <P>
	 */
	// 20190321 Thoughts for fixing this up:
	// Processing logic:
	//
	//   Tenet: Program may or may not specify the following about an associated PDB:
	//     - filename of PDB
	//     - version (magic: RSDS)
	//     - signature
	//     - age
	//     - GUID (probably only in later versions)
	//
	//   Tenet: PDB files may or may not specify the following about themselves:
	//     - version (date field indicating PDB version; also versioning dates of subcomponents)
	//     - signature
	//     - age
	//     - GUID (only in later versions)
	//
	//   Tenet: Can be headed (GUI) or headless processing
	//
	//   Logic Basics:
	//     - Need at least the filename.
	//     - No user interaction if headless.
	//
	//   Use cases:
	//     - Given Program PDB info, search/find matching PDB, and apply all possible; else fail
	//     - Given Program PDB info, if matching PDB not found, but similar exist, present
	//        all possibles to user for choice or cancel.  Choice would include the filename
	//        location along with the basic information pieces indicated above.  Option to
	//        apply data types only (to a DataTypeManager) or to additionally apply symbols.
	//        (Could dig into each PDB for possible compile information, but requires full
	//        parsing.)  Future may allow for a way to bring in symbol information into a
	//        temporary space that could allow the user to selectively choose symbols to apply
	//        to Program locations.
	//     - Given Program PDB info, if headless and exact match not found, option flag to fail
	//        with no information or to fail with the filenames and associated basic info.
	//     - Regardless of PDB info, if headless use "force" option with a single filename,
	//        which will force parsing and application of PDB file.  (No option to force
	//        partially apply any parts of the PDB--think on this more.)
	//   Additional use cases:
	//     - Any PDB file can be loaded for general perusing (maybe).
	//     - Multiple PDB files can be loaded at any given time.
	//     - Multiple PDB files can have been loaded and had their data type processed and put
	//        into data type Categories labeled with the PDB information (might need GUID
	//        and other attributes used to help uniquely identify each (perhaps part of the
	//        Category name)).  Perhaps the symbols for each PDB are available--perhaps just
	//        have each PDB available for further symbol/data type application.
	//
	//   Today's Logic:
	public String findPdb(Program program, PdbProgramAttributes programAttributes,
			boolean userInteractive, boolean includePeSpecifiedPdbPath, TaskMonitor monitor,
			MessageLog log, String messagePrefix) throws CancelledException {

		List<String> orderedListOfExistingFileNames =
			lookForPdb(program, includePeSpecifiedPdbPath, log, messagePrefix);
		if (orderedListOfExistingFileNames.isEmpty()) {
			String message = "Cannot find candidate PDB files.";
			log.appendMsg(messagePrefix, message);
			return null;
		}

		String pdbFilename = null;
		try {
			pdbFilename = choosePdb(orderedListOfExistingFileNames, programAttributes, monitor, log,
				messagePrefix);
		}
		catch (PdbException e) {
			String message = "Could not find appropriate PDB file.  Detailed issues may follow:\n" +
				e.toString();
			log.appendMsg(messagePrefix, message);
			return null;
		}

		return pdbFilename;
	}

	//==============================================================================================
	/**
	 * @param program Program under analysis.
	 * @param includePeSpecifiedPdbPath {@code true} if looking for PDB in PE-Header-Specified
	 * path location, which may be unsafe security-wise.
	 * @param log MessageLog to report to.
	 * @param messagePrefix prefix string for any error message written to the log
	 * @return Ordered List<String> of potential filenames
	 */
	private List<String> lookForPdb(Program program, boolean includePeSpecifiedPdbPath,
			MessageLog log, String messagePrefix) {
		String message = "";
		try {

			List<String> orderedListOfExistingFileNames = findPDB(new PdbProgramAttributes(program),
				includePeSpecifiedPdbPath, symbolsRepositoryDir);
			if (orderedListOfExistingFileNames.isEmpty()) {

				String pdbName = program.getOptions(Program.PROGRAM_INFO)
						.getString(PdbParserConstants.PDB_FILE, (String) null);
				if (pdbName == null) {
					message = "Program has no associated PDB file.";
				}
				else {
					message = "Unable to locate PDB file \"" + pdbName + "\" with matching GUID.";
				}
				if (SystemUtilities.isInHeadlessMode()) {
					message += "\n Use a script to set the PDB Symbol Location. I.e.,\n" +
						"    setAnalysisOption(currentProgram, \"PDB.Symbol Repository Path\", " +
						"\"/path/to/pdb/folder\");\n" +
						" This must be done using a pre-script (prior to analysis).";
				}
				else {
					message +=
						"\n You can manually load PDBs using the \"File->Load PDB File...\" action.";
					if (pdbName != null) {
						message += "\n Alternatively, you may set the PDB Symbol Repository Path" +
							"\n using \"Edit->Options for [program]\" prior to analysis.";
					}
				}
			}
			return orderedListOfExistingFileNames;
		}
		catch (PdbException pe) {
			message += pe.getMessage();
		}
		finally {
			if (message.length() > 0) {
				log.appendMsg(messagePrefix, message);
				log.setStatus(message);
			}
		}

		return null;
	}

	//==============================================================================================
	private String choosePdb(List<String> orderedListOfExistingFileNames,
			PdbProgramAttributes programAttributes, TaskMonitor monitor, MessageLog log,
			String messagePrefix) throws PdbException, CancelledException {
		String choice = findMatchingPdb(orderedListOfExistingFileNames, programAttributes, monitor);
		if (choice == null) {
			//choice = userSelectPdb(programAttributes, messagePrefix, log, monitor);
			String message = getNoMatchMessage(programAttributes, monitor);
			log.appendMsg(message);
		}
		return choice;
	}

	//==============================================================================================
	private String findMatchingPdb(List<String> orderedListOfExistingFileNames,
			PdbProgramAttributes programAttributes, TaskMonitor monitor)
			throws PdbException, CancelledException {

		String message = "";

		for (String filepath : orderedListOfExistingFileNames) {
			monitor.checkCanceled();
			monitor.setMessage("Attempting to find/process PDB file " + filepath + "...");
			try (AbstractPdb tryPdb = PdbParser.parse(filepath, new PdbReaderOptions(), monitor)) {
				PdbIdentifiers identifiers = tryPdb.getIdentifiers();
				identifiersByFilePath.put(filepath, identifiers);
				if (verifyPdbSignature(programAttributes, identifiers)) {
					monitor.setMessage("Parsing validated PDB file " + filepath + ".");
					return filepath;
				}
			}
			catch (Exception e) {
				// Ignore FileNotFoundException.
				if (!e.getClass().equals(FileNotFoundException.class)) {
					// Noting any exceptions.  Will only report if we have not successfully
					//  found a matching PDB without an exception being thrown for it.
					message += "Exception for attempted PDB " + filepath + ": " + e.toString();
				}
			}
		}
		if (!message.isEmpty()) {
			throw new PdbException(message);
		}
		return null;
	}

	//==============================================================================================
	@SuppressWarnings("unused") // for method not being called.
	private String userSelectPdb(PdbProgramAttributes programAttributes, String messagePrefix,
			MessageLog log, TaskMonitor monitor) throws CancelledException {

		String[] fileNames = new String[identifiersByFilePath.size()];
		String[] fileIdents = new String[identifiersByFilePath.size()];
		int i = 0;
		for (Map.Entry<String, PdbIdentifiers> entry : identifiersByFilePath.entrySet()) {
			monitor.checkCanceled();
			fileNames[i] = entry.getKey();
			fileIdents[i++] = formatPdbIdentifiers(entry.getKey(), entry.getValue()).toString();
		}

		String message = "Could not match program with PDB.\n";
		if (identifiersByFilePath.size() != 0) {
			message += "PDB File Options (Name Signature Age GUID):\n";
			for (String fileIdent : fileIdents) {
				message += fileIdent + "\n";
			}
		}

		if (SystemUtilities.isInHeadlessMode()) {
			message = "In Headless mode... skipping PDB processing.\n";
			log.appendMsg(messagePrefix, message);
			log.setStatus(message);
			return null;
		}
		String header =
			"Choose PDB or Cancel (for: " + formatPdbIdentifiers(programAttributes) + ")";
		String userChoice = OptionDialog.showInputChoiceDialog(null, header, "Choose", fileIdents,
			fileIdents[0], OptionDialog.CANCEL_OPTION);
		if (userChoice == null) {
			return null;
		}
		for (i = 0; i < fileIdents.length; i++) {
			if (userChoice.contentEquals(fileIdents[i])) {
				message = "User PDB Choice: " + userChoice;
				Msg.info(this, message); // Info for console.
				return fileNames[i];
			}
		}
		return null;
	}

	//==============================================================================================
	private String getNoMatchMessage(PdbProgramAttributes programAttributes, TaskMonitor monitor)
			throws CancelledException {
		StringBuilder builder = new StringBuilder();
		builder.append("ERROR: Could not run PDB Analyzer because a matched PDB was not found.\n");
		builder.append("PDB specification from PE header:\n");
		builder.append(formatPdbIdentifiers(programAttributes));

		builder.append("Discovered non-matches:\n");
		for (Map.Entry<String, PdbIdentifiers> entry : identifiersByFilePath.entrySet()) {
			monitor.checkCanceled();
			builder.append(formatPdbIdentifiers(entry.getKey(), entry.getValue()));
		}
		return builder.toString();
	}

	public static StringBuilder formatPdbIdentifiers(PdbProgramAttributes attributes) {
		Integer signature = (attributes.getPdbSignature() == null) ? null
				: Integer.valueOf(attributes.getPdbSignature());
		return formatPdbIdentifiers(attributes.getPdbFile(), signature,
			Integer.valueOf(attributes.getPdbAge(), 16), attributes.getPdbGuid());
	}

	public static StringBuilder formatPdbIdentifiers(String file, PdbIdentifiers identifiers) {
		return formatPdbIdentifiers(file, identifiers.getSignature(), identifiers.getAge(),
			identifiers.getGuid().toString());
	}

	private static StringBuilder formatPdbIdentifiers(String file, Integer signature, int age,
			String guidString) {
		StringBuilder builder = new StringBuilder();
		builder.append("  Location: ").append(file);
		if (signature != null) {
			builder.append(String.format("; Signature: 0X%08X", signature));
		}
		builder.append("; Age: 0x");
		builder.append(Integer.toHexString(age));
		if (guidString != null) {
			builder.append("; GUID: ");
			builder.append(guidString);
		}
		builder.append('\n');
		return builder;
	}

	//==============================================================================================
	/**
	 * Find a matching PDB file using attributes associated with the program. User can specify the
	 * type of file to search from (.pdb or .pdb.xml).
	 *
	 * @param pdbAttributes  PDB attributes associated with the program.
	 * @param includePeSpecifiedPdbPath {@code true} if looking for PDB in PE-Header-Specified
	 * path location, which may be unsafe security-wise.
	 * @param symbolsRepositoryDir Location of the local symbols repository (can be null).
	 * @return matching PDB file (or null, if not found).
	 * @throws PdbException if there was a problem with the PDB attributes.
	 */
	private static List<String> findPDB(PdbProgramAttributes pdbAttributes,
			boolean includePeSpecifiedPdbPath, File symbolsRepositoryDir) throws PdbException {

		// Store potential names of PDB files and potential locations of those files,
		// so that all possible combinations can be searched.
		// LinkedHashSet is used when we need to preserve order
		Set<String> guidSubdirPaths = new HashSet<>();

		String guidAgeString = pdbAttributes.getGuidAgeCombo();
		if (guidAgeString == null) {
			throw new PdbException(
				"Incomplete PDB information (GUID/Signature and/or age) associated with this program.\n" +
					"Either the program is not a PE, or it was not compiled with debug information.");
		}

		List<String> potentialPdbNames = pdbAttributes.getPotentialPdbFilenames();
		for (String potentialName : potentialPdbNames) {
			guidSubdirPaths.add(File.separator + potentialName + File.separator + guidAgeString);
		}

		return checkPathsForPdb(symbolsRepositoryDir, guidSubdirPaths, potentialPdbNames,
			pdbAttributes, includePeSpecifiedPdbPath);
	}

	//==============================================================================================
	/**
	 * Check potential paths in a specific order. If the symbolsRepositoryPath parameter is
	 * supplied and the directory exists, that directory will be searched first for the
	 * matching PDB file.
	 *
	 * If the file type is supplied, then only that file type will be searched for. Otherwise,
	 * the search process depends on the current operating system that Ghidra is running from:
	 *
	 *  - Windows: look in the symbolsRepositoryPath for a matching .pdb file. If one does not
	 *  		exist, look for a .pdb.xml file in symbolsRepositoryPath. If not found, then
	 *  		search for a matching .pdb file, then .pdb.xml file, in other directories.
	 *  - non-Windows: look in the symbolsRepositoryPath for a matching .pdb.xml file. If one does
	 *  		not exist, look for a .pdb file. If a .pdb file is found, return an error saying
	 *  		that it was found, but could not be processed. If no matches found in
	 *  		symbolsRepositoryPath, then look for .pdb.xml file, then .pdb.xml file in other
	 *  		directories.
	 *
	 * @param symbolsRepositoryDir  location of the local symbols repository (can be null)
	 * @param guidSubdirPaths  subdirectory paths (that include the PDB's GUID) that may contain
	 * 							a matching PDB
	 * @param potentialPdbNames  all potential filenames for the PDB file(s) that match the program
	 * @param pdbAttributes    PDB attributes associated with the program
	 * @param includePeSpecifiedPdbPath if true include paths derived from the PDB file path 
	 * determined at time of import.  NOTE: This option is considered unsafe and should not be
	 * enabled unless binary source is trusted and PDB file path is reasonable for this system.
	 * @return  matching PDB file, if found (else null)
	 */
	private static List<String> checkPathsForPdb(File symbolsRepositoryDir,
			Set<String> guidSubdirPaths, List<String> potentialPdbNames,
			PdbProgramAttributes pdbAttributes, boolean includePeSpecifiedPdbPath) {

		Set<File> symbolsRepoPaths =
			getSymbolsRepositoryPaths(symbolsRepositoryDir, guidSubdirPaths);
		Set<File> predefinedPaths =
			getPredefinedPaths(guidSubdirPaths, pdbAttributes, includePeSpecifiedPdbPath);

		// Start by searching in symbolsRepositoryDir, if available.

		List<String> orderedListOfExistingFileNames = new ArrayList<>();
		if (!symbolsRepoPaths.isEmpty()) {
			orderedListOfExistingFileNames
					.addAll(checkSpecificPathsForPdb(symbolsRepoPaths, potentialPdbNames));
		}

		orderedListOfExistingFileNames
				.addAll(checkSpecificPathsForPdb(predefinedPaths, potentialPdbNames));

		return orderedListOfExistingFileNames;

	}

	//==============================================================================================
	private static List<String> checkSpecificPathsForPdb(Set<File> paths,
			List<String> potentialPdbNames) {

		List<String> orderedListOfExistingFileNames = checkForPDBorXML(paths, potentialPdbNames);

		return orderedListOfExistingFileNames;
	}

	//==============================================================================================
	private static Set<File> getSymbolsRepositoryPaths(File symbolsRepositoryDir,
			Set<String> guidSubdirPaths) {

		Set<File> symbolsRepoPaths = new LinkedHashSet<>();

		// Collect sub-directories of the symbol repository that exist
		if (symbolsRepositoryDir != null && symbolsRepositoryDir.isDirectory()) {

			for (String guidSubdir : guidSubdirPaths) {
				File testDir = new File(symbolsRepositoryDir, guidSubdir);
				if (testDir.isDirectory()) {
					symbolsRepoPaths.add(testDir);
				}
			}

			// Check outer folder last
			symbolsRepoPaths.add(symbolsRepositoryDir);
		}

		return symbolsRepoPaths;
	}

	//==============================================================================================
	// Get list of "paths we know about" to search for PDBs
	private static Set<File> getPredefinedPaths(Set<String> guidSubdirPaths,
			PdbProgramAttributes pdbAttributes, boolean includePeSpecifiedPdbPath) {

		Set<File> predefinedPaths = new LinkedHashSet<>();

		getPathsFromAttributes(pdbAttributes, includePeSpecifiedPdbPath, predefinedPaths);
		getSymbolPaths(DEFAULT_SYMBOLS_DIR, guidSubdirPaths, predefinedPaths);
		getSymbolPaths(WINDOWS_SYMBOLS_DIR, guidSubdirPaths, predefinedPaths);
		getLibraryPaths(guidSubdirPaths, predefinedPaths);

		return predefinedPaths;
	}

	//==============================================================================================
	private static void getLibraryPaths(Set<String> guidSubdirPaths, Set<File> predefinedPaths) {
		String[] libraryPaths = LibrarySearchPathManager.getLibraryPaths();

		File libFile, subDir;

		for (String path : libraryPaths) {

			if ((libFile = new File(path)).isDirectory()) {
				predefinedPaths.add(libFile);

				// Check alternate locations
				for (String guidSubdir : guidSubdirPaths) {
					if ((subDir = new File(path, guidSubdir)).isDirectory()) {
						predefinedPaths.add(subDir);
					}
				}
			}
		}
	}

	//==============================================================================================
	/**
	 * TODO 20190403: Need to consider documentation at 
	 * <a href="https://docs.microsoft.com/en-us/windows/desktop/debug/symbol-paths">
	 * Symbol Paths</a>.
	 * <P>
	 * Says order:
	 * <li>C:\MySymbols
	 * <li>C:\MySymbols\ext, where ext is extension of binary (e.g., dll, exe, sys)
	 * <li>C:\MySymbols\symbols\ext
	 * <P>
	 */
	private static void getSymbolPaths(File symbolsDir, Set<String> guidSubdirPaths,
			Set<File> predefinedPaths) {
		// TODO: Need to provide better control of symbol directory preference
		// instead of only using default
		if (symbolsDir == null || !symbolsDir.isDirectory()) {
			return;
		}
		predefinedPaths.add(symbolsDir);

		// Check alternate locations
		String specialPdbPath = symbolsDir.getAbsolutePath();

		for (String guidSubdir : guidSubdirPaths) {
			File testDir = new File(specialPdbPath + guidSubdir);
			if (testDir.isDirectory()) {
				predefinedPaths.add(testDir);
			}
		}
	}

	//==============================================================================================
	private static void getPathsFromAttributes(PdbProgramAttributes pdbAttributes,
			boolean includePeSpecifiedPdbPath, Set<File> predefinedPaths) {
		if (pdbAttributes != null) {

			String currentPath = pdbAttributes.getPdbFile();

			if (currentPath != null && includePeSpecifiedPdbPath) {
				File parentDir = new File(currentPath).getParentFile();

				if (parentDir != null && parentDir.exists()) {
					predefinedPaths.add(parentDir);
				}
			}

			currentPath = pdbAttributes.getExecutablePath();

			if (currentPath != null && !currentPath.equals("unknown")) {
				File parentDir = new File(currentPath).getParentFile();

				if (parentDir != null && parentDir.exists()) {
					predefinedPaths.add(parentDir);
				}
			}
		}
	}

	//==============================================================================================
	/**
	 * Returns the first PDB-type file found. Assumes list of potentialPdbDirs is in the order
	 * in which the directories should be searched.
	 *
	 * @param potentialPdbDirs List<String> of paths
	 * @param potentialPdbNames List<String> of file names
	 * @return Ordered List<String> of potential filenames
	 */
	private static List<String> checkForPDBorXML(Set<File> potentialPdbDirs,
			List<String> potentialPdbNames) {

		List<String> orderedListOfExistingFileNames = new ArrayList<>();
		File file;

		for (File pdbPath : potentialPdbDirs) {

			for (String filename : potentialPdbNames) {

				file = new File(pdbPath, filename);

				// Note: isFile() also checks for existence
				if (file.isFile()) {
					orderedListOfExistingFileNames.add(file.getAbsolutePath());
				}
			}
		}

		return orderedListOfExistingFileNames;
	}

	//==============================================================================================
	public static boolean verifyPdbSignature(PdbProgramAttributes programAttributes,
			PdbIdentifiers identifiers) throws PdbException {

		String attributesGuidString = programAttributes.getPdbGuid();
		if (attributesGuidString == null) {
			// TODO: note that PdbProgramAttributes does not seem to be getting this value from 
			//  the program--getting it as a default value (e.g., from options or elsewhere).
			//  Should see if it is available in the program somewhere?
			String attributesSignatureString = programAttributes.getPdbSignature();
			if (attributesSignatureString == null) {
				throw new PdbException("No PDB GUID or Signature in file.\n Cannot match.");
			}
			int attributesSignature = Integer.parseInt(attributesSignatureString);
			if (attributesSignature != identifiers.getSignature()) {
				return false; // no match
			}
		}
		else {
			GUID pdbGuid = identifiers.getGuid();
			if (!attributesGuidString.equals(pdbGuid.toString())) {
				return false; // no match
			}
		}

		int attributesAge = Integer.parseInt(programAttributes.getPdbAge(), 16);
		if (attributesAge != identifiers.getAge()) {
			return false;
		}

		return true;
	}

	public static File getDefaultPdbSymbolsDir() {
		String pdbStorageLocation = Preferences.getProperty(PDB_SYMBOLS_DIR_PREFERENCE, null, true);
		File defaultSymbolsDir = DEFAULT_SYMBOLS_DIR;
		if (pdbStorageLocation != null) {
			File pdbDirectory = new File(pdbStorageLocation);
			if (pdbDirectory.isDirectory()) {
				defaultSymbolsDir = pdbDirectory;
			}
		}
		return defaultSymbolsDir;
	}

	public static void setDefaultPdbSymbolsDir(File symbolsDir) {
		Preferences.setProperty(PDB_SYMBOLS_DIR_PREFERENCE, symbolsDir.getAbsolutePath());
		Preferences.store();
	}

}
