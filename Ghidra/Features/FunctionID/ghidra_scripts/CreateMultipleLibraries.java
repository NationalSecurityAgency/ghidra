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
//Create multiple libraries in a single FID database
//  A root is chosen as a folder within the active project
//  Subfolders at a specific depth from this root form the roots of individual libraries
//    Library Name, Version, and Variant are created from the directory path elements
//@category FunctionID
import java.io.*;
import java.util.*;
import java.util.Map.Entry;

import generic.hash.FNV1a64MessageDigest;
import generic.hash.MessageDigest;
import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.db.*;
import ghidra.feature.fid.hash.FidHashQuad;
import ghidra.feature.fid.service.*;
import ghidra.feature.fid.service.FidPopulateResult.Disposition;
import ghidra.framework.model.*;
import ghidra.program.database.ProgramContentHandler;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public class CreateMultipleLibraries extends GhidraScript {

	private FidService service;
	private FidDB fidDb = null;
	private FidFile fidFile = null;
	private DomainFolder rootFolder = null;
	private int totalLibraries = 0;
	private boolean isCancelled = false;

	private String[] pathelement;
	private String currentLibraryName;
	private String currentLibraryVersion;
	private String currentLibraryVariant;

	private TreeMap<Long, String> duplicatemap = null;
	private FileOutputStream outlog = null;
	private File commonSymbolsFile = null;
	private List<String> commonSymbols = null;
	private LanguageID languageID = null;

	private MyFidPopulateResultReporter reporter = null;

	private static final int MASTER_DEPTH = 3;

	protected void outputLine(String line) {
		if (outlog != null) {
			try {
				outlog.write(line.getBytes());
				outlog.write('\n');
				outlog.flush();
			}
			catch (IOException e) {
				println("Unable to write to log");
			}
		}
		else {
			println(line);
		}
	}

	class MyFidPopulateResultReporter implements FidPopulateResultReporter {
		@Override
		public void report(FidPopulateResult result) {
			if (result == null) {
				return;
			}
			LibraryRecord libraryRecord = result.getLibraryRecord();
			String libraryFamilyName = libraryRecord.getLibraryFamilyName();
			String libraryVersion = libraryRecord.getLibraryVersion();
			String libraryVariant = libraryRecord.getLibraryVariant();
			outputLine(libraryFamilyName + ':' + libraryVersion + ':' + libraryVariant);

			outputLine(result.getTotalAttempted() + " total functions visited");
			outputLine(result.getTotalAdded() + " total functions added");
			outputLine(result.getTotalExcluded() + " total functions excluded");
			outputLine("Breakdown of exclusions:");
			for (Entry<Disposition, Integer> entry : result.getFailures().entrySet()) {
				if (entry.getKey() != Disposition.INCLUDED) {
					outputLine("    " + entry.getKey() + ": " + entry.getValue());
				}
			}
			outputLine("List of unresolved symbols:");
			TreeSet<String> symbols = new TreeSet<>();
			for (Location location : result.getUnresolvedSymbols()) {
				symbols.add(location.getFunctionName());
			}
			for (String symbol : symbols) {
				outputLine("    " + symbol);
			}
		}

	}

	private void hashFunction(Program program, ArrayList<Long> hashList)
			throws MemoryAccessException, CancelledException {
		FunctionManager functionManager = program.getFunctionManager();
		FunctionIterator functions = functionManager.getFunctions(true);
		while (functions.hasNext()) {
			monitor.checkCanceled();
			Function func = functions.next();
			FidHashQuad hashFunction = service.hashFunction(func);
			if (hashFunction == null) {
				continue; // No body
			}
			MessageDigest digest = new FNV1a64MessageDigest();
			digest.update(func.getName().getBytes(), TaskMonitor.DUMMY);
			digest.update(hashFunction.getFullHash());
			hashList.add(digest.digestLong());
		}
	}

	private void hashListProgram(DomainFile domainFile, ArrayList<Long> hashList)
			throws VersionException, CancelledException, IOException, MemoryAccessException {
		DomainObject domainObject = null;
		try {
			domainObject = domainFile.getDomainObject(this, false, true, TaskMonitor.DUMMY);
			if (!(domainObject instanceof Program)) {
				return;
			}
			Program program = (Program) domainObject;
			hashFunction(program, hashList);
		}
		finally {
			if (domainObject != null) {
				domainObject.release(this);
			}
		}

	}

	private long calculateFinalHash(ArrayList<Long> hashList) throws CancelledException {
		MessageDigest digest = new FNV1a64MessageDigest();
		Collections.sort(hashList);
		for (int i = 0; i < hashList.size(); ++i) {
			monitor.checkCanceled();
			digest.update(hashList.get(i));
		}
		return digest.digestLong();
	}

	private boolean checkForDuplicate(ArrayList<DomainFile> programs) throws CancelledException {
		String fullName =
			currentLibraryName + ':' + currentLibraryVersion + ':' + currentLibraryVariant;
		ArrayList<Long> hashList = new ArrayList<>();
		for (int i = 0; i < programs.size(); ++i) {
			monitor.checkCanceled();
			try {
				hashListProgram(programs.get(i), hashList);
			}
			catch (VersionException ex) {
				outputLine("Version exception for " + fullName);
			}
			catch (IOException ex) {
				outputLine("IO exception for " + fullName);
			}
			catch (MemoryAccessException ex) {
				outputLine("Memory access exception for " + fullName);
			}
		}
		long val = calculateFinalHash(hashList);
		String string = duplicatemap.get(val);
		boolean res;
		if (string != null) {
			outputLine(fullName + " duplicates " + string);
			res = true;
		}
		else {
			duplicatemap.put(val, fullName);
			res = false;
		}
		return res;
	}

	private boolean detectDups(DomainFolder folder) {
		boolean isDuplicate = false;
		try {
			ArrayList<DomainFile> programs = new ArrayList<>();
			findPrograms(programs, folder);

			isDuplicate = checkForDuplicate(programs);
		}
		catch (CancelledException e) {
			// cancelled by user; don't notify
			isCancelled = true;
		}
		return isDuplicate;
	}

	private void createLibraryNames() {
		// path should look like : compiler, project, version, options
		currentLibraryName = pathelement[1];
		currentLibraryVersion = pathelement[2];
		currentLibraryVariant = pathelement[0] + ':' + pathelement[3];
	}

	private void parseSymbols() throws IOException, CancelledException {
		if (commonSymbolsFile == null) {
			commonSymbols = null;
			return;
		}
		BufferedReader reader = new BufferedReader(new FileReader(commonSymbolsFile));
		commonSymbols = new LinkedList<>();
		String line = reader.readLine();
		while (line != null) {
			monitor.checkCanceled();
			if (line.length() != 0) {
				commonSymbols.add(line);
			}
			line = reader.readLine();
		}
		reader.close();
	}

	private void countLibraries(int depth, DomainFolder fold) {
		if (depth == 0) {
			totalLibraries += 1;
			return;
		}
		depth -= 1;
		DomainFolder[] subfold = fold.getFolders();
		for (DomainFolder element : subfold) {
			countLibraries(depth, element);
		}
	}

	/**
	 * Recursively finds all domain objects that are program files under a domain folder.
	 * @param programs the "return" value; found programs are placed in this collection
	 * @param myFolder the domain folder to search
	 * @throws CancelledException if the user cancels
	 */
	protected void findPrograms(ArrayList<DomainFile> programs, DomainFolder myFolder)
			throws CancelledException {
		if (myFolder == null) {
			return;
		}
		DomainFile[] files = myFolder.getFiles();
		for (DomainFile domainFile : files) {
			monitor.checkCanceled();
			if (domainFile.getContentType().equals(ProgramContentHandler.PROGRAM_CONTENT_TYPE)) {
				programs.add(domainFile);
			}
		}
		DomainFolder[] folders = myFolder.getFolders();
		for (DomainFolder domainFolder : folders) {
			monitor.checkCanceled();
			findPrograms(programs, domainFolder);
		}
	}

	private void populateLibrary(DomainFolder folder) {
		ArrayList<DomainFile> programs = new ArrayList<>();
		try {
			findPrograms(programs, folder);

			FidPopulateResult result = service.createNewLibraryFromPrograms(fidDb,
				currentLibraryName, currentLibraryVersion, currentLibraryVariant, programs, null,
				languageID, null, commonSymbols, TaskMonitor.DUMMY);
			reporter.report(result);
		}
		catch (CancelledException e) {
			isCancelled = true;
		}
		catch (MemoryAccessException e) {
			Msg.showError(this, null, "Unexpected memory access exception",
				"Please notify the Ghidra team:", e);
		}
		catch (VersionException e) {
			Msg.showError(this, null, "Version Exception",
				"One of the programs in your domain folder cannot be upgraded: " + e.getMessage());
		}
		catch (IllegalStateException e) {
			Msg.showError(this, null, "Illegal State Exception",
				"Unknown error: " + e.getMessage());
		}
		catch (IOException e) {
			Msg.showError(this, null, "FidDb IOException", "Please notify the Ghidra team:", e);
		}
	}

	private void generate(int depth, DomainFolder fold) {
		if (depth != 0) {
			pathelement[MASTER_DEPTH - depth] = fold.getName();
			depth -= 1;
			DomainFolder[] subfold = fold.getFolders();
			for (DomainFolder element : subfold) {
				generate(depth, element);
				if (isCancelled) {
					return;
				}
			}
			return;
		}
		pathelement[MASTER_DEPTH] = fold.getName();
		// Reaching here, we are at library depth in the folder hierarchy
		createLibraryNames();

		monitor.setMessage(
			currentLibraryName + ':' + currentLibraryVersion + ':' + currentLibraryVariant);
		boolean isDuplicate = false;
		if (duplicatemap != null) {
			isDuplicate = detectDups(fold);
		}
		if (!isDuplicate) {
			populateLibrary(fold);
		}
		monitor.incrementProgress(1);
	}

	@Override
	protected void run() throws Exception {
		pathelement = new String[MASTER_DEPTH + 1];
		service = new FidService();
		File askFile = null;

		try {
			askFile = askFile("Duplicate Results File", "OK");
			outlog = new FileOutputStream(askFile);
		}
		catch (CancelledException ex) {
			// ignore, means we use console
		}
		if (askYesNo("Do Duplication Detection", "Do you want to detect duplicates")) {
			duplicatemap = new TreeMap<>();
		}

		List<FidFile> nonInstallationFidFiles = FidFileManager.getInstance().getUserAddedFiles();
		if (nonInstallationFidFiles.isEmpty()) {
			throw new FileNotFoundException("Could not find any fidb files that can be populated");
		}
		fidFile = askChoice("Choose destination FidDB",
			"Please choose the destination FidDB for population", nonInstallationFidFiles,
			nonInstallationFidFiles.get(0));

		rootFolder =
			askProjectFolder("Select root folder containing all libraries (at a depth of " +
				Integer.toString(MASTER_DEPTH) + "):");

		try {
			commonSymbolsFile = askFile("Common symbols file (optional):", "OK");
		}
		catch (CancelledException e) {
			commonSymbolsFile = null;	// Common symbols file may be null
		}
		String lang = askString("Enter LanguageID To Process", "Language ID: ");
		languageID = new LanguageID(lang);

		parseSymbols();
		reporter = new MyFidPopulateResultReporter();
		fidDb = fidFile.getFidDB(true);

		countLibraries(MASTER_DEPTH, rootFolder);
		monitor.initialize(totalLibraries);
		try {
			generate(MASTER_DEPTH, rootFolder);
			fidDb.saveDatabase("Saving", monitor);
		}
		finally {
			fidDb.close();
		}

		if (outlog != null) {
			outlog.close();
		}
	}

}
