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
package ghidra.feature.fid.plugin;

import java.io.*;
import java.util.*;

import ghidra.feature.fid.db.*;
import ghidra.feature.fid.service.*;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.database.ProgramContentHandler;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * Inner class that implements the ingest task.
 */
public class IngestTask extends Task {
	private FidFile fidFile;
	private LibraryRecord libraryRecord;
	protected DomainFolder folder;
	protected String libraryFamilyName;
	protected String libraryVersion;
	protected String libraryVariant;
	private LanguageID languageId;
	private File commonSymbolsFile;
	private FidService fidService;
	private FidPopulateResultReporter reporter;

	public IngestTask(String title, FidFile fidFile, LibraryRecord libraryRecord,
			DomainFolder folder, String libraryFamilyName, String libraryVersion,
			String libraryVariant, String languageId, File commonSymbolsFile, FidService fidService,
			FidPopulateResultReporter reporter) {
		super(title);
		this.fidFile = fidFile;
		this.libraryRecord = libraryRecord;
		this.folder = folder;
		this.libraryFamilyName = libraryFamilyName;
		this.libraryVersion = libraryVersion;
		this.libraryVariant = libraryVariant;
		this.commonSymbolsFile = commonSymbolsFile;
		this.fidService = fidService;
		this.reporter = reporter;
		this.languageId = new LanguageID(languageId);
	}

	@Override
	public void run(TaskMonitor monitor) {

		FidDB fidDb = null;
		try {
			fidDb = fidFile.getFidDB(true);
		}
		catch (VersionException e) {
			// Version upgrades are not supported
			Msg.showError(this, null, "Failed to open FidDb",
				"Failed to open incompatible FidDb (may need to regenerate with this version of Ghidra): " +
					fidFile.getPath());
			return;
		}
		catch (IOException e) {
			Msg.showError(this, null, "Failed to open FidDb",
				"Failed to open FidDb: " + fidFile.getPath(), e);
			return;
		}

		try {
			List<String> commonSymbols = parseSymbols(monitor);
			ArrayList<DomainFile> programs = new ArrayList<DomainFile>();
			monitor.setMessage("Finding domain files...");
			monitor.setIndeterminate(true);
			findPrograms(programs, folder, monitor);
			monitor.setIndeterminate(false);

			monitor.setMessage("Populating library...");
			FidPopulateResult result = fidService.createNewLibraryFromPrograms(fidDb,
				libraryFamilyName, libraryVersion, libraryVariant, programs, null, languageId,
				libraryRecord == null ? null : Arrays.asList(libraryRecord), commonSymbols,
				monitor);
			reporter.report(result);
			fidDb.saveDatabase("Saving", monitor);
		}
		catch (CancelledException e) {
			// cancelled by user; don't notify
		}
		catch (MemoryAccessException e) {
			Msg.showError(this, null, "Unexpected memory access exception",
				"Please notify the Ghidra team:", e);
		}
		catch (VersionException e) {
			Msg.showError(this, null, "Version Exception",
				"One of the programs in your domain folder cannot be upgraded: " + e.getMessage());
		}
		catch (IOException e) {
			Msg.showError(this, null, "FidDb IOException", "Please notify the Ghidra team:", e);
		}
		finally {
			fidDb.close();
		}

	}

	private List<String> parseSymbols(TaskMonitor monitor) throws IOException, CancelledException {
		if (commonSymbolsFile == null) {
			return null;
		}
		BufferedReader reader = new BufferedReader(new FileReader(commonSymbolsFile));
		LinkedList<String> res = new LinkedList<String>();
		String line = reader.readLine();
		while (line != null) {
			monitor.checkCanceled();
			if (line.length() != 0) {
				res.add(line);
			}
			line = reader.readLine();
		}
		reader.close();
		return res;
	}

	/**
	 * Recursively finds all domain objects that are program files under a domain folder.
	 * @param programs the "return" value; found programs are placed in this collection
	 * @param myFolder the domain folder to search
	 * @param monitor a task monitor
	 * @throws CancelledException if the user cancels
	 */
	protected void findPrograms(ArrayList<DomainFile> programs, DomainFolder myFolder,
			TaskMonitor monitor) throws CancelledException {
		if (myFolder == null) {
			return;
		}
		DomainFile[] files = myFolder.getFiles();
		for (DomainFile domainFile : files) {
			monitor.checkCanceled();
			monitor.incrementProgress(1);
			if (domainFile.getContentType().equals(ProgramContentHandler.PROGRAM_CONTENT_TYPE)) {
				programs.add(domainFile);
			}
		}
		DomainFolder[] folders = myFolder.getFolders();
		for (DomainFolder domainFolder : folders) {
			monitor.checkCanceled();
			monitor.incrementProgress(1);
			findPrograms(programs, domainFolder, monitor);
		}
	}
}
