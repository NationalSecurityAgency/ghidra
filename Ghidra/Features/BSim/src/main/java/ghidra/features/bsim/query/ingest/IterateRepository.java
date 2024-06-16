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
package ghidra.features.bsim.query.ingest;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.protocol.ghidra.*;
import ghidra.program.database.ProgramContentHandler;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public abstract class IterateRepository {

	/**
	 * Perform processing on program obtained from repository.
	 * @param program program obtained from repository
	 * @param monitor processing task monitor
	 * @throws IOException if an error occured during processing.
	 * @throws CancelledException if processing was cancelled
	 */
	protected abstract void process(Program program, TaskMonitor monitor)
			throws IOException, CancelledException;

	/**
	 * Process the specified repository URL
	 * @param ghidraURL ghidra URL for existing server repository and optional
	 * folder path
	 * @param monitor task monitor
	 * @throws Exception if an error occurs during processing
	 * @throws CancelledException if processing is cancelled
	 */
	public void process(URL ghidraURL, TaskMonitor monitor) throws Exception, CancelledException {

		if (!GhidraURL.isServerRepositoryURL(ghidraURL) &&
			!GhidraURL.isLocalProjectURL(ghidraURL)) {
			throw new MalformedURLException("Unsupported repository URL: " + ghidraURL);
		}

		GhidraURLQuery.queryUrl(ghidraURL, new GhidraURLResultHandlerAdapter(true) {

			@Override
			public void processResult(DomainFolder domainFolder, URL url, TaskMonitor m)
					throws IOException, CancelledException {

				int totalFiles = getTotalFileCount(domainFolder);

				monitor.setMaximum(totalFiles);
				monitor.setShowProgressValue(true);

				process(domainFolder, monitor);
			}

			@Override
			public void processResult(DomainFile domainFile, URL url, TaskMonitor m)
					throws IOException, CancelledException {
				process(domainFile, monitor);
			}

		}, monitor);

	}

	private void process(DomainFolder folder, TaskMonitor monitor)
			throws IOException, CancelledException {

		for (DomainFile file : folder.getFiles()) {
			monitor.checkCancelled();
			process(file, monitor);
		}

		for (DomainFolder subfolder : folder.getFolders()) {
			monitor.checkCancelled();
			process(subfolder, monitor);
		}
	}

	/**
	 * Returns the total number of files under the given folder. This does a recursive 
	 * check to search all subdirs.
	 * 
	 * @param folder the folder to search
	 * @return total number of files in the folder (and its subfolders)
	 */
	private int getTotalFileCount(DomainFolder folder) {
		int count = 0;
		count += folder.getFiles().length;

		for (DomainFolder subfolder : folder.getFolders()) {
			count += getTotalFileCount(subfolder);
		}

		return count;
	}

	private void process(DomainFile file, TaskMonitor monitor)
			throws IOException, CancelledException {

		// Do not follow folder-links or consider program links.  Using content type
		// to filter is best way to control this.  If program links should be considered
		// "Program.class.isAssignableFrom(domainFile.getDomainObjectClass())"
		// should be used.
		if (!ProgramContentHandler.PROGRAM_CONTENT_TYPE.equals(file.getContentType())) {
			// NOTE: linked-folders and linked-files are not currently supported
			return; // skip non-program file
		}

		Program program = null;
		try {
			Msg.debug(IterateRepository.class, "Processing " + file.getPathname() + "...");
			monitor.setMessage("Processing: " + file.getName());
			monitor.incrementProgress(1);
			program = (Program) file.getReadOnlyDomainObject(this, -1, monitor);
			process(program, monitor);
		}
		catch (VersionException e) {
			Msg.error(IterateRepository.class,
				"Failed to process file " + file.getPathname() + ": " + e.getMessage());
		}
		finally {
			if (program != null) {
				program.release(this);
			}
		}
	}
}
