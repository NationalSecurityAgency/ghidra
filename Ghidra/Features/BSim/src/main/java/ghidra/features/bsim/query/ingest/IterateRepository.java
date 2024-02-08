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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;

import ghidra.features.bsim.query.LSHException;
import ghidra.framework.client.NotConnectedException;
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
	 * @throws Exception if an error occured during processing.
	 * @throws CancelledException if processing was cancelled
	 */
	protected abstract void process(Program program, TaskMonitor monitor)
			throws Exception, CancelledException;

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

		URL repoURL = GhidraURL.getProjectURL(ghidraURL);
		String path = GhidraURL.getProjectPathname(ghidraURL);

		String finalelement = null;
		path = path.trim();
		if (!path.endsWith("/")) {
			int pos = path.lastIndexOf('/');
			if (pos >= 0) {
				String tmp = path.substring(0, pos + 1);
				if (tmp.length() != 0 && !tmp.equals("/")) {
					finalelement = path.substring(pos + 1);		// A possible file name at the end of the path
					path = tmp;

					if (GhidraURL.isServerRepositoryURL(ghidraURL)) {
						ghidraURL = new URL(repoURL + path);
					}
					else {
						ghidraURL = new URL(repoURL + "?" + path);
					}
				}
			}
		}

		try {
			GhidraURLConnection c = (GhidraURLConnection) ghidraURL.openConnection();

			Msg.debug(IterateRepository.class, "Opening ghidra repository: " + ghidraURL);
			Object obj = c.getContent();
			if (!(obj instanceof GhidraURLWrappedContent)) {
				throw new IOException("Connect to repository folder failed");
			}

			Object consumer = new Object();

			GhidraURLWrappedContent wrappedContent = (GhidraURLWrappedContent) obj;
			Object content = null;
			try {
				content = wrappedContent.getContent(consumer);
				if (!(content instanceof DomainFolder)) {
					throw new IOException("Connect to repository folder failed");
				}

				DomainFolder folder = (DomainFolder) content;

				int totalFiles = getTotalFileCount(folder);

				monitor.setMaximum(totalFiles);
				monitor.setShowProgressValue(true);

				if (finalelement != null) {
					DomainFolder subfolder = folder.getFolder(finalelement);

					if (subfolder != null) {
						folder = subfolder;
						// fall thru to the DomainFile and DomainFolder loop
					}
					else {
						DomainFile file = folder.getFile(finalelement);

						if (file == null) {
							throw new IOException("Bad folder/file element: " + finalelement);
						}

						process(file, monitor);
						return;
					}
				}

				process(folder, monitor);
			}
			finally {
				if (content != null) {
					wrappedContent.release(content, consumer);
				}
			}
		}
		catch (NotConnectedException e) {
			throw new IOException(
				"Ghidra repository connection failed (" + repoURL + "): " + e.getMessage());
		}
		catch (FileNotFoundException e) {
			throw new IOException("Repository path not found: " + path);
		}
	}

	private void process(DomainFolder folder, TaskMonitor monitor)
			throws Exception, CancelledException {

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
			throws Exception, CancelledException {

		// Do not follow folder-links or consider program links.  Using content type
		// to filter is best way to control this.  If program links should be considered
		// "Program.class.isAssignableFrom(domainFile.getDomainObjectClass())"
		// should be used.
		if (!ProgramContentHandler.PROGRAM_CONTENT_TYPE.equals(file.getContentType())) {
			// NOTE: linked-folders and linked-files are not currently supported
			return; // skip non-program file
		}

		Program program = null;
		Object consumer = new Object();
		try {
			Msg.debug(IterateRepository.class, "Processing " + file.getPathname() + "...");
			monitor.setMessage("Processing: " + file.getName());
			monitor.incrementProgress(1);
			program = (Program) file.getReadOnlyDomainObject(consumer, -1, monitor);
			process(program, monitor);
		}
		catch (VersionException e) {
			Msg.error(IterateRepository.class,
				"Failed to process file " + file.getPathname() + ": " + e.getMessage());
		}
		finally {
			if (program != null) {
				program.release(consumer);
			}
		}
	}
}
