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
package pdb.symbolserver;

import java.util.*;
import java.util.stream.Collectors;

import java.io.File;
import java.io.IOException;

import org.apache.commons.io.FilenameUtils;

import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import pdb.PdbUtils;

/**
 * A (lowercase-'S') service that searches for and fetches symbol files
 * from a set of local and remote {@link SymbolServer symbolservers}. (not to be 
 * confused with a Plugin service)
 * <p>
 * Instances of this class are meant to be easily created when needed
 * and just as easily thrown away when not used or when the search 
 * path configuration changes.
 * <p>
 * A SymbolServerService instance requires a {@link SymbolStore} and
 * optionally a list of {@link SymbolServer}s.
 */
public class SymbolServerService {

	private SymbolStore symbolStore;	// also the first element of the symbolServers list
	private List<SymbolServer> symbolServers;

	/**
	 * Creates a new SymbolServerService instance.
	 * <p>
	 * @param symbolStore a {@link SymbolStore} - where all
	 *  remote files are placed when downloaded. Also treated as a SymbolServer
	 *  and searched first
	 * @param symbolServers  a list of {@link SymbolServer symbol servers} - searched in order
	 */
	public SymbolServerService(SymbolStore symbolStore, List<SymbolServer> symbolServers) {
		this.symbolStore = symbolStore;
		this.symbolServers = new ArrayList<>();
		this.symbolServers.add(symbolStore);
		this.symbolServers.addAll(symbolServers);
	}

	/**
	 * Returns true if this SymbolServerService is fully valid.
	 * Will be false if the symbol storage location isn't a {@link LocalSymbolStore}.
	 * 
	 * @return boolean true if this instance is valid, false if not valid
	 */
	public boolean isValid() {
		return symbolStore instanceof LocalSymbolStore;
	}

	/**
	 * Returns the {@link SymbolStore}, which is the primary / first location queried and
	 * used to store any symbol files retrieved from a remote symbol server. 
	 * 
	 * @return the {@link SymbolStore}
	 */
	public SymbolStore getSymbolStore() {
		return symbolStore;
	}

	/**
	 * Returns the list of {@link SymbolServer}s.
	 * 
	 * @return the list of {@link SymbolServer}s
	 */
	public List<SymbolServer> getSymbolServers() {
		return new ArrayList<>(symbolServers.subList(1, symbolServers.size()));
	}

	/**
	 * Returns the number of configured symbol servers that are considered 'remote'.
	 * @return number of remote symbol servers
	 */
	public int getRemoteSymbolServerCount() {
		int remoteSymbolServerCount = (int) getSymbolServers()
				.stream()
				.filter(ss -> !ss.isLocal())
				.count();

		return remoteSymbolServerCount;
	}

	/**
	 * Searches all {@link SymbolServer symbol servers} for a matching pdb symbol file.
	 * 
	 * @param symbolFileInfo {@link SymbolFileInfo} bag of information
	 *   about the file to search for
	 * @param monitor {@link TaskMonitor} to update with search progress and to
	 *   allow the user to cancel the operation
	 * @return a list of {@link SymbolFileLocation} instances
	 * @throws CancelledException if cancelled
	 */
	public List<SymbolFileLocation> find(SymbolFileInfo symbolFileInfo, TaskMonitor monitor)
			throws CancelledException {
		return find(symbolFileInfo, FindOption.NO_OPTIONS, monitor);
	}

	/**
	 * Searches all {@link SymbolServer symbol servers} for a matching pdb symbol file.
	 * <p>
	 * Returns a list of matches.
	 * <p>
	 * Use {@link SymbolFileLocation#isExactMatch(SymbolFileInfo)} to test elements in the
	 * result list for exactness.
	 * <p>
	 * 
	 * @param symbolFileInfo Pdb file info to search for
	 * @param findOptions set of {@link FindOption} to control the search.
	 *  See {@link FindOption#NO_OPTIONS} or 
	 *  {@link FindOption#of(FindOption...) FindOptions.of(option1, option2...)}
	 * @param monitor {@link TaskMonitor}
	 * @return list of {@link SymbolFileLocation}s
	 * @throws CancelledException if operation canceled by user
	 */
	public List<SymbolFileLocation> find(SymbolFileInfo symbolFileInfo,
			Set<FindOption> findOptions, TaskMonitor monitor) throws CancelledException {

		List<SymbolFileLocation> allFindResults = new ArrayList<>();
		Set<String> uniqueSymbolFilePaths = new HashSet<>();

		for_each_symbol_server_loop: for (SymbolServer symbolServer : symbolServers) {
			monitor.checkCanceled();
			if (!symbolServer.isLocal() && !findOptions.contains(FindOption.ALLOW_REMOTE)) {
				Msg.debug(this,
					logPrefix() + ": skipping non-local symbol server " +
						symbolServer.getDescriptiveName());
				continue;
			}

			Msg.debug(this, logPrefix() + ": querying " + symbolServer.getDescriptiveName() +
				" for " + symbolFileInfo.getDescription());

			List<SymbolFileLocation> symbolServerFindResults =
				symbolServer.find(symbolFileInfo, findOptions, monitor);

			Msg.debug(this,
				logPrefix() + ": got " + symbolServerFindResults.size() + " results from " +
					symbolServer.getDescriptiveName());

			// only add unique file locations
			for (SymbolFileLocation symbolFileLocation : symbolServerFindResults) {
				if (uniqueSymbolFilePaths.add(symbolFileLocation.getLocationStr())) {
					allFindResults.add(symbolFileLocation);
					if (findOptions.contains(FindOption.ONLY_FIRST_RESULT)) {
						break for_each_symbol_server_loop;
					}
				}
			}
		}

		Msg.debug(this, logPrefix() + ": found " + allFindResults.size() + " matches");

		return allFindResults;

	}

	/**
	 * Returns the local file path of the symbol file specified by symbolFileLocation.
	 *  
	 * @param symbolFileLocation {@link SymbolFileLocation}, returned 
	 *  by {@link #find(SymbolFileInfo, Set, TaskMonitor) find()} 
	 * @param monitor {@link TaskMonitor}
	 * @return {@link File} path to the local pdb file, never null
	 * @throws CancelledException if user cancels operation
	 * @throws IOException if error or problem getting file
	 */
	public File getSymbolFile(SymbolFileLocation symbolFileLocation, TaskMonitor monitor)
			throws CancelledException, IOException {
		Msg.debug(this,
			logPrefix() + ": getting symbol file: " + symbolFileLocation.getLocationStr());

		SymbolFileLocation localSymbolFileLocation =
			ensureLocalUncompressedFile(symbolFileLocation, monitor);

		Msg.debug(this,
			logPrefix() + ": local file now: " + localSymbolFileLocation.getLocationStr());

		SymbolStore symbolStore = (SymbolStore) localSymbolFileLocation.getSymbolServer();

		return symbolStore.getFile(localSymbolFileLocation.getPath());
	}

	/**
	 * Converts a possibly remote {@link SymbolFileLocation} to a location that is local and
	 * uncompressed.
	 * 
	 * @param symbolFileLocation possibly remote {@link SymbolFileLocation}
	 * @param monitor {@link TaskMonitor} to display progress and allow canceling
	 * @return {@link SymbolFileLocation} that is local (possibly the same  instance if already
	 * local)
	 * @throws CancelledException if canceled
	 * @throws IOException if error
	 */
	public SymbolFileLocation getLocalSymbolFileLocation(SymbolFileLocation symbolFileLocation,
			TaskMonitor monitor) throws CancelledException, IOException {
		Msg.debug(this,
			logPrefix() + ": getting symbol file: " + symbolFileLocation.getLocationStr());

		SymbolFileLocation localSymbolFileLocation =
			ensureLocalUncompressedFile(symbolFileLocation, monitor);

		return localSymbolFileLocation;
	}

	private SymbolFileLocation ensureLocalUncompressedFile(SymbolFileLocation symbolFileLocation,
			TaskMonitor monitor) throws IOException, CancelledException {
		if (!(symbolFileLocation.getSymbolServer() instanceof SymbolStore)) {
			Msg.debug(this, logPrefix() + ": copying file " + symbolFileLocation.getLocationStr() +
				" from remote to local " + symbolStore.getName());

			// copy from remote store to our main local symbol store
			String remoteFilename = FilenameUtils.getName(symbolFileLocation.getPath());
			try (SymbolServerInputStream symbolServerInputStream =
				symbolFileLocation.getSymbolServer()
						.getFileStream(symbolFileLocation.getPath(), monitor)) {
				String newPath =
					symbolStore.putStream(symbolFileLocation.getFileInfo(), symbolServerInputStream,
						remoteFilename, monitor);
				symbolFileLocation =
					new SymbolFileLocation(newPath, symbolStore, symbolFileLocation.getFileInfo());
			}
		}

		// symbolFileLocation now must be on a SymbolStore, so safe to cast
		SymbolStore localSymbolStore = (SymbolStore) symbolFileLocation.getSymbolServer();

		if (SymbolStore.isCompressedFilename(symbolFileLocation.getPath())) {
			File cabFile = localSymbolStore.getFile(symbolFileLocation.getPath());
			File temporaryExtractFile = new File(symbolStore.getAdminDir(),
				"ghidra_cab_extract_tmp_" + System.currentTimeMillis());

			Msg.debug(this,
				logPrefix() + ": decompressing file " + symbolFileLocation.getLocationStr());

			String originalName =
				PdbUtils.extractSingletonCabToFile(cabFile, temporaryExtractFile, monitor);
			String uncompressedPath =
				symbolStore.giveFile(symbolFileLocation.getFileInfo(), temporaryExtractFile,
					originalName, monitor);

			symbolFileLocation = new SymbolFileLocation(uncompressedPath, symbolStore,
				symbolFileLocation.getFileInfo());

			Msg.debug(this,
				logPrefix() + ": new decompressed file " + symbolFileLocation.getLocationStr());
		}

		return symbolFileLocation;
	}

	private String logPrefix() {
		return getClass().getSimpleName();
	}

	@Override
	public String toString() {
		return String.format(
			"SymbolServerService:\n\tsymbolStore: %s,\n\tsymbolServers:\n\t\t%s\n",
			symbolStore.toString(),
			symbolServers.subList(1, symbolServers.size())
					.stream()
					.map(SymbolServer::toString)
					.collect(Collectors.joining("\n\t\t")));
	}

}
