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
package ghidra.plugins.importer.batch;

import java.io.IOException;
import java.util.*;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import javax.swing.SwingConstants;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.*;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.crypto.CryptoSession;
import ghidra.plugins.importer.batch.BatchGroup.BatchLoadConfig;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.CryptoException;
import ghidra.util.task.*;

/**
 * This is the main state of a batch import task, containing the segregated groupings of
 * applications.
 * <p>
 * This class also handles populating the batch groups by recursively descending into files
 * and the contents of those files.
 */
public class BatchInfo {
	public static final int MAXDEPTH_UNLIMITED = -1;
	public static final int MAXDEPTH_DEFAULT = 2;

	private FileSystemService fsService = FileSystemService.getInstance();

	/*
	 * These structures need to be synchronized to ensure thread visibility, since they are 
	 * written to by a background thread and read from the Swing thread.  
	 * 
	 * For now, concurrent modification is not an issue, since the client does not read from
	 * these structures while they are being written, as the writes happen during a blocking
	 * operation.
	 */
	private Map<BatchSegregatingCriteria, BatchGroup> groupsByCriteria =
		Collections.synchronizedMap(new HashMap<>());
	private Set<FSRL> userAddedFSRLs = Collections.synchronizedSet(new HashSet<>());
	private List<UserAddedSourceInfo> userAddedSources =
		Collections.synchronizedList(new ArrayList<>());

	/**
	 * Maximum depth of containers (ie. filesystems) to recurse into when processing
	 * a file added by the user.
	 * <p>
	 * maxDepth of less than or equal to 0 == unlimited.
	 * <p>
	 * maxDepth of 1 == no recursing into containers found in added file, just try it
	 * with a loader.
	 * <p>
	 * Default is {@link #MAXDEPTH_DEFAULT}.
	 */
	private int maxDepth;

	private UserAddedSourceInfo currentUASI;

	/**
	 * Creates a new BatchInfo object with a default {@link #maxDepth}.
	 */
	public BatchInfo() {
		this(MAXDEPTH_DEFAULT);
	}

	/**
	 * Creates a new BatchInfo object using the specified maxDepth.
	 *
	 * @param maxDepth see {@link #maxDepth}.
	 */
	public BatchInfo(int maxDepth) {
		this.maxDepth = maxDepth;
	}

	/**
	 * Returns a list of the {@link BatchGroup}s that have been found when processing
	 * the added files.
	 *
	 * @return {@link List} of {@link BatchGroup}s.
	 */
	public List<BatchGroup> getGroups() {
		return new ArrayList<>(groupsByCriteria.values());
	}

	/**
	 * Returns the count of how many importable objects (ie. {@link LoadSpec}s) were found.
	 *
	 * @return count of importable objects.
	 */
	public int getTotalCount() {
		int count = 0;
		for (BatchGroup batchGroup : groupsByCriteria.values()) {
			count += batchGroup.getBatchLoadConfig().size();
		}
		return count;
	}

	/**
	 * Returns the count of how many files were found while processing the source files.
	 *
	 * @return count of files found while processing source files.
	 */
	public int getTotalRawCount() {
		int count = 0;
		for (UserAddedSourceInfo uasi : userAddedSources) {
			count += uasi.getRawFileCount();
		}
		return count;
	}

	/**
	 * Returns the count of applications in enabled {@link BatchGroup}s... in other
	 * words, the number of objects that would be imported during this batch.
	 *
	 * @return count of enabled applications.
	 */
	public int getEnabledCount() {
		int count = 0;
		for (BatchGroup batchGroup : groupsByCriteria.values()) {
			if (batchGroup.isEnabled()) {
				count += batchGroup.getBatchLoadConfig().size();
			}
		}
		return count;
	}

	/**
	 * Removes a user-added source file (and all the embedded files inside it) from this
	 * batch.
	 *
	 * @param fsrl {@link FSRL} of the file to remove.
	 */
	public void remove(FSRL fsrl) {
		for (Iterator<Entry<BatchSegregatingCriteria, BatchGroup>> iterator =
			groupsByCriteria.entrySet().iterator(); iterator.hasNext();) {
			Entry<BatchSegregatingCriteria, BatchGroup> entry = iterator.next();
			BatchGroup bg = entry.getValue();
			bg.removeDescendantsOf(fsrl);
			if (bg.isEmpty()) {
				iterator.remove();
			}
		}

		for (Iterator<UserAddedSourceInfo> iterator =
			userAddedSources.iterator(); iterator.hasNext();) {
			UserAddedSourceInfo uasi = iterator.next();
			if (uasi.getFSRL().equals(fsrl)) {
				iterator.remove();
			}
		}
		userAddedFSRLs.remove(fsrl);
	}

	/**
	 * Adds a file to this batch as the direct result of a user action.
	 * <p>
	 * If the file is a container for other files, this method will iterate through those
	 * child files and recursively try to add them using this method.
	 * <p>
	 * @param fsrl {@link FSRL} of the file to add.
	 * @param taskMonitor {@link TaskMonitor} to watch and update with progress.
	 * @return boolean true if something in the the file produced something to import.
	 * @throws IOException if io error when reading files.
	 * @throws CancelledException if user cancels.
	 */
	public boolean addFile(FSRL fsrl, TaskMonitor taskMonitor)
			throws IOException, CancelledException {

		fsrl = fsService.getFullyQualifiedFSRL(fsrl, taskMonitor);
		if (userAddedFSRLs.contains(fsrl)) {
			throw new IOException("Batch already contains file " + fsrl);
		}

		currentUASI = new UserAddedSourceInfo(fsrl);
		userAddedSources.add(currentUASI);
		userAddedFSRLs.add(currentUASI.getFSRL());

		int startCount = getTotalCount();
		boolean result = doAddFile(fsrl, taskMonitor);
		int endCount = getTotalCount();

		currentUASI.setFileCount(endCount - startCount);

		return result;
	}

	/**
	 * The main worker for adding a file to the batch session.
	 * <p>
	 * The file is probed for high-priority filesystems first, then if no matches,
	 * Ghidra loaders, and then if no matches, all filesystems.
	 * <p>
	 * @param fsrl {@link FSRL} of the file to probe and process
	 * @param taskMonitor {@link TaskMonitor} to watch and update.
	 * @return boolean true if something in the the file produced something to import.
	 * @throws IOException if io error when reading files.
	 * @throws CancelledException if user cancels.
	 */
	private boolean doAddFile(FSRL fsrl, TaskMonitor taskMonitor)
			throws IOException, CancelledException {

		// use the fsrl param instead of file.getFSRL() as param may have more info (ie. md5)

		try (RefdFile refdFile = fsService.getRefdFile(fsrl, taskMonitor)) {
			GFile file = refdFile.file;
			if (file.isDirectory()) {
				processFS(file.getFilesystem(), file, taskMonitor);
				return true;
			}

			if (processAsFS(fsrl, taskMonitor)) {
				return true;
			}

			if (processWithLoader(fsrl, taskMonitor)) {
				return true;
			}

			// the file was not of interest, let it be removed from the cache
			fsService.releaseFileCache(fsrl);

			return false;
		}
	}

	private boolean shouldTerminateRecurse(FSRL fsrl) {
		if (maxDepth <= 0) {
			return false;
		}

		int initialLevel = currentUASI.getFSRL().getNestingDepth();
		int fsrlLevel = fsrl.getNestingDepth();
		return (fsrlLevel - initialLevel) > maxDepth - 1;
	}

	/**
	 * Returns true if any of the user source files had containers that were not
	 * recursed into because of the {@link #maxDepth} limit.
	 *
	 * @return true if any of the user source files had containers that were not
	 * recursed into because of the {@link #maxDepth} limit.
	 */
	public boolean wasRecurseTerminatedEarly() {
		for (UserAddedSourceInfo uasi : userAddedSources) {
			if (uasi.wasRecurseTerminatedEarly()) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Checks the found applications and returns true if only a single binary was found,
	 * even if multiple loaders claim it.
	 * 
	 * @return true if single binary and batch is probably not correct importer.
	 */
	public boolean isSingleApp() {
		Set<String> foundLoaders = new HashSet<>();
		for (BatchGroup group : groupsByCriteria.values()) {
			for (BatchLoadConfig batchLoadConfig : group.getBatchLoadConfig()) {
				String loaderID =
					batchLoadConfig.getLoadSpecs().iterator().next().getLoader().getName();
				if (!foundLoaders.add(loaderID)) {
					return false;
				}
			}
		}
		return true;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		for (BatchGroup similarApps : groupsByCriteria.values()) {
			sb.append(similarApps.toString());
			sb.append("\n");
		}
		return sb.toString();
	}

	private boolean processAsFS(FSRL fsrl, TaskMonitor taskMonitor)
			throws CancelledException {

		try (FileSystemRef fsRef = fsService.probeFileForFilesystem(fsrl, taskMonitor,
			FileSystemProbeConflictResolver.CHOOSEFIRST)) {
			if (fsRef == null) {
				return false;
			}
			GFileSystem fs = fsRef.getFilesystem();

			currentUASI.incContainerCount();
			if (shouldTerminateRecurse(fs.getFSRL())) {
				currentUASI.setRecurseTerminatedEarly(true);
				return true;
			}
			currentUASI.setMaxNestLevel(
				Math.max(currentUASI.getMaxNestLevel(), fs.getFSRL().getNestingDepth()));

			processFS(fs, null, taskMonitor);
			return true;
		}
		catch (IOException ioe) {
			Msg.warn(this,
				"Error while probing file " + fsrl + " for filesystems: " + ioe.getMessage());
			return false;
		}
	}

	/**
	 * Recursively handles files in an already opened GFileSystem.
	 * @param fs {@link GFileSystem} containing the startDir
	 * @param startDir {@link GFile} ref to the directory to process, null if root of the filesystem.
	 * @param taskMonitor {@link TaskMonitor} to watch and update.
	 * @throws CancelledException if user cancels
	 * @throws IOException if io error while reading files.
	 */
	private void processFS(GFileSystem fs, GFile startDir, TaskMonitor taskMonitor)
			throws CancelledException, IOException {

		// TODO: drop FSUtils.listFileSystem and do recursion here.
		for (GFile file : FSUtilities.listFileSystem(fs, startDir, null, taskMonitor)) {
			taskMonitor.checkCanceled();
			FSRL fqFSRL;
			try {
				fqFSRL = fsService.getFullyQualifiedFSRL(file.getFSRL(), taskMonitor);
			}
			catch (IOException e) {
				Msg.warn(this, "Error getting info for " + file.getFSRL());
				continue;
			}
			doAddFile(fqFSRL, taskMonitor);
			currentUASI.incRawFileCount();
		}
	}

	/**
	 * Tries to open a file using Ghidra {@link Loader}s.
	 * <p>
	 * The {@link BinaryLoader} is unconditionally skipped.
	 *
	 * @param fsrl {@link FSRL} of the file to open
	 * @param monitor {@link TaskMonitor} to use
	 * @return boolean true if successfully processed with a loader, false if no loader claimed
	 * the file.
	 * @throws IOException if io error during processing
	 * @throws CancelledException if user cancels.
	 */
	private boolean processWithLoader(FSRL fsrl, TaskMonitor monitor)
			throws IOException, CancelledException {

		try (ByteProvider provider = fsService.getByteProvider(fsrl, false, monitor)) {
			LoaderMap loaderMap = pollLoadersForLoadSpecs(provider, fsrl, monitor);
			for (Loader loader : loaderMap.keySet()) {
				Collection<LoadSpec> loadSpecs = loaderMap.get(loader);
				BatchSegregatingCriteria bsc =
					new BatchSegregatingCriteria(loader, loadSpecs, provider);
				BatchGroup batchGroup = groupsByCriteria.get(bsc);
				if (batchGroup == null) {
					batchGroup = new BatchGroup(bsc);
					groupsByCriteria.put(bsc, batchGroup);
				}
				batchGroup.add(provider, loadSpecs, fsrl, currentUASI);
			}

			return loaderMap.keySet().size() > 0;
		}
		catch (IOException ioe) {
			Msg.warn(this, "Error while probing file " + fsrl + " for loader applications: " +
				ioe.getMessage());
			return false;
		}
	}

	private LoaderMap pollLoadersForLoadSpecs(ByteProvider provider, FSRL fsrl, TaskMonitor monitor) {
		monitor.setMessage(fsrl.getName());
		return LoaderService.getSupportedLoadSpecs(provider,
			loader -> !(loader instanceof BinaryLoader));
	}

	/**
	 * Returns the {@link List} of files added via {@link #addFile(FSRL, TaskMonitor)}.
	 *
	 * @return {@link List} of files added via {@link #addFile(FSRL, TaskMonitor)}.
	 */
	public List<UserAddedSourceInfo> getUserAddedSources() {
		return userAddedSources;
	}

	/**
	 * Maximum depth of containers (ie. filesystems) to recurse into when processing
	 * a file added by the user
	 *
	 * @return the current maximum depth of containers (ie. filesystems) to recurse into when processing
	 * a file added by the user.
	 */
	public int getMaxDepth() {
		return maxDepth;
	}

	/**
	 * Sets a new max container recursive depth limit for this batch import
	 * <p>
	 * Doing this requires rescanning all original user-added source files and stopping
	 * at the new max depth.
	 * <p>
	 * @param newMaxDepth new value for the max depth
	 */
	public void setMaxDepth(int newMaxDepth) {

		//@formatter:off
		new TaskBuilder("Scanning Source Files", monitor -> doSetMaxDepth(newMaxDepth, monitor))
			.setStatusTextAlignment(SwingConstants.LEADING)
			.setHasProgress(false) // indeterminate			
			.launchModal()
			;
		//@formatter:on
	}

	/**
	 * Adds the given files to this batch import
	 * 
	 * @param filesToAdd the files to add
	 * @return any files that failed to load; exceptions will be logged
	 */
	List<FSRL> addFiles(List<FSRL> filesToAdd) {

		//@formatter:off
		AddFilesRunnable runnable = new AddFilesRunnable(filesToAdd);
		new TaskBuilder("Adding Source Files", runnable)
			.setStatusTextAlignment(SwingConstants.LEADING)
			.setHasProgress(false) // indeterminate
			.launchModal()
			;
		//@formatter:on

		return runnable.getBadFiles();
	}

	private void doSetMaxDepth(int newMaxDepth, TaskMonitor monitor) {

		if (newMaxDepth == maxDepth) {
			return;
		}

		// TODO: make this smarter and when switching from higher maxDepth to lower,
		// just remove existing files that are deeper.  Recalculating user added source info 
		// number is hard so I'm skipping it now.

		Msg.trace(this, "Switching maxDepth from " + maxDepth + " to " + newMaxDepth);

		//@formatter:off
		List<FSRL> files = userAddedSources
			.stream()
			.map(source -> {
				return source.getFSRL(); 
			})
			.collect(Collectors.toList())
			;
		//@formatter:on

		groupsByCriteria.clear();
		userAddedSources.clear();
		userAddedFSRLs.clear();
		maxDepth = newMaxDepth;

		doAddFiles(files, monitor);
	}

	private List<FSRL> doAddFiles(List<FSRL> filesToAdd, TaskMonitor monitor) {

		BatchTaskMonitor batchMonitor = new BatchTaskMonitor(monitor);

		// start a new CryptoSession to group all password prompting by multiple container
		// files into a single session, enabling "Cancel All" to really cancel all password
		// prompts
		try (CryptoSession cryptoSession = fsService.newCryptoSession()) {
			List<FSRL> badFiles = new ArrayList<>();
			for (FSRL fsrl : filesToAdd) {
				Msg.trace(this, "Adding " + fsrl);
				batchMonitor.setPrefix("Processing " + fsrl.getName() + ": ");

				try {
					monitor.checkCanceled();
					addFile(fsrl, batchMonitor);
				}
				catch (CryptoException ce) {
					FSUtilities.displayException(this, null, "Error Adding File To Batch Import",
						"Error while adding " + fsrl.getName() + " to batch import", ce);
				}
				catch (IOException ioe) {
					Msg.error(this, "Error while adding " + fsrl.getName() + " to batch import",
						ioe);
					badFiles.add(fsrl);
				}
				catch (CancelledException e) {
					Msg.debug(this, "Cancelling Add File task while adding " + fsrl.getName());
					// Note: the workflow for this felt odd: press cancel; confirm cancel; press Ok 
					//       on dialog showing files not processed.
					// It seems like the user should not have to see the second dialog
					// badFiles.addAll(filesToAdd.subList(i, filesToAdd.size()));
				}
			}

			return badFiles;
		}
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private class AddFilesRunnable implements MonitoredRunnable {

		private List<FSRL> files;
		private List<FSRL> badFiles;

		AddFilesRunnable(List<FSRL> files) {
			this.files = files;
		}

		@Override
		public void monitoredRun(TaskMonitor monitor) {
			badFiles = doAddFiles(files, monitor);
		}

		List<FSRL> getBadFiles() {
			return badFiles;
		}
	}

	/** A task monitor that allows us to control the message content and the progress */
	private class BatchTaskMonitor extends WrappingTaskMonitor {

		private String prefix;

		BatchTaskMonitor(TaskMonitor delegate) {
			super(delegate);
		}

		void setPrefix(String prefix) {
			this.prefix = prefix;
		}

		@Override
		public void setMessage(String message) {
			super.setMessage(prefix + " " + message);
		}

		@Override
		public void initialize(long max) {
			// we control the max value
		}

		@Override
		public void setProgress(long value) {
			// we control the progress
		}
	}

}
