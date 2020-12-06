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
package ghidra.plugins.importer.tasks;

import java.io.IOException;
import java.util.List;

import org.apache.commons.io.FilenameUtils;

import generic.stl.Pair;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.formats.gfilesystem.*;
import ghidra.framework.model.*;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.plugin.importer.ImporterUtilities;
import ghidra.plugin.importer.ProgramMappingService;
import ghidra.plugins.importer.batch.*;
import ghidra.plugins.importer.batch.BatchGroup.BatchLoadConfig;
import ghidra.program.model.listing.Program;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * Performs a batch import using the data provided in the {@link BatchInfo} object which
 * specifies what files and the import language that should be used.
 * <p>
 * If there are just a few files to import, they will be opened using the ProgramManager,
 * otherwise the programManager parameter will be unused.
 */
public class ImportBatchTask extends Task {
	public static final int MAX_PROGRAMS_TO_OPEN = 50;

	private BatchInfo batchInfo;
	private DomainFolder destFolder;
	private boolean stripLeadingPath = true;
	private boolean stripAllContainerPath = false;
	private ProgramManager programManager;
	private int totalObjsImported;
	private int totalAppsImported;
	private int totalEnabledApps;

	/**
	 * Start a Batch Import session with an already populated {@link BatchInfo}
	 * instance.
	 * <p>
	 * @param batchInfo {@link BatchInfo} state object
	 * @param destFolder {@link DomainFolder} where to place imported files
	 * @param programManager {@link ProgramManager} to use when opening newly imported files, null ok
	 * @param stripLeading boolean true if each import source's leading path should be omitted
	 * when creating the destination project folder path.
	 * @param stripAllContainerPath boolean true if each imported file's parent container
	 * source path should be completely omitted when creating the destination project folder path.
	 * (the imported file's path within its container is still used)
	 */
	public ImportBatchTask(BatchInfo batchInfo, DomainFolder destFolder,
			ProgramManager programManager, boolean stripLeading, boolean stripAllContainerPath) {
		super("Batch Import Task", true, true, false, false);

		this.batchInfo = batchInfo;
		this.destFolder = destFolder;
		this.totalEnabledApps = batchInfo.getEnabledCount();
		this.programManager = programManager;
		this.stripLeadingPath = stripLeading;
		this.stripAllContainerPath = stripAllContainerPath;
	}

	@Override
	public void run(TaskMonitor monitor) {

		try {
			doBatchImport(monitor);
		}
		catch (CancelledException e) {
			Msg.debug(this, "Batch import cancelled");
		}
		catch (IOException ce) {
			Msg.error(this, "Error during batch import: ", ce);
		}
		finally {
			Msg.showInfo(this, null, "Batch Import Summary",
				"Batch Import finished.\nImported " + totalObjsImported + " files.");
		}
	}

	private void doBatchImport(TaskMonitor monitor) throws CancelledException, IOException {
		Msg.info(this,
			"Starting batch import of " + totalEnabledApps + " programs into " + destFolder);
		for (BatchGroup batchGroup : batchInfo.getGroups()) {
			if (!batchGroup.isEnabled()) {
				continue;
			}
			if (monitor.isCancelled()) {
				Msg.info(this, "Stopping batch import due to cancel");
				break;
			}
			doImportBatchGroup(batchGroup, monitor);
		}
	}

	private void doImportBatchGroup(BatchGroup batchGroup, TaskMonitor monitor)
			throws CancelledException, IOException {
		BatchGroupLoadSpec selectedBatchGroupLoadSpec = batchGroup.getSelectedBatchGroupLoadSpec();
		for (BatchLoadConfig loadConfig : batchGroup.getBatchLoadConfig()) {
			if (monitor.isCancelled()) {
				return;
			}
			doImportApp(loadConfig, selectedBatchGroupLoadSpec, monitor);
		}
	}

	private void doImportApp(BatchLoadConfig batchLoadConfig,
			BatchGroupLoadSpec selectedBatchGroupLoadSpec, TaskMonitor monitor)
			throws CancelledException, IOException {
		try (ByteProvider byteProvider =
			FileSystemService.getInstance().getByteProvider(batchLoadConfig.getFSRL(), monitor)) {
			LoadSpec loadSpec = batchLoadConfig.getLoadSpec(selectedBatchGroupLoadSpec);
			if (loadSpec == null) {
				Msg.error(this,
					"Failed to get load spec from application that matches choosen batch load spec " +
						selectedBatchGroupLoadSpec);
				return;
			}
			Pair<DomainFolder, String> destInfo = getDestinationInfo(batchLoadConfig, destFolder);

			Object consumer = new Object();
			try {
				MessageLog messageLog = new MessageLog();
				List<DomainObject> importedObjects = loadSpec.getLoader()
						.load(byteProvider,
							fixupProjectFilename(destInfo.second), destInfo.first, loadSpec,
							getOptionsFor(batchLoadConfig, loadSpec, byteProvider), messageLog,
							consumer,
							monitor);

				// TODO: accumulate batch results
				if (importedObjects != null) {
					try {
						processImportResults(importedObjects, batchLoadConfig, monitor);
					}
					finally {
						releaseAll(importedObjects, consumer);
					}
				}
				totalAppsImported++;

				Msg.info(this, "Imported " + destInfo.first + "/ " + destInfo.second + ", " +
					totalAppsImported + " of " + totalEnabledApps);
				if (messageLog.hasMessages()) {
					Msg.info(this, "Additional info:\n" + messageLog.toString());
				}
			}
			catch (CancelledException e) {
				Msg.debug(this, "Batch Import cancelled");
			}
			catch (DuplicateNameException | InvalidNameException | VersionException
					| IOException | IllegalArgumentException e) {
				Msg.error(this, "Import failed for " + batchLoadConfig.getPreferredFileName(), e);
			}
		}
	}

	private String fixupProjectFilename(String filename) {
		// replaces any invalid characters with underscores
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < filename.length(); i++) {
			char ch = filename.charAt(i);
			sb.append(LocalFileSystem.isValidNameCharacter(ch) ? ch : '_');
		}
		return sb.toString();
	}

	private void releaseAll(List<DomainObject> importedObjects, Object consumer) {
		for (DomainObject obj : importedObjects) {
			if (obj.isUsedBy(consumer)) {
				obj.release(consumer);
			}
		}
	}

	/*
	 * sets the imported program's source properties, creates fsrl associations,
	 * updates task statistics,  opens the imported program (if allowed), and
	 * calls the ImportManagerServiceListener callback.
	 */
	private void processImportResults(List<DomainObject> importedObjects, BatchLoadConfig appInfo,
			TaskMonitor monitor) throws CancelledException, IOException {

		for (DomainObject obj : importedObjects) {
			if (obj instanceof Program) {
				Program program = (Program) obj;
				ImporterUtilities.setProgramProperties(program, appInfo.getFSRL(), monitor);

				if (programManager != null && totalObjsImported < MAX_PROGRAMS_TO_OPEN) {
					programManager.openProgram(program,
						totalObjsImported == 0 ? ProgramManager.OPEN_CURRENT
								: ProgramManager.OPEN_VISIBLE);
				}

				ProgramMappingService.createAssociation(appInfo.getFSRL(), program);
			}
			totalObjsImported++;
		}
	}

	/**
	 * Convert a imported file's FSRL into a target project path, using the import options
	 * {@link #stripAllContainerPath} and {@link #stripLeadingPath}.
	 * <p>
	 * Not private so it can be accessed by unit tests.
	 *
	 * @param fsrl {@link FSRL} to convert to a path
	 * @param userSrc {@link FSRL} of the container file that is the parent of the FSRL being
	 * converted.
	 * @param stripLeadingPath boolean option that causes the path to the file the user
	 * picked to be truncated or left intact.
	 * @param stripInteriorContainerPath boolean option that causes the interior paths (ie.
	 * anything inside the user-added source directory or container file) to be stripped.
	 * @return String path (with '/' separators) created according to the user's options
	 * {@link #stripAllContainerPath} and {@link #stripLeadingPath}.
	 */
	static String fsrlToPath(FSRL fsrl, FSRL userSrc, boolean stripLeadingPath,
			boolean stripInteriorContainerPath) {

		String fullPath = fsrl.toPrettyFullpathString().replace('|', '/');
		String userSrcPath = userSrc.toPrettyFullpathString().replace('|', '/');
		int filename = fullPath.lastIndexOf('/') + 1;
		int uas = userSrcPath.length();
		int container = uas + 1;

		int leadStart = (stripLeadingPath == false) ? 0 : userSrcPath.lastIndexOf('/') + 1;
		int leadEnd = Math.min(filename, userSrcPath.length());
		String leading = (leadStart < filename) ? fullPath.substring(leadStart, leadEnd) : "";
		String containerPath = container < filename && !stripInteriorContainerPath
				? fullPath.substring(container, filename)
				: "";
		String filenameStr = fullPath.substring(filename);
		String result = FSUtilities.appendPath(leading, containerPath, filenameStr);
		return result;
	}

	private Pair<DomainFolder, String> getDestinationInfo(BatchLoadConfig batchLoadConfig,
			DomainFolder rootDestinationFolder) {
		FSRL fsrl = batchLoadConfig.getFSRL();
		String pathStr = fsrlToPath(fsrl, batchLoadConfig.getUasi().getFSRL(), stripLeadingPath,
			stripAllContainerPath);
		String preferredName = batchLoadConfig.getPreferredFileName();

		String fsrlFilename = fsrl.getName();
		if (!fsrlFilename.equals(preferredName)) {
			pathStr = FSUtilities.appendPath(pathStr, preferredName);
		}
		// REGEX doc: match any character in the set ('\\', ':', '|') and replace with '/'
		pathStr = pathStr.replaceAll("[\\\\:|]+", "/");
		String parentDir = FilenameUtils.getFullPathNoEndSeparator(pathStr);
		if (parentDir == null) {
			parentDir = "";
		}
		String destFilename = FilenameUtils.getName(pathStr);
		try {
			DomainFolder batchDestFolder =
				ProjectDataUtils.createDomainFolderPath(rootDestinationFolder, parentDir);
			return new Pair<>(batchDestFolder, destFilename);
		}
		catch (InvalidNameException | IOException e) {
			Msg.error(this, "Problem creating project folder root: " +
				rootDestinationFolder.getPathname() + ", subpath: " + parentDir, e);
		}

		return new Pair<>(rootDestinationFolder, fsrlFilename);
	}

	private List<Option> getOptionsFor(BatchLoadConfig batchLoadConfig, LoadSpec loadSpec,
			ByteProvider byteProvider) {
		List<Option> options =
			batchLoadConfig.getLoader().getDefaultOptions(byteProvider, loadSpec, null, false);
		return options;
	}
}
