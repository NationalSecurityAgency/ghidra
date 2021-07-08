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
package ghidra.plugin.importer;

import java.io.IOException;
import java.net.MalformedURLException;
import java.util.*;

import ghidra.app.services.ProgramManager;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.*;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.datastruct.FixedSizeHashMap;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Provides a best-effort<sup>[1]</sup> mapping / association between Ghidra Program/DomainFile
 * objects and GFilesystem files (identified by their {@link FSRL}).
 * <p>
 * As there is no current feature that allows you to quickly query the metadata of
 * Programs/DomainFile objects in the current project, finding a Program by its MD5 or by a
 * original source location string is not easily possible.
 * <p>
 * Threadsafe.
 * <p>
 * The current implementation searches current open Ghidra Programs and maintains a
 * short-lived, in-memory only mapping of FSRL-&gt;DomainFile paths
 * (manually updated by users of the ProgramMappingService when
 * they do an import or other operation that creates a Ghidra DomainFile by calling
 * {@link #createAssociation(FSRL, DomainFile)} and friends.)
 * <p>
 * [1] - best-effort (adverb): meaning a dirty hack.
 */
public class ProgramMappingService {
	public static final String PROGRAM_METADATA_MD5 = "Executable MD5";
	public static final String PROGRAM_SOURCE_FSRL = "FSRL";

	private static final int FSRL_TO_PATH_MAP_SIZE = 1000;

	/**
	 * LRU mapping from FSRL to the project path string of a DomainFile object.
	 * <p>
	 * Limited in size to {@value #FSRL_TO_PATH_MAP_SIZE}.
	 */
	private static Map<FSRL, String> fsrlToProjectPathMap =
		new FixedSizeHashMap<>(FSRL_TO_PATH_MAP_SIZE);

	private ProgramMappingService() {
		// utils class; cannot instantiate
	}

	/**
	 * Clears {@link ProgramMappingService} data.
	 * <p>
	 * This should be done whenever the project is opened/closed.
	 */
	public static void clear() {
		synchronized (fsrlToProjectPathMap) {
			fsrlToProjectPathMap.clear();
		}
	}

	/**
	 * Returns true if there is a current open Ghidra {@link Program} that has metadata
	 * that links it to the specified {@link FSRL}.
	 * <p>
	 * (ie. an open program has a MD5 or FSRL metadata value that matches the fsrl param.)
	 *
	 * @param fsrl {@link FSRL} to search for in open program info.
	 * @return boolean true if found.
	 */
	public static boolean isFileOpen(FSRL fsrl) {
		String expectedMD5 = fsrl.getMD5();

		List<DomainFile> openDomainFiles = findOpenFiles();

		Object consumer = new Object();
		for (DomainFile df : openDomainFiles) {
			DomainObject openedDomainObject = df.getOpenedDomainObject(consumer);
			try {
				if (openedDomainObject instanceof Program) {
					Program program = (Program) openedDomainObject;
					Options propertyList = program.getOptions(Program.PROGRAM_INFO);
					String fsrlStr =
						propertyList.getString(ProgramMappingService.PROGRAM_SOURCE_FSRL, null);
					String md5 =
						propertyList.getString(ProgramMappingService.PROGRAM_METADATA_MD5, null);

					if ((expectedMD5 != null && expectedMD5.equals(md5)) ||
						fsrl.isEquivalent(fsrlStr)) {
						createAssociation(fsrl, program);
						return true;
					}
				}
			}
			finally {
				if (openedDomainObject != null && openedDomainObject.isUsedBy(consumer)) {
					openedDomainObject.release(consumer);
				}
			}
		}
		return false;
	}

	/**
	 * Returns true if the specified {@link FSRL} has a matched Ghidra {@link DomainFile}
	 * in the current project.
	 * <p>
	 * @param fsrl {@link FSRL} to search for
	 * @return boolean true if file exists in project.
	 */
	public static boolean isFileImportedIntoProject(FSRL fsrl) {
		return isFileOpen(fsrl) || (getCachedDomainFileFor(fsrl) != null);
	}

	/**
	 * Returns a reference to a {@link DomainFile} in the current {@link Project} that matches
	 * the specified {@link FSRL}.
	 * <p>
	 * This method only consults an internal fsrl-to-DomainFile mapping that is short-lived
	 * and not persisted.
	 * <p>
	 * @param fsrl {@link FSRL} to search for
	 * @return {@link DomainFile} that was previously associated via
	 * 			{@link #createAssociation(FSRL, DomainFile)} and friends.
	 */
	public static DomainFile getCachedDomainFileFor(FSRL fsrl) {
		String path = null;
		synchronized (fsrlToProjectPathMap) {
			path = fsrlToProjectPathMap.get(fsrl);
			if (path == null && fsrl.getMD5() != null) {
				fsrl = fsrl.withMD5(null);
				path = fsrlToProjectPathMap.get(fsrl);
			}
		}

		if (path == null) {
			return null;
		}

		DomainFile domainFile = getProjectFile(path);
		if (domainFile == null) {
			// The domainFile will be null if the cached path is no longer valid.  Remove
			// the stale path from the cache.
			synchronized (fsrlToProjectPathMap) {
				if (Objects.equals(fsrlToProjectPathMap.get(fsrl), path)) {
					fsrlToProjectPathMap.remove(fsrl);
				}
			}
		}
		return domainFile;
	}

	/**
	 * Creates a short-lived association between a {@link FSRL} and an open {@link Program}.
	 * <p>
	 * @param fsrl {@link FSRL} of where the {@link Program} was imported from.
	 * @param program {@link Program} to associate to.
	 */
	public static void createAssociation(FSRL fsrl, Program program) {
		synchronized (fsrlToProjectPathMap) {
			fsrlToProjectPathMap.put(fsrl, program.getDomainFile().getPathname());
			fsrlToProjectPathMap.put(fsrl.withMD5(null), program.getDomainFile().getPathname());
		}
	}

	/**
	 * Creates a short-lived association between a {@link FSRL} and a {@link DomainFile}.
	 *
	 * @param fsrl {@link FSRL} of where the DomainFile was imported from.
	 * @param domainFile {@link DomainFile} to associate with
	 */
	public static void createAssociation(FSRL fsrl, DomainFile domainFile) {
		createAssociation(fsrl, domainFile, false);
	}

	private static void createAssociation(FSRL fsrl, DomainFile domainFile,
			boolean onlyAddIfEnoughRoomInCache) {
		synchronized (fsrlToProjectPathMap) {
			if (!onlyAddIfEnoughRoomInCache ||
				fsrlToProjectPathMap.size() < FSRL_TO_PATH_MAP_SIZE) {
				fsrlToProjectPathMap.put(fsrl, domainFile.getPathname());
				fsrlToProjectPathMap.put(fsrl.withMD5(null), domainFile.getPathname());
			}
		}
	}

	/**
	 * Attempts to create an association between the specified open {@code program} and
	 * any {@link FSRL} metadata found in the {@link Program}s properties.
	 * <p>
	 * Used by event handlers that get notified about a {@link Program} being opened to
	 * opportunistically link that program to its source FSRL if the metadata is present.
	 * <p>
	 * @param program {@link Program} to rummage around in its metadata looking for FSRL info.
	 */
	public static void createAutoAssocation(Program program) {
		if (program != null) {
			Options propertyList = program.getOptions(Program.PROGRAM_INFO);
			String fsrlStr =
				propertyList.getString(ProgramMappingService.PROGRAM_SOURCE_FSRL, null);
			if (fsrlStr != null) {
				try {
					FSRL fsrl = FSRL.fromString(fsrlStr);
					synchronized (fsrlToProjectPathMap) {
						if (!fsrlToProjectPathMap.containsKey(fsrl)) {
							fsrlToProjectPathMap.put(fsrl, program.getDomainFile().getPathname());
						}
					}
				}
				catch (MalformedURLException e) {
					Msg.error(ProgramMappingService.class, "Bad FSRL found: " + fsrlStr +
						", program: " + program.getDomainFile().getPathname());
				}
			}
		}
	}

	/**
	 * Returns an open {@link Program} instance that matches the specified
	 * {@link FSRL}, either from the set of currently open programs, or by
	 * requesting the specified {@link ProgramManager} to
	 * open a {@link DomainFile} that was found to match this GFile.
	 * <p>
	 * @param fsrl {@link FSRL} of program original location.
	 * @param consumer Object that will be used to pin the matching Program open.  Caller
	 * must release the consumer when done.
	 * @param programManager {@link ProgramManager} that will be used to open DomainFiles
	 * if necessary.
	 * @param openState one of {@link ProgramManager#OPEN_VISIBLE},
	 * 			{@link ProgramManager#OPEN_HIDDEN}, {@link ProgramManager#OPEN_VISIBLE}
	 * @return {@link Program} which was imported from the specified FSRL, or null if not found.
	 */
	public static Program findMatchingProgramOpenIfNeeded(FSRL fsrl, Object consumer,
			ProgramManager programManager, int openState) {
		return findMatchingProgramOpenIfNeeded(fsrl, null, consumer, programManager, openState);
	}

	/**
	 * Returns an open {@link Program} instance that matches the specified
	 * {@link FSRL}, either from the set of currently open programs, or by
	 * requesting the specified {@link ProgramManager} to
	 * open a {@link DomainFile} that was found to match this GFile.
	 * <p>
	 * @param fsrl {@link FSRL} of program original location.
	 * @param domainFile optional {@link DomainFile} that corresponds to the FSRL param.
	 * @param consumer Object that will be used to pin the matching Program open.  Caller
	 * must release the consumer when done.
	 * @param programManager {@link ProgramManager} that will be used to open DomainFiles
	 * if necessary.
	 * @param openState one of {@link ProgramManager#OPEN_VISIBLE},
	 * 			{@link ProgramManager#OPEN_HIDDEN}, {@link ProgramManager#OPEN_VISIBLE}
	 * @return {@link Program} which was imported from the specified FSRL, or null if not found.
	 */
	public static Program findMatchingProgramOpenIfNeeded(FSRL fsrl, DomainFile domainFile,
			Object consumer, ProgramManager programManager, int openState) {
		Program program = findMatchingOpenProgram(fsrl, consumer);
		if (program != null) {
			programManager.openProgram(program, openState);
			return program;
		}
		DomainFile df = (domainFile == null) ? getCachedDomainFileFor(fsrl) : domainFile;
		if (df == null || programManager == null) {
			return null;
		}

		program = programManager.openProgram(df, DomainFile.DEFAULT_VERSION, openState);
		if (program != null) {
			program.addConsumer(consumer);
		}
		return program;
	}

	/**
	 * Returns a currently open Ghidra {@link Program} that has metadata that links it
	 * to the specified {@code file} parameter.
	 * <p>
	 * (ie. an open program has a MD5 or FSRL metadata value that matches the file)
	 * <p>
	 * See also {@link #isFileOpen(FSRL)}.
	 * <p>
	 * @param fsrl {@link FSRL} to use when inspecting each open Program's metadata.
	 * @param consumer Object that will be used to pin the matching Program open.  Caller
	 * must release the consumer when done.
	 * @return Already open {@link Program} that has matching metadata, or null if not found.
	 */
	public static Program findMatchingOpenProgram(FSRL fsrl, Object consumer) {
		String expectedMD5 = fsrl.getMD5();

		// use a temp consumer to hold the domainObject open because the caller-supplied
		// consumer might already have been used to open one of the files we are querying.
		Object tmpConsumer = new Object();
		List<DomainFile> openDomainFiles = getOpenFiles();
		for (DomainFile df : openDomainFiles) {
			DomainObject openedDomainObject = df.getOpenedDomainObject(tmpConsumer);
			try {
				if (openedDomainObject instanceof Program) {
					Program program = (Program) openedDomainObject;
					Options propertyList = program.getOptions(Program.PROGRAM_INFO);
					String fsrlStr =
						propertyList.getString(ProgramMappingService.PROGRAM_SOURCE_FSRL, null);
					String md5 =
						propertyList.getString(ProgramMappingService.PROGRAM_METADATA_MD5, null);

					if ((expectedMD5 != null && expectedMD5.equals(md5)) ||
						fsrl.isEquivalent(fsrlStr)) {
						// lock the domain file with the caller-supplied consumer now that
						// we've found it.
						df.getOpenedDomainObject(consumer);
						return program;
					}
				}
			}
			finally {
				if (openedDomainObject != null) {
					openedDomainObject.release(tmpConsumer);
				}
			}
		}
		return null;
	}

	/**
	 * Recursively searches the current active {@link Project} for {@link DomainFile}s that
	 * have metadata that matches a {@link FSRL} in the specified list.
	 * <p>
	 * Warning, this operation is expensive and should only be done in a Task thread.
	 * <p>
	 * @param fsrls List of {@link FSRL} to match against the metadata of each DomainFile in Project.
	 * @param monitor {@link TaskMonitor} to watch for cancel and update with progress.
	 * @return Map of FSRLs to {@link DomainFile}s of the found files, never null.
	 */
	public static Map<FSRL, DomainFile> searchProjectForMatchingFiles(List<FSRL> fsrls,
			TaskMonitor monitor) {

		Project project = AppInfo.getActiveProject();
		if (project == null) {
			// this should not be possible if this call is being run as a task
			return Collections.emptyMap();
		}

		ProjectData projectData = project.getProjectData();
		int fc = projectData.getFileCount();
		if (fc > 0) {
			monitor.setShowProgressValue(true);
			monitor.setMaximum(fc);
			monitor.setProgress(0);
		}
		else {
			monitor.setIndeterminate(true);
		}
		monitor.setMessage("Searching project for matching files");

		Map<String, FSRL> fsrlsToFindByMD5;
		try {
			fsrlsToFindByMD5 = buildFullyQualifiedFSRLMap(fsrls, monitor);
		}
		catch (CancelledException ce) {
			Msg.info(ProgramMappingService.class, "Canceling project search");
			return Collections.emptyMap();
		}

		Map<FSRL, DomainFile> results = new HashMap<>();

		Iterable<DomainFile> files = ProjectDataUtils.descendantFiles(projectData.getRootFolder());
		for (DomainFile domainFile : files) {
			if (monitor.isCancelled() || fsrlsToFindByMD5.isEmpty()) {
				break;
			}

			monitor.incrementProgress(1);
			Map<String, String> metadata = domainFile.getMetadata();

			FSRL dfFSRL = getFSRLFromMetadata(metadata, domainFile);
			if (dfFSRL != null) {
				// side effect: create association between the FSRL in the DomainFile's props
				// to the DomainFile's path if there is room in the cache.
				// (ie. don't blow out the cache for files that haven't been requested yet)
				createAssociation(dfFSRL, domainFile, true);
			}
			String dfMD5 = (dfFSRL != null) ? dfFSRL.getMD5() : getMD5FromMetadata(metadata);
			if (dfMD5 != null) {
				FSRL matchedFSRL = fsrlsToFindByMD5.get(dfMD5);
				if (matchedFSRL != null) {
					results.put(matchedFSRL, domainFile);
					fsrlsToFindByMD5.remove(dfMD5);
				}
			}
		}

		return results;
	}

	private static String getMD5FromMetadata(Map<String, String> metadata) {
		return metadata.get(PROGRAM_METADATA_MD5);
	}

	private static FSRL getFSRLFromMetadata(Map<String, String> metadata, DomainFile domainFile) {
		String dfFSRLStr = metadata.get(PROGRAM_SOURCE_FSRL);
		if (dfFSRLStr != null) {
			try {
				FSRL dfFSRL = FSRL.fromString(dfFSRLStr);
				return dfFSRL;
			}
			catch (MalformedURLException e) {
				Msg.warn(ProgramMappingService.class,
					"Domain file " + domainFile.getPathname() + " has a bad FSRL: " + dfFSRLStr);
			}
		}
		return null;
	}

	private static DomainFile getProjectFile(String path) {

		Project project = AppInfo.getActiveProject();
		if (project != null) {
			ProjectData data = project.getProjectData();
			if (data != null) {
				return data.getFile(path);
			}
		}
		return null;
	}

	private static List<DomainFile> getOpenFiles() {

		List<DomainFile> files = new ArrayList<>();
		Project project = AppInfo.getActiveProject();
		if (project != null) {
			files = project.getOpenData();
		}
		return files;
	}

	private static List<DomainFile> findOpenFiles() {

		List<DomainFile> files = new ArrayList<>();
		Project project = AppInfo.getActiveProject();
		if (project != null) {
			ProjectData data = project.getProjectData();
			if (data != null) {
				data.findOpenFiles(files);
			}
		}
		return files;
	}

	private static Map<String, FSRL> buildFullyQualifiedFSRLMap(List<FSRL> fsrls,
			TaskMonitor monitor) throws CancelledException {
		Map<String, FSRL> result = new HashMap<>();
		for (FSRL fsrl : fsrls) {
			try {
				FSRL fqFSRL = FileSystemService.getInstance().getFullyQualifiedFSRL(fsrl, monitor);
				String expectedMD5 = fqFSRL.getMD5();
				result.put(expectedMD5, fsrl);
			}
			catch (IOException e) {
				// ignore and continue
			}
		}
		return result;
	}

}
