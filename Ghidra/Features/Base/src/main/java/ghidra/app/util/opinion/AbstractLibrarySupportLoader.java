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
package ghidra.app.util.opinion;

import java.io.File;
import java.io.IOException;
import java.nio.file.AccessMode;
import java.util.*;
import java.util.stream.Collectors;

import org.apache.commons.io.FilenameUtils;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.FileByteProvider;
import ghidra.app.util.importer.LibrarySearchPathManager;
import ghidra.app.util.importer.MessageLog;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.framework.model.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

/**
 * An abstract {@link Loader} that provides a framework to conveniently load {@link Program}s with
 * support for linking against libraries contained in other {@link Program}s.
 * <p>
 * Subclasses may override various protected methods to customize how libraries are loaded.
 */
public abstract class AbstractLibrarySupportLoader extends AbstractProgramLoader {

	public static final String LINK_EXISTING_OPTION_NAME = "Link Existing Project Libraries";
	static final boolean LINK_EXISTING_OPTION_DEFAULT = true;

	public static final String LINK_SEARCH_FOLDER_OPTION_NAME = "Project Library Search Folder";
	static final String LINK_SEARCH_FOLDER_OPTION_DEFAULT = "";

	public static final String LOCAL_LIBRARY_OPTION_NAME = "Load Local Libraries From Disk";
	static final boolean LOCAL_LIBRARY_OPTION_DEFAULT = false;

	public static final String SYSTEM_LIBRARY_OPTION_NAME = "Load System Libraries From Disk";
	static final boolean SYSTEM_LIBRARY_OPTION_DEFAULT = false;

	public static final String DEPTH_OPTION_NAME = "Recursive Library Load Depth";
	static final int DEPTH_OPTION_DEFAULT = 1;

	public static final String LIBRARY_DEST_FOLDER_OPTION_NAME = "Library Destination Folder";
	static final String LIBRARY_DEST_FOLDER_OPTION_DEFAULT = "";

	/**
	 * Loads bytes in a particular format into the given {@link Program}.
	 *
	 * @param provider The bytes to load.
	 * @param loadSpec The {@link LoadSpec} to use during load.
	 * @param options The load options.
	 * @param program The {@link Program} to load into.
	 * @param monitor A cancelable task monitor.
	 * @param log The message log.
	 * @throws IOException if there was an IO-related problem loading.
	 * @throws CancelledException if the user cancelled the load.
	 */
	protected abstract void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException;

	@Override
	protected List<LoadedProgram> loadProgram(ByteProvider provider, String programName,
			DomainFolder programFolder, LoadSpec loadSpec, List<Option> options, MessageLog log,
			Object consumer, TaskMonitor monitor) throws CancelledException, IOException {

		List<LoadedProgram> loadedProgramList = new ArrayList<>();
		List<String> libraryNameList = new ArrayList<>();

		boolean success = false;
		try {
			// Load the primary program
			Program program = doLoad(provider, programName, programFolder, loadSpec,
				libraryNameList, options, consumer, log, monitor);
			loadedProgramList.add(new LoadedProgram(program, programFolder));

			// Load the libraries
			List<LoadedProgram> libraries = loadLibraries(provider, program, programFolder,
				loadSpec, options, log, consumer, libraryNameList, monitor);
			loadedProgramList.addAll(libraries);

			success = true;
			return loadedProgramList;
		}
		finally {
			if (!success) {
				release(loadedProgramList, consumer);
			}
		}
	}

	@Override
	protected boolean loadProgramInto(ByteProvider provider, LoadSpec loadSpec,
			List<Option> options, MessageLog log, Program program, TaskMonitor monitor)
			throws CancelledException, IOException {

		LanguageCompilerSpecPair pair = loadSpec.getLanguageCompilerSpec();
		LanguageID languageID = program.getLanguageID();
		CompilerSpecID compilerSpecID = program.getCompilerSpec().getCompilerSpecID();
		if (!(pair.languageID.equals(languageID) && pair.compilerSpecID.equals(compilerSpecID))) {
			log.appendMsg(provider.getAbsolutePath() +
				" does not have the same language/compiler spec as program " + program.getName());
			return false;
		}
		log.appendMsg("----- Loading " + provider.getAbsolutePath() + " -----");
		load(provider, loadSpec, options, program, monitor, log);
		return true;
	}

	@Override
	protected void postLoadProgramFixups(List<LoadedProgram> loadedPrograms, List<Option> options,
			MessageLog messageLog, TaskMonitor monitor) throws CancelledException, IOException {
		if (loadedPrograms.isEmpty()) {
			return;
		}
		if (isLinkExistingLibraries(options) || isLoadLocalLibraries(options) ||
			isLoadSystemLibraries(options)) {
			DomainFolder programFolder = loadedPrograms.get(0).destinationFolder();
			DomainFolder linkSearchFolder = getLinkSearchFolder(programFolder, options);
			fixupExternalLibraries(loadedPrograms.stream().map(e -> e.program()).toList(),
				linkSearchFolder, true, messageLog, monitor);
		}
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.GENERIC_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 50;
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, loadIntoProgram);
		list.add(new Option(LINK_EXISTING_OPTION_NAME, LINK_EXISTING_OPTION_DEFAULT, Boolean.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-linkExistingProjectLibraries"));
		list.add(new Option(LINK_SEARCH_FOLDER_OPTION_NAME, LINK_SEARCH_FOLDER_OPTION_DEFAULT,
			String.class, Loader.COMMAND_LINE_ARG_PREFIX + "-projectLibrarySearchFolder"));
		list.add(new Option(LOCAL_LIBRARY_OPTION_NAME, LOCAL_LIBRARY_OPTION_DEFAULT, Boolean.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-loadLocalLibraries"));
		list.add(new Option(SYSTEM_LIBRARY_OPTION_NAME, SYSTEM_LIBRARY_OPTION_DEFAULT, Boolean.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-loadSystemLibraries"));
		list.add(new Option(DEPTH_OPTION_NAME, DEPTH_OPTION_DEFAULT, Integer.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-libraryLoadDepth"));
		list.add(new Option(LIBRARY_DEST_FOLDER_OPTION_NAME, LIBRARY_DEST_FOLDER_OPTION_DEFAULT,
			String.class, Loader.COMMAND_LINE_ARG_PREFIX + "-libraryDestinationFolder"));
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		if (options != null) {
			for (Option option : options) {
				String name = option.getName();
				if (name.equals(LINK_EXISTING_OPTION_NAME) ||
					name.equals(LOCAL_LIBRARY_OPTION_NAME) ||
					name.equals(SYSTEM_LIBRARY_OPTION_NAME)) {
					if (!Boolean.class.isAssignableFrom(option.getValueClass())) {
						return "Invalid type for option: " + name + " - " + option.getValueClass();
					}
				}
				else if (name.equals(DEPTH_OPTION_NAME)) {
					if (!Integer.class.isAssignableFrom(option.getValueClass())) {
						return "Invalid type for option: " + name + " - " + option.getValueClass();
					}
				}
				else if (name.equals(LINK_SEARCH_FOLDER_OPTION_NAME) ||
					name.equals(LIBRARY_DEST_FOLDER_OPTION_NAME)) {
					if (!String.class.isAssignableFrom(option.getValueClass())) {
						return "Invalid type for option: " + name + " - " + option.getValueClass();
					}
				}
			}
		}
		return super.validateOptions(provider, loadSpec, options, program);
	}

	/**
	 * Checks to see if existing libraries should be linked
	 * 
	 * @param options a {@link List} of {@link Option}s
	 * @return True if existing libraries should be linked; otherwise, false
	 */
	protected boolean isLinkExistingLibraries(List<Option> options) {
		boolean isLinkExistingLibraries = LINK_EXISTING_OPTION_DEFAULT;
		if (options != null) {
			for (Option option : options) {
				String optName = option.getName();
				if (optName.equals(LINK_EXISTING_OPTION_NAME)) {
					isLinkExistingLibraries = (Boolean) option.getValue();
				}
			}
		}
		return isLinkExistingLibraries;
	}

	/**
	 * Gets the {@link DomainFolder project folder} to search for existing libraries
	 * 
	 * @param programFolder The {@link DomainFolder} that the main program is being loaded into
	 * @param options a {@link List} of {@link Option}s
	 * @return The path of the project folder to search for existing libraries, or null if no
	 *   project folders should be searched
	 */
	protected DomainFolder getLinkSearchFolder(DomainFolder programFolder,
			List<Option> options) {
		if (!shouldSearchAllPaths(options) && !isLinkExistingLibraries(options)) {
			return null;
		}
		String folderPath = LINK_SEARCH_FOLDER_OPTION_DEFAULT;
		if (options != null) {
			for (Option option : options) {
				String optName = option.getName();
				if (optName.equals(LINK_SEARCH_FOLDER_OPTION_NAME)) {
					folderPath = (String) option.getValue();
				}
			}
		}

		if (folderPath.equals(LINK_SEARCH_FOLDER_OPTION_DEFAULT)) {
			return programFolder;
		}

		return programFolder.getProjectData().getFolder(FilenameUtils.separatorsToUnix(folderPath));
	}

	/**
	 * Checks to see if local libraries should be loaded.  Local libraries are libraries that live
	 * in the same directory as the imported program.
	 * 
	 * @param options a {@link List} of {@link Option}s
	 * @return True if local libraries should be loaded; otherwise, false
	 */
	protected boolean isLoadLocalLibraries(List<Option> options) {
		boolean isLoadLocalLibraries = LOCAL_LIBRARY_OPTION_DEFAULT;
		if (options != null) {
			for (Option option : options) {
				String optName = option.getName();
				if (optName.equals(LOCAL_LIBRARY_OPTION_NAME)) {
					isLoadLocalLibraries = (Boolean) option.getValue();
				}
			}
		}
		return isLoadLocalLibraries;
	}

	/**
	 * Checks to see if system libraries should be loaded.  System libraries are libraries that live
	 * in the directories specified in the GUI path list.
	 * 
	 * @param options a {@link List} of {@link Option}s
	 * @return True if system libraries should be loaded; otherwise, false
	 */
	protected boolean isLoadSystemLibraries(List<Option> options) {
		boolean isLoadSystemLibraries = SYSTEM_LIBRARY_OPTION_DEFAULT;
		if (options != null) {
			for (Option option : options) {
				String optName = option.getName();
				if (optName.equals(SYSTEM_LIBRARY_OPTION_NAME)) {
					isLoadSystemLibraries = (Boolean) option.getValue();
				}
			}
		}
		return isLoadSystemLibraries;
	}

	/**
	 * Gets the desired recursive library load depth
	 * 
	 * @param options a {@link List} of {@link Option}s
	 * @return The desired recursive library load depth
	 */
	protected int getLibraryLoadDepth(List<Option> options) {
		int depth = DEPTH_OPTION_DEFAULT;
		if (options != null) {
			for (Option option : options) {
				String optName = option.getName();
				if (optName.equals(DEPTH_OPTION_NAME)) {
					depth = (int) option.getValue();
				}
			}
		}
		return depth;
	}

	/**
	 * Gets the {@link DomainFolder project folder} to load the libraries into
	 * 
	 * @param programFolder The {@link DomainFolder} that the main program is being loaded into
	 * @param options a {@link List} of {@link Option}s
	 * @return The path of the project folder to load the libraries into
	 */
	protected DomainFolder getLibraryDestinationFolder(DomainFolder programFolder,
			List<Option> options) {
		String folderPath = LIBRARY_DEST_FOLDER_OPTION_DEFAULT;
		if (options != null) {
			for (Option option : options) {
				String optName = option.getName();
				if (optName.equals(LIBRARY_DEST_FOLDER_OPTION_NAME)) {
					folderPath = (String) option.getValue();
				}
			}
		}

		if (folderPath.equals(LIBRARY_DEST_FOLDER_OPTION_DEFAULT)) {
			return programFolder;
		}

		return programFolder.getProjectData().getFolder(FilenameUtils.separatorsToUnix(folderPath));
	}

	/**
	 * Checks whether or not to search for libraries using all possible search paths, regardless
	 * of what options are set
	 * 
	 * @param options a {@link List} of {@link Option}s
	 * @return True if all possible search paths should be used, regardless of what options are set
	 */
	protected boolean shouldSearchAllPaths(List<Option> options) {
		return false;
	}

	/**
	 * Specifies if the library filenames specified by this loader should be exact case match
	 * or case-insensitive.
	 * <p>
	 * Derived loader classes should override this method and specify if the OS that normally
	 * handles this type of binary is case-insensitive.
	 *
	 * @return True if case-insensitive or false if case-sensitive.
	 */
	protected boolean isCaseInsensitiveLibraryFilenames() {
		return false;
	}

	/**
	 * Specifies if this loader can refer to library filenames without filename extensions.
	 * <p>
	 * Derived loader classes should override this method if library filename extensions are
	 * optional.  If they are required, there is no need to override this method.
	 * 
	 * @return True if library filename extensions are optional; otherwise, false
	 */
	protected boolean isOptionalLibraryFilenameExtensions() {
		return false;
	}

	/**
	 * Creates a {@link ByteProvider} for the given library file
	 * 
	 * @param libFile The library file to get a {@link ByteProvider} for
	 * @param loadSpec An optional {@link LoadSpec} the {@link ByteProvider} should conform to
	 * @param log The log
	 * @return A {@link ByteProvider} for the given library file, or null if one could not be
	 *   created that matches the given {@link LoadSpec}
	 * @throws IOException If there was an IO-related issue
	 */
	protected ByteProvider createLibraryByteProvider(File libFile, LoadSpec loadSpec,
			MessageLog log) throws IOException {
		return new FileByteProvider(libFile, FileSystemService.getInstance().getLocalFSRL(libFile),
			AccessMode.READ);
	}

	/**
	 * Checks whether or not the given library should be loaded.
	 * <p>
	 * It may be appropriate to not load a specific library after examining its bytes.
	 * 
	 * @param libraryName The name of the library
	 * @param libraryFile The library {@link File}
	 * @param provider The library bytes
	 * @param desiredLoadSpec The desired {@link LoadSpec}
	 * @param log The log
	 * @return True if the given library should be loaded; otherwise, false
	 * @throws IOException If an IO-related error occurred
	 */
	protected boolean shouldLoadLibrary(String libraryName, File libraryFile, ByteProvider provider,
			LoadSpec desiredLoadSpec, MessageLog log) throws IOException {
		if (matchSupportedLoadSpec(desiredLoadSpec, provider) == null) {
			log.appendMsg("Skipping library which is the wrong architecture: " + libraryFile);
			return false;
		}
		return true;
	}

	/**
	 * Performs optional follow-on actions after an the given library has been loaded
	 * 
	 * @param library The loaded library {@link Program}
	 * @param libraryName The name of the library
	 * @param libraryFile The library {@link File}
	 * @param provider The library bytes
	 * @param loadSpec The {@link LoadSpec} used for the load
	 * @param options The options
	 * @param log The log
	 * @param monitor A cancel.able monitor
	 * @return True if the library should be saved to the project; otherwise, false
	 * @throws IOException If an IO-related error occurred
	 * @throws CancelledException If the user cancelled the action
	 */
	protected boolean processLibrary(Program library, String libraryName, File libraryFile,
			ByteProvider provider, LoadSpec loadSpec, List<Option> options, MessageLog log,
			TaskMonitor monitor) throws IOException, CancelledException {
		return isLoadLocalLibraries(options) || isLoadSystemLibraries(options);
	}

	/**
	 * Loads the given list of libraries into the given {@link DomainFolder folder}
	 *
	 * @param provider The {@link ByteProvider} of the program being loaded
	 * @param program The {@link Program} being loaded
	 * @param programFolder The domain folder where the new program will be stored, if null
	 *   the program should not be pre-saved. NOTE: the newly imported libraries will not be written
	 *   to this folder yet, that is handled in a later follow on step.
	 * @param desiredLoadSpec The desired {@link LoadSpec}
	 * @param options The load options
	 * @param log The log
	 * @param consumer A consumer object for {@link DomainObject}s generated
	 * @param monitor A cancelable task monitor
	 * @return A {@link List} of newly loaded programs and libraries.  Any program in the list is 
	 *   the caller's responsibility to release.
	 * @throws IOException if there was an IO-related problem loading
	 * @throws CancelledException if the user cancelled the load
	 */
	private List<LoadedProgram> loadLibraries(ByteProvider provider, Program program,
			DomainFolder programFolder, LoadSpec desiredLoadSpec, List<Option> options,
			MessageLog log, Object consumer, List<String> libraryNameList, TaskMonitor monitor)
			throws CancelledException, IOException {

		List<LoadedProgram> loadedPrograms = new ArrayList<>();
		Set<String> processed = new HashSet<>();
		Queue<UnprocessedLibrary> unprocessed =
			createUnprocessedQueue(libraryNameList, getLibraryLoadDepth(options));
		List<String> searchPaths = getLibrarySearchPaths(provider, options);
		DomainFolder linkSearchFolder = getLinkSearchFolder(programFolder, options);
		DomainFolder libraryDestFolder = getLibraryDestinationFolder(programFolder, options);

		while (!unprocessed.isEmpty()) {
			monitor.checkCanceled();
			UnprocessedLibrary unprocessedLibrary = unprocessed.remove();
			String libraryName = unprocessedLibrary.name();
			int depth = unprocessedLibrary.depth();
			if (depth == 0 || processed.contains(libraryName)) {
				continue;
			}
			processed.add(libraryName);
			boolean foundLibrary = false;
			if (linkSearchFolder != null && findLibrary(libraryName, linkSearchFolder) != null) {
				log.appendMsg("Library " + libraryName + ": Already loaded ");
			}
			else if (!searchPaths.isEmpty()) {
				String simpleLibraryName = FilenameUtils.getName(libraryName);

				List<File> candidateLibraryFiles =
					findLibrary(FilenameUtils.separatorsToUnix(libraryName), searchPaths);
				for (File candidateLibraryFile : candidateLibraryFiles) {
					monitor.checkCanceled();
					List<String> newLibraryList = new ArrayList<>();
					Program library =
						loadLibrary(simpleLibraryName, programFolder, candidateLibraryFile,
							desiredLoadSpec, newLibraryList, options, consumer, log, monitor);
					for (String newLibraryName : newLibraryList) {
						unprocessed.add(new UnprocessedLibrary(newLibraryName, depth - 1));
					}
					if (library != null) {
						foundLibrary = true;
						if (processLibrary(library, libraryName, candidateLibraryFile, provider,
							desiredLoadSpec, options, log, monitor)) {
							loadedPrograms.add(new LoadedProgram(library, libraryDestFolder));
							log.appendMsg(
								"Library " + libraryName + ": Saving " + candidateLibraryFile);
						}
						else {
							library.release(consumer);
							log.appendMsg(
								"Library " + libraryName + ": Examining " + candidateLibraryFile);
						}
						break;
					}
				}
				if (!foundLibrary) {
					log.appendMsg("Library " + libraryName + ": Not found");
				}
			}
		}
		return loadedPrograms;
	}

	/**
	 * Find the library within the specified {@link DomainFolder folder}.  This method will handle 
	 * relative path normalization.
	 * <p>
	 * If the library path is a simple name without any path separators, only the given folder 
	 * will be searched.
	 * <p>
	 * If the library path has a path, it will be treated as a relative path under
	 * given folder and if found that {@link DomainFile} will be returned.
	 * <p>
	 * If the library path has a path and it wasn't found under the given folder, the
	 * filename part of library path will be used to search the given folder for matches.
	 * <p>
	 * @param libraryPath path with filename of the library to find
	 * @param folder {@link DomainFolder} within which imported libraries will be searched.
	 *   If null this method will return null.
	 * @return The found {@link DomainFile} or null if not found
	 */
	private DomainFile findLibrary(String libraryPath, DomainFolder folder) {
		if (folder == null) {
			return null;
		}

		// Lookup by full project path
		// NOTE: probably no need to support optional extensions and case-insensitivity for this case
		String projectPath = appendPath(folder.getPathname(), libraryPath);
		DomainFile ret =
			folder.getProjectData().getFile(FilenameUtils.separatorsToUnix(projectPath));
		if (ret != null) {
			return ret;
		}

		// Quick lookup by library filename (ignoring full library path) in given folder.
		// We try this first to hopefully avoid needing to iterate over the files in the folder
		// factoring in case and extensions
		String libraryName = FilenameUtils.getName(libraryPath);
		if ((ret = folder.getFile(libraryName)) != null) {
			return ret;
		}

		// Factoring in case and optional file extensions, iterate over given folder looking for
		// a match
		boolean noExtension = FilenameUtils.getExtension(libraryName).equals("");
		Comparator<String> comparator = getLibraryNameComparator();
		for (DomainFile file : folder.getFiles()) {
			String candidateName = file.getName();
			if (isOptionalLibraryFilenameExtensions() && noExtension) {
				candidateName = FilenameUtils.getBaseName(candidateName);
			}
			if (comparator.compare(candidateName, libraryName) == 0) {
				return file;
			}
		}

		return null;
	}

	/**
	 * Find the library on the filesystem, returning a {@link List} of possible candidate files.
	 * <p>
	 * Each search path directory will be searched for the library file in order.
	 * <p>
	 * If the library file specifies a path, it is treated as a relative subdirectory of
	 * each search path directory that is searched, and if not found, the filename part of
	 * the library is used to search just the search path directory.
	 * <p>
	 * If the library specifies an absolute path, its native path is searched on the local 
	 * filesystem.
	 * <p>
	 * @param libraryPath Either a path_and_filename, or just a filename of a library
	 *   that should be searched for
	 * @param searchPaths A {@link List} of filesystem paths on the local filesystem that will be
	 *   searched
	 * @return A {@link List} of files that match the requested library path
	 */
	private List<File> findLibrary(String libraryPath, List<String> searchPaths) {

		String libraryName = FilenameUtils.getName(libraryPath);
		List<File> results = new ArrayList<>();

		for (String searchPath : searchPaths) {

			// ignore garbage entries: relative, non-existent, not directory
			searchPath = FilenameUtils.normalizeNoEndSeparator(searchPath);
			if (searchPath == null || searchPath.isEmpty()) {
				continue;
			}
			File searchDir = new File(searchPath);
			if (!searchDir.isAbsolute() || !searchDir.isDirectory()) {
				continue;
			}

			// 1) Try as possible subpath under the search path
			String candidatePath =
				FilenameUtils.separatorsToSystem(appendPath(searchPath, libraryPath));
			File f = resolveLibraryFile(new File(candidatePath));
			if (f == null || !f.isFile()) {
				// 2) Fall back to looking for the library in the user specified search path, sans
				//    any subpath built into the library string
				f = resolveLibraryFile(new File(searchDir, libraryName));
			}
			if (f != null && f.isFile() && !results.contains(f)) {
				results.add(f);
			}
		}

		if (FilenameUtils.getPrefixLength(libraryPath) > 0) {
			// 3) Search the local filesystem (as if the importPath list contained "/")
			// if the specified library string specifies an absolute path
			File f = resolveLibraryFile(new File(libraryPath));
			if (f != null && f.isAbsolute() && f.isFile() && !results.contains(f)) {
				results.add(f);
			}
		}

		return results;
	}

	/**
	 * Imports a library file into a ghidra project. Use this method if you already have
	 * a {@link ByteProvider} available.
	 * 
	 * @param libraryName The name of the library to load
	 * @param libraryFolder The domain folder where the new library program will be stored, if null
	 *   the program should not be pre-saved. NOTE: the newly imported libraries will not be written
	 *   to this folder yet, that is handled in a later follow on step.
	 * @param libraryFile The library file to load
	 * @param desiredLoadSpec The desired {@link LoadSpec}
	 * @param libraryNameList A {@link List} to be populated with the given library's dependent
	 *   library names
	 * @param options The load options
	 * @param log The log
	 * @param consumer A consumer object for {@link DomainObject}s generated
	 * @param monitor A cancelable task monitor
	 * @return The loaded {@link Program}, or null if the load was not successful
	 * @throws CancelledException if the user cancelled the load operation
	 * @throws IOException if there was an IO-related error during the load
	 */
	private Program loadLibrary(String libraryName, DomainFolder libraryFolder, File libraryFile,
			LoadSpec desiredLoadSpec, List<String> libraryNameList, List<Option> options,
			Object consumer, MessageLog log, TaskMonitor monitor)
			throws CancelledException, IOException {

		try (ByteProvider provider = createLibraryByteProvider(libraryFile, desiredLoadSpec, log)) {
			if (!shouldLoadLibrary(libraryName, libraryFile, provider, desiredLoadSpec, log)) {
				return null;
			}

			LoadSpec libLoadSpec = matchSupportedLoadSpec(desiredLoadSpec, provider);
			if (libLoadSpec == null) {
				log.appendMsg("Skipping library which is the wrong architecture: " + libraryFile);
				return null;
			}

			Program library = doLoad(provider, libraryName, libraryFolder, libLoadSpec,
				libraryNameList, options, consumer, log, monitor);

			if (library == null) {
				log.appendMsg("Library " + libraryFile + " failed to load for some reason");
				return null;
			}

			return library;
		}
	}

	/**
	 * Loads the given provider
	 * 
	 * @param provider The {@link ByteProvider} to load
	 * @param programName The name of the new program
	 * @param programFolder The folder to load the program into
	 * @param loadSpec The {@link LoadSpec}
	 * @param libraryNameList A {@link List} to be populated with the loaded program's dependent
	 *   library names
	 * @param options The load options
	 * @param log The log
	 * @param consumer A consumer object for {@link DomainObject}s generated
	 * @param monitor A cancelable task monitor
	 * @return The newly loaded {@link Program}
	 * @throws CancelledException if the user cancelled the load operation
	 * @throws IOException if there was an IO-related error during the load
	 */
	private Program doLoad(ByteProvider provider, String programName, DomainFolder programFolder,
			LoadSpec loadSpec, List<String> libraryNameList, List<Option> options, Object consumer,
			MessageLog log, TaskMonitor monitor) throws CancelledException, IOException {
		LanguageCompilerSpecPair pair = loadSpec.getLanguageCompilerSpec();
		Language language = getLanguageService().getLanguage(pair.languageID);
		CompilerSpec compilerSpec = language.getCompilerSpecByID(pair.compilerSpecID);

		monitor.setMessage(provider.getName());

		Address imageBaseAddr = language.getAddressFactory()
				.getDefaultAddressSpace()
				.getAddress(
					loadSpec.getDesiredImageBase());
		Program program = createProgram(provider, programName, imageBaseAddr, getName(), language,
			compilerSpec, consumer);


		int transactionID = program.startTransaction("Loading");
		boolean success = false;
		try {
			log.appendMsg("----- Loading " + provider.getAbsolutePath() + " -----");
			load(provider, loadSpec, options, program, monitor, log);

			createDefaultMemoryBlocks(program, language, log);

			ExternalManager extMgr = program.getExternalManager();
			String[] externalNames = extMgr.getExternalLibraryNames();
			Comparator<String> comparator = getLibraryNameComparator();
			Arrays.sort(externalNames, comparator);
			for (String name : externalNames) {
				if (comparator.compare(name, provider.getName()) == 0 ||
					comparator.compare(name, program.getName()) == 0 ||
					Library.UNKNOWN.equals(name)) {
					// skip self-references and UNKNOWN library...
					continue;
				}
				libraryNameList.add(name);
			}

			success = true;
			return program;
		}
		finally {
			program.endTransaction(transactionID, success);
			if (!success) {
				program.release(consumer);
				program = null;
			}
		}
	}

	/**
	 * For each program in the given list, fix up its external library entries so that they point 
	 * to a path in the project.
	 * <p>
	 * Other programs in the given list are matched first, then the ghidraLibSearchFolders are 
	 * searched for matches.
	 *
	 * @param programs the list of programs to resolve against each other.  Programs not saved
	 *   to the project will be considered as a valid external library.
	 * @param searchFolder the {@link DomainFolder} which imported libraries will be searched.  
	 *   This folder will be searched if a library is not found within the list of 
	 *   programs supplied.  If null, only the list of programs will be considered.
	 * @param saveIfModified flag to have this method save any programs it modifies
	 * @param messageLog log for messages.
	 * @param monitor the task monitor
	 * @throws IOException if there was an IO-related problem resolving.
	 * @throws CancelledException if the user cancelled the load.
	 */
	private void fixupExternalLibraries(List<Program> programs, DomainFolder searchFolder,
			boolean saveIfModified, MessageLog messageLog, TaskMonitor monitor)
			throws CancelledException, IOException {

		Map<String, Program> progsByName = programs.stream()
				.filter(Objects::nonNull)
				.collect(
					Collectors.toMap((p) -> p.getDomainFile().getName(), (p) -> p));

		monitor.initialize(progsByName.size());
		for (Program program : progsByName.values()) {
			monitor.incrementProgress(1);
			if (monitor.isCancelled()) {
				return;
			}

			ExternalManager extManager = program.getExternalManager();
			String[] extLibNames = extManager.getExternalLibraryNames();
			if (extLibNames.length == 0 ||
				(extLibNames.length == 1 && Library.UNKNOWN.equals(extLibNames[0]))) {
				continue; // skip program if no libraries defined
			}

			monitor.setMessage("Resolving..." + program.getName());
			int id = program.startTransaction("Resolving external references");
			try {
				resolveExternalLibraries(program, progsByName, searchFolder, monitor, messageLog);
			}
			finally {
				program.endTransaction(id, true);
				if (saveIfModified && program.canSave() && program.isChanged()) {
					program.save("Resolve external references", monitor);
				}
			}
		}
	}

	/**
	 * Fix up program's external library entries so that they point to a path in the  project.
	 * <p>
	 * Other programs in the map are matched first, then the ghidraLibSearchFolders 
	 * are searched for matches.
	 *
	 * @param program the program whose Library entries are to be resolved.  An open transaction
	 *   on program is required.
	 * @param progsByName map of recently imported programs to be considered
	 *   first when resolving external Libraries.  Programs not saved to the project
	 *   will be ignored.
	 * @param searchFolder the {@link DomainFolder} which imported libraries will be searched.  
	 *   This folder will be searched if a library is not found within the list of 
	 *   programs supplied.  If null, only the list of programs will be considered.
	 * @param messageLog log for messages.
	 * @param monitor the task monitor
	 * @throws CancelledException if the user cancelled the load.
	 */
	private void resolveExternalLibraries(Program program, Map<String, Program> progsByName,
			DomainFolder searchFolder, TaskMonitor monitor, MessageLog messageLog)
			throws CancelledException {
		ExternalManager extManager = program.getExternalManager();
		String[] extLibNames = extManager.getExternalLibraryNames();
		messageLog.appendMsg("Linking external programs to " + program.getName() + "...");
		for (String externalLibName : extLibNames) {
			if (Library.UNKNOWN.equals(externalLibName)) {
				continue;
			}
			monitor.checkCanceled();
			try {
				String externalFileName = FilenameUtils.getName(externalLibName);
				DomainObject matchingExtProgram = findLibrary(progsByName, externalFileName);
				if (matchingExtProgram != null && matchingExtProgram.getDomainFile().exists()) {
					extManager.setExternalPath(externalLibName,
						matchingExtProgram.getDomainFile().getPathname(), false);
					messageLog.appendMsg("  [" + externalLibName + "] -> [" +
						matchingExtProgram.getDomainFile().getPathname() + "]");
				}
				else {
					DomainFile alreadyImportedLib = findLibrary(externalLibName, searchFolder);
					if (alreadyImportedLib != null) {
						extManager.setExternalPath(externalLibName,
							alreadyImportedLib.getPathname(), false);
						messageLog.appendMsg("  [" + externalLibName + "] -> [" +
							alreadyImportedLib.getPathname() + "] (previously imported)");
					}
					else {
						messageLog.appendMsg("  [" + externalLibName + "] -> not found");
					}
				}
			}
			catch (InvalidInputException e) {
				Msg.error(this, "Bad library name: " + externalLibName, e);
			}
		}
	}

	/**
	 * A library that has not been processed by the loader yet
	 * 
	 * @param name The name of the library
	 * @param depth The recursive load depth of the library (based on the original binary being
	 *   loaded)
	 */
	private record UnprocessedLibrary(String name, int depth) {/**/}

	/**
	 * Creates a new {@link Queue} of {@link UnprocessedLibrary}s, initialized filled with the
	 * library names in the given list
	 * 
	 * @param libraryNames A {@link List} of unprocessed library names
	 * @param depth The initial load depth of each library
	 * @return A {@link Queue} of {@link UnprocessedLibrary}s
	 */
	private Queue<UnprocessedLibrary> createUnprocessedQueue(List<String> libraryNames, int depth) {
		return libraryNames.stream()
				.map(name -> new UnprocessedLibrary(name, depth))
				.collect(Collectors.toCollection(LinkedList::new));
	}

	/**
	 * Gets a {@link List} of priority-ordered paths used to search for libraries
	 * 
	 * @param provider The {@link ByteProvider} of the program being loaded
	 * @param options The options
	 * @return A {@link List} of priority-ordered paths used to search for libraries
	 */
	private List<String> getLibrarySearchPaths(ByteProvider provider, List<Option> options) {
		String parent = getProviderFilePath(provider);
		List<String> paths = new ArrayList<>();
		if (shouldSearchAllPaths(options) || isLoadLocalLibraries(options) && parent != null) {
			paths.add(parent);
		}
		if (shouldSearchAllPaths(options) || isLoadSystemLibraries(options)) {
			paths.addAll(LibrarySearchPathManager.getLibraryPathsList());
		}
		return paths;
	}
	
	/**
	 * Find the library within the given {@link Map} of {@link Program}s
	 * 
	 * @param programsByName The map to search
	 * @param libraryName The library name to lookup
	 * @return The found {@link Program} or null if not found
	 */
	private Program findLibrary(Map<String, Program> programsByName, String libraryName) {
		Comparator<String> comparator = getLibraryNameComparator();
		boolean noExtension = FilenameUtils.getExtension(libraryName).equals("");
		for (String key : programsByName.keySet()) {
			String candidateName = key;
			if (isOptionalLibraryFilenameExtensions() && noExtension) {
				candidateName = FilenameUtils.getBaseName(candidateName);
			}
			if (comparator.compare(candidateName, libraryName) == 0) {
				return programsByName.get(key);
			}
		}
		return null;
	}

	/**
	 * Appends the given path elements to form a single path
	 * 
	 * @param pathElements The path elements to append to one another
	 * @return A single path consisting of the given path elements appended together
	 */
	private String appendPath(String... pathElements) {
		StringBuilder sb = new StringBuilder();
		for (String pathElement : pathElements) {
			if (pathElement == null || pathElement.isEmpty()) {
				continue;
			}
			boolean sbEndsWithSlash =
				sb.length() > 0 && "/\\".indexOf(sb.charAt(sb.length() - 1)) != -1;
			boolean elementStartsWithSlash = "/\\".indexOf(pathElement.charAt(0)) != -1;

			if (!sbEndsWithSlash && !elementStartsWithSlash && sb.length() > 0) {
				sb.append("/");
			}
			else if (elementStartsWithSlash && sbEndsWithSlash) {
				pathElement = pathElement.substring(1);
			}
			sb.append(pathElement);
		}

		return sb.toString();
	}

	/**
	 * Ensures the given {@link LoadSpec} matches one supported by the loader
	 * 
	 * @param desiredLoadSpec The desired {@link LoadSpec}
	 * @param provider The provider
	 * @return A supported {@link LoadSpec} that matches the desired one, or null of none matched
	 * @throws IOException if there was an IO-related error
	 */
	protected LoadSpec matchSupportedLoadSpec(LoadSpec desiredLoadSpec, ByteProvider provider)
			throws IOException {
		LanguageCompilerSpecPair desiredPair = desiredLoadSpec.getLanguageCompilerSpec();
		Collection<LoadSpec> supportedLoadSpecs = findSupportedLoadSpecs(provider);
		if (supportedLoadSpecs != null) { // shouldn't be null, but protect against rogue loaders
			for (LoadSpec supportedLoadSpec : supportedLoadSpecs) {
				if (desiredPair.equals(supportedLoadSpec.getLanguageCompilerSpec())) {
					return supportedLoadSpec;
				}
			}
		}
		return null;
	}

	/**
	 * Resolves the given library path to an existing {@link File} on disk.  Some {@link Loader}s
	 * have relaxed requirements on what counts as a valid library filename match.  For example, 
	 * case-insensitive lookup may be allowed, and filename extensions may be optional.
	 * 
	 * @param libraryFile The library file to resolve
	 * @return The library file resolved to an existing {@link File} on disk, or null if it did not
	 *   resolve
	 */
	private File resolveLibraryFile(File libraryFile) {
		File ret = libraryFile;
		if (isCaseInsensitiveLibraryFilenames()) {
			ret = FileUtilities.resolveFileCaseInsensitive(libraryFile);
		}
		if (ret.exists()) {
			return ret;
		}
		if (isOptionalLibraryFilenameExtensions() &&
			FilenameUtils.getExtension(libraryFile.toString()).equals("")) {
			File[] files = libraryFile.getParentFile().listFiles();
			if (files != null) {
				Comparator<String> libNameComparator = getLibraryNameComparator();
				for (File file : files) {
					String baseName = FilenameUtils.getBaseName(file.toString());
					if (libNameComparator.compare(libraryFile.getName(), baseName) == 0) {
						return file;
					}
				}
			}
		}
		return null;
	}

	/**
	 * Returns the path the loaded {@link ByteProvider} is located in.
	 * <p>
	 * Special case when the ByteProvider specifies a {@link FSRL}, try to get the 'real'
	 * path on the local filesystem, otherwise return null.
	 *
	 * @param provider The {@link ByteProvider}.
	 * @return The path the loaded {@link ByteProvider} is located in.
	 */
	private String getProviderFilePath(ByteProvider provider) {
		FSRL fsrl = provider.getFSRL();
		if ((fsrl != null) && !fsrl.getFS().hasContainer()) {
			return FilenameUtils.getFullPathNoEndSeparator(fsrl.getPath());
		}
		File f = provider.getFile();
		return (f != null) ? f.getParent() : null;
	}

	/**
	 * Gets a {@link Comparator} for comparing library filenames
	 * 
	 * @return A {@link Comparator} for comparing library filenames
	 */
	private Comparator<String> getLibraryNameComparator() {
		return isCaseInsensitiveLibraryFilenames()
				? String.CASE_INSENSITIVE_ORDER
				: (s1, s2) -> s1.compareTo(s2);
	}
}
