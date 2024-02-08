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
import java.nio.file.*;
import java.util.*;
import java.util.stream.Collectors;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.ObjectUtils;

import ghidra.app.util.Option;
import ghidra.app.util.OptionUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.LibrarySearchPathManager;
import ghidra.app.util.importer.MessageLog;
import ghidra.formats.gfilesystem.*;
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
	protected List<Loaded<Program>> loadProgram(ByteProvider provider, String loadedName,
			Project project, String projectFolderPath, LoadSpec loadSpec, List<Option> options,
			MessageLog log, Object consumer, TaskMonitor monitor)
			throws CancelledException, IOException {

		List<Loaded<Program>> loadedProgramList = new ArrayList<>();
		List<String> libraryNameList = new ArrayList<>();

		boolean success = false;
		try {
			// Load the primary program
			Program program = doLoad(provider, loadedName, loadSpec, libraryNameList, options,
				consumer, log, monitor);
			loadedProgramList.add(new Loaded<>(program, loadedName, projectFolderPath));
			log.appendMsg("------------------------------------------------\n");

			// Load the libraries
			List<Loaded<Program>> libraries = loadLibraries(provider, program, project,
				projectFolderPath, loadSpec, options, log, consumer, libraryNameList, monitor);
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
	protected void loadProgramInto(ByteProvider provider, LoadSpec loadSpec,
			List<Option> options, MessageLog log, Program program, TaskMonitor monitor)
			throws CancelledException, LoadException, IOException {

		LanguageCompilerSpecPair pair = loadSpec.getLanguageCompilerSpec();
		LanguageID languageID = program.getLanguageID();
		CompilerSpecID compilerSpecID = program.getCompilerSpec().getCompilerSpecID();
		if (!(pair.languageID.equals(languageID) && pair.compilerSpecID.equals(compilerSpecID))) {
			String message = provider.getAbsolutePath() +
				" does not have the same language/compiler spec as program " + program.getName();
			log.appendMsg(message);
			throw new LoadException(message);
		}
		log.appendMsg("Loading " + provider.getAbsolutePath() + "...");
		load(provider, loadSpec, options, program, monitor, log);
		log.appendMsg("--------------------------------------------------------------------\n");
	}

	@Override
	protected void postLoadProgramFixups(List<Loaded<Program>> loadedPrograms, Project project,
			List<Option> options, MessageLog messageLog, TaskMonitor monitor)
			throws CancelledException, IOException {
		if (loadedPrograms.isEmpty()) {
			return;
		}
		if (isLinkExistingLibraries(options) || isLoadLocalLibraries(options) ||
			isLoadSystemLibraries(options)) {
			String projectFolderPath = loadedPrograms.get(0).getProjectFolderPath();
			List<DomainFolder> searchFolders = new ArrayList<>();
			String destPath = getLibraryDestinationFolderPath(project, projectFolderPath, options);
			DomainFolder destSearchFolder =
				getLibraryDestinationSearchFolder(project, destPath, options);
			DomainFolder linkSearchFolder =
				getLinkSearchFolder(project, projectFolderPath, options);
			if (destSearchFolder != null) {
				searchFolders.add(destSearchFolder);
			}
			if (linkSearchFolder != null) {
				searchFolders.add(linkSearchFolder);
			}
			fixupExternalLibraries(loadedPrograms, searchFolders, messageLog, monitor);
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
					String value = (String) option.getValue();
					if (!value.isEmpty() && !value.startsWith("/")) {
						return "Invalid absolute project path for option: " + name;
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
		return OptionUtils.getOption(LINK_EXISTING_OPTION_NAME, options,
			LINK_EXISTING_OPTION_DEFAULT);
	}

	/**
	 * Gets the {@link DomainFolder project folder} to search for existing libraries
	 * 
	 * @param project The {@link Project}. Could be null if there is no project.
	 * @param projectFolderPath The project folder path the program will get saved to. Could be null
	 *   if the program is not getting saved to the project.
	 * @param options a {@link List} of {@link Option}s
	 * @return The path of the project folder to search for existing libraries, or null if no
	 *   project folders can be or should be searched
	 */
	protected DomainFolder getLinkSearchFolder(Project project, String projectFolderPath,
			List<Option> options) {
		if (!shouldSearchAllPaths(options) && !isLinkExistingLibraries(options)) {
			return null;
		}
		if (project == null) {
			return null;
		}

		String linkSearchFolderPath = OptionUtils.getOption(LINK_SEARCH_FOLDER_OPTION_NAME, options,
			LINK_SEARCH_FOLDER_OPTION_DEFAULT);

		ProjectData projectData = project.getProjectData();
		if (linkSearchFolderPath.isBlank()) {
			if (projectFolderPath == null) {
				return null;
			}
			return projectData.getFolder(projectFolderPath);
		}

		return projectData.getFolder(FilenameUtils.separatorsToUnix(linkSearchFolderPath));
	}

	/**
	 * Checks to see if local libraries should be loaded.  Local libraries are libraries that live
	 * in the same directory as the imported program.
	 * 
	 * @param options a {@link List} of {@link Option}s
	 * @return True if local libraries should be loaded; otherwise, false
	 */
	protected boolean isLoadLocalLibraries(List<Option> options) {
		return OptionUtils.getOption(LOCAL_LIBRARY_OPTION_NAME, options,
			LOCAL_LIBRARY_OPTION_DEFAULT);
	}

	/**
	 * Checks to see if system libraries should be loaded.  System libraries are libraries that live
	 * in the directories specified in the GUI path list.
	 * 
	 * @param options a {@link List} of {@link Option}s
	 * @return True if system libraries should be loaded; otherwise, false
	 */
	protected boolean isLoadSystemLibraries(List<Option> options) {
		return OptionUtils.getOption(SYSTEM_LIBRARY_OPTION_NAME, options,
			SYSTEM_LIBRARY_OPTION_DEFAULT);
	}

	/**
	 * Gets the desired recursive library load depth
	 * 
	 * @param options a {@link List} of {@link Option}s
	 * @return The desired recursive library load depth
	 */
	protected int getLibraryLoadDepth(List<Option> options) {
		return OptionUtils.getOption(DEPTH_OPTION_NAME, options, DEPTH_OPTION_DEFAULT);
	}

	/**
	 * Gets the project folder path to load the libraries into.  It does not have to exist in the
	 * project yet.
	 * 
	 * @param project The {@link Project}. Could be null if there is no project.
	 * @param projectFolderPath The project folder path the program will get saved to. Could be null
	 *   if the program is not getting saved to the project.
	 * @param options a {@link List} of {@link Option}s
	 * @return The path of the project folder to load the libraries into.  Could be null if the 
	 *   specified project is null or a destination folder path could not be determined.
	 */
	protected String getLibraryDestinationFolderPath(Project project, String projectFolderPath,
			List<Option> options) {
		if (project == null) {
			return null;
		}

		String libraryDestinationFolderPath = OptionUtils.getOption(LIBRARY_DEST_FOLDER_OPTION_NAME,
			options, LIBRARY_DEST_FOLDER_OPTION_DEFAULT);

		if (libraryDestinationFolderPath.isBlank()) {
			return projectFolderPath;
		}

		return FilenameUtils.separatorsToUnix(libraryDestinationFolderPath);
	}

	/**
	 * Gets the {@link DomainFolder project folder} that libraries are loaded into, to search for
	 * existing libraries.  It will only be returned if the options to load new libraries into the
	 * project are set.
	 * 
	 * @param project The {@link Project}. Could be null if there is no project.
	 * @param libraryDestinationFolderPath The path of the project folder to load the libraries 
	 *   into.  Could be null (@see #getLibraryDestinationFolderPath(Project, String, List)).
	 * @param options a {@link List} of {@link Option}s
	 * @return The path of the destination project folder to search for existing libraries, or null
	 *   if the destination folder is not being used or should not be searched
	 */
	protected DomainFolder getLibraryDestinationSearchFolder(Project project,
			String libraryDestinationFolderPath, List<Option> options) {
		if (project == null || libraryDestinationFolderPath == null) {
			return null;
		}
		if (!isLoadLocalLibraries(options) && !isLoadSystemLibraries(options)) {
			return null;
		}
		return project.getProjectData().getFolder(libraryDestinationFolderPath);
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
	 * Creates a {@link ByteProvider} for the given library {@link FSRL}
	 * 
	 * @param libFsrl The library {@link FSRL} to get a {@link ByteProvider} for
	 * @param loadSpec An optional {@link LoadSpec} the {@link ByteProvider} should conform to
	 * @param log The log
	 * @param monitor A cancellable monitor
	 * @return A {@link ByteProvider} for the given library {@link FSRL}, or null if one could not 
	 *   be created that matches the given {@link LoadSpec}
	 * @throws IOException If there was an IO-related issue
	 * @throws CancelledException If the user cancelled the operation
	 */
	protected ByteProvider createLibraryByteProvider(FSRL libFsrl, LoadSpec loadSpec,
			MessageLog log, TaskMonitor monitor) throws IOException, CancelledException {
		return FileSystemService.getInstance().getByteProvider(libFsrl, true, monitor);
	}

	/**
	 * Checks whether or not the given library should be loaded.
	 * <p>
	 * It may be appropriate to not load a specific library after examining its bytes.
	 * 
	 * @param libraryName The name of the library
	 * @param libraryFsrl The library {@link FSRL}
	 * @param provider The library bytes
	 * @param desiredLoadSpec The desired {@link LoadSpec}
	 * @param log The log
	 * @return True if the given library should be loaded; otherwise, false
	 * @throws IOException If an IO-related error occurred
	 */
	protected boolean shouldLoadLibrary(String libraryName, FSRL libraryFsrl,
			ByteProvider provider, LoadSpec desiredLoadSpec, MessageLog log) throws IOException {
		return true;
	}

	/**
	 * Performs optional follow-on actions after an the given library has been loaded
	 * 
	 * @param library The loaded library {@link Program}
	 * @param libraryName The name of the library
	 * @param libraryFsrl The library {@link FSRL}
	 * @param provider The library bytes
	 * @param loadSpec The {@link LoadSpec} used for the load
	 * @param options The options
	 * @param log The log
	 * @param monitor A cancelable monitor
	 * @throws IOException If an IO-related error occurred
	 * @throws CancelledException If the user cancelled the action
	 */
	protected void processLibrary(Program library, String libraryName, FSRL libraryFsrl,
			ByteProvider provider, LoadSpec loadSpec, List<Option> options, MessageLog log,
			TaskMonitor monitor) throws IOException, CancelledException {
		// Default behavior is to do nothing
	}

	/**
	 * Loads the given list of libraries into the given {@link DomainFolder folder}
	 *
	 * @param provider The {@link ByteProvider} of the program being loaded
	 * @param program The {@link Program} being loaded
	 * @param project The {@link Project}. Could be null if there is no project.
	 * @param projectFolderPath The project folder path the program will get saved to. Could be null
	 *   if the program is not getting saved to the project.
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
	private List<Loaded<Program>> loadLibraries(ByteProvider provider, Program program,
			Project project, String projectFolderPath, LoadSpec desiredLoadSpec,
			List<Option> options, MessageLog log, Object consumer, List<String> libraryNameList,
			TaskMonitor monitor) throws CancelledException, IOException {

		List<Loaded<Program>> loadedPrograms = new ArrayList<>();
		Set<String> processed = new TreeSet<>(getLibraryNameComparator());
		Queue<UnprocessedLibrary> unprocessed =
			createUnprocessedQueue(libraryNameList, getLibraryLoadDepth(options));
		boolean loadLocalLibraries = isLoadLocalLibraries(options);
		boolean loadSystemLibraries = isLoadSystemLibraries(options);
		List<FileSystemSearchPath> customSearchPaths =
			getCustomLibrarySearchPaths(provider, options, log, monitor);
		List<FileSystemSearchPath> localSearchPaths =
			getLocalLibrarySearchPaths(provider, options, log, monitor);
		List<FileSystemSearchPath> systemSearchPaths =
			getSystemLibrarySearchPaths(options, log, monitor);
		DomainFolder linkSearchFolder = getLinkSearchFolder(project, projectFolderPath, options);
		String libraryDestFolderPath =
			getLibraryDestinationFolderPath(project, projectFolderPath, options);
		DomainFolder libraryDestFolder =
			getLibraryDestinationSearchFolder(project, libraryDestFolderPath, options);

		boolean success = false;
		try {
			while (!unprocessed.isEmpty()) {
				monitor.checkCancelled();
				UnprocessedLibrary unprocessedLibrary = unprocessed.remove();
				String libraryName = unprocessedLibrary.name();
				int depth = unprocessedLibrary.depth();
				if (depth == 0 || processed.contains(libraryName)) {
					continue;
				}
				processed.add(libraryName);
				if (libraryDestFolder != null &&
					findLibrary(libraryName, libraryDestFolder) != null) {
					log.appendMsg("Found %s in %s...".formatted(libraryName, libraryDestFolder));
					log.appendMsg("------------------------------------------------\n");
				}
				else if (linkSearchFolder != null &&
					findLibrary(libraryName, linkSearchFolder) != null) {
					log.appendMsg("Found %s in %s...".formatted(libraryName, linkSearchFolder));
					log.appendMsg("------------------------------------------------\n");
				}
				else if (!customSearchPaths.isEmpty() || !localSearchPaths.isEmpty() ||
					!systemSearchPaths.isEmpty()) {
					// Note that it is possible to have local (or system) search paths with those
					// options turned off (if shouldSearchAllPaths() is overridden to return true).
					// In this case, we still want to process those libraries, but we 
					// do not want to save them, so they can be released.
					boolean found = false;
					boolean loaded = false;
					if (!customSearchPaths.isEmpty()) {
						log.appendMsg("Searching %d custom path%s for library %s...".formatted(
							customSearchPaths.size(), customSearchPaths.size() > 1 ? "s" : "",
							libraryName));
						Loaded<Program> loadedLibrary = loadLibraryFromSearchPaths(libraryName,
							provider, customSearchPaths, libraryDestFolderPath, unprocessed, depth,
							desiredLoadSpec, options, log, consumer, monitor);
						if (loadedLibrary != null) {
							found = true;
							loaded = true;
							loadedPrograms.add(loadedLibrary);
						}
					}
					if (!loaded && !localSearchPaths.isEmpty()) {
						log.appendMsg("Searching %d local path%s for library %s...".formatted(
							localSearchPaths.size(), localSearchPaths.size() > 1 ? "s" : "",
							libraryName));
						Loaded<Program> loadedLibrary = loadLibraryFromSearchPaths(libraryName,
							provider, localSearchPaths, libraryDestFolderPath, unprocessed, depth,
							desiredLoadSpec, options, log, consumer, monitor);
						if (loadedLibrary != null) {
							found = true;
							if (loadLocalLibraries) {
								loaded = true;
								loadedPrograms.add(loadedLibrary);
							}
							else {
								loadedLibrary.release(consumer);
							}
						}
					}
					if (!loaded && !systemSearchPaths.isEmpty()) {
						log.appendMsg("Searching %d system path%s for library %s...".formatted(
							systemSearchPaths.size(), systemSearchPaths.size() > 1 ? "s" : "",
							libraryName));
						Loaded<Program> loadedLibrary = loadLibraryFromSearchPaths(libraryName,
							provider, systemSearchPaths, libraryDestFolderPath, unprocessed, depth,
							desiredLoadSpec, options, log, consumer, monitor);
						if (loadedLibrary != null) {
							found = true;
							if (loadSystemLibraries) {
								loaded = true;
								loadedPrograms.add(loadedLibrary);
							}
							else {
								loadedLibrary.release(consumer);
							}
						}
					}
					if (!found) {
						log.appendMsg("Library not found.");
					}
					else {
						if (loaded) {
							log.appendMsg("Saving library to: " +
								loadedPrograms.get(loadedPrograms.size() - 1).toString());
						}
						else {
							log.appendMsg("Library not saved to project.");
						}
					}
					log.appendMsg("------------------------------------------------\n");
				}
			}
			success = true;
			return loadedPrograms;
		}
		finally {
			if (!success) {
				release(loadedPrograms, consumer);
			}
			for (FileSystemSearchPath fsSearchPath : localSearchPaths) {
				if (!fsSearchPath.fsRef().isClosed()) {
					fsSearchPath.fsRef().close();
				}
			}
			for (FileSystemSearchPath fsSearchPath : systemSearchPaths) {
				if (!fsSearchPath.fsRef().isClosed()) {
					fsSearchPath.fsRef().close();
				}
			}
		}
	}

	/**
	 * Loads the given library into the given {@link DomainFolder folder} if it can find it in
	 * the given {@link List} of search paths
	 *
	 * @param libraryName The name of the library to load
	 * @param provider The {@link ByteProvider} of the program being loaded
	 * @param fsSearchPaths A {@link List} of {@link FileSystemSearchPath}s that will be searched
	 * @param libraryDestFolderPath The path of the project folder to load the libraries into. 
	 *   Could be null if the specified project is null or a destination folder path could not be 
	 *   determined.
	 * @param unprocessed The {@link Queue} of {@link UnprocessedLibrary unprocessed libraries}
	 * @param depth The load depth of the library to load
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
	private Loaded<Program> loadLibraryFromSearchPaths(String libraryName,
			ByteProvider provider, List<FileSystemSearchPath> fsSearchPaths,
			String libraryDestFolderPath, Queue<UnprocessedLibrary> unprocessed, int depth,
			LoadSpec desiredLoadSpec, List<Option> options, MessageLog log, Object consumer,
			TaskMonitor monitor) throws CancelledException, IOException {

		Program library = null;
		if (libraryDestFolderPath != null) {
			String libraryPath = FilenameUtils.getPath(libraryName);
			if (libraryPath != null && !libraryPath.isEmpty()) {
				if (!libraryDestFolderPath.endsWith("/")) {
					libraryDestFolderPath += "/";
				}
				libraryDestFolderPath += libraryPath;
			}
		}
		String simpleLibraryName = FilenameUtils.getName(libraryName);
		List<FSRL> candidateLibraryFsrls =
			findLibrary(Path.of(libraryName), fsSearchPaths, log, monitor);

		boolean success = false;
		try {
			for (FSRL candidateLibraryFsrl : candidateLibraryFsrls) {
				monitor.checkCancelled();
				List<String> newLibraryList = new ArrayList<>();
				library = loadLibrary(simpleLibraryName, candidateLibraryFsrl,
					desiredLoadSpec, newLibraryList, options, consumer, log, monitor);
				for (String newLibraryName : newLibraryList) {
					unprocessed.add(new UnprocessedLibrary(newLibraryName, depth - 1));
				}
				if (library == null) {
					continue;
				}
				processLibrary(library, libraryName, candidateLibraryFsrl, provider,
					desiredLoadSpec, options, log, monitor);
				success = true;
				return new Loaded<Program>(library, simpleLibraryName, libraryDestFolderPath);
			}
			return null;
		}
		finally {
			if (!success && library != null) {
				library.release(consumer);
			}
		}
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
		String projectPath = concatenatePaths(folder.getPathname(), libraryPath);
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
	 * Find the library in a {@link GFileSystem}, returning a {@link List} of possible candidate 
	 * {@link GFile files}.
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
	 * @param libraryPath The library {@link Path}.  This will be either an absolute path, a
	 *   relative path, or just a filename.
	 * @param fsSearchPaths A {@link List} of {@link FileSystemSearchPath}s that will be searched
	 * @param log The log
	 * @param monitor A cancelable task monitor
	 * @return A {@link List} of {@link GFile files} that match the requested library path
	 * @throws CancelledException if the user cancelled the operation
	 */
	private List<FSRL> findLibrary(Path libraryPath, List<FileSystemSearchPath> fsSearchPaths,
			MessageLog log, TaskMonitor monitor) throws CancelledException {
		
		List<FSRL> results = new ArrayList<>();
		FileSystemService fsService = FileSystemService.getInstance();

		Path libraryParentPath = libraryPath.getParent();
		String libraryName = libraryPath.getFileName().toString();

		for (FileSystemSearchPath fsSearchPath : fsSearchPaths) {
			monitor.checkCancelled();

			try {
				// Handle 3 different library-lookup cases:

				// 1) libraryPath is library name, relative path, or absolute path from the root
				//    of the searchPath.  We need to join our fsSearchPath with our 
				//    libraryParentPath
				Path combinedParentPath =
					ObjectUtils.allNotNull(fsSearchPath.fsPath(), libraryParentPath)
							? fsSearchPath.fsPath().resolve(libraryParentPath)
							: ObjectUtils.firstNonNull(fsSearchPath.fsPath(), libraryParentPath);
				FSRL resolvedFsrl = resolveLibraryFile(fsSearchPath.fsRef().getFilesystem(),
					combinedParentPath, libraryName);
				if (resolvedFsrl != null) {
					results.add(resolvedFsrl);
					continue;
				}

				// 2) libraryPath is an absolute path and should be looked up as-is on the
				//    LocalFileSystem.  Note that the root of the LocalFileSystem should not be
				//    assumed to be in searchPaths for this case (otherwise case 1 would find it)
				if (libraryParentPath != null && libraryParentPath.isAbsolute()) {
					resolvedFsrl = resolveLibraryFile(fsService.getLocalFS(), libraryParentPath,
						libraryName);
					if (resolvedFsrl != null) {
						results.add(resolvedFsrl);
						continue;
					}
				}

				// 3) libraryPath is some kind of path that we haven't found yet, so handle a
				//    flat-directory structure by just appending filename part of the path to the
				//    searchPath.  Not sure if this case is still necessary but supporting for
				//    legacy support.
				resolvedFsrl = resolveLibraryFile(fsSearchPath.fsRef().getFilesystem(),
					fsSearchPath.fsPath(), libraryName);
				if (resolvedFsrl != null) {
					results.add(resolvedFsrl);
					continue;
				}
			}
			catch (IOException e) {
				log.appendException(e);
				continue;
			}
		}

		return results;
	}

	/**
	 * Imports a library file into a ghidra project. Use this method if you already have
	 * a {@link ByteProvider} available.
	 * 
	 * @param libraryName The name of the library to load
	 * @param libraryFsrl The library {@link FSRL} to load
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
	private Program loadLibrary(String libraryName, FSRL libraryFsrl, LoadSpec desiredLoadSpec,
			List<String> libraryNameList, List<Option> options, Object consumer, MessageLog log,
			TaskMonitor monitor) throws CancelledException, IOException {

		try (ByteProvider provider =
			createLibraryByteProvider(libraryFsrl, desiredLoadSpec, log, monitor)) {
			if (!shouldLoadLibrary(libraryName, libraryFsrl, provider, desiredLoadSpec, log)) {
				return null;
			}

			LoadSpec libLoadSpec = matchSupportedLoadSpec(desiredLoadSpec, provider);
			if (libLoadSpec == null) {
				log.appendMsg("Skipping library which is the wrong architecture: " + libraryFsrl);
				return null;
			}

			return doLoad(provider, libraryName, libLoadSpec, libraryNameList,
				options, consumer, log, monitor);
		}
	}

	/**
	 * Loads the given provider
	 * 
	 * @param provider The {@link ByteProvider} to load
	 * @param programName The name of the new program
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
	private Program doLoad(ByteProvider provider, String programName, LoadSpec loadSpec,
			List<String> libraryNameList, List<Option> options, Object consumer, MessageLog log,
			TaskMonitor monitor) throws CancelledException, IOException {
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
			log.appendMsg("Loading %s...".formatted(provider.getFSRL()));
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
			program.endTransaction(transactionID, true); // More efficient to commit when program will be discarded
			if (!success) {
				program.release(consumer);
			}
		}
	}

	/**
	 * For each {@link Loaded} {@link Program} in the given list, fix up its external library 
	 * entries so that they point to a path in the project.
	 * <p>
	 * Other {@link Program}s in the given list are matched first, then the given 
	 * {@link DomainFolder search folder} is searched for matches.
	 *
	 * @param loadedPrograms the list of {@link Loaded} {@link Program}s
	 * @param searchFolders an ordered list of {@link DomainFolder}s which imported libraries will 
	 *   be searched. These folders will be searched if a library is not found within the list of 
	 *   programs supplied.
	 * @param messageLog log for messages.
	 * @param monitor the task monitor
	 * @throws IOException if there was an IO-related problem resolving.
	 * @throws CancelledException if the user cancelled the load.
	 */
	private void fixupExternalLibraries(List<Loaded<Program>> loadedPrograms,
			List<DomainFolder> searchFolders, MessageLog messageLog, TaskMonitor monitor)
			throws CancelledException, IOException {

		monitor.initialize(loadedPrograms.size());
		for (Loaded<Program> loadedProgram : loadedPrograms) {
			monitor.increment();

			Program program = loadedProgram.getDomainObject();
			ExternalManager extManager = program.getExternalManager();
			String[] extLibNames = extManager.getExternalLibraryNames();
			if (extLibNames.length == 0 ||
				(extLibNames.length == 1 && Library.UNKNOWN.equals(extLibNames[0]))) {
				continue; // skip program if no libraries defined
			}

			monitor.setMessage("Resolving..." + program.getName());
			int id = program.startTransaction("Resolving external references");
			try {
				resolveExternalLibraries(program, loadedPrograms, searchFolders, monitor,
					messageLog);
			}
			finally {
				program.endTransaction(id, true);
			}
		}
	}

	/**
	 * Fix up program's external library entries so that they point to a path in the project.
	 * <p>
	 * Other programs in the map are matched first, then the ghidraLibSearchFolders 
	 * are searched for matches.
	 *
	 * @param program the program whose Library entries are to be resolved.  An open 
	 *   transaction on program is required.
	 * @param loadedPrograms the list of {@link Loaded} {@link Program}s
	 * @param searchFolders an order list of {@link DomainFolder}s which imported libraries will be
	 *   searched. These folders will be searched if a library is not found within the list of 
	 *   programs supplied.
	 * @param messageLog log for messages.
	 * @param monitor the task monitor
	 * @throws CancelledException if the user cancelled the load.
	 */
	private void resolveExternalLibraries(Program program,
			List<Loaded<Program>> loadedPrograms, List<DomainFolder> searchFolders,
			TaskMonitor monitor, MessageLog messageLog) throws CancelledException {
		ExternalManager extManager = program.getExternalManager();
		String[] extLibNames = extManager.getExternalLibraryNames();
		messageLog.appendMsg(
			"Linking the External Programs of '%s' to imported libraries..."
					.formatted(program.getName()));
		for (String externalLibName : extLibNames) {
			if (Library.UNKNOWN.equals(externalLibName)) {
				continue;
			}
			monitor.checkCancelled();
			try {
				Loaded<Program> matchingExtProgram = findLibrary(loadedPrograms, externalLibName);
				if (matchingExtProgram != null) {
					String path =
						matchingExtProgram.getProjectFolderPath() + matchingExtProgram.getName();
					extManager.setExternalPath(externalLibName, path, false);
					messageLog.appendMsg("  [" + externalLibName + "] -> [" + path + "]");
				}
				else {
					boolean found = false;
					for (DomainFolder searchFolder : searchFolders) {
						DomainFile alreadyImportedLib = findLibrary(externalLibName, searchFolder);
						if (alreadyImportedLib != null) {
							extManager.setExternalPath(externalLibName,
								alreadyImportedLib.getPathname(), false);
							messageLog.appendMsg("  [" + externalLibName + "] -> [" +
								alreadyImportedLib.getPathname() + "] (previously imported)");
							found = true;
							break;
						}
					}
					if (!found) {
						messageLog.appendMsg("  [" + externalLibName + "] -> not found in project");
					}
				}
			}
			catch (InvalidInputException e) {
				Msg.error(this, "Bad library name: " + externalLibName, e);
			}
		}
		messageLog.appendMsg("------------------------------------------------\n");
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
	 * A file system search path
	 * 
	 * @param fsRef A {@link FileSystemRef}
	 * @param fsPath A {@link Path} relative to the root of the file system, or null for the root
	 */
	protected record FileSystemSearchPath(FileSystemRef fsRef, Path fsPath) {}

	/**
	 * Gets a {@link List} of priority-ordered custom {@link FileSystemSearchPath}s used to search 
	 * for libraries.  The default implementation of this method returns an empty {@link List}.
	 * Subclasses can override it as needed.
	 * 
	 * @param provider The {@link ByteProvider} of the program being loaded
	 * @param options The options
	 * @param log The log
	 * @param monitor A cancelable task monitor
	 * @return A {@link List} of priority-ordered custom {@link FileSystemSearchPath}s used to
	 *   search for libraries
	 */
	protected List<FileSystemSearchPath> getCustomLibrarySearchPaths(ByteProvider provider,
			List<Option> options, MessageLog log, TaskMonitor monitor) {
		return List.of();
	}

	/**
	 * Gets a {@link List} of priority-ordered local {@link FileSystemSearchPath}s used to search 
	 * for libraries
	 * 
	 * @param provider The {@link ByteProvider} of the program being loaded
	 * @param options The options
	 * @param log The log
	 * @param monitor A cancelable task monitor
	 * @return A {@link List} of priority-ordered local {@link FileSystemSearchPath}s used to
	 *   search for libraries
	 */
	private List<FileSystemSearchPath> getLocalLibrarySearchPaths(ByteProvider provider,
			List<Option> options, MessageLog log, TaskMonitor monitor) {
		List<FileSystemSearchPath> result = new ArrayList<>();
		FileSystemService fsService = FileSystemService.getInstance();
		if (isLoadLocalLibraries(options) || shouldSearchAllPaths(options)) {
			FSRL providerFsrl = provider.getFSRL();
			if (providerFsrl != null) {
				try (RefdFile fileRef = fsService.getRefdFile(providerFsrl, monitor)) {
					GFile parentFile = fileRef.file.getParentFile();
					File f = new File(parentFile.getPath()); // File API will sanitize Windows-style paths
					result.add(new FileSystemSearchPath(fileRef.fsRef, f.toPath()));
				}
				catch (IOException | CancelledException e) {
					log.appendException(e);
				}
			}
		}
		return result;
	}

	/**
	 * Gets a {@link List} of priority-ordered system {@link FileSystemSearchPath}s used to search 
	 * for libraries
	 * 
	 * @param options The options
	 * @param log The log
	 * @param monitor A cancelable task monitor
	 * @return A {@link List} of priority-ordered system {@link FileSystemSearchPath}s used to 
	 *   search for libraries
	 */
	private List<FileSystemSearchPath> getSystemLibrarySearchPaths(List<Option> options,
			MessageLog log, TaskMonitor monitor) {
		List<FileSystemSearchPath> result = new ArrayList<>();
		FileSystemService fsService = FileSystemService.getInstance();
		if (isLoadSystemLibraries(options) || shouldSearchAllPaths(options)) {
			List<Path> searchPaths = new ArrayList<>();
			for (String str : LibrarySearchPathManager.getLibraryPathsList()) {
				if (str.isBlank()) {
					continue;
				}
				try {
					Path path = Path.of(str.trim()).normalize();
					if (path.isAbsolute() && Files.exists(path)) {
						searchPaths.add(path);
					}
				}
				catch (InvalidPathException e) {
					log.appendMsg("Skipping invalid system library search path: \"" + str + "\"");
				}
			}
			for (Path searchPath : searchPaths) {
				try {
					FSRL searchFSRL =
						fsService.getLocalFSRL(searchPath.toFile().getCanonicalFile());
					FileSystemRef fsRef =
						fsService.probeFileForFilesystem(searchFSRL, monitor, null);
					if (fsRef != null) {
						result.add(new FileSystemSearchPath(fsRef, null));
					}
				}
				catch (IOException | CancelledException e) {
					log.appendException(e);
				}
			}
		}
		return result;
	}
	
	/**
	 * Find the library within the given {@link Map} of {@link Program}s
	 * 
	 * @param loadedPrograms the list of {@link Loaded} {@link Program}s
	 * @param libraryName The library name to lookup.  Depending on the type of library, this could
	 *   be a simple filename or an absolute path.
	 * @return The found {@link Loaded} {@link Program} or null if not found
	 */
	private Loaded<Program> findLibrary(List<Loaded<Program>> loadedPrograms, String libraryName) {
		Comparator<String> comparator = getLibraryNameComparator();
		boolean noExtension = FilenameUtils.getExtension(libraryName).equals("");
		boolean absolute = libraryName.startsWith("/");
		for (Loaded<Program> loadedProgram : loadedPrograms) {
			String candidateName = loadedProgram.getName();
			if (isOptionalLibraryFilenameExtensions() && noExtension) {
				candidateName = FilenameUtils.getBaseName(candidateName);
			}
			if (absolute) {
				String loadedProgramPath = loadedProgram.getProjectFolderPath() + candidateName;
				if (loadedProgramPath.endsWith(libraryName)) {
					return loadedProgram;
				}
			}
			else if (comparator.compare(candidateName, libraryName) == 0) {
				return loadedProgram;
			}
		}
		return null;
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
	 * Resolves the given library path to an existing {@link FSRL}.  Some {@link Loader}s
	 * have relaxed requirements on what counts as a valid library filename match.  For example, 
	 * case-insensitive lookup may be allowed, and filename extensions may be optional.
	 * 
	 * @param fs The {@link GFileSystem file system} to resolve in
	 * @param libraryParentPath The {@link Path} of the libraries parent directory, relative to the
	 *   given file system (could be null)
	 * @param libraryName The library name
	 * @return The library resolved to an existing {@link FSRL}, or null if it did not resolve
	 * @throws IOException If an IO-related problem occurred
	 */
	protected FSRL resolveLibraryFile(GFileSystem fs, Path libraryParentPath, String libraryName)
			throws IOException {
		GFile libraryParentDir = fs.lookup(
			libraryParentPath != null ? FilenameUtils.separatorsToUnix(libraryParentPath.toString())
					: null);
		boolean compareWithoutExtension = isOptionalLibraryFilenameExtensions() &&
			FilenameUtils.getExtension(libraryName).equals("");
		if (libraryParentDir != null) {
			Comparator<String> libNameComparator = getLibraryNameComparator();
			for (GFile file : fs.getListing(libraryParentDir)) {
				if (file.isDirectory()) {
					continue;
				}
				String compareName = file.getName();
				if (compareWithoutExtension) {
					compareName = FilenameUtils.getBaseName(compareName);
				}
				if (libNameComparator.compare(libraryName, compareName) == 0) {
					return file.getFSRL();
				}
			}
		}
		return null;
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
