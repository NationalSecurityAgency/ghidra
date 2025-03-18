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
import java.nio.file.Path;
import java.util.*;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.commons.io.FilenameUtils;

import ghidra.app.util.Option;
import ghidra.app.util.OptionUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.*;
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

	public static final String LOAD_LIBRARY_OPTION_NAME = "Load Libraries From Disk";
	static final boolean LOAD_LIBRARY_OPTION_DEFAULT = false;

	public static final String LIBRARY_SEARCH_PATH_DUMMY_OPTION_NAME = "Library Search Paths";

	public static final String DEPTH_OPTION_NAME = "Recursive Library Load Depth";
	static final int DEPTH_OPTION_DEFAULT = 1;

	public static final String LIBRARY_DEST_FOLDER_OPTION_NAME = "Library Destination Folder";
	static final String LIBRARY_DEST_FOLDER_OPTION_DEFAULT = "";

	public static final String LOAD_ONLY_LIBRARIES_OPTION_NAME = "Only Load Libraries"; // hidden
	static final boolean LOAD_ONLY_LIBRARIES_OPTION_DEFAULT = false;

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
			// Load (or get) the primary program
			Program program = null;
			if (!shouldLoadOnlyLibraries(options)) {
				program = doLoad(provider, loadedName, loadSpec, libraryNameList, options, consumer,
					log, monitor);
				loadedProgramList.add(new Loaded<>(program, loadedName, projectFolderPath));
				log.appendMsg("------------------------------------------------\n");
			}
			else if (project != null) {
				ProjectData projectData = project.getProjectData();
				DomainFile domainFile = projectData.getFile(projectFolderPath + "/" + loadedName);
				if (domainFile == null) {
					throw new LoadException(
						"Cannot load only libraries for a non-existant program");
				}
				program = (Program) domainFile.getOpenedDomainObject(consumer);
				if (program == null) {
					throw new LoadException("Failed to acquire a Program");
				}
				loadedProgramList.add(new Loaded<>(program, domainFile));
				libraryNameList.addAll(getLibraryNames(provider, program));
			}

			// Load the libraries
			loadedProgramList.addAll(loadLibraries(provider, program, project, projectFolderPath,
				loadSpec, options, log, consumer, libraryNameList, monitor));

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

	/**
	 * {@inheritDoc}
	 * <p>
	 * Fix up program's external library entries so that they point to a path in the project.
	 */
	@Override
	protected void postLoadProgramFixups(List<Loaded<Program>> loadedPrograms, Project project,
			LoadSpec loadSpec, List<Option> options, MessageLog messageLog, TaskMonitor monitor)
			throws CancelledException, IOException {
		if (loadedPrograms.isEmpty() ||
			(!isLinkExistingLibraries(options) && !isLoadLibraries(options))) {
			return;
		}

		List<DomainFolder> searchFolders =
			getLibrarySearchFolders(loadedPrograms, project, options);

		List<LibrarySearchPath> searchPaths = getLibrarySearchPaths(
			loadedPrograms.getFirst().getDomainObject(), loadSpec, options, messageLog, monitor);

		List<Loaded<Program>> saveablePrograms =
			loadedPrograms.stream().filter(Predicate.not(Loaded::shouldDiscard)).toList();

		monitor.initialize(saveablePrograms.size());
		for (Loaded<Program> loadedProgram : saveablePrograms) {
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
				resolveExternalLibraries(program, saveablePrograms, searchFolders, searchPaths,
					options, monitor, messageLog);
			}
			finally {
				program.endTransaction(id, true);
			}
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
		list.add(new DomainFolderOption(LINK_SEARCH_FOLDER_OPTION_NAME,
			Loader.COMMAND_LINE_ARG_PREFIX + "-projectLibrarySearchFolder"));
		list.add(new Option(LOAD_LIBRARY_OPTION_NAME, LOAD_LIBRARY_OPTION_DEFAULT, Boolean.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-loadLibraries"));
		list.add(new LibrarySearchPathDummyOption(LIBRARY_SEARCH_PATH_DUMMY_OPTION_NAME));
		list.add(new Option(DEPTH_OPTION_NAME, DEPTH_OPTION_DEFAULT, Integer.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-libraryLoadDepth"));
		list.add(new DomainFolderOption(LIBRARY_DEST_FOLDER_OPTION_NAME,
			Loader.COMMAND_LINE_ARG_PREFIX + "-libraryDestinationFolder"));
		list.add(new Option(LOAD_ONLY_LIBRARIES_OPTION_NAME, Boolean.class,
			LOAD_ONLY_LIBRARIES_OPTION_DEFAULT,
			Loader.COMMAND_LINE_ARG_PREFIX + "-loadOnlyLibraries", null, null, true));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		if (options != null) {
			for (Option option : options) {
				String name = option.getName();
				if (name.equals(LINK_EXISTING_OPTION_NAME) ||
					name.equals(LOAD_LIBRARY_OPTION_NAME) ||
					name.equals(LOAD_ONLY_LIBRARIES_OPTION_NAME)) {
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
	 * @param program The {@link Program} being loaded
	 * @param projectFolderPath The project folder path the program will get saved to. Could be null
	 *   if the program is not getting saved to the project.
	 * @param options a {@link List} of {@link Option}s
	 * @return The path of the project folder to search for existing libraries, or null if no
	 *   project folders can be or should be searched
	 */
	protected DomainFolder getLinkSearchFolder(Project project, Program program,
			String projectFolderPath, List<Option> options) {
		if (!shouldSearchAllPaths(program, options) && !isLinkExistingLibraries(options)) {
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
	 * Checks to see if libraries from disk should be loaded
	 * 
	 * @param options a {@link List} of {@link Option}s
	 * @return True if libraries from disk should be loaded; otherwise, false
	 */
	protected boolean isLoadLibraries(List<Option> options) {
		return OptionUtils.getOption(LOAD_LIBRARY_OPTION_NAME, options,
			LOAD_LIBRARY_OPTION_DEFAULT);
	}

	/**
	 * Checks to see if only libraries should be loaded (i.e., not the main program)
	 * 
	 * @param options a {@link List} of {@link Option}s
	 * @return True if only libraries should be loaded; otherwise, false
	 */
	protected boolean shouldLoadOnlyLibraries(List<Option> options) {
		return OptionUtils.getOption(LOAD_ONLY_LIBRARIES_OPTION_NAME, options,
			LOAD_ONLY_LIBRARIES_OPTION_DEFAULT);
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
		if (!isLoadLibraries(options)) {
			return null;
		}
		return project.getProjectData().getFolder(libraryDestinationFolderPath);
	}

	/**
	 * Gets a {@link List} of library search {@link DomainFolder folders} based on the current
	 * options
	 * 
	 * @param loadedPrograms the list of {@link Loaded} {@link Program}s
	 * @param project The {@link Project} to load into. Could be null if there is no project.
	 * @param options The {@link List} of {@link Option}s
	 * @return A {@link List} of library search {@link DomainFolder folders} based on the current
	 * options
	 */
	protected List<DomainFolder> getLibrarySearchFolders(List<Loaded<Program>> loadedPrograms,
			Project project, List<Option> options) {
		List<DomainFolder> searchFolders = new ArrayList<>();
		String projectFolderPath = loadedPrograms.get(0).getProjectFolderPath();
		String destPath = getLibraryDestinationFolderPath(project, projectFolderPath, options);
		DomainFolder destSearchFolder =
			getLibraryDestinationSearchFolder(project, destPath, options);
		DomainFolder linkSearchFolder = getLinkSearchFolder(project,
			loadedPrograms.getFirst().getDomainObject(), projectFolderPath, options);
		Optional.ofNullable(destSearchFolder).ifPresent(searchFolders::add);
		Optional.ofNullable(linkSearchFolder).ifPresent(searchFolders::add);
		return searchFolders;
	}

	/**
	 * Checks whether or not to search for libraries using all possible search paths, regardless
	 * of what options are set
	 * 
	 * @param program The {@link Program} being loaded
	 * @param options a {@link List} of {@link Option}s
	 * @return True if all possible search paths should be used, regardless of what options are set
	 */
	protected boolean shouldSearchAllPaths(Program program, List<Option> options) {
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
	 * Performs optional follow-on actions after an the given library has been loaded
	 * 
	 * @param library The loaded library {@link Program}
	 * @param libraryName The name of the library
	 * @param libraryFsrl The library {@link FSRL}
	 * @param provider The library bytes
	 * @param unprocessed The {@link Queue} of {@link UnprocessedLibrary unprocessed libraries}
	 * @param depth The load depth of the library to load
	 * @param loadSpec The {@link LoadSpec} used for the load
	 * @param options The options
	 * @param log The log
	 * @param monitor A cancelable monitor
	 * @throws IOException If an IO-related error occurred
	 * @throws CancelledException If the user cancelled the action
	 */
	protected void processLibrary(Program library, String libraryName, FSRL libraryFsrl,
			ByteProvider provider, Queue<UnprocessedLibrary> unprocessed, int depth,
			LoadSpec loadSpec, List<Option> options, MessageLog log, TaskMonitor monitor)
			throws IOException, CancelledException {
		// Default behavior is to do nothing
	}

	/**
	 * Loads the given list of libraries as {@link Loaded} {@link Program}s
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
		Queue<UnprocessedLibrary> unprocessed = createUnprocessedQueue(libraryNameList, options);
		boolean loadLibraries = isLoadLibraries(options);
		List<LibrarySearchPath> customSearchPaths =
			getCustomLibrarySearchPaths(provider, options, log, monitor);
		List<LibrarySearchPath> searchPaths =
			getLibrarySearchPaths(program, desiredLoadSpec, options, log, monitor);
		DomainFolder linkSearchFolder =
			getLinkSearchFolder(project, program, projectFolderPath, options);
		String libraryDestFolderPath =
			getLibraryDestinationFolderPath(project, projectFolderPath, options);
		DomainFolder libraryDestFolder =
			getLibraryDestinationSearchFolder(project, libraryDestFolderPath, options);

		boolean success = false;
		try {
			while (!unprocessed.isEmpty()) {
				monitor.checkCancelled();
				UnprocessedLibrary unprocessedLibrary = unprocessed.remove();
				String library = unprocessedLibrary.name().trim();
				int depth = unprocessedLibrary.depth();
				if (depth == 0 || processed.contains(library)) {
					continue;
				}
				processed.add(library);
				if (findLibraryInProject(library, libraryDestFolder, searchPaths, options,
					monitor) != null) {
					log.appendMsg("Found %s in %s...".formatted(library, libraryDestFolder));
					log.appendMsg("------------------------------------------------\n");
				}
				else if (findLibraryInProject(library, linkSearchFolder, searchPaths, options,
					monitor) != null) {
					log.appendMsg("Found %s in %s...".formatted(library, linkSearchFolder));
					log.appendMsg("------------------------------------------------\n");
				}
				else if (isLoadLibraries(options) || shouldSearchAllPaths(program, options)) {
					Loaded<Program> loadedLibrary = loadLibraryFromSearchPaths(library, provider,
						customSearchPaths, libraryDestFolderPath, unprocessed, depth,
						desiredLoadSpec, options, log, consumer, monitor);
					if (loadedLibrary == null) {
						loadedLibrary = loadLibraryFromSearchPaths(library, provider, searchPaths,
							libraryDestFolderPath, unprocessed, depth, desiredLoadSpec, options,
							log, consumer, monitor);
					}
					if (loadedLibrary != null) {
						boolean discarding = !loadLibraries || unprocessedLibrary.discard();
						loadedLibrary.setDiscard(discarding);
						loadedPrograms.add(loadedLibrary);
						log.appendMsg(discarding ? "Library not saved to project."
								: "Saving library to: " + loadedLibrary);
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
			Stream.of(customSearchPaths, searchPaths)
					.flatMap(Collection::stream)
					.forEach(fsSearchPath -> {
						if (!fsSearchPath.fsRef().isClosed()) {
							fsSearchPath.fsRef().close();
						}
					});
			FileSystemService.getInstance().closeUnusedFileSystems();
		}
	}

	/**
	 * Loads the given library into the given {@link DomainFolder folder} if it can find it in
	 * the given {@link List} of search paths
	 *
	 * @param library The library to load
	 * @param provider The {@link ByteProvider} of the program being loaded
	 * @param searchPaths A {@link List} of {@link LibrarySearchPath}s that will be searched
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
	 * @return The {@link Loaded} library, or null if it was not found. The returned library is the
	 *   caller's responsibility to release.
	 * @throws IOException if there was an IO-related problem loading
	 * @throws CancelledException if the user cancelled the load
	 */
	private Loaded<Program> loadLibraryFromSearchPaths(String library, ByteProvider provider,
			List<LibrarySearchPath> searchPaths, String libraryDestFolderPath,
			Queue<UnprocessedLibrary> unprocessed, int depth, LoadSpec desiredLoadSpec,
			List<Option> options, MessageLog log, Object consumer, TaskMonitor monitor)
			throws CancelledException, IOException {

		if (searchPaths.isEmpty()) {
			return null;
		}

		log.appendMsg("Searching %d path%s for library %s...".formatted(searchPaths.size(),
			searchPaths.size() > 1 ? "s" : "", library));

		Program libraryProgram = null;
		String simpleLibraryName = FilenameUtils.getName(library);
		boolean isAbsolute = new File(library).isAbsolute();

		boolean success = false;
		try {
			List<FSRL> candidateLibraryFsrls =
				findLibraryOnDisk(library, searchPaths, log, monitor);
			if (candidateLibraryFsrls.isEmpty()) {
				log.appendMsg("Library not found.");
				return null;
			}

			for (FSRL candidateLibraryFsrl : candidateLibraryFsrls) {
				monitor.checkCancelled();
				List<String> newLibraryList = new ArrayList<>();
				libraryProgram = loadLibrary(simpleLibraryName, candidateLibraryFsrl,
					desiredLoadSpec, newLibraryList, options, consumer, log, monitor);
				for (String newLibraryName : newLibraryList) {
					unprocessed.add(new UnprocessedLibrary(newLibraryName, depth - 1, false));
				}
				if (libraryProgram == null) {
					continue;
				}
				processLibrary(libraryProgram, library, candidateLibraryFsrl, provider, unprocessed,
					depth, desiredLoadSpec, options, log, monitor);
				success = true;
				String folderPath = libraryDestFolderPath;
				if (folderPath != null) {
					if (isAbsolute) {
						folderPath = joinPaths(folderPath, FilenameUtils.getFullPath(library));
					}
				}
				return new Loaded<Program>(libraryProgram, simpleLibraryName, folderPath);
			}
		}
		finally {
			if (!success && libraryProgram != null) {
				libraryProgram.release(consumer);
			}
		}
		return null;
	}

	/**
	 * Find the library within the specified {@link DomainFolder root search folder}.  This method 
	 * will handle relative path normalization.
	 * <p>
	 * If the library path is a simple name without any path separators, only the given folder 
	 * will be searched.
	 * <p>
	 * If the library path has a path, it will be treated as a relative path under
	 * given folder and if found that {@link DomainFile} will be returned.
	 * <p>
	 * If the library path has a path and it wasn't found under the given folder, the
	 * filename part of library path will be used to search the given folder for matches.
	 * 
	 * @param library library to find
	 * @param rootSearchFolder {@link DomainFolder root folder} within which imported libraries will
	 *   be searched. If null this method will return null.
	 * @param searchPaths A {@link List} of {@link LibrarySearchPath}s that will be searched
	 * @param options The load options
	 * @param monitor A cancelable task monitor
	 * @return The found {@link DomainFile} or null if not found
	 * @throws CancelledException if the user cancelled the load
	 */
	protected DomainFile findLibraryInProject(String library, DomainFolder rootSearchFolder,
			List<LibrarySearchPath> searchPaths, List<Option> options, TaskMonitor monitor)
			throws CancelledException {
		if (rootSearchFolder == null) {
			return null;
		}

		// Lookup by full project path
		// NOTE: probably no need to support optional extensions and case-insensitivity for this case
		String projectPath = joinPaths(rootSearchFolder.getPathname(), library);
		ProjectData projectData = rootSearchFolder.getProjectData();
		DomainFile ret = projectData.getFile(projectPath);
		if (ret != null) {
			return ret;
		}

		// Quick lookup by library filename (ignoring full library path) in given folder.
		// We try this first to hopefully avoid needing to iterate over the files in the folder
		// factoring in case and extensions
		String libraryName = FilenameUtils.getName(library);
		if ((ret = rootSearchFolder.getFile(libraryName)) != null) {
			return ret;
		}

		// Factoring in case and optional file extensions, iterate over given folder looking for
		// a match
		boolean noExtension = FilenameUtils.getExtension(libraryName).equals("");
		Comparator<String> comparator = getLibraryNameComparator();
		for (DomainFile file : rootSearchFolder.getFiles()) {
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
	 * If the library specifies an absolute path, its native path is also searched on the local 
	 * filesystem.
	 * 
	 * @param library The library. This will be either an absolute path, a relative path, or just a 
	 *   filename.
	 * @param searchPaths A {@link List} of {@link LibrarySearchPath}s that will be searched
	 * @param log The log
	 * @param monitor A cancelable task monitor
	 * @return A {@link List} of {@link GFile files} that match the requested library path
	 * @throws CancelledException if the user cancelled the operation
	 */
	private List<FSRL> findLibraryOnDisk(String library, List<LibrarySearchPath> searchPaths,
			MessageLog log, TaskMonitor monitor) throws CancelledException {

		List<FSRL> results = new ArrayList<>();

		try {
			for (LibrarySearchPath searchPath : searchPaths) {
				monitor.checkCancelled();
				String fullLibraryPath = joinPaths(searchPath.relativeFsPath(), library);
				GFileSystem fs = searchPath.fsRef().getFilesystem();
				FSRL fsrl = resolveLibraryFile(fs, fullLibraryPath);
				Optional.ofNullable(fsrl).ifPresent(results::add);
			}

			if (results.isEmpty() && new File(library).isAbsolute()) {
				LocalFileSystem localFS = FileSystemService.getInstance().getLocalFS();
				FSRL fsrl = resolveLibraryFile(localFS, library);
				Optional.ofNullable(fsrl).ifPresent(results::add);
			}
		}
		catch (IOException e) {
			log.appendException(e);
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
			libraryNameList.addAll(getLibraryNames(provider, program));
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
	 * Gets a {@link List} of library names that the given {@link Program} imports from
	 * 
	 * @param provider The {@link ByteProvider} to get the library names from
	 * @param program The {@link Program} to get the library names from
	 * @return A {@link List} of library names that the given {@link Program} imports from
	 * 
	 */
	private List<String> getLibraryNames(ByteProvider provider, Program program) {
		List<String> libraryNames = new ArrayList<>();
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
			libraryNames.add(name);
		}
		return libraryNames;
	}

	private void resolveExternalLibraries(Program program, List<Loaded<Program>> loadedPrograms,
			List<DomainFolder> searchFolders, List<LibrarySearchPath> fsSearchPaths,
			List<Option> options, TaskMonitor monitor, MessageLog messageLog)
			throws CancelledException {
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
				Loaded<Program> match = findLibraryInLoadedList(loadedPrograms, externalLibName);
				if (match != null) {
					String path = match.getProjectFolderPath() + match.getName();
					extManager.setExternalPath(externalLibName, path, false);
					messageLog.appendMsg("  [" + externalLibName + "] -> [" + path + "]");
				}
				else {
					boolean found = false;
					for (DomainFolder searchFolder : searchFolders) {
						DomainFile alreadyImportedLib = findLibraryInProject(externalLibName,
							searchFolder, fsSearchPaths, options, monitor);
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
	 * @param discard True if the library should be discarded (not saved) after processing
	 */
	protected record UnprocessedLibrary(String name, int depth, boolean discard) {/**/}

	/**
	 * Creates a new {@link Queue} of {@link UnprocessedLibrary}s, initialized filled with the
	 * library names in the given list
	 * 
	 * @param libraryNames A {@link List} of unprocessed library names
	 * @param options The options
	 * @return A {@link Queue} of {@link UnprocessedLibrary}s
	 */
	private Queue<UnprocessedLibrary> createUnprocessedQueue(List<String> libraryNames,
			List<Option> options) {
		int depth = getLibraryLoadDepth(options);
		return libraryNames.stream()
				.map(name -> new UnprocessedLibrary(name, depth, false))
				.collect(Collectors.toCollection(LinkedList::new));
	}

	/**
	 * A library search path
	 * 
	 * @param fsRef The root {@link FileSystemRef}
	 * @param relativeFsPath A {@link Path} relative to the root of the file system, or null for the
	 *   root
	 */
	protected record LibrarySearchPath(FileSystemRef fsRef, String relativeFsPath) {}

	/**
	 * Gets a {@link List} of priority-ordered custom {@link LibrarySearchPath}s used to search 
	 * for libraries.  The default implementation of this method returns an empty {@link List}.
	 * Subclasses can override it as needed.
	 * 
	 * @param provider The {@link ByteProvider} of the program being loaded
	 * @param options The options
	 * @param log The log
	 * @param monitor A cancelable task monitor
	 * @return A {@link List} of priority-ordered custom {@link LibrarySearchPath}s used to
	 *   search for libraries
	 * @throws CancelledException if the user cancelled the load
	 */
	protected List<LibrarySearchPath> getCustomLibrarySearchPaths(ByteProvider provider,
			List<Option> options, MessageLog log, TaskMonitor monitor) throws CancelledException {
		return List.of();
	}

	/**
	 * Checks to make sure the given search path {@link FSRL} is valid before processing it.
	 * Subclasses can override it as needed.
	 * 
	 * @param fsrl The search path {@link FSRL}
	 * @param loadSpec The {@link LoadSpec} to use during load.
	 * @param monitor A cancelable task monitor
	 * @return True is the search path is valid; otherwise, false
	 * @throws CancelledException if the user cancelled the load
	 */
	protected boolean isValidSearchPath(FSRL fsrl, LoadSpec loadSpec, TaskMonitor monitor)
			throws CancelledException {
		monitor.checkCancelled();
		return true;
	}

	/**
	 * Gets a {@link List} of priority-ordered {@link LibrarySearchPath}s used to search for 
	 * libraries
	 * 
	 * @param program The {@link Program} being loaded
	 * @param loadSpec The {@link LoadSpec} to use during load
	 * @param options The options
	 * @param log The log
	 * @param monitor A cancelable task monitor
	 * @return A {@link List} of priority-ordered {@link LibrarySearchPath}s used to search for 
	 *   libraries
	 * @throws CancelledException if the user cancelled the load
	 */
	protected List<LibrarySearchPath> getLibrarySearchPaths(Program program, LoadSpec loadSpec,
			List<Option> options, MessageLog log, TaskMonitor monitor) throws CancelledException {
		if (!isLoadLibraries(options) && !shouldSearchAllPaths(program, options)) {
			return List.of();
		}

		FileSystemService fsService = FileSystemService.getInstance();
		List<LibrarySearchPath> result = new ArrayList<>();
		boolean success = false;
		try {
			for (FSRL fsrl : LibrarySearchPathManager.getLibraryFsrlList(program, log, monitor)) {

				if (!isValidSearchPath(fsrl, loadSpec, monitor)) {
					continue;
				}

				if (fsService.isLocal(fsrl)) {
					try {
						FileSystemRef fileRef =
							fsService.probeFileForFilesystem(fsrl, monitor, null);
						if (fileRef != null) {
							result.add(new LibrarySearchPath(fileRef, null));
						}
					}
					catch (IOException e) {
						log.appendMsg(e.getMessage());
					}
				}
				else {
					try (RefdFile fileRef = fsService.getRefdFile(fsrl, monitor)) {
						if (fileRef != null) {
							File f = new File(fileRef.file.getPath()); // File API will sanitize Windows-style paths
							result.add(new LibrarySearchPath(fileRef.fsRef.dup(), f.getPath()));
						}
					}
					catch (IOException e) {
						log.appendMsg(e.getMessage());
					}
				}
			}
			success = true;
		}
		finally {
			if (!success) {
				result.forEach(fsSearchPath -> fsSearchPath.fsRef().close());
			}
		}
		return result;
	}

	/**
	 * Find the library within the given {@link List} of {@link Loaded} {@link Program}s
	 * 
	 * @param loadedPrograms the list of {@link Loaded} {@link Program}s
	 * @param libraryName The library name to lookup.  Depending on the type of library, this could
	 *   be a simple filename or an absolute path.
	 * @return The found {@link Loaded} {@link Program} or null if not found
	 */
	protected Loaded<Program> findLibraryInLoadedList(List<Loaded<Program>> loadedPrograms,
			String libraryName) {
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
	 * @param library The library. This will be either an absolute path, a relative path, or just a 
	 *   filename.
	 * @return The library resolved to an existing {@link FSRL}, or null if it did not resolve
	 * @throws IOException If an IO-related problem occurred
	 */
	protected FSRL resolveLibraryFile(GFileSystem fs, String library) throws IOException {
		Comparator<String> baseNameComp = getLibraryNameComparator();
		Comparator<String> nameComp = isOptionalLibraryFilenameExtensions() &&
			FilenameUtils.getExtension(library).isEmpty()
					? (s1, s2) -> baseNameComp.compare(FilenameUtils.getBaseName(s1),
						FilenameUtils.getBaseName(s2))
					: baseNameComp;

		GFile foundFile = fs.lookup(library, nameComp);
		return foundFile != null && !foundFile.isDirectory() ? foundFile.getFSRL() : null;
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
