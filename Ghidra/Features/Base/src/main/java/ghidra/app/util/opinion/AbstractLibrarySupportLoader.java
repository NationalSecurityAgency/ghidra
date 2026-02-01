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

import java.io.IOException;
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
import ghidra.plugin.importer.ImporterPlugin;
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

	/**
	 * Option to attempt to fix up the {@link Loaded} {@link Program}'s external programs with
	 * libraries discovered in the project. This alone does not cause new library programs to be 
	 * loaded.
	 */
	public static final String LINK_EXISTING_OPTION_NAME = "Link Existing Project Libraries";
	static final boolean LINK_EXISTING_OPTION_DEFAULT = true;

	/**
	 * Path of a {@link DomainFolder} to search for libraries
	 */
	public static final String LINK_SEARCH_FOLDER_OPTION_NAME = "Project Library Search Folder";
	static final String LINK_SEARCH_FOLDER_OPTION_DEFAULT = "";

	/**
	 * Whether or not to search for libraries on disk (or in a {@link GFileSystem})
	 */
	public static final String LOAD_LIBRARY_OPTION_NAME = "Load Libraries From Disk";
	static final boolean LOAD_LIBRARY_OPTION_DEFAULT = false;
	
	/**
	 * A dummy option used to produce a custom renderer to select library search paths.
	 * 
	 * @see LibrarySearchPathDummyOption
	 */
	public static final String LIBRARY_SEARCH_PATH_DUMMY_OPTION_NAME = "Library Search Paths";

	/**
	 * How many levels of libraries to load
	 */
	public static final String DEPTH_OPTION_NAME = "Recursive Library Load Depth";
	static final int DEPTH_OPTION_DEFAULT = 1;

	/**
	 * Path of a {@link DomainFolder} to save libraries to. This location will also be used as
	 * a location to {@link #LINK_EXISTING_OPTION_NAME search for already-loaded libraries}.
	 */
	public static final String LIBRARY_DEST_FOLDER_OPTION_NAME = "Library Destination Folder";
	static final String LIBRARY_DEST_FOLDER_OPTION_DEFAULT = "";

	public static final String MIRROR_LAYOUT_OPTION_NAME = "Mirror Library Disk Layout";

	/**
	 * A hidden option used by the {@link ImporterPlugin}'s "Load Libraries" action to inform this
	 * {@link Loader} that the {@link Program} to import has already been saved to the project and
	 * is currently open, and that only libraries should be loaded.
	 */
	public static final String LOAD_ONLY_LIBRARIES_OPTION_NAME = "Only Load Libraries"; // hidden
	static final boolean LOAD_ONLY_LIBRARIES_OPTION_DEFAULT = false;

	/**
	 * Loads bytes in a particular format into the given {@link Program}.
	 *
	 * @param program The {@link Program} to load into.
	 * @param settings The {@link Loader.ImporterSettings}
	 * @throws IOException if there was an IO-related problem loading.
	 * @throws CancelledException if the user cancelled the load.
	 */
	protected abstract void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException;

	/**
	 * {@inheritDoc}
	 * <p>
	 * In addition to loading the given program bytes, this implementation will attempt to locate
	 * the libraries that the program links to from the
	 * {@link #LINK_SEARCH_FOLDER_OPTION_NAME project library search folder}, the
	 * {@link #LIBRARY_DEST_FOLDER_OPTION_NAME library destination folder} and the
	 * {@link #LOAD_LIBRARY_OPTION_NAME libraries found on disk}. All of these locations are
	 * controlled by loader options.
	 * <P>
	 * If the hidden {@link #LOAD_ONLY_LIBRARIES_OPTION_NAME} option is set and the given project
	 * is not {@code null}, it is assumed that a {@link DomainFile} exists at 
	 * {@code projectFolderPath/loadedName}, is open, and the provider corresponds to its contents.
	 * If this is the case, the primary (first) {@link Loaded} {@link Program} in the returned list
	 * will NOT be affected by a {@link LoadResults#save(TaskMonitor)} operation. It will be the 
	 * responsibility of the user to save this open program if desired.
	 * 
	 * @return A {@link List} of one or more {@link Loaded} {@link Program}s (created but not 
	 *   saved). The first element in the {@link List} will the primary program, with the remaining
	 *   elements being any newly loaded libraries.
	 * @throws LoadException if the load failed in an unexpected way. If the
	 *   {@link #LOAD_ONLY_LIBRARIES_OPTION_NAME} option is set, this exception will be thrown if
	 *   the {@link DomainFile} at {@code projectFolderPath/loadedName} does not correspond to an 
	 *   open {@link Program}.
	 */
	@Override
	protected List<Loaded<Program>> loadProgram(ImporterSettings settings)
			throws CancelledException, IOException {

		List<Loaded<Program>> loadedProgramList = new ArrayList<>();
		List<String> libraryNameList = new ArrayList<>();

		boolean success = false;
		try {
			// Load (or get) the primary program
			Program program = null;
			if (!shouldLoadOnlyLibraries(settings)) {
				program = doLoad(libraryNameList, settings);
				loadedProgramList.add(new Loaded<>(program, settings));
				settings.log().appendMsg("------------------------------------------------\n");
			}
			else {
				if (settings.project() == null) {
					throw new LoadException("Cannot load only libraries...project is null");
				}
				String projectPath = FSUtilities.appendPath(settings.projectRootPath(),
					settings.importName());
				DomainFile domainFile = settings.project().getProjectData().getFile(projectPath);
				if (domainFile == null) {
					throw new LoadException(
						"Cannot load only libraries for a non-existant program");
				}
				if (!Program.class.isAssignableFrom(domainFile.getDomainObjectClass())) {
					throw new LoadException("Cannot load only libraries for a non-program");
				}
				program = (Program) domainFile.getOpenedDomainObject(settings.consumer());
				if (program == null) {
					throw new LoadException("Failed to acquire an open Program");
				}
				loadedProgramList.add(new LoadedOpen<>(program, domainFile,
					FSRL.fromProgram(program), settings.consumer()));
				libraryNameList.addAll(getLibraryNames(settings.provider(), program));
			}

			// Load the libraries
			loadedProgramList.addAll(loadLibraries(program, libraryNameList, settings));

			success = true;
			return loadedProgramList;
		}
		finally {
			if (!success) {
				loadedProgramList.forEach(Loaded::close);
			}
		}
	}

	@Override
	protected void loadProgramInto(Program program, ImporterSettings settings)
			throws CancelledException, LoadException, IOException {

		LanguageCompilerSpecPair pair = settings.loadSpec().getLanguageCompilerSpec();
		LanguageID languageID = program.getLanguageID();
		CompilerSpecID compilerSpecID = program.getCompilerSpec().getCompilerSpecID();
		if (!(pair.languageID.equals(languageID) && pair.compilerSpecID.equals(compilerSpecID))) {
			String message = settings.provider().getAbsolutePath() +
				" does not have the same language/compiler spec as program " + program.getName();
			settings.log().appendMsg(message);
			throw new LoadException(message);
		}
		settings.log().appendMsg("Loading " + settings.provider().getAbsolutePath() + "...");
		load(program, settings);
		settings.log()
				.appendMsg(
					"--------------------------------------------------------------------\n");
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * Fix up program's external library entries so that they point to a path in the project.
	 */
	@Override
	protected void postLoadProgramFixups(List<Loaded<Program>> loadedPrograms,
			ImporterSettings settings) throws CancelledException, IOException {

		TaskMonitor monitor = settings.monitor();

		if (loadedPrograms.isEmpty() ||
			(!isLinkExistingLibraries(settings) && !isLoadLibraries(settings))) {
			return;
		}

		List<DomainFolder> searchFolders = getLibrarySearchFolders(loadedPrograms, settings);

		Program firstProgram = loadedPrograms.getFirst().getDomainObject(this);
		List<LibrarySearchPath> searchPaths;
		try {
			searchPaths = getLibrarySearchPaths(firstProgram, settings);
		}
		finally {
			firstProgram.release(this);
		}

		List<Loaded<Program>> saveablePrograms = loadedPrograms
				.stream()
				.filter(loaded -> loaded.check(Predicate.not(Program::isTemporary)))
				.toList();

		monitor.initialize(saveablePrograms.size());
		for (Loaded<Program> loadedProgram : saveablePrograms) {
			monitor.increment();

			Program program = loadedProgram.getDomainObject(this);
			try {
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
						settings);
				}
				finally {
					program.endTransaction(id, true);
				}
			}
			finally {
				program.release(this);
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
			DomainObject domainObject, boolean loadIntoProgram, boolean mirrorFsLayout) {
		List<Option> list = super.getDefaultOptions(provider, loadSpec, domainObject,
			loadIntoProgram, mirrorFsLayout);

		list.add(new Option(LINK_EXISTING_OPTION_NAME, LINK_EXISTING_OPTION_DEFAULT, Boolean.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-linkExistingProjectLibraries"));
		list.add(new DomainFolderOption(LINK_SEARCH_FOLDER_OPTION_NAME,
			Loader.COMMAND_LINE_ARG_PREFIX + "-projectLibrarySearchFolder", mirrorFsLayout));
		list.add(new Option(LOAD_LIBRARY_OPTION_NAME, LOAD_LIBRARY_OPTION_DEFAULT, Boolean.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-loadLibraries"));
		list.add(new LibrarySearchPathDummyOption(LIBRARY_SEARCH_PATH_DUMMY_OPTION_NAME));
		list.add(new Option(DEPTH_OPTION_NAME, DEPTH_OPTION_DEFAULT, Integer.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-libraryLoadDepth"));
		list.add(new DomainFolderOption(LIBRARY_DEST_FOLDER_OPTION_NAME,
			Loader.COMMAND_LINE_ARG_PREFIX + "-libraryDestinationFolder", mirrorFsLayout));
		list.add(new Option(MIRROR_LAYOUT_OPTION_NAME, Boolean.class, mirrorFsLayout,
			Loader.COMMAND_LINE_ARG_PREFIX + "-libraryMirrorLayout", null, null, mirrorFsLayout));
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
					name.equals(MIRROR_LAYOUT_OPTION_NAME) ||
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
	 * @param settings The {@link Loader.ImporterSettings}
	 * @return True if existing libraries should be linked; otherwise, false
	 */
	protected boolean isLinkExistingLibraries(ImporterSettings settings) {
		return OptionUtils.getOption(LINK_EXISTING_OPTION_NAME, settings.options(),
			LINK_EXISTING_OPTION_DEFAULT);
	}

	/**
	 * Gets the {@link DomainFolder project folder} to search for existing libraries
	 * 
	 * @param program The {@link Program} being loaded
	 * @param settings The {@link Loader.ImporterSettings}
	 * @return The path of the project folder to search for existing libraries, or null if no
	 *   project folders can be or should be searched
	 */
	protected DomainFolder getLinkSearchFolder(Program program, ImporterSettings settings) {
		if (!shouldSearchAllPaths(program, settings) && !isLinkExistingLibraries(settings)) {
			return null;
		}
		if (settings.project() == null) {
			return null;
		}

		ProjectData projectData = settings.project().getProjectData();
		if (settings.mirrorFsLayout()) {
			return projectData.getFolder(settings.projectRootPath());
		}

		String linkSearchFolderPath = OptionUtils.getOption(LINK_SEARCH_FOLDER_OPTION_NAME,
			settings.options(), LINK_SEARCH_FOLDER_OPTION_DEFAULT);

		String projectFolderPath = FSUtilities.appendPath(settings.projectRootPath(),
			settings.importPathOnly());

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
	 * @param settings The {@link Loader.ImporterSettings}
	 * @return True if libraries from disk should be loaded; otherwise, false
	 */
	protected boolean isLoadLibraries(ImporterSettings settings) {
		return OptionUtils.getOption(LOAD_LIBRARY_OPTION_NAME, settings.options(),
			LOAD_LIBRARY_OPTION_DEFAULT);
	}

	/**
	 * Checks to see if library organization mirrors filesystem layout
	 * 
	 * @param settings The {@link Loader.ImporterSettings}
	 * @return True if library organization mirrors filesystem layout; false if flat layout
	 */
	protected boolean isMirroredLayout(ImporterSettings settings) {
		return OptionUtils.getOption(MIRROR_LAYOUT_OPTION_NAME, settings.options(),
			settings.mirrorFsLayout());
	}

	/**
	 * Checks to see if only libraries should be loaded (i.e., not the main program)
	 * 
	 * @param settings The {@link Loader.ImporterSettings}
	 * @return True if only libraries should be loaded; otherwise, false
	 */
	protected boolean shouldLoadOnlyLibraries(ImporterSettings settings) {
		return OptionUtils.getOption(LOAD_ONLY_LIBRARIES_OPTION_NAME, settings.options(),
			LOAD_ONLY_LIBRARIES_OPTION_DEFAULT);
	}

	/**
	 * Gets the desired recursive library load depth
	 * 
	 * @param settings The {@link Loader.ImporterSettings}
	 * @return The desired recursive library load depth
	 */
	protected int getLibraryLoadDepth(ImporterSettings settings) {
		return OptionUtils.getOption(DEPTH_OPTION_NAME, settings.options(), DEPTH_OPTION_DEFAULT);
	}

	/**
	 * Gets the project folder path to load the libraries into.  It does not have to exist in the
	 * project yet.
	 * 
	 * @param settings The {@link Loader.ImporterSettings}
	 * @return The path of the project folder to load the libraries into.  Could be null if the 
	 *   specified project is null or a destination folder path could not be determined.
	 */
	protected String getLibraryDestinationFolderPath(ImporterSettings settings) {
		if (settings.project() == null) {
			return null;
		}

		if (settings.mirrorFsLayout()) {
			return settings.projectRootPath();
		}

		String libraryDestinationFolderPath = OptionUtils.getOption(LIBRARY_DEST_FOLDER_OPTION_NAME,
			settings.options(), LIBRARY_DEST_FOLDER_OPTION_DEFAULT);

		if (libraryDestinationFolderPath.isBlank()) {
			return settings.projectRootPath();
		}

		return FilenameUtils.separatorsToUnix(libraryDestinationFolderPath);
	}

	/**
	 * Gets the {@link DomainFolder project folder} that libraries are loaded into, to search for
	 * existing libraries.  It will only be returned if the options to load new libraries into the
	 * project are set.
	 * 
	 * @param libraryDestinationFolderPath The path of the project folder to load the libraries 
	 *   into.  Could be null (@see #getLibraryDestinationFolderPath(Project, String, List)).
	 * @param settings The {@link Loader.ImporterSettings}
	 * @return The path of the destination project folder to search for existing libraries, or null
	 *   if the destination folder is not being used or should not be searched
	 */
	protected DomainFolder getLibraryDestinationSearchFolder(String libraryDestinationFolderPath,
			ImporterSettings settings) {
		if (settings.project() == null || libraryDestinationFolderPath == null) {
			return null;
		}
		if (!isLoadLibraries(settings)) {
			return null;
		}
		return settings.project().getProjectData().getFolder(libraryDestinationFolderPath);
	}

	/**
	 * Gets a {@link List} of library search {@link DomainFolder folders} based on the current
	 * options
	 * 
	 * @param loadedPrograms the list of {@link Loaded} {@link Program}s
	 * @param settings The {@link Loader.ImporterSettings}
	 * @return A {@link List} of library search {@link DomainFolder folders} based on the current
	 * options
	 */
	protected List<DomainFolder> getLibrarySearchFolders(List<Loaded<Program>> loadedPrograms,
			ImporterSettings settings) {
		Program firstProgram = loadedPrograms.getFirst().getDomainObject(this);
		try {
			List<DomainFolder> searchFolders = new ArrayList<>();
			String destPath = getLibraryDestinationFolderPath(settings);
			DomainFolder destSearchFolder = getLibraryDestinationSearchFolder(destPath, settings);
			DomainFolder linkSearchFolder = getLinkSearchFolder(firstProgram, settings);
			Optional.ofNullable(destSearchFolder).ifPresent(searchFolders::add);
			Optional.ofNullable(linkSearchFolder).ifPresent(searchFolders::add);
			return searchFolders;
		}
		finally {
			firstProgram.release(this);
		}
	}

	/**
	 * Checks whether or not to search for libraries using all possible search paths, regardless
	 * of what options are set
	 * 
	 * @param program The {@link Program} being loaded
	 * @param settings The {@link Loader.ImporterSettings}
	 * @return True if all possible search paths should be used, regardless of what options are set
	 */
	protected boolean shouldSearchAllPaths(Program program, ImporterSettings settings) {
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
	 * @param unprocessed The {@link Queue} of {@link UnprocessedLibrary unprocessed libraries}
	 * @param depth The load depth of the library to load
	 * @param settings The {@link Loader.ImporterSettings}
	 * @throws IOException If an IO-related error occurred
	 * @throws CancelledException If the user cancelled the action
	 */
	protected void processLibrary(Program library, String libraryName, FSRL libraryFsrl,
			Queue<UnprocessedLibrary> unprocessed, int depth, ImporterSettings settings)
			throws IOException, CancelledException {
		// Default behavior is to do nothing
	}

	/**
	 * Loads the given list of libraries as {@link Loaded} {@link Program}s
	 *
	 * @param program The {@link Program} being loaded
	 * @param libraryNameList The {@link List} of libraries to load
	 * @param settings The {@link Loader.ImporterSettings}
	 * @return A {@link List} of newly loaded programs and libraries. Any program in the list is 
	 *   the caller's responsibility to release.
	 * @throws IOException if there was an IO-related problem loading
	 * @throws CancelledException if the user cancelled the load
	 */
	private List<Loaded<Program>> loadLibraries(Program program, List<String> libraryNameList,
			ImporterSettings settings) throws CancelledException, IOException {
		ByteProvider provider = settings.provider();
		List<Option> options = settings.options();
		MessageLog log = settings.log();
		TaskMonitor monitor = settings.monitor();

		List<Loaded<Program>> loadedPrograms = new ArrayList<>();
		Set<String> processed = new TreeSet<>(getLibraryNameComparator());
		Queue<UnprocessedLibrary> unprocessed = createUnprocessedQueue(libraryNameList, settings);
		boolean loadLibraries = isLoadLibraries(settings);
		List<LibrarySearchPath> customSearchPaths =
			getCustomLibrarySearchPaths(provider, options, log, monitor);
		List<LibrarySearchPath> searchPaths = getLibrarySearchPaths(program, settings);
		DomainFolder linkSearchFolder = getLinkSearchFolder(program, settings);
		String libraryDestFolderPath = getLibraryDestinationFolderPath(settings);
		DomainFolder libraryDestFolder =
			getLibraryDestinationSearchFolder(libraryDestFolderPath, settings);

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
				if (findLibraryInProject(library, libraryDestFolder, searchPaths,
					settings) != null) {
					log.appendMsg("Found %s in %s...".formatted(library, libraryDestFolder));
					log.appendMsg("------------------------------------------------\n");
				}
				else if (findLibraryInProject(library, linkSearchFolder, searchPaths,
					settings) != null) {
					log.appendMsg("Found %s in %s...".formatted(library, linkSearchFolder));
					log.appendMsg("------------------------------------------------\n");
				}
				else if (isLoadLibraries(settings) || shouldSearchAllPaths(program, settings)) {
					Loaded<Program> loadedLibrary = loadLibraryFromSearchPaths(library,
						customSearchPaths, libraryDestFolderPath, unprocessed, depth, settings);
					if (loadedLibrary == null) {
						loadedLibrary = loadLibraryFromSearchPaths(library, searchPaths,
							libraryDestFolderPath, unprocessed, depth, settings);
					}
					if (loadedLibrary != null) {
						boolean temporary = !loadLibraries || unprocessedLibrary.temporary();
						loadedLibrary.apply(p -> p.setTemporary(temporary));
						loadedPrograms.add(loadedLibrary);
						log.appendMsg(temporary ? "Library not saved to project."
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
				loadedPrograms.forEach(Loaded::close);
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
	 * @param searchPaths A {@link List} of {@link LibrarySearchPath}s that will be searched
	 * @param unprocessed The {@link Queue} of {@link UnprocessedLibrary unprocessed libraries}
	 * @param depth The load depth of the library to load
	 * @param settings The {@link Loader.ImporterSettings}
	 * @return The {@link Loaded} library, or null if it was not found. The returned library is the
	 *   caller's responsibility to release.
	 * @throws IOException if there was an IO-related problem loading
	 * @throws CancelledException if the user cancelled the load
	 */
	private Loaded<Program> loadLibraryFromSearchPaths(String library,
			List<LibrarySearchPath> searchPaths, String libraryDestFolderPath,
			Queue<UnprocessedLibrary> unprocessed, int depth, ImporterSettings settings)
			throws CancelledException, IOException {

		if (searchPaths.isEmpty()) {
			return null;
		}

		List<Option> options = settings.options();
		LoadSpec desiredLoadSpec = settings.loadSpec();
		Object consumer = settings.consumer();
		MessageLog log = settings.log();
		TaskMonitor monitor = settings.monitor();

		log.appendMsg("Searching %d path%s for library %s...".formatted(searchPaths.size(),
			searchPaths.size() > 1 ? "s" : "", library));

		Program libraryProgram = null;

		boolean success = false;
		try {
			List<GFile> candidateLibraryFiles =
				findLibraryOnDisk(library, searchPaths, log, monitor);
			if (candidateLibraryFiles.isEmpty()) {
				log.appendMsg("Library not found.");
				return null;
			}

			for (GFile candidateLibraryFile : candidateLibraryFiles) {
				monitor.checkCancelled();
				FSRL candidateLibraryFsrl = candidateLibraryFile.getFSRL();
				List<String> newLibraryList = new ArrayList<>();

				try (ByteProvider provider = createLibraryByteProvider(candidateLibraryFsrl,
					desiredLoadSpec, log, monitor)) {
					LoadSpec libLoadSpec = matchSupportedLoadSpec(settings.loadSpec(), provider);
					if (libLoadSpec == null) {
						log.appendMsg("Skipping library which is the wrong architecture: " +
							candidateLibraryFsrl);
						continue;
					}
					if (isMirroredLayout(settings)) {
						library = FSUtilities.mirroredProjectPath(candidateLibraryFsrl.getPath());
					}
					ImporterSettings librarySettings =
						new ImporterSettings(provider, library, settings.project(),
							libraryDestFolderPath, isMirroredLayout(settings), libLoadSpec, options,
							consumer, log, monitor);
					libraryProgram = doLoad(newLibraryList, librarySettings);
					for (String newLibraryName : newLibraryList) {
						unprocessed.add(new UnprocessedLibrary(newLibraryName, depth - 1, false));
					}
					if (libraryProgram == null) {
						continue;
					}
					processLibrary(libraryProgram, library, candidateLibraryFsrl, unprocessed,
						depth, librarySettings);
					success = true;
					return new Loaded<Program>(libraryProgram, librarySettings);
				}
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
	 * Find the library within the specified {@link DomainFolder}.
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
	 * @param library The library to find. Depending on the type of library, this could be a simple
	 *   filename or an absolute path.
	 * @param folder {@link DomainFolder root folder} within which imported libraries will
	 *   be searched. If null this method will return null.
	 * @param searchPaths A {@link List} of {@link LibrarySearchPath}s that will be searched
	 * @param settings The {@link Loader.ImporterSettings}
	 * @return The found {@link DomainFile} or null if not found
	 * @throws CancelledException if the user cancelled the load
	 */
	protected DomainFile findLibraryInProject(String library, DomainFolder folder,
			List<LibrarySearchPath> searchPaths, ImporterSettings settings)
			throws CancelledException {
		if (folder == null) {
			return null;
		}

		ProjectData projectData = folder.getProjectData();

		if (isMirroredLayout(settings)) {
			// Perform the lookup based on file system search path layout within the project
			for (LibrarySearchPath searchPath : searchPaths) {
				settings.monitor().checkCancelled();

				GFileSystem fs = searchPath.fsRef().getFilesystem();
				String fsPath = FSUtilities.mirroredProjectPath(
					FSUtilities.appendPath(fs.getFSRL().getPath(), searchPath.relativeFsPath()));
				String projectPath =
					FSUtilities.appendPath(folder.getPathname(), fsPath, library);
				DomainFolder parentFolder =
					projectData.getFolder(FilenameUtils.getFullPath(projectPath));
				if (parentFolder == null) {
					continue;
				}
				DomainFile ret =
					lookupLibraryInFolder(FilenameUtils.getName(library), parentFolder);
				if (ret != null) {
					return ret;
				}
			}
			return null;
		}

		if (isAbsoluteLibraryPath(library)) {
			String parentProjectPath =
				FSUtilities.appendPath(folder.getPathname(), FilenameUtils.getFullPath(library));
			folder = projectData.getFolder(parentProjectPath);
			if (folder == null) {
				return null;
			}
		}

		String libraryName = FilenameUtils.getName(library);
		DomainFile file = folder.getFile(libraryName);
		if (file != null) {
			return file;
		}

		return lookupLibraryInFolder(libraryName, folder);
	}

	/**
	 * Looks in the given {@link DomainFolder} for the given name using the loader's 
	 * {@link #getLibraryNameComparator() library name comparator}
	 * 
	 * @param libraryName The library name to search for (no path included)
	 * @param folder The {@link DomainFolder} to search in
	 * @return A matching library {@link DomainFile}, or {@code null} if one was not found
	 */
	protected DomainFile lookupLibraryInFolder(String libraryName, DomainFolder folder) {
		return Arrays.stream(folder.getFiles())
				.filter(df -> getLibraryNameComparator().compare(df.getName(), libraryName) == 0)
				.findFirst()
				.orElse(null);
	}

	/**
	 * Find the library in a {@link GFileSystem}, returning a {@link List} of possible candidate 
	 * {@link GFile files}.
	 * <p>
	 * Each search path directory will be searched for the library file in order.
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
	private List<GFile> findLibraryOnDisk(String library, List<LibrarySearchPath> searchPaths,
			MessageLog log, TaskMonitor monitor) throws CancelledException {

		List<GFile> results = new ArrayList<>();

		try {
			for (LibrarySearchPath searchPath : searchPaths) {
				monitor.checkCancelled();
				String fullLibraryPath =
					FSUtilities.appendPath(searchPath.relativeFsPath(), library);
				GFileSystem fs = searchPath.fsRef().getFilesystem();
				GFile file = lookupLibraryInFs(fullLibraryPath, fs);
				Optional.ofNullable(file).ifPresent(results::add);
			}

			if (results.isEmpty() && isAbsoluteLibraryPath(library)) {
				LocalFileSystem localFS = FileSystemService.getInstance().getLocalFS();
				GFile file = lookupLibraryInFs(library, localFS);
				Optional.ofNullable(file).ifPresent(results::add);
			}
		}
		catch (IOException e) {
			log.appendException(e);
		}

		return results;
	}

	/**
	 * Loads the given provider
	 * 
	 * @param libraryNameList A {@link List} to be populated with the loaded program's dependent
	 *   library names
	 * @param settings The {@link Loader.ImporterSettings}
	 * @return The newly loaded {@link Program}
	 * @throws CancelledException if the user cancelled the load operation
	 * @throws IOException if there was an IO-related error during the load
	 */
	private Program doLoad(List<String> libraryNameList, ImporterSettings settings)
			throws CancelledException, IOException {
		MessageLog log = settings.log();

		Program program = createProgram(settings);

		int transactionID = program.startTransaction("Loading");
		boolean success = false;
		try {
			log.appendMsg("Loading %s...".formatted(settings.provider().getFSRL()));
			load(program, settings);
			createDefaultMemoryBlocks(program, settings);
			libraryNameList.addAll(getLibraryNames(settings.provider(), program));
			success = true;
			return program;
		}
		finally {
			program.endTransaction(transactionID, true); // More efficient to commit when program will be discarded
			if (!success) {
				program.release(settings.consumer());
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
			ImporterSettings settings) throws CancelledException {
		ExternalManager extManager = program.getExternalManager();
		MessageLog log = settings.log();
		TaskMonitor monitor = settings.monitor();
		String[] extLibNames = extManager.getExternalLibraryNames();
		log.appendMsg("Linking the External Programs of '%s' to imported libraries..."
				.formatted(program.getName()));
		for (String externalLibName : extLibNames) {
			if (Library.UNKNOWN.equals(externalLibName)) {
				continue;
			}
			monitor.checkCancelled();
			try {
				Loaded<Program> match = findLibraryInLoadedList(loadedPrograms, externalLibName);
				if (match != null) {
					extManager.setExternalPath(externalLibName, FSUtilities
							.appendPath(match.getProjectFolderPath(), match.getName()),
						false);
					log.appendMsg("  [" + externalLibName + "] -> [" + match.getName() + "]");
				}
				else {
					boolean found = false;
					for (DomainFolder searchFolder : searchFolders) {
						DomainFile alreadyImportedLib = findLibraryInProject(externalLibName,
							searchFolder, fsSearchPaths, settings);
						if (alreadyImportedLib != null) {
							extManager.setExternalPath(externalLibName,
								alreadyImportedLib.getPathname(), false);
							log.appendMsg("  [" + externalLibName + "] -> [" +
								alreadyImportedLib.getPathname() + "] (previously imported)");
							found = true;
							break;
						}
					}
					if (!found) {
						log.appendMsg("  [" + externalLibName + "] -> not found in project");
					}
				}
			}
			catch (InvalidInputException e) {
				Msg.error(this, "Bad library name: " + externalLibName, e);
			}
		}
		log.appendMsg("------------------------------------------------\n");
	}

	/**
	 * A library that has not been processed by the loader yet
	 * 
	 * @param name The name of the library
	 * @param depth The recursive load depth of the library (based on the original binary being
	 *   loaded)
	 * @param temporary True if the library is temporary and should be discarded prior to returning
	 *   from the load
	 */
	protected record UnprocessedLibrary(String name, int depth, boolean temporary) {/**/}

	/**
	 * Creates a new {@link Queue} of {@link UnprocessedLibrary}s, initialized filled with the
	 * library names in the given list
	 * 
	 * @param libraryNames A {@link List} of unprocessed library names
	 * @param settings The {@link Loader.ImporterSettings}
	 * @return A {@link Queue} of {@link UnprocessedLibrary}s
	 */
	private Queue<UnprocessedLibrary> createUnprocessedQueue(List<String> libraryNames,
			ImporterSettings settings) {
		int depth = getLibraryLoadDepth(settings);
		return libraryNames.stream()
				.map(name -> new UnprocessedLibrary(name, depth, false))
				.collect(Collectors.toCollection(LinkedList::new));
	}

	/**
	 * A library search path
	 * 
	 * @param fsRef The root {@link FileSystemRef}
	 * @param relativeFsPath string path, relative to the root of the file system, or null for the
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
	 * @param settings The {@link Loader.ImporterSettings}
	 * @return True is the search path is valid; otherwise, false
	 * @throws CancelledException if the user cancelled the load
	 */
	protected boolean isValidSearchPath(FSRL fsrl, ImporterSettings settings)
			throws CancelledException {
		settings.monitor().checkCancelled();
		return true;
	}

	/**
	 * Gets a {@link List} of priority-ordered {@link LibrarySearchPath}s used to search for 
	 * libraries
	 * 
	 * @param program The {@link Program} being loaded
	 * @param settings The {@link Loader.ImporterSettings}
	 * @return A {@link List} of priority-ordered {@link LibrarySearchPath}s used to search for 
	 *   libraries
	 * @throws CancelledException if the user cancelled the load
	 */
	protected List<LibrarySearchPath> getLibrarySearchPaths(Program program,
			ImporterSettings settings) throws CancelledException {

		if (!isLoadLibraries(settings) && !shouldSearchAllPaths(program, settings) &&
			!(isMirroredLayout(settings) && isLinkExistingLibraries(settings))) {
			return List.of();
		}

		FileSystemService fsService = FileSystemService.getInstance();
		List<LibrarySearchPath> result = new ArrayList<>();
		boolean success = false;
		try {
			for (FSRL fsrl : LibrarySearchPathManager.getLibraryFsrlList(program, settings.log(),
				settings.monitor())) {

				if (!isValidSearchPath(fsrl, settings)) {
					continue;
				}

				if (fsService.isLocal(fsrl)) {
					try {
						// It might be a container file that we want to look inside of, so probe
						if (fsService.getLocalFS().getLocalFile(fsrl).isFile()) {
							FileSystemRef fileRef =
								fsService.probeFileForFilesystem(fsrl, settings.monitor(), null);
							if (fileRef != null) {
								result.add(new LibrarySearchPath(fileRef, null));
								continue;
							}
						}
					}
					catch (IOException e) {
						settings.log().appendMsg(e.getMessage());
					}
				}

				try (RefdFile fileRef = fsService.getRefdFile(fsrl, settings.monitor())) {
					if (fileRef != null) {
						result.add(
							new LibrarySearchPath(fileRef.fsRef.dup(), fileRef.file.getPath()));
					}
				}
				catch (IOException e) {
					settings.log().appendMsg(e.getMessage());
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
	 * @param library The library name to lookup.  Depending on the type of library, this could
	 *   be a simple filename or an absolute path.
	 * @return The found {@link Loaded} {@link Program} or null if not found
	 */
	protected Loaded<Program> findLibraryInLoadedList(List<Loaded<Program>> loadedPrograms,
			String library) {
		return loadedPrograms.stream()
				.filter(e -> getLibraryNameComparator().compare(e.getName(), library) == 0)
				.findFirst()
				.orElse(null);
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
	 * Looks in the given {@link GFileSystem} for the given library using the loader's 
	 * {@link #getLibraryNameComparator() library name comparator}
	 * 
	 * @param fs The {@link GFileSystem file system} to look in in
	 * @param library The library. Depending on the type of library, this could be a simple filename
	 *   or an absolute path.
	 * @return A matching library {@link GFile}, or {@code null} if one was not found
	 * @throws IOException If an IO-related problem occurred
	 */
	protected GFile lookupLibraryInFs(String library, GFileSystem fs) throws IOException {
		GFile foundFile = fs.lookup(library, getLibraryNameComparator());
		return foundFile != null && !foundFile.isDirectory() ? foundFile : null;
	}

	/**
	 * {@return a {@link Comparator} for comparing library names}
	 * <p>
	 * No assumptions should be made about whether the library name includes path information or
	 * not.
	 */
	protected Comparator<String> getLibraryNameComparator() {
		return (s1, s2) -> FilenameUtils.getName(s1).compareTo(FilenameUtils.getName(s2));
	}

	/**
	 * Performs a platform-independent test to see if the given path is absolute
	 * 
	 * @param path The path to test
	 * @return True if the given path is absolute; otherwise, false
	 */
	private boolean isAbsoluteLibraryPath(String path) {
		return FilenameUtils.getPrefixLength(path) > 0;
	}
}
