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
import java.util.*;
import java.util.stream.Collectors;

import org.apache.commons.io.FilenameUtils;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.RandomAccessByteProvider;
import ghidra.app.util.importer.LibrarySearchPathManager;
import ghidra.app.util.importer.MessageLog;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.framework.model.*;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

/**
 * An abstract {@link Loader} that provides a framework to conveniently load {@link Program}s with
 * support for linking against libraries contained in other {@link Program}s.
 * Subclasses are responsible for the actual load.
 * <p>
 */
public abstract class AbstractLibrarySupportLoader extends AbstractProgramLoader {

	public static final String SYM_OPTION_NAME = "Create Export Symbol Files";
	public static final String LIB_OPTION_NAME = "Load External Libraries";

	static final boolean IS_CREATE_EXPORT_SYMBOL_FILES_DEFAULT = true;
	static final boolean IS_LOAD_LIBRARIES_DEFAULT = false;

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
	protected List<Program> loadProgram(ByteProvider provider, String programName,
			DomainFolder programFolder, LoadSpec loadSpec, List<Option> options, MessageLog log,
			Object consumer, TaskMonitor monitor) throws CancelledException, IOException {

		Set<String> libraryNameSet = new HashSet<>();
		Set<String> resolvedSet = new HashSet<>();
		List<Program> programList = new ArrayList<>();

		boolean success = false;
		try {
			Program program = doLoad(provider, programName, programFolder, loadSpec, options, log,
				consumer, monitor, libraryNameSet);
			programList.add(program);

			monitor.checkCanceled();

			String parent = getProviderFilePath(provider);

			List<String> paths = LibrarySearchPathManager.getLibraryPathsList();
			if (parent != null) {
				// add the imported file's parent directory as first search location.
				paths.add(0, parent);
			}

			loadLibraries(programFolder, paths, loadSpec, options, log, consumer, libraryNameSet,
				resolvedSet, programList, monitor);

			apply(programList, options, log, monitor);
			success = true;
			return programList;
		}
		finally {
			if (!success) {
				release(programList, consumer);
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
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, loadIntoProgram);
		list.add(new Option(SYM_OPTION_NAME, IS_CREATE_EXPORT_SYMBOL_FILES_DEFAULT, Boolean.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-createExportSymbolFiles"));
		list.add(new Option(LIB_OPTION_NAME, IS_LOAD_LIBRARIES_DEFAULT, Boolean.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-loadExternalLibs"));
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {

		if (options != null) {
			for (Option option : options) {
				String name = option.getName();
				if (name.equals(SYM_OPTION_NAME) || name.equals(LIB_OPTION_NAME)) {
					if (!Boolean.class.isAssignableFrom(option.getValueClass())) {
						return "Invalid type for option: " + name + " - " + option.getValueClass();
					}
				}
			}
		}
		return super.validateOptions(provider, loadSpec, options, program);
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
	protected void postLoadProgramFixups(List<Program> loadedPrograms, DomainFolder folder,
			List<Option> options, MessageLog messageLog, TaskMonitor monitor)
			throws CancelledException, IOException {
		resolveExternalLibs(loadedPrograms, folder, true, messageLog, monitor);
	}

	/**
	 * Specifies if the library filenames specified by this loader should be exact case match
	 * or case-insensitive.
	 * <p>
	 * Derived loader classes should override this method and specify if the OS that normally
	 * handles this type of binary is case-insensitive.
	 * <p>
	 * @return - true if case-insensitive or false if case-sensitive.
	 */
	protected boolean isCaseInsensitiveLibraryFilenames() {
		return false;
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
	 * Attempts to import all libraries listed in {@code unprocessedLibs}, placing the newly
	 * created {@link DomainObject} instances in {@code programList}.
	 *
	 * @param programFolder The domain folder where the new program will be stored, if null
	 *   the program should not be pre-saved. NOTE: the newly imported libraries will not be written
	 *   to this folder yet, that is handled in a later follow on step.
	 * @param paths A list of paths on the local filesystem to search for library files.
	 * @param loadSpec The {@link LoadSpec}.
	 * @param options The load options.
	 * @param log The log.
	 * @param consumer A consumer object for {@link DomainObject}s generated.
	 * @param unprocessedLibs A list of libraries that need to be loaded.
	 * @param processedLibs A list of libraries that have been loaded (used to prevent the same 
	 *   library from being processed more than once)
	 * @param programList A list to hold newly loaded programs and libraries.  Any program
	 *      added to the list is the callers responsibility to release.
	 * @param monitor A cancelable task monitor.
	 * @throws IOException if there was an IO-related problem loading.
	 * @throws CancelledException if the user cancelled the load.
	 */
	private void loadLibraries(DomainFolder programFolder, List<String> paths, LoadSpec loadSpec,
			List<Option> options, MessageLog log, Object consumer, Set<String> unprocessedLibs,
			Set<String> processedLibs, List<Program> programList, TaskMonitor monitor)
			throws CancelledException, IOException {

		// TODO warning - hack alert
		if (loadSpec.getLoader() instanceof PeLoader) {
			if (!isCreateExportSymbolFiles(options) && !isLoadLibraries(options)) {
				return;
			}
		}
		else {
			if (!isLoadLibraries(options)) {
				return;
			}
		}

		for (String libName : new HashSet<>(unprocessedLibs)) {
			monitor.checkCanceled();
			unprocessedLibs.remove(libName);
			if (processedLibs.contains(libName)) {
				continue;
			}
			boolean libImported = false;
			if (findAlreadyImportedLibrary(libName, programFolder) == null) {
				log.appendMsg("Searching for referenced library: " + libName + " ...");
				String simpleLibName = FilenameUtils.getName(libName);

				List<File> candidateLibFiles =
					findLibraryFileToImport(FilenameUtils.separatorsToUnix(libName), paths);
				for (File libFile : candidateLibFiles) {
					monitor.checkCanceled();
					if (importLibrary(simpleLibName, programFolder, libFile, loadSpec, options, log,
						consumer, unprocessedLibs, programList, monitor)) {
						libImported = true;
						log.appendMsg("Found and imported external library: " + libFile);
						break;
					}
				}
				if (!libImported) {
					log.appendMsg("Unable to find external library: " + libName);
				}
			}
			processedLibs.add(libName);
		}
		log.appendMsg(
			"Finished importing referenced libraries for: " + programList.get(0).getName());
	}

	private void apply(List<Program> programs, List<Option> options, MessageLog log,
			TaskMonitor monitor) throws CancelledException {
		monitor.initialize(programs.size());

		for (int i = 0; i < programs.size() && isCreateExportSymbolFiles(options); ++i) {
			Program p = programs.get(i);

			monitor.checkCanceled();
			monitor.setProgress(i);

			int id = p.startTransaction("apply");
			boolean success = false;
			try {
				applyLibrarySymbols(p, log, monitor);
				applyImports(p, log, monitor);

				success = true;
			}
			finally {
				p.endTransaction(id, success);
			}
		}

		LibraryLookupTable.cleanup();
	}

	private boolean isCreateExportSymbolFiles(List<Option> options) {
		boolean isCreateExportSymbolFiles = IS_CREATE_EXPORT_SYMBOL_FILES_DEFAULT;
		if (options != null) {
			for (Option option : options) {
				String optName = option.getName();
				if (optName.equals(SYM_OPTION_NAME)) {
					isCreateExportSymbolFiles = (Boolean) option.getValue();
				}
			}
		}
		return isCreateExportSymbolFiles;
	}

	private boolean isLoadLibraries(List<Option> options) {
		boolean isLoadLibraries = IS_LOAD_LIBRARIES_DEFAULT;
		if (options != null) {
			for (Option option : options) {
				String optName = option.getName();
				if (optName.equals(LIB_OPTION_NAME)) {
					isLoadLibraries = (Boolean) option.getValue();
				}
			}
		}
		return isLoadLibraries;
	}

	private Program doLoad(ByteProvider provider, String programName, DomainFolder programFolder,
			LoadSpec loadSpec, List<Option> options, MessageLog log, Object consumer,
			TaskMonitor monitor, Set<String> unprocessedLibraries)
			throws CancelledException, IOException {
		LanguageCompilerSpecPair pair = loadSpec.getLanguageCompilerSpec();
		Language language = getLanguageService().getLanguage(pair.languageID);
		CompilerSpec compilerSpec = language.getCompilerSpecByID(pair.compilerSpecID);

		monitor.setMessage(provider.getName());

		Address imageBaseAddr = language.getAddressFactory().getDefaultAddressSpace().getAddress(
			loadSpec.getDesiredImageBase());
		Program program = createProgram(provider, programName, imageBaseAddr, getName(), language,
			compilerSpec, consumer);

		int transactionID = program.startTransaction("importing");
		boolean success = false;
		try {
			log.appendMsg("----- Loading " + provider.getAbsolutePath() + " -----");
			load(provider, loadSpec, options, program, monitor, log);

			createDefaultMemoryBlocks(program, language, log);

			if (unprocessedLibraries != null) {
				ExternalManager extMgr = program.getExternalManager();
				String[] externalNames = extMgr.getExternalLibraryNames();
				Arrays.sort(externalNames);
				for (String name : externalNames) {
					if (name.equals(provider.getName()) || Library.UNKNOWN.equals(name)) {
						// skip self-references and UNKNOWN library...
						continue;
					}
					unprocessedLibraries.add(name);
				}
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
	 * For each program in the programs list, fix up its external Library entries so
	 * that they point to a path in the ghidra project.
	 * <p>
	 * Other programs in the programs list are matched first, then the
	 * ghidraLibSearchFolders are searched for matches.
	 *
	 * @param programs the list of programs to resolve against each other.  Programs not saved
	 * to the project will be considered as a valid external library.
	 * @param domainFolder the {@link DomainFolder} folder within which imported libraries will
	 * be searched.  This folder will be searched if a library is not found within the
	 * list of programs supplied.  If null, only the list of programs will be considered.
	 * @param saveIfModified flag to have this method save any programs it modifies
	 * @param messageLog log for messages.
	 * @param monitor the task monitor
	 * @throws IOException if there was an IO-related problem resolving.
	 * @throws CancelledException if the user cancelled the load.
	 */
	private void resolveExternalLibs(List<Program> programs, DomainFolder domainFolder,
			boolean saveIfModified, MessageLog messageLog, TaskMonitor monitor)
			throws CancelledException, IOException {

		Map<String, Program> progsByName = programs.stream().filter(Objects::nonNull).collect(
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
			int id = program.startTransaction("resolving external references");
			try {
				resolveExternalLibs(program, progsByName, domainFolder, monitor, messageLog);
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
	 * Fix up program's external Library entries so
	 * that they point to a path in the ghidra project.
	 * <p>
	 * Other programs in the progsByName map are matched first, then the
	 * ghidraLibSearchFolders are searched for matches.
	 *
	 * @param program the program whose Library entries are to be resolved.  An open transaction
	 * on program is required.
	 * @param progsByName map of recently imported programs to be considered
	 * first when resolving external Libraries.  Programs not saved to the project
	 * will be ignored.
	 * @param domainFolder the {@link DomainFolder} folder within which imported libraries will
	 * be searched.  This folder will be searched if a library is not found within the
	 * progsByName map.  If null, only progsByName will be considered.
	 * @param messageLog log for messages.
	 * @param monitor the task monitor
	 * @throws CancelledException if the user cancelled the load.
	 */
	private void resolveExternalLibs(Program program, Map<String, Program> progsByName,
			DomainFolder domainFolder, TaskMonitor monitor, MessageLog messageLog)
			throws CancelledException {
		ExternalManager extManager = program.getExternalManager();
		String[] extLibNames = extManager.getExternalLibraryNames();
		for (String externalLibName : extLibNames) {
			if (Library.UNKNOWN.equals(externalLibName)) {
				continue;
			}
			monitor.checkCanceled();
			try {
				String externalFileName = FilenameUtils.getName(externalLibName);
				DomainObject matchingExtProgram = progsByName.get(externalFileName);
				if (matchingExtProgram != null && matchingExtProgram.getDomainFile().exists()) {
					extManager.setExternalPath(externalLibName,
						matchingExtProgram.getDomainFile().getPathname(), false);
					messageLog.appendMsg("  [" + externalLibName + "] -> [" +
						matchingExtProgram.getDomainFile().getPathname() + "]");
				}
				else {
					DomainFile alreadyImportedLib =
						findAlreadyImportedLibrary(externalLibName, domainFolder);
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
	 * Find the libPathFilename within the specified importFolder.  This method will handle
	 * relative path normalization.
	 * <p>
	 * If libPathFilename is a simple name without any path separators, only the
	 * importFolder folder will be searched.
	 * <p>
	 * If libPathFilename has a path, it will be treated as a relative path under
	 * {@code importFolder} and if found that DomainFile will be returned.
	 * <p>
	 * If libPathFilename has a path and it wasn't found under importFolder, the
	 * filename part of libPathFilename will be used to search the importFolder for matches.
	 * <p>
	 * @param libPathFilename String path with filename of the library to find
	 * @param domainFolder {@link DomainFolder} folder within which imported libraries will
	 * be searched.  If null this method will return null.
	 * @return found {@link DomainFile} or null if not found
	 */
	protected DomainFile findAlreadyImportedLibrary(String libPathFilename,
			DomainFolder domainFolder) {
		if (domainFolder == null) {
			return null;
		}

		String projectPath = appendPath(domainFolder.getPathname(), libPathFilename);
		DomainFile alreadyImportedLibDF =
			domainFolder.getProjectData().getFile(FilenameUtils.separatorsToUnix(projectPath));
		if (alreadyImportedLibDF == null) {
			alreadyImportedLibDF = domainFolder.getFile(FilenameUtils.getName(libPathFilename));
		}
		if (alreadyImportedLibDF != null) {
			return alreadyImportedLibDF;
		}
		return null;
	}

	private static String appendPath(String... pathStrs) {
		StringBuilder sb = new StringBuilder();
		for (String pathEle : pathStrs) {
			if (pathEle == null || pathEle.isEmpty()) {
				continue;
			}
			boolean sbEndsWithSlash =
				sb.length() > 0 && "/\\".indexOf(sb.charAt(sb.length() - 1)) != -1;
			boolean eleStartsWithSlash = "/\\".indexOf(pathEle.charAt(0)) != -1;

			if (!sbEndsWithSlash && !eleStartsWithSlash && sb.length() > 0) {
				sb.append("/");
			}
			else if (eleStartsWithSlash && sbEndsWithSlash) {
				pathEle = pathEle.substring(1);
			}
			sb.append(pathEle);
		}

		return sb.toString();
	}

	/**
	 * Searches the local filesystem for the specified library file, returning a List
	 * of possible candidate files.
	 * <p>
	 * Each importPath directory will be searched for the library file in order.
	 * <p>
	 * If the library file specifies a path, it is treated as a relative subdirectory of
	 * each importPath directory that is searched, and if not found, the filename part of
	 * the library is used to search just the importPath directory.
	 * <p>
	 * If the library specifies a path, its native path is searched on the local filesystem.
	 * <p>
	 * @param libPathFilename - either a path_and_filename, or just a filename of a library
	 * that should be searched for.
	 * @param importPaths - list of filesystem paths on the local computer that will be
	 * searched.
	 * @return a List of Files (possibly empty, never null) that match the requested filename.
	 */
	private List<File> findLibraryFileToImport(String libPathFilename, List<String> importPaths) {

		String libName = FilenameUtils.getName(libPathFilename);
		List<File> results = new ArrayList<>();

		for (String importPath : importPaths) {

			// ignore garbage importPath entries: relative, non-existent, not directory
			importPath = FilenameUtils.normalizeNoEndSeparator(importPath);
			if (importPath == null || importPath.isEmpty()) {
				continue;
			}
			File importPathDir = new File(importPath);
			if (!importPathDir.isAbsolute() || !importPathDir.isDirectory()) {
				continue;
			}

			// 1) Try as possible subpath under the importPath
			String candidatePath =
				FilenameUtils.separatorsToSystem(appendPath(importPath, libPathFilename));
			File f = resolveLibraryFile(new File(candidatePath));
			if (f == null || !f.isFile()) {
				// 2) Fall back to looking for the library in the user specified importPath, sans any
				// subpath built into the library string.
				f = resolveLibraryFile(new File(importPathDir, libName));
			}
			if (f != null && f.isFile() && !results.contains(f)) {
				results.add(f);
			}
		}

		boolean searchLocalFileSystemAlso = true;
		boolean libSpecifiesPath = FilenameUtils.getPrefixLength(libPathFilename) > 0;
		if (searchLocalFileSystemAlso && libSpecifiesPath) {
			// 3) Search the local filesystem (as if the importPath list contained "/")
			// if the specified library string specifies a path.
			File f = resolveLibraryFile(new File(libPathFilename));
			if (f != null && f.isAbsolute() && f.isFile() && !results.contains(f)) {
				results.add(f);
			}
		}

		return results;
	}

	/**
	 * Imports a library file into a ghidra project.
	 * 
	 * @param libName the name of the library to import
	 * @param libFolder the library folder
	 * @param libFile the library file to load
	 * @param loadSpec the {@link LoadSpec}
	 * @param options the load options
	 * @param log the message log
	 * @param consumer consumer object for the {@link Program} generated
	 * @param unprocessedLibs list of libraries that need to be loaded
	 * @param programList list of programs to add the imported library to
	 * @param monitor the task monitor
	 * @return true if the load was successful
	 * @throws CancelledException if the user cancelled the load operation
	 * @throws IOException if there was an error during the load
	 */
	protected boolean importLibrary(String libName, DomainFolder libFolder, File libFile,
			LoadSpec loadSpec, List<Option> options, MessageLog log, Object consumer,
			Set<String> unprocessedLibs, List<Program> programList, TaskMonitor monitor)
			throws CancelledException, IOException {

		if (!libFile.isFile()) {
			return false;
		}

		try (RandomAccessByteProvider provider = new RandomAccessByteProvider(libFile)) {
			return importLibrary(libName, libFolder, libFile, provider, loadSpec, options, log,
				consumer, unprocessedLibs, programList, monitor);
		}
	}

	/**
	 * Imports a library file into a ghidra project. Use this method if you already have
	 * a {@link ByteProvider} available.
	 * 
	 * @param libName the name of the library to import
	 * @param libFolder the library folder
	 * @param libFile the library file to load
	 * @param provider the byte provider
	 * @param loadSpec the {@link LoadSpec}
	 * @param options the load options
	 * @param log the message log
	 * @param consumer consumer object for the {@link Program} generated
	 * @param unprocessedLibs list of libraries that need to be loaded
	 * @param programList list of programs to add the imported library to
	 * @param monitor the task monitor
	 * @return true if the load was successful
	 * @throws CancelledException if the user cancelled the load operation
	 * @throws IOException if there was an error during the load
	 */
	protected boolean importLibrary(String libName, DomainFolder libFolder, File libFile,
			ByteProvider provider, LoadSpec loadSpec, List<Option> options, MessageLog log,
			Object consumer, Set<String> unprocessedLibs, List<Program> programList,
			TaskMonitor monitor) throws CancelledException, IOException {

		Program lib = null;
		int size = loadSpec.getLanguageCompilerSpec().getLanguageDescription().getSize();

		LoadSpec libLoadSpec = getLoadSpec(loadSpec, provider);
		if (libLoadSpec == null) {
			log.appendMsg("Skipping library which is the wrong architecture: " + libFile);
			return false;
		}
		if (!isLoadLibraries(options)) {
			// TODO: LibraryLookupTable support currently assumes Windows for x86 (32 or 64 bit).
			//       Need to investigate adding support for other architectures
			if (LibraryLookupTable.hasFileAndPathAndTimeStampMatch(libFile, size)) {
				return true;// no need to really import it
			}
			else if (LibraryLookupTable.libraryLookupTableFileExists(libName, size)) {
				log.appendMsg("WARNING! Using existing exports file for " + libName +
					" which may not be an exact match");
				return true;// pretend it was imported to prevent it from giving up the related imports
			}
		}

		lib = doLoad(provider, libName, libFolder, libLoadSpec, options, log, consumer, monitor,
			unprocessedLibs);

		if (lib == null) {
			log.appendMsg("Library " + libFile + " failed to load for some reason");
			return false;
		}

		createExportsFile(libName, libFile, log, monitor, size, lib);

		if (isLoadLibraries(options)) {
			programList.add(lib);
		}
		else {
			lib.release(consumer);
		}

		return true;

	}

	/**
	 * Creates the library exports file, if necessary
	 * 
	 * @param libName the name of the library
	 * @param libFile the library file
	 * @param log the message log
	 * @param monitor the task monitor
	 * @param size the language size
	 * @param program the loaded library program
	 * @throws CancelledException thrown is task cancelled
	 * 
	 */
	protected void createExportsFile(String libName, File libFile, MessageLog log,
			TaskMonitor monitor, int size, Program program) throws CancelledException {

		if (!LibraryLookupTable.libraryLookupTableFileExists(libName, size) ||
			!LibraryLookupTable.hasFileAndPathAndTimeStampMatch(libFile, size)) {
			try {
				// Need to write correct library exports file (LibrarySymbolTable)
				// for use with related imports
				LibraryLookupTable.createFile(program, true, monitor);
			}
			catch (IOException e) {
				log.appendMsg("Unable to create exports file for " + libFile);
				Msg.error(this, "Unable to create exports file for " + libFile, e);
			}
		}
	}

	protected LoadSpec getLoadSpec(LoadSpec loadSpec, ByteProvider provider) throws IOException {
		LanguageCompilerSpecPair pair = loadSpec.getLanguageCompilerSpec();
		Collection<LoadSpec> loadSpecs = findSupportedLoadSpecs(provider);
		if (loadSpecs != null) { // shouldn't be null, but protect against rogue loaders
			for (LoadSpec ls : loadSpecs) {
				if (pair.equals(ls.getLanguageCompilerSpec())) {
					return ls;
				}
			}
		}
		return null;
	}

	/**
	 * Applies the library symbol table to the {@link Program} being loaded. For example, if you 
	 * load "mfc42.dll", it will create the named symbols along with the ordinals.
	 *
	 * @param program The program being loaded.
	 * @param log The message log.
	 * @param monitor A cancelable task monitor.
	 * @throws CancelledException if the user cancelled the load.
	 */
	private void applyLibrarySymbols(Program program, MessageLog log, TaskMonitor monitor)
			throws CancelledException {
		monitor.setMessage("Applying information..." + program.getName());

		// Check based on the original program name, not on the name I gave this program
		int size = program.getLanguage().getLanguageDescription().getSize();

		LibrarySymbolTable symtab = LibraryLookupTable.getSymbolTable(
			new File(program.getExecutablePath()).getName(), size);
		if (symtab == null) {
			// now try based on the name given to the program
			symtab = LibraryLookupTable.getSymbolTable(program.getName(), size);
			if (symtab == null) {
				return;
			}
		}
		if (!isVersionMatch(program, symtab, log)) {
			return;
		}

		SymbolIterator iter =
			program.getSymbolTable().getSymbolIterator(SymbolUtilities.ORDINAL_PREFIX + "*", true);
		while (iter.hasNext()) {
			monitor.checkCanceled();
			Symbol ordSym = iter.next();
			if (!ordSym.getAddress().isMemoryAddress()) {
				continue;
			}
			if (!ordSym.getParentNamespace().equals(program.getGlobalNamespace())) {
				continue;
			}
			int ordinal = SymbolUtilities.getOrdinalValue(ordSym.getName());
			LibraryExportedSymbol les = symtab.getSymbol(ordinal);
			if (les == null || les.getName() == null) {
				continue;
			}
			try {
				Symbol nameSym =
					program.getSymbolTable().getGlobalSymbol(les.getName(), ordSym.getAddress());
				if (nameSym == null) {
					String name = les.getName();
					Symbol s = program.getSymbolTable().createLabel(ordSym.getAddress(), name,
						program.getGlobalNamespace(), SourceType.IMPORTED);
					s.setPrimary();
				}
			}
			catch (InvalidInputException e) {
				log.appendMsg("Error creating label named " + les.getName() + " at address " +
					ordSym.getAddress() + ": " + e.getMessage());
			}
		}
	}

	/**
	 * Applies the library symbol table to the imported symbols of the specified
	 * {@link Program}. Symbols may also be demangled (although this could be a mistake).
	 * 
	 * @param program The {@link Program} whose imports should be resolved.
	 * @param log import message log
	 * @param monitor task monitor, if cancelled partial results may exist
	 */
	private void applyImports(Program program, MessageLog log, TaskMonitor monitor) {
		monitor.setMessage("Applying imports..." + program.getName());

		ReferenceManager rm = program.getReferenceManager();
		ExternalManager em = program.getExternalManager();

		String[] libs = em.getExternalLibraryNames();

		for (String lib : libs) {
			if (monitor.isCancelled()) {
				return;
			}

			int size = program.getLanguage().getLanguageDescription().getSize();

			LibrarySymbolTable symtab = LibraryLookupTable.getSymbolTable(lib, size);

			ExternalReference[] erArray = getExternalReferences(rm, lib);
			for (ExternalReference element : erArray) {
				if (monitor.isCancelled()) {
					return;
				}

				String symName = element.getLabel();

				// this check belongs here, because we want to demangled even
				// if we do not have a symbol table...
				if (symtab == null) {
					continue;
				}

				ExternalLocation extLoc = element.getExternalLocation();

				// if symbol is imported by ordinal, then see if the
				// library contains a name for that ordinal. if so,
				// then rename the symbol

				LibraryExportedSymbol expSym = symtab.getSymbol(symName);
				if (expSym == null) {
					try {
						int ord = SymbolUtilities.getOrdinalValue(symName);
						if (ord == -1) {
							continue;
						}

						expSym = symtab.getSymbol(ord);

						if (expSym == null) {
							log.appendMsg("Unable to locate symbol [" + symName + "] in [" +
								LibraryLookupTable.getExistingExportsFile(lib, size) +
								"]. Please verify the version is correct.");
							continue;
						}

						extLoc.setLocation(expSym.getName(), extLoc.getAddress(),
							SourceType.IMPORTED);
					}
					catch (DuplicateNameException | InvalidInputException e) {
						log.appendMsg("Error creating label: ", e.getMessage());
					}
				}

				Listing listing = program.getListing();
				Data data = listing.getDataAt(element.getFromAddress());

				int purgeSize = expSym.getPurge();
				// no purge size for 64-bit programs
				boolean isNot32Bit = data.getMinAddress().getAddressSpace().getSize() > 32;
				if ((purgeSize == -1 || purgeSize < -1024 || purgeSize > 1024) || isNot32Bit) {
					continue;
				}

				// Create or get external function
				Function extFunc = extLoc.createFunction();

				extFunc.setStackPurgeSize(purgeSize);
				if (expSym.hasNoReturn()) {
					extFunc.setNoReturn(true);
				}
// TODO: This should not be done at time of import and should be done
// by a late running analyzer (e.g., stack analyzer) if no signature
// has been established
//				int stackShift = program.getCompilerSpec().getDefaultCallingConvention().getStackshift();
//				if (stackShift == -1) {
//					stackShift = 0;
//				}

//				int numParams = expSym.getPurge() / 4;
//				if (numParams > 0) {
//					// HACK: assumes specific stack-based x86 convention
//					try {
//						Parameter[] params = new Parameter[numParams];
//						for (int ind = 0; ind < numParams; ind++) {
//							params[ind] = new ParameterImpl(null, Undefined.getUndefinedDataType(4),
//								ind * 4 + stackShift, p);
//						}
//						extFunc.replaceParameters(FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
//							false, SourceType.ANALYSIS, params);
//					}
//					catch (InvalidInputException | DuplicateNameException e) {
//						log.appendMsg("Error creating label: ", e.getMessage());
//					}
//				}

			}
		}
	}

	private static String getRidOfVersionAlias(String version) {
		if (version == null) {
			return null;
		}

		int aliasOpenParenPosition = version.indexOf('(');

		if (aliasOpenParenPosition == -1) {
			return version.trim();
		}

		return version.substring(0, aliasOpenParenPosition).trim();
	}

	private boolean isVersionMatch(DomainObject p, LibrarySymbolTable symtab, MessageLog log) {
		String version = getRidOfVersionAlias(symtab.getVersion());

		Options options = p.getOptions(Program.PROGRAM_INFO);
		String programVersion =
			getRidOfVersionAlias(options.getString("ProductVersion", (String) null));

		if (programVersion == null) {
			return false;
		}

		boolean match = programVersion.equalsIgnoreCase(version);

		if (!match) {
			log.appendMsg("Library version mismatch in .exports file for " + p.getName());
			log.appendMsg("   expected " + programVersion + " but was " + version);
		}
		return match;
	}

	private ExternalReference[] getExternalReferences(ReferenceManager rm, String externalName) {
		ArrayList<ExternalReference> list = new ArrayList<>();
		ReferenceIterator iter = rm.getExternalReferences();
		while (iter.hasNext()) {
			ExternalReference ref = (ExternalReference) iter.next();
			if (ref.getLibraryName().equals(externalName)) {
				list.add(ref);
			}
		}
		ExternalReference[] arr = new ExternalReference[list.size()];
		list.toArray(arr);
		return arr;
	}

	/**
	 * Ensures library files from case-insensitive/case-sensitive OS's are handled correctly.
	 * <p>
	 * For loaders that handle binaries from insensitive OS's (ie. Windows), the supplied
	 * libFile parameter will be searched for in a case-insensitive manner.
	 * <p>
	 * For loaders that handle binaries from sensitive OS's (ie. Linux), the supplied
	 * libFile parameter will be returned unchanged, and the success or failure of matching
	 * the libFile to the actual file on the filesystem will depend on the host OS's
	 * case-sensitivity.
	 * <p>
	 * @param libFile File to match in a OS specific manner
	 * @return Matched File (which may or may not exist on the filesystem) or
	 * null if the file name case is mis-matched or bad.
	 */
	private File resolveLibraryFile(File libFile) {
		if (isCaseInsensitiveLibraryFilenames()) {
			return FileUtilities.resolveFileCaseInsensitive(libFile);
		}

		// For loaders from OS's that are case-sensitive, return the file unchanged.
		// The case-sensitivity of the file matching will depend on the host OS doing the import.
		// If this behavior is found to be undesirable, FileUtilities.resolveFileCaseSensitive()
		// can be used to force libFile to be case sensitive.
		return libFile;
	}
}
