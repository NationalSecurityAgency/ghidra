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
package ghidra.app.util.importer;

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.function.Predicate;

import generic.stl.Pair;
import ghidra.app.util.Option;
import ghidra.app.util.bin.*;
import ghidra.app.util.opinion.*;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.framework.model.*;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Used to load (import) a new {@link Program}
 */
public class ProgramLoader {

	/**
	 * Gets a new {@link ProgramLoader} {@link Builder} which can be used to load a new 
	 * {@link Program}
	 * 
	 * @return A new {@link ProgramLoader} {@link Builder} which can be used to load a new 
	 *   {@link Program}
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * A class to configure and perform a {@link Program} load
	 */
	public static class Builder {

		private ByteProvider provider;
		private FSRL fsrl;
		private File file;
		private byte[] bytes;
		private Project project;
		private String projectFolderPath;
		private String importNameOverride;
		private Predicate<Loader> loaderFilter = LoaderService.ACCEPT_ALL;
		private List<Pair<String, String>> loaderArgs = new ArrayList<>();
		private LanguageID languageId;
		private CompilerSpecID compilerSpecId;
		private MessageLog log = new MessageLog();
		private TaskMonitor monitor = TaskMonitor.DUMMY;

		/**
		 * Create a new {@link Builder}. Not intended to be used outside of {@link ProgramLoader}.
		 */
		private Builder() {
			// Prevent public instantiation
		}

		/**
		 * Sets the required import source to the given {@link ByteProvider}.
		 * <p>
		 * NOTE: Any previously defined sources will be overwritten.
		 * <p>
		 * NOTE: Ownership of the given {@link ByteProvider} is not transfered to this 
		 * {@link Builder}, so it is the responsibility of the caller to properly 
		 * {@link ByteProvider#close() close} it when done.
		 * 
		 * @param p The {@link ByteProvider} to import. A {@code null} value will unset the source.
		 * @return This {@link Builder}
		 */
		public Builder source(ByteProvider p) {
			this.provider = p;
			this.fsrl = null;
			this.file = null;
			this.bytes = null;
			return this;
		}

		/**
		 * Sets the required import source to the given {@link FSRL}
		 * <p>
		 * NOTE: Any previously defined sources will be overwritten
		 * 
		 * @param f The {@link FSRL} to import. A {@code null} value will unset the source.
		 * @return This {@link Builder}
		 */
		public Builder source(FSRL f) {
			this.provider = null;
			this.fsrl = f;
			this.file = null;
			this.bytes = null;
			return this;
		}

		/**
		 * Sets the required import source to the given {@link File}
		 * <p>
		 * NOTE: Any previously defined sources will be overwritten
		 * 
		 * @param f The {@link File} to import. A {@code null} value will unset the source.
		 * @return This {@link Builder}
		 */
		public Builder source(File f) {
			this.provider = null;
			this.fsrl = null;
			this.file = f;
			this.bytes = null;
			return this;
		}

		/**
		 * Sets the required import source to the given bytes
		 * <p>
		 * NOTE: {@link #load()} will fail if a {@link #name(String)} is not set
		 * <p>
		 * NOTE: Any previously defined sources will be overwritten
		 * 
		 * @param b The bytes to import. A {@code null} value will unset the source.
		 * @return This {@link Builder}
		 */
		public Builder source(byte[] b) {
			this.provider = null;
			this.fsrl = null;
			this.file = null;
			this.bytes = b;
			return this;
		}

		/**
		 * Sets the required import source to the given filesystem path
		 * <p>
		 * NOTE: Any previously defined sources will be overwritten
		 * 
		 * @param path The filesystem path to import. A {@code null} value will unset the source.
		 * @return This {@link Builder}
		 */
		public Builder source(String path) {
			return source(new File(path));
		}

		/**
		 * Sets the {@link Project}. Loaders can use this to take advantage of existing 
		 * {@link DomainFolder}s and {@link DomainFile}s to do custom behaviors such as loading
		 * libraries.
		 * <p>
		 * By default, no {@link Project} is associated with the {@link ProgramLoader}. 
		 * 
		 * @param p The {@link Project}. A {@code null} value will unset the project.
		 * @return This {@link Builder}
		 */
		public Builder project(Project p) {
			this.project = p;
			return this;
		}

		/**
		 * Sets the suggested project folder path for the {@link Loaded} {@link Program}s. This is 
		 * just a suggestion, and a {@link Loader} implementation reserves the right to change it 
		 * for each {@link Loaded} result. The {@link Loaded} results should be queried for their 
		 * true project folder paths using {@link Loaded#getProjectFolderPath()}.
		 * <p>
		 * The default project folder path is the root of the project ({@code "/"}).
		 * 
		 * @param path The suggested project folder path. A {@code null} value will revert the path
		 *   back to the default value of ({@code "/"}).
		 * @return This {@link Builder}
		 */
		public Builder projectFolderPath(String path) {
			this.projectFolderPath = path;
			return this;
		}

		/**
		 * Sets the name to use for the imported {@link Program}.
		 * <p>
		 * The default is the {@link Loader}'s preferred name.
		 * 
		 * @param name The name to use for the imported {@link Program}. A {@code null} value will
		 *   revert the name to the {@link Loader}'s preferred name.
		 * @return This {@link Builder}
		 */
		public Builder name(String name) {
			this.importNameOverride = name;
			return this;
		}

		/**
		 * Sets the acceptable {@link Loader}s to use during import.
		 * <p>
		 * By default, all {@link Loader}s are accepted ({@link LoaderService#ACCEPT_ALL}).
		 * 
		 * @param filter A filter used to limit the {@link Loader}s used during import. A 
		 *   {@code null} value will revert back to the default ({@link LoaderService#ACCEPT_ALL}).
		 * @return This {@link Builder}
		 */
		public Builder loaders(Predicate<Loader> filter) {
			this.loaderFilter = filter != null ? filter : LoaderService.ACCEPT_ALL;
			return this;
		}

		/**
		 * Sets the acceptable {@link Loader} to use during import.
		 * <p>
		 * By default, all {@link Loader}s are accepted ({@link LoaderService#ACCEPT_ALL}).
		 * 
		 * @param cls The class of the {@link Loader} to use during import. A {@code null} value 
		 *   will revert back to the default ({@link LoaderService#ACCEPT_ALL}).
		 * @return This {@link Builder}
		 */
		public Builder loaders(Class<? extends Loader> cls) {
			this.loaderFilter =
				cls != null ? loader -> loader.getClass().equals(cls) : LoaderService.ACCEPT_ALL;
			return this;
		}

		/**
		 * Sets the acceptable {@link Loader} to use during import.
		 * <p>
		 * By default, all {@link Loader}s are accepted ({@link LoaderService#ACCEPT_ALL}).
		 * 
		 * @param clsName The class name of the {@link Loader} to use during import. A {@code null}
		 *   value will revert back to the default ({@link LoaderService#ACCEPT_ALL}).
		 * @return This {@link Builder}
		 * @throws InvalidInputException if the given loader class name did not correspond to a
		 *   {@link Loader}
		 */
		public Builder loaders(String clsName) throws InvalidInputException {
			Class<? extends Loader> cls = LoaderService.getLoaderClassByName(clsName);
			if (cls == null) {
				throw new InvalidInputException("Loader '%s' does not exist!".formatted(clsName));
			}
			return loaders(cls);
		}
	
		/**
		 * Sets the {@link Loader}s to use during import.
		 * <p>
		 * By default, all {@link Loader}s are accepted ({@link LoaderService#ACCEPT_ALL}).
		 *
		 * @param cls A {@link List} of classes of {@link Loader}s to use during import. A 
		 *   {@code null} value will revert back to the default ({@link LoaderService#ACCEPT_ALL}).
		 * @return This {@link Builder}
		 */
		public Builder loaders(List<Class<? extends Loader>> cls) {
			this.loaderFilter =
				cls != null ? loader -> cls.contains(loader.getClass()) : LoaderService.ACCEPT_ALL;
			return this;
		}
	
		/**
		 * Sets the {@link Loader} arguments to use during import.
		 * <p>
		 * By default, no {@link Loader} arguments are used.
		 * 
		 * @param args A {@link List} of {@link Loader} argument name/value {@link Pair}s to use 
		 *   during import. A {@code null} value will result in no {@link Loader} arguments being
		 *   used.
		 * @return This {@link Builder}
		 */
		public Builder loaderArgs(List<Pair<String, String>> args) {
			this.loaderArgs = args != null ? new ArrayList<>(args) : new ArrayList<>();
			return this;
		}
	
		/**
		 * Adds the given {@link Loader} argument to use during import.
		 * 
		 * @param name A single {@link Loader} argument name to use during import.
		 * @param value The value that corresponds to the argument {@code name}
		 * @return This {@link Builder}
		 */
		public Builder addLoaderArg(String name, String value) {
			this.loaderArgs.add(new Pair<String, String>(name, value));
			return this;
		}

		/**
		 * Sets the language to use during import.
		 * <p>
		 * By default, the first "preferred" language is used.
		 * 
		 * @param id The language id to use during import. A {@code null} value will result in the
		 *   first "preferred" language being used.
		 * @return This {@link Builder}
		 */
		public Builder language(String id) {
			this.languageId = id != null ? new LanguageID(id) : null;
			return this;
		}

		/**
		 * Sets the language to use during import.
		 * <p>
		 * By default, the first "preferred" language is used.
		 * 
		 * @param id The {@link LanguageID} to use during import. A {@code null} value will result 
		 *   in the first "preferred" language being used.
		 * @return This {@link Builder}
		 */
		public Builder language(LanguageID id) {
			this.languageId = id;
			return this;
		}

		/**
		 * Sets the language to use during import.
		 * <p>
		 * By default, the first "preferred" language is used.
		 * 
		 * @param language The {@link Language} to use during import. A {@code null} value will 
		 *   result in the first "preferred" language being used.
		 * @return This {@link Builder}
		 */
		public Builder language(Language language) {
			this.languageId = language != null ? language.getLanguageID() : null;
			return this;
		}

		/**
		 * Sets the compiler to use during import.
		 * <p>
		 * By default, the processor's default compiler is used.
		 * 
		 * @param id The compiler spec id to use during import. A {@code null} value will result in
		 *   the language's default compiler being used.
		 * @return This {@link Builder}
		 */
		public Builder compiler(String id) {
			this.compilerSpecId = id != null ? new CompilerSpecID(id) : null;
			return this;
		}

		/**
		 * Sets the compiler to use during import.
		 * <p>
		 * By default, the processor's default compiler is used.
		 * 
		 * @param id The {@link CompilerSpecID} to use during import. A {@code null} value will 
		 *   result in the language's default compiler being used.
		 * @return This {@link Builder}
		 */
		public Builder compiler(CompilerSpecID id) {
			this.compilerSpecId = id;
			return this;
		}

		/**
		 * Sets the compiler to use during import.
		 * <p>
		 * By default, the processor's default compiler is used.
		 * 
		 * @param cspec The {@link CompilerSpec} to use during import. A {@code null} value will 
		 *   result in the language's default compiler being used.
		 * @return This {@link Builder}
		 */
		public Builder compiler(CompilerSpec cspec) {
			this.compilerSpecId = cspec != null ? cspec.getCompilerSpecID() : null;
			return this;
		}
		
		/**
		 * Sets the {@link MessageLog log} to use during import.
		 * <p>
		 * By default, no log is used.
		 * 
		 * @param messageLog The {@link MessageLog log} to use during import. A {@code null} value
		 *   will result in not logging.
		 * @return This {@link Builder}
		 */
		public Builder log(MessageLog messageLog) {
			this.log = messageLog;
			return this;
		}

		/**
		 * Sets the {@link TaskMonitor} to use during import.
		 * <p>
		 * By default, {@link TaskMonitor#DUMMY} is used.
		 * 
		 * @param mon The {@link TaskMonitor} to use during import. A {@code null} value will result
		 *   in {@link TaskMonitor#DUMMY} being used.
		 * @return This {@link Builder}
		 */
		public Builder monitor(TaskMonitor mon) {
			this.monitor = mon;
			return this;
		}

		/**
		 * Loads the specified {@link #source(ByteProvider) source} with this {@link Builder}'s 
		 * current configuration
		 * 
		 * @return The {@link LoadResults} which contains one or more {@link Loaded} 
		 *   {@link Program}s (created but not saved)
		 * @throws IOException if there was an IO-related problem loading
		 * @throws LanguageNotFoundException if there was a problem getting the language		
		 * @throws CancelledException if the operation was cancelled 
		 * @throws VersionException if there was an issue with database versions, probably due to a 
		 *   failed language upgrade
		 * @throws LoadException if there was a problem loading
		 */
		public LoadResults<Program> load() throws IOException, LanguageNotFoundException,
				CancelledException, VersionException, LoadException {
			return load(this);
		}

		/**
		 * Loads the specified {@link #source(ByteProvider) source} with this {@link Builder}'s 
		 * current configuration.
		 * <p>
		 * NOTE: This method exists to maintain compatibility with the {@link AutoImporter} class,
		 * whose methods require consumer objects to be passed in. It should not be used by clients
		 * (use {@link #load()} instead, which uses a built-in consumer).
		 * 
		 * @param consumer A reference to the object "consuming" the returned {@link LoadResults}, 
		 *   used to ensure the underlying {@link Program}s are only closed when every consumer is 
		 *   done with it (see {@link LoadResults#close()}).
		 * @return The {@link LoadResults} which contains one or more {@link Loaded} 
		 *   {@link Program}s (created but not saved)
		 * @throws IOException if there was an IO-related problem loading
		 * @throws LanguageNotFoundException if there was a problem getting the language		
		 * @throws CancelledException if the operation was cancelled 
		 * @throws VersionException if there was an issue with database versions, probably due to a 
		 *   failed language upgrade
		 * @throws LoadException if there was a problem loading
		 * @deprecated Use {@link #load()} instead
		 */
		@SuppressWarnings("unchecked")
		@Deprecated(since = "12.0", forRemoval = true)
		LoadResults<Program> load(Object consumer) throws IOException, LanguageNotFoundException,
				CancelledException, VersionException, LoadException {
			try (ByteProvider p = getSourceAsProvider()) {

				LoadSpec loadSpec = getLoadSpec(p);
				List<Option> loaderOptions = getLoaderOptions(p, loadSpec);
				String importName = importNameOverride != null ? importNameOverride
						: loadSpec.getLoader().getPreferredFileName(p);

				// Load
				Msg.info(ProgramLoader.class, "Using Loader: " + loadSpec.getLoader().getName());
				Msg.info(ProgramLoader.class,
					"Using Language/Compiler: " + loadSpec.getLanguageCompilerSpec());
				Msg.info(ProgramLoader.class, "Using Library Search Path: " +
					Arrays.toString(LibrarySearchPathManager.getLibraryPaths()));
				LoadResults<? extends DomainObject> loadResults = loadSpec.getLoader()
						.load(p, importName, project, projectFolderPath, loadSpec, loaderOptions,
							log, Objects.requireNonNullElse(consumer, this), monitor);

				// Optionally echo loader message log to application.log
				if (!Loader.loggingDisabled && log.hasMessages()) {
					Msg.info(ProgramLoader.class, "Additional info:\n" + log);
				}

				// Filter out and release non-Programs
				List<Loaded<Program>> loadedPrograms = new ArrayList<>();
				for (Loaded<? extends DomainObject> loaded : loadResults) {
					if (Program.class.isAssignableFrom(loaded.getDomainObjectType())) {
						loadedPrograms.add((Loaded<Program>) loaded);
					}
					else {
						try {
							loaded.close();
						}
						catch (Exception e) {
							throw new IOException(e);
						}
					}
				}
				if (loadedPrograms.isEmpty()) {
					throw new LoadException("Domain objects were loaded, but none were Programs");
				}
				return new LoadResults<>(loadedPrograms);
			}
		}

		/**
		 * Gets this {@link Builder}'s source as a {@link ByteProvider}
		 * <p>
		 * NOTE: The returned {@link ByteProvider} should always be 
		 * {@link ByteProvider#close() closed} by the caller. If this {@link Builder}'s source
		 * originated from a {@link ByteProvider}, the {@link ByteProvider#close()} will be a
		 * no-op. 
		 * 
		 * @return This {@link Builder}'s source as a {@link Byte Provider}
		 * @throws IOException if there was an IO-related problem
		 * @throws LoadException if there was no defined source
		 * @throws CancelledException if the operation was cancelled
		 */
		private ByteProvider getSourceAsProvider()
				throws IOException, LoadException, CancelledException {
			FileSystemService fsService = FileSystemService.getInstance();
			ByteProvider p;
			if (provider != null) {
				p = new ByteProviderWrapper(provider, provider.getFSRL()); // wrap to prevent closing
			}
			else if (fsrl != null) {
				p = fsService.getByteProvider(fsrl, true, monitor);
			}
			else if (file != null) {
				p = fsService.getByteProvider(fsService.getLocalFSRL(file), true, monitor);
			}
			else if (bytes != null) {
				if (importNameOverride == null) {
					throw new LoadException(
						"Byte source does not have a name (was name() called?)");
				}
				p = new ByteArrayProvider(bytes);
			}
			else {
				throw new LoadException("No source to import!");
			}
			return p;
		}

		/**
		 * Gets the {@link LoadSpec} from the given {@link ByteProvider}
		 * 
		 * @param p The {@link ByteProvider}
		 * @return A {@link LoadSpec}
		 * @throws LanguageNotFoundException if there was a problem getting the language
		 * @throws LoadException if a {@link LoadSpec} was not found
		 */
		private LoadSpec getLoadSpec(ByteProvider p)
				throws LanguageNotFoundException, LoadException {
			LoaderMap loaderMap = LoaderService.getSupportedLoadSpecs(p, loaderFilter);
			LoadSpecChooser loadSpecChooser =
				languageId != null ? new LcsHintLoadSpecChooser(languageId, compilerSpecId)
						: (compilerSpecId != null ? new CsHintLoadSpecChooser(compilerSpecId)
								: LoadSpecChooser.CHOOSE_THE_FIRST_PREFERRED);
			LoadSpec loadSpec = loadSpecChooser.choose(loaderMap);
			if (loadSpec == null) {
				String name = Objects.requireNonNullElse(p.getName(), "???");
				Msg.info(ProgramLoader.class, "No load spec found for import file: " + name);
				throw new LoadException("No load spec found");
			}
			return loadSpec;
		}

		/**
		 * Gets the {@link Loader} {@link Option}s, with any loader arguments applied
		 * 
		 * @param p The {@link ByteProvider}
		 * @param loadSpec The {@link LoadSpec}
		 * @return The {@link Loader} {@link Option}s, with any loader arguments applied
		 * @throws LanguageNotFoundException if there was a problem getting the language
		 * @throws LoadException if the {@link Loader} had {@code null} options
		 */
		private List<Option> getLoaderOptions(ByteProvider p, LoadSpec loadSpec)
				throws LanguageNotFoundException, LoadException {
			List<Option> options = loadSpec.getLoader().getDefaultOptions(p, loadSpec, null, false);
			if (options == null) {
				throw new LoadException("Cannot load with null options");
			}

			if (loaderArgs == null) {
				return options;
			}

			LanguageCompilerSpecPair languageCompilerSpecPair =
				loadSpec.getLanguageCompilerSpec();
			AddressFactory addrFactory = null; // Address type options not permitted if null
			if (languageCompilerSpecPair != null) {
				// It is assumed that if languageCompilerSpecPair exists, then language will be found
				addrFactory = DefaultLanguageService.getLanguageService()
						.getLanguage(languageCompilerSpecPair.languageID)
						.getAddressFactory();
			}

			for (Pair<String, String> pair : loaderArgs) {
				String arg = pair.first, val = pair.second;
				boolean foundIt = false;
				for (Option option : options) {
					if (option.getArg() != null && arg.equalsIgnoreCase(option.getArg())) {
						Object oldVal = option.getValue();
						if (option.parseAndSetValueByType(val, addrFactory)) {
							Msg.info(ProgramLoader.class, String.format(
								"Successfully applied \"%s\" to \"%s\" (old: \"%s\", new: \"%s\")",
								arg, option.getName(), oldVal, val));
						}
						else {
							Msg.error(ProgramLoader.class, String.format(
								"Failed to apply \"%s\" to \"%s\" (old: \"%s\", bad: \"%s\")", arg,
								option.getName(), oldVal, val));
							return null;
						}
						foundIt = true;
						break;
					}
				}
				if (!foundIt) {
					Msg.warn(ProgramLoader.class, "Skipping unsupported " + arg + " argument");
				}
			}
			return options;
		}
	}
}
