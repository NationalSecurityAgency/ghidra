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
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

import generic.stl.Pair;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.*;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.framework.model.*;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Utility methods to do {@link Program} imports automatically (without requiring user interaction)
 */
public final class AutoImporter {
	private AutoImporter() {
		// service class; cannot instantiate
	}

	/**
	 * Automatically imports the given {@link File} with the best matching {@link Loader} for the
	 * {@link File}'s format.
	 * <p>
	 * Note that when the import completes, the returned {@link Loaded} {@link Program}s are not 
	 * saved to a project.  That is the responsibility of the caller (see 
	 * {@link LoadResults#save(Project, Object, MessageLog, TaskMonitor)}).
	 * <p>
	 * It is also the responsibility of the caller to release the returned {@link Loaded} 
	 * {@link Program}s with {@link LoadResults#release(Object)} when they are no longer needed.
	 * 
	 * @param file The {@link File} to import
	 * @param project The {@link Project}.  Loaders can use this to take advantage of existing
	 *   {@link DomainFolder}s and {@link DomainFile}s to do custom behaviors such as loading
	 *   libraries. Could be null if there is no project.
	 * @param projectFolderPath A suggested project folder path for the {@link Loaded} 
	 *   {@link Program}s. This is just a suggestion, and a {@link Loader} implementation 
	 *   reserves the right to change it for each {@link Loaded} result. The {@link Loaded} results 
	 *   should be queried for their true project folder paths using 
	 *   {@link Loaded#getProjectFolderPath()}.
	 * @param consumer A consumer
	 * @param messageLog The log
	 * @param monitor A task monitor
	 * @return The {@link LoadResults} which contains one ore more {@link Loaded} {@link Program}s 
	 *   (created but not saved)
	 * @throws IOException if there was an IO-related problem loading
	 * @throws CancelledException if the operation was cancelled 
	 * @throws DuplicateNameException if the load resulted in a {@link Program} naming conflict
	 * @throws InvalidNameException if an invalid {@link Program} name was used during load
	 * @throws VersionException if there was an issue with database versions, probably due to a 
	 *   failed language upgrade
	 * @throws LoadException if nothing was loaded
	 */
	public static LoadResults<Program> importByUsingBestGuess(File file, Project project,
			String projectFolderPath, Object consumer, MessageLog messageLog, TaskMonitor monitor)
			throws IOException, CancelledException, DuplicateNameException, InvalidNameException,
			VersionException, LoadException {
		return importByUsingBestGuess(fileToFsrl(file), project, projectFolderPath, consumer,
			messageLog, monitor);
	}

	/**
	 * Automatically imports the given {@link FSRL} with the best matching {@link Loader} for the
	 * {@link File}'s format.
	 * <p>
	 * Note that when the import completes, the returned {@link Loaded} {@link Program}s are not 
	 * saved to a project.  That is the responsibility of the caller (see 
	 * {@link LoadResults#save(Project, Object, MessageLog, TaskMonitor)}).
	 * <p>
	 * It is also the responsibility of the caller to release the returned {@link Loaded} 
	 * {@link Program}s with {@link LoadResults#release(Object)} when they are no longer needed.
	 * 
	 * @param fsrl The {@link FSRL} to import
	 * @param project The {@link Project}.  Loaders can use this to take advantage of existing
	 *   {@link DomainFolder}s and {@link DomainFile}s to do custom behaviors such as loading
	 *   libraries. Could be null if there is no project.
	 * @param projectFolderPath A suggested project folder path for the {@link Loaded} 
	 *   {@link Program}s. This is just a suggestion, and a {@link Loader} implementation 
	 *   reserves the right to change it for each {@link Loaded} result. The {@link Loaded} results 
	 *   should be queried for their true project folder paths using 
	 *   {@link Loaded#getProjectFolderPath()}.
	 * @param consumer A consumer
	 * @param messageLog The log
	 * @param monitor A task monitor
	 * @return The {@link LoadResults} which contains one ore more {@link Loaded} {@link Program}s 
	 *   (created but not saved)
	 * @throws IOException if there was an IO-related problem loading
	 * @throws CancelledException if the operation was cancelled 
	 * @throws DuplicateNameException if the load resulted in a {@link Program} naming conflict
	 * @throws InvalidNameException if an invalid {@link Program} name was used during load
	 * @throws VersionException if there was an issue with database versions, probably due to a 
	 *   failed language upgrade
	 * @throws LoadException if nothing was loaded
	 */
	public static LoadResults<Program> importByUsingBestGuess(FSRL fsrl, Project project,
			String projectFolderPath, Object consumer, MessageLog messageLog, TaskMonitor monitor)
			throws IOException, CancelledException, DuplicateNameException, InvalidNameException,
			VersionException, LoadException {
		return importFresh(fsrl, project, projectFolderPath, consumer, messageLog, monitor,
			LoaderService.ACCEPT_ALL, LoadSpecChooser.CHOOSE_THE_FIRST_PREFERRED, null,
			OptionChooser.DEFAULT_OPTIONS);
	}

	/**
	 * Automatically imports the give {@link ByteProvider bytes} with the best matching 
	 * {@link Loader} for the {@link ByteProvider}'s format.
	 * <p>
	 * Note that when the import completes, the returned {@link Loaded} {@link Program}s are not 
	 * saved to a project.  That is the responsibility of the caller (see 
	 * {@link LoadResults#save(Project, Object, MessageLog, TaskMonitor)}).
	 * <p>
	 * It is also the responsibility of the caller to release the returned {@link Loaded} 
	 * {@link Program}s with {@link LoadResults#release(Object)} when they are no longer needed.
	 * 
	 * @param provider The bytes to import
	 * @param project The {@link Project}.  Loaders can use this to take advantage of existing
	 *   {@link DomainFolder}s and {@link DomainFile}s to do custom behaviors such as loading
	 *   libraries. Could be null if there is no project.
	 * @param projectFolderPath A suggested project folder path for the {@link Loaded} 
	 *   {@link Program}s. This is just a suggestion, and a {@link Loader} implementation 
	 *   reserves the right to change it for each {@link Loaded} result. The {@link Loaded} results 
	 *   should be queried for their true project folder paths using 
	 *   {@link Loaded#getProjectFolderPath()}.
	 * @param consumer A consumer
	 * @param messageLog The log
	 * @param monitor A task monitor
	 * @return The {@link LoadResults} which contains one ore more {@link Loaded} {@link Program}s 
	 *   (created but not saved)
	 * @throws IOException if there was an IO-related problem loading
	 * @throws CancelledException if the operation was cancelled 
	 * @throws DuplicateNameException if the load resulted in a {@link Program} naming conflict
	 * @throws InvalidNameException if an invalid {@link Program} name was used during load
	 * @throws VersionException if there was an issue with database versions, probably due to a 
	 *   failed language upgrade
	 * @throws LoadException if nothing was loaded
	 */
	public static LoadResults<Program> importByUsingBestGuess(ByteProvider provider,
			Project project, String projectFolderPath, Object consumer, MessageLog messageLog,
			TaskMonitor monitor) throws IOException, CancelledException, DuplicateNameException,
			InvalidNameException, VersionException, LoadException {
		return importFresh(provider, project, projectFolderPath, consumer, messageLog, monitor,
			LoaderService.ACCEPT_ALL, LoadSpecChooser.CHOOSE_THE_FIRST_PREFERRED, null,
			OptionChooser.DEFAULT_OPTIONS);
	}

	/**
	 * Automatically imports the given {@link File} with the given type of {@link Loader}.
	 * <p>
	 * Note that when the import completes, the returned {@link Loaded} {@link Program}s are not 
	 * saved to a project.  That is the responsibility of the caller (see 
	 * {@link LoadResults#save(Project, Object, MessageLog, TaskMonitor)}).
	 * <p>
	 * It is also the responsibility of the caller to release the returned {@link Loaded} 
	 * {@link Program}s with {@link LoadResults#release(Object)} when they are no longer needed.
	 * 
	 * @param file The {@link File} to import
	 * @param project The {@link Project}.  Loaders can use this to take advantage of existing
	 *   {@link DomainFolder}s and {@link DomainFile}s to do custom behaviors such as loading
	 *   libraries. Could be null if there is no project.
	 * @param projectFolderPath A suggested project folder path for the {@link Loaded} 
	 *   {@link Program}s. This is just a suggestion, and a {@link Loader} implementation 
	 *   reserves the right to change it for each {@link Loaded} result. The {@link Loaded} results 
	 *   should be queried for their true project folder paths using 
	 *   {@link Loaded#getProjectFolderPath()}.
	 * @param loaderClass The {@link Loader} class to use
	 * @param loaderArgs A {@link List} of optional {@link Loader}-specific arguments
	 * @param consumer A consumer
	 * @param messageLog The log
	 * @param monitor A task monitor
	 * @return The {@link LoadResults} which contains one ore more {@link Loaded} {@link Program}s 
	 *   (created but not saved)
	 * @throws IOException if there was an IO-related problem loading
	 * @throws CancelledException if the operation was cancelled 
	 * @throws DuplicateNameException if the load resulted in a {@link Program} naming conflict
	 * @throws InvalidNameException if an invalid {@link Program} name was used during load
	 * @throws VersionException if there was an issue with database versions, probably due to a 
	 *   failed language upgrade
	 * @throws LoadException if nothing was loaded
	 */
	public static LoadResults<Program> importByUsingSpecificLoaderClass(File file,
			Project project, String projectFolderPath, Class<? extends Loader> loaderClass,
			List<Pair<String, String>> loaderArgs, Object consumer, MessageLog messageLog,
			TaskMonitor monitor) throws IOException, CancelledException, DuplicateNameException,
			InvalidNameException, VersionException, LoadException {
		return importByUsingSpecificLoaderClass(fileToFsrl(file), project, projectFolderPath,
			loaderClass, loaderArgs, consumer, messageLog, monitor);
	}

	/**
	 * Automatically imports the given {@link FSRL} with the given type of {@link Loader}.
	 * <p>
	 * Note that when the import completes, the returned {@link Loaded} {@link Program}s are not 
	 * saved to a project.  That is the responsibility of the caller (see 
	 * {@link LoadResults#save(Project, Object, MessageLog, TaskMonitor)}).
	 * <p>
	 * It is also the responsibility of the caller to release the returned {@link Loaded} 
	 * {@link Program}s with {@link LoadResults#release(Object)} when they are no longer needed.
	 * 
	 * @param fsrl The {@link FSRL} to import
	 * @param project The {@link Project}.  Loaders can use this to take advantage of existing
	 *   {@link DomainFolder}s and {@link DomainFile}s to do custom behaviors such as loading
	 *   libraries. Could be null if there is no project.
	 * @param projectFolderPath A suggested project folder path for the {@link Loaded} 
	 *   {@link Program}s. This is just a suggestion, and a {@link Loader} implementation 
	 *   reserves the right to change it for each {@link Loaded} result. The {@link Loaded} results 
	 *   should be queried for their true project folder paths using 
	 *   {@link Loaded#getProjectFolderPath()}.
	 * @param loaderClass The {@link Loader} class to use
	 * @param loaderArgs A {@link List} of optional {@link Loader}-specific arguments
	 * @param consumer A consumer
	 * @param messageLog The log
	 * @param monitor A task monitor
	 * @return The {@link LoadResults} which contains one ore more {@link Loaded} {@link Program}s 
	 *   (created but not saved)
	 * @throws IOException if there was an IO-related problem loading
	 * @throws CancelledException if the operation was cancelled 
	 * @throws DuplicateNameException if the load resulted in a {@link Program} naming conflict
	 * @throws InvalidNameException if an invalid {@link Program} name was used during load
	 * @throws VersionException if there was an issue with database versions, probably due to a 
	 *   failed language upgrade
	 * @throws LoadException if nothing was loaded
	 */
	public static LoadResults<Program> importByUsingSpecificLoaderClass(FSRL fsrl, Project project,
			String projectFolderPath, Class<? extends Loader> loaderClass,
			List<Pair<String, String>> loaderArgs, Object consumer, MessageLog messageLog,
			TaskMonitor monitor) throws IOException, CancelledException, DuplicateNameException,
			InvalidNameException, VersionException, LoadException {
		SingleLoaderFilter loaderFilter = new SingleLoaderFilter(loaderClass, loaderArgs);
		return importFresh(fsrl, project, projectFolderPath, consumer, messageLog, monitor,
			loaderFilter, LoadSpecChooser.CHOOSE_THE_FIRST_PREFERRED, null,
			new LoaderArgsOptionChooser(loaderFilter));
	}

	/**
	 * Automatically imports the given {@link File} with the best matching {@link Loader} that
	 * supports the given language and compiler specification.
	 * <p>
	 * Note that when the import completes, the returned {@link Loaded} {@link Program}s are not 
	 * saved to a project.  That is the responsibility of the caller (see 
	 * {@link LoadResults#save(Project, Object, MessageLog, TaskMonitor)}).
	 * <p>
	 * It is also the responsibility of the caller to release the returned {@link Loaded} 
	 * {@link Program}s with {@link LoadResults#release(Object)} when they are no longer needed.
	 * 
	 * @param file The {@link File} to import
	 * @param project The {@link Project}.  Loaders can use this to take advantage of existing
	 *   {@link DomainFolder}s and {@link DomainFile}s to do custom behaviors such as loading
	 *   libraries. Could be null if there is no project.
	 * @param projectFolderPath A suggested project folder path for the {@link Loaded} 
	 *   {@link Program}s. This is just a suggestion, and a {@link Loader} implementation 
	 *   reserves the right to change it for each {@link Loaded} result. The {@link Loaded} results 
	 *   should be queried for their true project folder paths using 
	 *   {@link Loaded#getProjectFolderPath()}.
	 * @param language The desired {@link Language}
	 * @param compilerSpec The desired {@link CompilerSpec compiler specification}
	 * @param consumer A consumer
	 * @param messageLog The log
	 * @param monitor A task monitor
	 * @return The {@link LoadResults} which contains one ore more {@link Loaded} {@link Program}s 
	 *   (created but not saved)
	 * @throws IOException if there was an IO-related problem loading
	 * @throws CancelledException if the operation was cancelled 
	 * @throws DuplicateNameException if the load resulted in a {@link Program} naming conflict
	 * @throws InvalidNameException if an invalid {@link Program} name was used during load
	 * @throws VersionException if there was an issue with database versions, probably due to a 
	 *   failed language upgrade
	 * @throws LoadException if nothing was loaded
	 */
	public static LoadResults<Program> importByLookingForLcs(File file, Project project,
			String projectFolderPath, Language language, CompilerSpec compilerSpec, Object consumer,
			MessageLog messageLog, TaskMonitor monitor) throws IOException, CancelledException,
			DuplicateNameException, InvalidNameException, VersionException, LoadException {
		return importByLookingForLcs(fileToFsrl(file), project, projectFolderPath, language,
			compilerSpec, consumer, messageLog, monitor);
	}

	/**
	 * Automatically imports the given {@link FSRL} with the best matching {@link Loader} that
	 * supports the given language and compiler specification.
	 * <p>
	 * Note that when the import completes, the returned {@link Loaded} {@link Program}s are not 
	 * saved to a project.  That is the responsibility of the caller (see 
	 * {@link LoadResults#save(Project, Object, MessageLog, TaskMonitor)}).
	 * <p>
	 * It is also the responsibility of the caller to release the returned {@link Loaded} 
	 * {@link Program}s with {@link LoadResults#release(Object)} when they are no longer needed.
	 * 
	 * @param fsrl The {@link FSRL} to import
	 * @param project The {@link Project}.  Loaders can use this to take advantage of existing
	 *   {@link DomainFolder}s and {@link DomainFile}s to do custom behaviors such as loading
	 *   libraries. Could be null if there is no project.
	 * @param projectFolderPath A suggested project folder path for the {@link Loaded} 
	 *   {@link Program}s. This is just a suggestion, and a {@link Loader} implementation 
	 *   reserves the right to change it for each {@link Loaded} result. The {@link Loaded} results 
	 *   should be queried for their true project folder paths using 
	 *   {@link Loaded#getProjectFolderPath()}.
	 * @param language The desired {@link Language}
	 * @param compilerSpec The desired {@link CompilerSpec compiler specification}
	 * @param consumer A consumer
	 * @param messageLog The log
	 * @param monitor A task monitor
	 * @return The {@link LoadResults} which contains one ore more {@link Loaded} {@link Program}s 
	 *   (created but not saved)
	 * @throws IOException if there was an IO-related problem loading
	 * @throws CancelledException if the operation was cancelled 
	 * @throws DuplicateNameException if the load resulted in a {@link Program} naming conflict
	 * @throws InvalidNameException if an invalid {@link Program} name was used during load
	 * @throws VersionException if there was an issue with database versions, probably due to a 
	 *   failed language upgrade
	 * @throws LoadException if nothing was loaded
	 */
	public static LoadResults<Program> importByLookingForLcs(FSRL fsrl, Project project,
			String projectFolderPath, Language language, CompilerSpec compilerSpec, Object consumer,
			MessageLog messageLog, TaskMonitor monitor) throws IOException, CancelledException,
			DuplicateNameException, InvalidNameException, VersionException, LoadException {
		return importFresh(fsrl, project, projectFolderPath, consumer, messageLog, monitor,
			LoaderService.ACCEPT_ALL, new LcsHintLoadSpecChooser(language, compilerSpec), null,
			OptionChooser.DEFAULT_OPTIONS);
	}

	/**
	 * Automatically imports the given {@link File} with the given type of {@link Loader}, language,
	 * and compiler specification.
	 * <p>
	 * Note that when the import completes, the returned {@link Loaded} {@link Program}s are not 
	 * saved to a project.  That is the responsibility of the caller (see 
	 * {@link LoadResults#save(Project, Object, MessageLog, TaskMonitor)}).
	 * <p>
	 * It is also the responsibility of the caller to release the returned {@link Loaded} 
	 * {@link Program}s with {@link LoadResults#release(Object)} when they are no longer needed.
	 * 
	 * @param file The {@link File} to import
	 * @param project The {@link Project}.  Loaders can use this to take advantage of existing
	 *   {@link DomainFolder}s and {@link DomainFile}s to do custom behaviors such as loading
	 *   libraries. Could be null if there is no project.
	 * @param projectFolderPath A suggested project folder path for the {@link Loaded} 
	 *   {@link Program}s. This is just a suggestion, and a {@link Loader} implementation 
	 *   reserves the right to change it for each {@link Loaded} result. The {@link Loaded} results 
	 *   should be queried for their true project folder paths using 
	 *   {@link Loaded#getProjectFolderPath()}.
	 * @param loaderClass The {@link Loader} class to use
	 * @param loaderArgs A {@link List} of optional {@link Loader}-specific arguments
	 * @param language The desired {@link Language}
	 * @param compilerSpec The desired {@link CompilerSpec compiler specification}
	 * @param consumer A consumer
	 * @param messageLog The log
	 * @param monitor A task monitor
	 * @return The {@link LoadResults} which contains one ore more {@link Loaded} {@link Program}s 
	 *   (created but not saved)
	 * @throws IOException if there was an IO-related problem loading
	 * @throws CancelledException if the operation was cancelled 
	 * @throws DuplicateNameException if the load resulted in a {@link Program} naming conflict
	 * @throws InvalidNameException if an invalid {@link Program} name was used during load
	 * @throws VersionException if there was an issue with database versions, probably due to a 
	 *   failed language upgrade
	 */
	public static LoadResults<Program> importByUsingSpecificLoaderClassAndLcs(File file,
			Project project, String projectFolderPath, Class<? extends Loader> loaderClass,
			List<Pair<String, String>> loaderArgs, Language language, CompilerSpec compilerSpec,
			Object consumer, MessageLog messageLog, TaskMonitor monitor) throws IOException,
			CancelledException, DuplicateNameException, InvalidNameException, VersionException {
		return importByUsingSpecificLoaderClassAndLcs(fileToFsrl(file), project, projectFolderPath,
			loaderClass, loaderArgs, language, compilerSpec, consumer, messageLog, monitor);
	}

	/**
	 * Automatically imports the given {@link FSRL} with the given type of {@link Loader}, language,
	 * and compiler specification.
	 * <p>
	 * Note that when the import completes, the returned {@link Loaded} {@link Program}s are not 
	 * saved to a project.  That is the responsibility of the caller (see 
	 * {@link LoadResults#save(Project, Object, MessageLog, TaskMonitor)}).
	 * <p>
	 * It is also the responsibility of the caller to release the returned {@link Loaded} 
	 * {@link Program}s with {@link LoadResults#release(Object)} when they are no longer needed.
	 * 
	 * @param fsrl The {@link FSRL} to import
	 * @param project The {@link Project}.  Loaders can use this to take advantage of existing
	 *   {@link DomainFolder}s and {@link DomainFile}s to do custom behaviors such as loading
	 *   libraries. Could be null if there is no project.
	 * @param projectFolderPath A suggested project folder path for the {@link Loaded} 
	 *   {@link Program}s. This is just a suggestion, and a {@link Loader} implementation 
	 *   reserves the right to change it for each {@link Loaded} result. The {@link Loaded} results 
	 *   should be queried for their true project folder paths using 
	 *   {@link Loaded#getProjectFolderPath()}.
	 * @param loaderClass The {@link Loader} class to use
	 * @param loaderArgs A {@link List} of optional {@link Loader}-specific arguments
	 * @param language The desired {@link Language}
	 * @param compilerSpec The desired {@link CompilerSpec compiler specification}
	 * @param consumer A consumer
	 * @param messageLog The log
	 * @param monitor A task monitor
	 * @return The {@link LoadResults} which contains one ore more {@link Loaded} {@link Program}s 
	 *   (created but not saved)
	 * @throws IOException if there was an IO-related problem loading
	 * @throws CancelledException if the operation was cancelled 
	 * @throws DuplicateNameException if the load resulted in a {@link Program} naming conflict
	 * @throws InvalidNameException if an invalid {@link Program} name was used during load
	 * @throws VersionException if there was an issue with database versions, probably due to a 
	 *   failed language upgrade
	 */
	public static LoadResults<Program> importByUsingSpecificLoaderClassAndLcs(FSRL fsrl,
			Project project, String projectFolderPath, Class<? extends Loader> loaderClass,
			List<Pair<String, String>> loaderArgs, Language language, CompilerSpec compilerSpec,
			Object consumer, MessageLog messageLog, TaskMonitor monitor) throws IOException,
			CancelledException, DuplicateNameException, InvalidNameException, VersionException {
		SingleLoaderFilter loaderFilter = new SingleLoaderFilter(loaderClass, loaderArgs);
		return importFresh(fsrl, project, projectFolderPath, consumer, messageLog, monitor,
			loaderFilter, new LcsHintLoadSpecChooser(language, compilerSpec), null,
			new LoaderArgsOptionChooser(loaderFilter));
	}

	private static final Predicate<Loader> BINARY_LOADER =
		new SingleLoaderFilter(BinaryLoader.class);

	/**
	 * Automatically imports the given {@link File} with the {@link BinaryLoader}, using the given
	 * language and compiler specification.
	 * <p>
	 * Note that when the import completes, the returned {@link Loaded} {@link Program} is 
	 * not saved to a project.  That is the responsibility of the caller (see 
	 * {@link Loaded#save(Project, MessageLog, TaskMonitor)}).
	 * <p>
	 * It is also the responsibility of the caller to release the returned {@link Loaded} 
	 * {@link Program} with {@link Loaded#release(Object)} when it is no longer needed.
	 * 
	 * @param file The {@link File} to import
	 * @param project The {@link Project}.  Loaders can use this to take advantage of existing
	 *   {@link DomainFolder}s and {@link DomainFile}s to do custom behaviors such as loading
	 *   libraries. Could be null if there is no project.
	 * @param projectFolderPath A suggested project folder path for the {@link Loaded} 
	 *   {@link Program}. This is just a suggestion, and a {@link Loader} implementation 
	 *   reserves the right to change it for the {@link Loaded} result. The {@link Loaded} result 
	 *   should be queried for its true project folder paths using 
	 *   {@link Loaded#getProjectFolderPath()}.
	 * @param language The desired {@link Language}
	 * @param compilerSpec The desired {@link CompilerSpec compiler specification}
	 * @param consumer A consumer
	 * @param messageLog The log
	 * @param monitor A task monitor
	 * @return The {@link Loaded} {@link Program} (created but not saved)
	 * @throws IOException if there was an IO-related problem loading
	 * @throws CancelledException if the operation was cancelled 
	 * @throws DuplicateNameException if the load resulted in a {@link Program} naming conflict
	 * @throws InvalidNameException if an invalid {@link Program} name was used during load
	 * @throws VersionException if there was an issue with database versions, probably due to a 
	 *   failed language upgrade
	 * @throws LoadException if nothing was loaded
	 */
	public static Loaded<Program> importAsBinary(File file, Project project,
			String projectFolderPath, Language language, CompilerSpec compilerSpec, Object consumer,
			MessageLog messageLog, TaskMonitor monitor) throws IOException, CancelledException,
			DuplicateNameException, InvalidNameException, VersionException, LoadException {
		LoadResults<Program> loadResults = importFresh(file, project, projectFolderPath, consumer,
			messageLog, monitor, BINARY_LOADER, new LcsHintLoadSpecChooser(language, compilerSpec),
			null, OptionChooser.DEFAULT_OPTIONS);
		loadResults.releaseNonPrimary(consumer);
		return loadResults.getPrimary();
	}

	/**
	 * Automatically imports the given {@link ByteProvider} bytes with the {@link BinaryLoader}, 
	 * using the given language and compiler specification.
	 * <p>
	 * Note that when the import completes, the returned {@link Loaded} {@link Program} is 
	 * not saved to a project.  That is the responsibility of the caller (see 
	 * {@link Loaded#save(Project, MessageLog, TaskMonitor)}).
	 * <p>
	 * It is also the responsibility of the caller to release the returned {@link Loaded} 
	 * {@link Program} with {@link Loaded#release(Object)} when it is no longer needed.
	 * 
	 * @param bytes The bytes to import
	 * @param project The {@link Project}.  Loaders can use this to take advantage of existing
	 *   {@link DomainFolder}s and {@link DomainFile}s to do custom behaviors such as loading
	 *   libraries. Could be null if there is no project.
	 * @param projectFolderPath A suggested project folder path for the {@link Loaded} 
	 *   {@link Program}. This is just a suggestion, and a {@link Loader} implementation 
	 *   reserves the right to change it the {@link Loaded} result. The {@link Loaded} result 
	 *   should be queried for its true project folder paths using 
	 *   {@link Loaded#getProjectFolderPath()}.
	 * @param language The desired {@link Language}
	 * @param compilerSpec The desired {@link CompilerSpec compiler specification}
	 * @param consumer A consumer
	 * @param messageLog The log
	 * @param monitor A task monitor
	 * @return The {@link Loaded} {@link Program} (created but not saved)
	 * @throws IOException if there was an IO-related problem loading
	 * @throws CancelledException if the operation was cancelled 
	 * @throws DuplicateNameException if the load resulted in a {@link Program} naming conflict
	 * @throws InvalidNameException if an invalid {@link Program} name was used during load
	 * @throws VersionException if there was an issue with database versions, probably due to a 
	 *   failed language upgrade
	 * @throws LoadException if nothing was loaded
	 */
	public static Loaded<Program> importAsBinary(ByteProvider bytes, Project project,
			String projectFolderPath, Language language, CompilerSpec compilerSpec,
			Object consumer, MessageLog messageLog, TaskMonitor monitor) throws IOException,
			CancelledException, DuplicateNameException, InvalidNameException, VersionException,
			LoadException {
		LoadResults<Program> loadResults = importFresh(bytes, project, projectFolderPath, consumer,
			messageLog, monitor, BINARY_LOADER, new LcsHintLoadSpecChooser(language, compilerSpec),
			null, OptionChooser.DEFAULT_OPTIONS);
		loadResults.releaseNonPrimary(consumer);
		return loadResults.getPrimary();
	}

	/**
	 * Automatically imports the given {@link File} with advanced options.
	 * <p>
	 * Note that when the import completes, the returned {@link Loaded} {@link Program}s are not 
	 * saved to a project.  That is the responsibility of the caller (see 
	 * {@link LoadResults#save(Project, Object, MessageLog, TaskMonitor)}).
	 * <p>
	 * It is also the responsibility of the caller to release the returned {@link Loaded} 
	 * {@link Program}s with {@link LoadResults#release(Object)} when they are no longer needed.
	 * 
	 * @param file The {@link File} to import
	 * @param project The {@link Project}.  Loaders can use this to take advantage of existing
	 *   {@link DomainFolder}s and {@link DomainFile}s to do custom behaviors such as loading
	 *   libraries. Could be null if there is no project.
	 * @param projectFolderPath A suggested project folder path for the {@link Loaded} 
	 *   {@link Program}s. This is just a suggestion, and a {@link Loader} implementation 
	 *   reserves the right to change it for each {@link Loaded} result. The {@link Loaded} results 
	 *   should be queried for their true project folder paths using 
	 *   {@link Loaded#getProjectFolderPath()}.
	 * @param loaderFilter A {@link Predicate} used to choose what {@link Loader}(s) get used
	 * @param loadSpecChooser A {@link LoadSpecChooser} used to choose what {@link LoadSpec}(s) get
	 *   used
	 * @param importNameOverride The name to use for the imported thing.  Null to use the 
	 *   {@link Loader}'s preferred name.
	 * @param optionChooser A {@link OptionChooser} used to choose what {@link Loader} options get
	 *   used
	 * @param consumer A consumer
	 * @param messageLog The log
	 * @param monitor A task monitor
	 * @return The {@link LoadResults} which contains one ore more {@link Loaded} {@link Program}s 
	 *   (created but not saved)
	 * @throws IOException if there was an IO-related problem loading
	 * @throws CancelledException if the operation was cancelled 
	 * @throws DuplicateNameException if the load resulted in a {@link Program} naming conflict
	 * @throws InvalidNameException if an invalid {@link Program} name was used during load
	 * @throws VersionException if there was an issue with database versions, probably due to a 
	 *   failed language upgrade
	 * @throws LoadException if nothing was loaded
	 */
	public static LoadResults<Program> importFresh(File file, Project project,
			String projectFolderPath, Object consumer, MessageLog messageLog, TaskMonitor monitor,
			Predicate<Loader> loaderFilter, LoadSpecChooser loadSpecChooser,
			String importNameOverride, OptionChooser optionChooser) throws IOException,
			CancelledException, DuplicateNameException, InvalidNameException, VersionException,
			LoadException {
		return importFresh(fileToFsrl(file), project, projectFolderPath, consumer, messageLog,
			monitor, loaderFilter, loadSpecChooser, importNameOverride, optionChooser);
	}

	/**
	 * Automatically imports the given {@link FSRL} with advanced options.
	 * <p>
	 * Note that when the import completes, the returned {@link Loaded} {@link Program}s are not 
	 * saved to a project.  That is the responsibility of the caller (see 
	 * {@link LoadResults#save(Project, Object, MessageLog, TaskMonitor)}).
	 * <p>
	 * It is also the responsibility of the caller to release the returned {@link Loaded} 
	 * {@link Program}s with {@link LoadResults#release(Object)} when they are no longer needed.
	 * 
	 * @param fsrl The {@link FSRL} to import
	 * @param project The {@link Project}.  Loaders can use this to take advantage of existing
	 *   {@link DomainFolder}s and {@link DomainFile}s to do custom behaviors such as loading
	 *   libraries. Could be null if there is no project.
	 * @param projectFolderPath A suggested project folder path for the {@link Loaded} 
	 *   {@link Program}s. This is just a suggestion, and a {@link Loader} implementation 
	 *   reserves the right to change it for each {@link Loaded} result. The {@link Loaded} results 
	 *   should be queried for their true project folder paths using 
	 *   {@link Loaded#getProjectFolderPath()}.
	 * @param loaderFilter A {@link Predicate} used to choose what {@link Loader}(s) get used
	 * @param loadSpecChooser A {@link LoadSpecChooser} used to choose what {@link LoadSpec}(s) get
	 *   used
	 * @param importNameOverride The name to use for the imported thing.  Null to use the 
	 *   {@link Loader}'s preferred name.
	 * @param optionChooser A {@link OptionChooser} used to choose what {@link Loader} options get
	 *   used
	 * @param consumer A consumer
	 * @param messageLog The log
	 * @param monitor A task monitor
	 * @return The {@link LoadResults} which contains one ore more {@link Loaded} {@link Program}s 
	 *   (created but not saved)
	 * @throws IOException if there was an IO-related problem loading
	 * @throws CancelledException if the operation was cancelled 
	 * @throws DuplicateNameException if the load resulted in a {@link Program} naming conflict
	 * @throws InvalidNameException if an invalid {@link Program} name was used during load
	 * @throws VersionException if there was an issue with database versions, probably due to a 
	 *   failed language upgrade
	 * @throws LoadException if nothing was loaded
	 */
	public static LoadResults<Program> importFresh(FSRL fsrl, Project project,
			String projectFolderPath, Object consumer, MessageLog messageLog, TaskMonitor monitor,
			Predicate<Loader> loaderFilter, LoadSpecChooser loadSpecChooser,
			String importNameOverride, OptionChooser optionChooser)
			throws IOException, CancelledException, DuplicateNameException, InvalidNameException,
			VersionException, LoadException {
		if (fsrl == null) {
			throw new LoadException("Cannot load null fsrl");
		}

		try (ByteProvider provider =
			FileSystemService.getInstance().getByteProvider(fsrl, true, monitor)) {
			return importFresh(provider, project, projectFolderPath, consumer, messageLog, monitor,
				loaderFilter, loadSpecChooser, importNameOverride, optionChooser);
		}
	}

	/**
	 * Automatically imports the given {@link ByteProvider bytes} with advanced options.
	 * <p>
	 * Note that when the import completes, the returned {@link Loaded} {@link Program}s are not 
	 * saved to a project.  That is the responsibility of the caller (see 
	 * {@link LoadResults#save(Project, Object, MessageLog, TaskMonitor)}).
	 * <p>
	 * It is also the responsibility of the caller to release the returned {@link Loaded} 
	 * {@link Program}s with {@link LoadResults#release(Object)} when they are no longer needed.
	 * 
	 * @param provider The bytes to import
	 * @param project The {@link Project}.  Loaders can use this to take advantage of existing
	 *   {@link DomainFolder}s and {@link DomainFile}s to do custom behaviors such as loading
	 *   libraries. Could be null if there is no project.
	 * @param projectFolderPath A suggested project folder path for the {@link Loaded} 
	 *   {@link Program}s. This is just a suggestion, and a {@link Loader} implementation 
	 *   reserves the right to change it for each {@link Loaded} result. The {@link Loaded} results 
	 *   should be queried for their true project folder paths using 
	 *   {@link Loaded#getProjectFolderPath()}.
	 * @param loaderFilter A {@link Predicate} used to choose what {@link Loader}(s) get used
	 * @param loadSpecChooser A {@link LoadSpecChooser} used to choose what {@link LoadSpec}(s) get
	 *   used
	 * @param importNameOverride The name to use for the imported thing.  Null to use the 
	 *   {@link Loader}'s preferred name.
	 * @param optionChooser A {@link OptionChooser} used to choose what {@link Loader} options get
	 *   used
	 * @param consumer A consumer
	 * @param messageLog The log
	 * @param monitor A task monitor
	 * @return The {@link LoadResults} which contains one ore more {@link Loaded} {@link Program}s 
	 *   (created but not saved)
	 * @throws IOException if there was an IO-related problem loading
	 * @throws CancelledException if the operation was cancelled 
	 * @throws DuplicateNameException if the load resulted in a {@link Program} naming conflict
	 * @throws InvalidNameException if an invalid {@link Program} name was used during load
	 * @throws VersionException if there was an issue with database versions, probably due to a 
	 *   failed language upgrade
	 * @throws LoadException if nothing was loaded
	 */
	public static LoadResults<Program> importFresh(ByteProvider provider, Project project,
			String projectFolderPath, Object consumer, MessageLog messageLog, TaskMonitor monitor,
			Predicate<Loader> loaderFilter, LoadSpecChooser loadSpecChooser,
			String importNameOverride, OptionChooser optionChooser) throws IOException,
			CancelledException, DuplicateNameException, InvalidNameException, VersionException,
			LoadException {

		if (provider == null) {
			throw new LoadException("Cannot load null provider");
		}

		// Get the load spec
		LoadSpec loadSpec = getLoadSpec(loaderFilter, loadSpecChooser, provider);
		if (loadSpec == null) {
			throw new LoadException("No load spec found");
		}

		// Get the preferred import name
		String importName = loadSpec.getLoader().getPreferredFileName(provider);
		if (importNameOverride != null) {
			importName = importNameOverride;
		}

		// Collect options
		LanguageCompilerSpecPair languageCompilerSpecPair = loadSpec.getLanguageCompilerSpec();
		AddressFactory addrFactory = null;// Address type options not permitted if null
		if (languageCompilerSpecPair != null) {
			// It is assumed that if languageCompilerSpecPair exists, then language will be found
			addrFactory = DefaultLanguageService.getLanguageService()
					.getLanguage(
						languageCompilerSpecPair.languageID)
					.getAddressFactory();
		}
		List<Option> loaderOptions = optionChooser.choose(
			loadSpec.getLoader().getDefaultOptions(provider, loadSpec, null, false), addrFactory);
		if (loaderOptions == null) {
			throw new LoadException("Cannot load with null options");
		}

		// Import
		Msg.info(AutoImporter.class, "Using Loader: " + loadSpec.getLoader().getName());
		Msg.info(AutoImporter.class,
			"Using Language/Compiler: " + loadSpec.getLanguageCompilerSpec());
		LoadResults<? extends DomainObject> loadResults = loadSpec.getLoader()
				.load(provider, importName, project, projectFolderPath, loadSpec, loaderOptions,
					messageLog, consumer, monitor);

		// Filter out and release non-Programs
		List<Loaded<Program>> loadedPrograms = new ArrayList<>();
		for (Loaded<? extends DomainObject> loaded : loadResults) {
			if (loaded.getDomainObject() instanceof Program program) {
				loadedPrograms.add(
					new Loaded<Program>(program, loaded.getName(), loaded.getProjectFolderPath()));
			}
			else {
				loaded.release(consumer);
			}
		}
		if (loadedPrograms.isEmpty()) {
			throw new LoadException("Domain objects were loaded, but none were Programs");
		}
		return new LoadResults<>(loadedPrograms);
	}

	private static LoadSpec getLoadSpec(Predicate<Loader> loaderFilter,
			LoadSpecChooser loadSpecChooser, ByteProvider provider) {
		LoaderMap loaderMap = LoaderService.getSupportedLoadSpecs(provider, loaderFilter);

		LoadSpec loadSpec = loadSpecChooser.choose(loaderMap);
		if (loadSpec != null) {
			return loadSpec;
		}

		File f = provider.getFile();
		String name = f != null ? f.getAbsolutePath() : provider.getName();
		Msg.info(AutoImporter.class, "No load spec found for import file: " + name);
		return null;
	}

	/**
	 * Converts a {@link File} to a local file system {@link FSRL}
	 * @param file The {@link File} to convert
	 * @return A {@link FSRL} that represents the given {@link File}
	 * @throws LoadException if the given {@link File} is null
	 */
	private static FSRL fileToFsrl(File file) throws LoadException {
		if (file == null) {
			throw new LoadException("Cannot load null file");
		}
		return FileSystemService.getInstance().getLocalFSRL(file);
	}
}
