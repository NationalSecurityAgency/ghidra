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
import java.util.List;
import java.util.function.Predicate;

import generic.stl.Pair;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.*;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.framework.model.*;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Utility methods to do {@link Program} imports automatically (without requiring user interaction)
 * 
 * @deprecated Use {@link ProgramLoader}
 */
@Deprecated(since = "12.0", forRemoval = true)
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
	 * {@link LoadResults#save(TaskMonitor)}).
	 * <p>
	 * It is also the responsibility of the caller to close the returned {@link Loaded} 
	 * {@link Program}s with {@link LoadResults#close()} when they are no longer needed.
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
	 * @param consumer A reference to the object "consuming" the returned {@link LoadResults}, used
	 *   to ensure the underlying {@link Program}s are only closed when every consumer is done
	 *   with it (see {@link LoadResults#close()}).
	 * @param messageLog The log
	 * @param monitor A task monitor
	 * @return The {@link LoadResults} which contains one or more {@link Loaded} {@link Program}s 
	 *   (created but not saved)
	 * @throws IOException if there was an IO-related problem loading
	 * @throws CancelledException if the operation was cancelled 
	 * @throws DuplicateNameException if the load resulted in a {@link Program} naming conflict
	 * @throws InvalidNameException if an invalid {@link Program} name was used during load
	 * @throws VersionException if there was an issue with database versions, probably due to a 
	 *   failed language upgrade
	 * @throws LoadException if nothing was loaded
	 * @deprecated Use {@link ProgramLoader}
	 */
	@Deprecated(since = "12.0", forRemoval = true)
	public static LoadResults<Program> importByUsingBestGuess(File file, Project project,
			String projectFolderPath, Object consumer, MessageLog messageLog, TaskMonitor monitor)
			throws IOException, CancelledException, DuplicateNameException, InvalidNameException,
			VersionException, LoadException {
		return ProgramLoader.builder()
				.source(file)
				.project(project)
				.projectFolderPath(projectFolderPath)
				.log(messageLog)
				.monitor(monitor)
				.load(consumer);
	}

	/**
	 * Automatically imports the given {@link FSRL} with the best matching {@link Loader} for the
	 * {@link File}'s format.
	 * <p>
	 * Note that when the import completes, the returned {@link Loaded} {@link Program}s are not 
	 * saved to a project.  That is the responsibility of the caller (see 
	 * {@link LoadResults#save(TaskMonitor)}).
	 * <p>
	 * It is also the responsibility of the caller to close the returned {@link Loaded} 
	 * {@link Program}s with {@link LoadResults#close()} when they are no longer needed.
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
	 * @param consumer A reference to the object "consuming" the returned {@link LoadResults}, used
	 *   to ensure the underlying {@link Program}s are only closed when every consumer is done
	 *   with it (see {@link LoadResults#close()}).
	 * @param messageLog The log
	 * @param monitor A task monitor
	 * @return The {@link LoadResults} which contains one or more {@link Loaded} {@link Program}s 
	 *   (created but not saved)
	 * @throws IOException if there was an IO-related problem loading
	 * @throws CancelledException if the operation was cancelled 
	 * @throws DuplicateNameException if the load resulted in a {@link Program} naming conflict
	 * @throws InvalidNameException if an invalid {@link Program} name was used during load
	 * @throws VersionException if there was an issue with database versions, probably due to a 
	 *   failed language upgrade
	 * @throws LoadException if nothing was loaded
	 * @deprecated Use {@link ProgramLoader}
	 */
	@Deprecated(since = "12.0", forRemoval = true)
	public static LoadResults<Program> importByUsingBestGuess(FSRL fsrl, Project project,
			String projectFolderPath, Object consumer, MessageLog messageLog, TaskMonitor monitor)
			throws IOException, CancelledException, DuplicateNameException, InvalidNameException,
			VersionException, LoadException {
		return ProgramLoader.builder()
				.source(fsrl)
				.project(project)
				.projectFolderPath(projectFolderPath)
				.log(messageLog)
				.monitor(monitor)
				.load(consumer);
	}

	/**
	 * Automatically imports the give {@link ByteProvider bytes} with the best matching 
	 * {@link Loader} for the {@link ByteProvider}'s format.
	 * <p>
	 * Note that when the import completes, the returned {@link Loaded} {@link Program}s are not 
	 * saved to a project.  That is the responsibility of the caller (see 
	 * {@link LoadResults#save(TaskMonitor)}).
	 * <p>
	 * It is also the responsibility of the caller to close the returned {@link Loaded} 
	 * {@link Program}s with {@link LoadResults#close()} when they are no longer needed.
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
	 * @param consumer A reference to the object "consuming" the returned {@link LoadResults}, used
	 *   to ensure the underlying {@link Program}s are only closed when every consumer is done
	 *   with it (see {@link LoadResults#close()}).
	 * @param messageLog The log
	 * @param monitor A task monitor
	 * @return The {@link LoadResults} which contains one or more {@link Loaded} {@link Program}s 
	 *   (created but not saved)
	 * @throws IOException if there was an IO-related problem loading
	 * @throws CancelledException if the operation was cancelled 
	 * @throws DuplicateNameException if the load resulted in a {@link Program} naming conflict
	 * @throws InvalidNameException if an invalid {@link Program} name was used during load
	 * @throws VersionException if there was an issue with database versions, probably due to a 
	 *   failed language upgrade
	 * @throws LoadException if nothing was loaded
	 * @deprecated Use {@link ProgramLoader}
	 */
	@Deprecated(since = "12.0", forRemoval = true)
	public static LoadResults<Program> importByUsingBestGuess(ByteProvider provider,
			Project project, String projectFolderPath, Object consumer, MessageLog messageLog,
			TaskMonitor monitor) throws IOException, CancelledException, DuplicateNameException,
			InvalidNameException, VersionException, LoadException {
		return ProgramLoader.builder()
				.source(provider)
				.project(project)
				.projectFolderPath(projectFolderPath)
				.log(messageLog)
				.monitor(monitor)
				.load(consumer);
	}

	/**
	 * Automatically imports the given {@link File} with the given type of {@link Loader}.
	 * <p>
	 * Note that when the import completes, the returned {@link Loaded} {@link Program}s are not 
	 * saved to a project.  That is the responsibility of the caller (see 
	 * {@link LoadResults#save(TaskMonitor)}).
	 * <p>
	 * It is also the responsibility of the caller to close the returned {@link Loaded} 
	 * {@link Program}s with {@link LoadResults#close()} when they are no longer needed.
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
	 * @param consumer A reference to the object "consuming" the returned {@link LoadResults}, used
	 *   to ensure the underlying {@link Program}s are only closed when every consumer is done
	 *   with it (see {@link LoadResults#close()}).
	 * @param messageLog The log
	 * @param monitor A task monitor
	 * @return The {@link LoadResults} which contains one or more {@link Loaded} {@link Program}s 
	 *   (created but not saved)
	 * @throws IOException if there was an IO-related problem loading
	 * @throws CancelledException if the operation was cancelled 
	 * @throws DuplicateNameException if the load resulted in a {@link Program} naming conflict
	 * @throws InvalidNameException if an invalid {@link Program} name was used during load
	 * @throws VersionException if there was an issue with database versions, probably due to a 
	 *   failed language upgrade
	 * @throws LoadException if nothing was loaded
	 * @deprecated Use {@link ProgramLoader}
	 */
	@Deprecated(since = "12.0", forRemoval = true)
	public static LoadResults<Program> importByUsingSpecificLoaderClass(File file,
			Project project, String projectFolderPath, Class<? extends Loader> loaderClass,
			List<Pair<String, String>> loaderArgs, Object consumer, MessageLog messageLog,
			TaskMonitor monitor) throws IOException, CancelledException, DuplicateNameException,
			InvalidNameException, VersionException, LoadException {
		return ProgramLoader.builder()
				.source(file)
				.project(project)
				.projectFolderPath(projectFolderPath)
				.loaders(loaderClass)
				.loaderArgs(loaderArgs)
				.log(messageLog)
				.monitor(monitor)
				.load(consumer);
	}

	/**
	 * Automatically imports the given {@link FSRL} with the given type of {@link Loader}.
	 * <p>
	 * Note that when the import completes, the returned {@link Loaded} {@link Program}s are not 
	 * saved to a project.  That is the responsibility of the caller (see 
	 * {@link LoadResults#save(TaskMonitor)}).
	 * <p>
	 * It is also the responsibility of the caller to close the returned {@link Loaded} 
	 * {@link Program}s with {@link LoadResults#close()} when they are no longer needed.
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
	 * @param consumer A reference to the object "consuming" the returned {@link LoadResults}, used
	 *   to ensure the underlying {@link Program}s are only closed when every consumer is done
	 *   with it (see {@link LoadResults#close()}).
	 * @param messageLog The log
	 * @param monitor A task monitor
	 * @return The {@link LoadResults} which contains one or more {@link Loaded} {@link Program}s 
	 *   (created but not saved)
	 * @throws IOException if there was an IO-related problem loading
	 * @throws CancelledException if the operation was cancelled 
	 * @throws DuplicateNameException if the load resulted in a {@link Program} naming conflict
	 * @throws InvalidNameException if an invalid {@link Program} name was used during load
	 * @throws VersionException if there was an issue with database versions, probably due to a 
	 *   failed language upgrade
	 * @throws LoadException if nothing was loaded
	 * @deprecated Use {@link ProgramLoader}
	 */
	@Deprecated(since = "12.0", forRemoval = true)
	public static LoadResults<Program> importByUsingSpecificLoaderClass(FSRL fsrl, Project project,
			String projectFolderPath, Class<? extends Loader> loaderClass,
			List<Pair<String, String>> loaderArgs, Object consumer, MessageLog messageLog,
			TaskMonitor monitor) throws IOException, CancelledException, DuplicateNameException,
			InvalidNameException, VersionException, LoadException {
		return ProgramLoader.builder()
				.source(fsrl)
				.project(project)
				.projectFolderPath(projectFolderPath)
				.loaders(loaderClass)
				.loaderArgs(loaderArgs)
				.log(messageLog)
				.monitor(monitor)
				.load(consumer);
	}

	/**
	 * Automatically imports the given {@link File} with the best matching {@link Loader} that
	 * supports the given language and compiler specification.
	 * <p>
	 * Note that when the import completes, the returned {@link Loaded} {@link Program}s are not 
	 * saved to a project.  That is the responsibility of the caller (see 
	 * {@link LoadResults#save(TaskMonitor)}).
	 * <p>
	 * It is also the responsibility of the caller to close the returned {@link Loaded} 
	 * {@link Program}s with {@link LoadResults#close()} when they are no longer needed.
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
	 * @param consumer A reference to the object "consuming" the returned {@link LoadResults}, used
	 *   to ensure the underlying {@link Program}s are only closed when every consumer is done
	 *   with it (see {@link LoadResults#close()}).
	 * @param messageLog The log
	 * @param monitor A task monitor
	 * @return The {@link LoadResults} which contains one or more {@link Loaded} {@link Program}s 
	 *   (created but not saved)
	 * @throws IOException if there was an IO-related problem loading
	 * @throws CancelledException if the operation was cancelled 
	 * @throws DuplicateNameException if the load resulted in a {@link Program} naming conflict
	 * @throws InvalidNameException if an invalid {@link Program} name was used during load
	 * @throws VersionException if there was an issue with database versions, probably due to a 
	 *   failed language upgrade
	 * @throws LoadException if nothing was loaded
	 * @deprecated Use {@link ProgramLoader}
	 */
	@Deprecated(since = "12.0", forRemoval = true)
	public static LoadResults<Program> importByLookingForLcs(File file, Project project,
			String projectFolderPath, Language language, CompilerSpec compilerSpec, Object consumer,
			MessageLog messageLog, TaskMonitor monitor) throws IOException, CancelledException,
			DuplicateNameException, InvalidNameException, VersionException, LoadException {
		return ProgramLoader.builder()
				.source(file)
				.project(project)
				.projectFolderPath(projectFolderPath)
				.language(language)
				.compiler(compilerSpec)
				.log(messageLog)
				.monitor(monitor)
				.load(consumer);
	}

	/**
	 * Automatically imports the given {@link FSRL} with the best matching {@link Loader} that
	 * supports the given language and compiler specification.
	 * <p>
	 * Note that when the import completes, the returned {@link Loaded} {@link Program}s are not 
	 * saved to a project.  That is the responsibility of the caller (see 
	 * {@link LoadResults#save(TaskMonitor)}).
	 * <p>
	 * It is also the responsibility of the caller to close the returned {@link Loaded} 
	 * {@link Program}s with {@link LoadResults#close()} when they are no longer needed.
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
	 * @param consumer A reference to the object "consuming" the returned {@link LoadResults}, used
	 *   to ensure the underlying {@link Program}s are only closed when every consumer is done
	 *   with it (see {@link LoadResults#close()}).
	 * @param messageLog The log
	 * @param monitor A task monitor
	 * @return The {@link LoadResults} which contains one or more {@link Loaded} {@link Program}s 
	 *   (created but not saved)
	 * @throws IOException if there was an IO-related problem loading
	 * @throws CancelledException if the operation was cancelled 
	 * @throws DuplicateNameException if the load resulted in a {@link Program} naming conflict
	 * @throws InvalidNameException if an invalid {@link Program} name was used during load
	 * @throws VersionException if there was an issue with database versions, probably due to a 
	 *   failed language upgrade
	 * @throws LoadException if nothing was loaded
	 * @deprecated Use {@link ProgramLoader}
	 */
	@Deprecated(since = "12.0", forRemoval = true)
	public static LoadResults<Program> importByLookingForLcs(FSRL fsrl, Project project,
			String projectFolderPath, Language language, CompilerSpec compilerSpec, Object consumer,
			MessageLog messageLog, TaskMonitor monitor) throws IOException, CancelledException,
			DuplicateNameException, InvalidNameException, VersionException, LoadException {
		return ProgramLoader.builder()
				.source(fsrl)
				.project(project)
				.projectFolderPath(projectFolderPath)
				.language(language)
				.compiler(compilerSpec)
				.log(messageLog)
				.monitor(monitor)
				.load(consumer);
	}

	/**
	 * Automatically imports the given {@link File} with the given type of {@link Loader}, language,
	 * and compiler specification.
	 * <p>
	 * Note that when the import completes, the returned {@link Loaded} {@link Program}s are not 
	 * saved to a project.  That is the responsibility of the caller (see 
	 * {@link LoadResults#save(TaskMonitor)}).
	 * <p>
	 * It is also the responsibility of the caller to close the returned {@link Loaded} 
	 * {@link Program}s with {@link LoadResults#close()} when they are no longer needed.
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
	 * @param consumer A reference to the object "consuming" the returned {@link LoadResults}, used
	 *   to ensure the underlying {@link Program}s are only closed when every consumer is done
	 *   with it (see {@link LoadResults#close()}).
	 * @param messageLog The log
	 * @param monitor A task monitor
	 * @return The {@link LoadResults} which contains one or more {@link Loaded} {@link Program}s 
	 *   (created but not saved)
	 * @throws IOException if there was an IO-related problem loading
	 * @throws CancelledException if the operation was cancelled 
	 * @throws DuplicateNameException if the load resulted in a {@link Program} naming conflict
	 * @throws InvalidNameException if an invalid {@link Program} name was used during load
	 * @throws VersionException if there was an issue with database versions, probably due to a 
	 *   failed language upgrade
	 * @deprecated Use {@link ProgramLoader}
	 */
	@Deprecated(since = "12.0", forRemoval = true)
	public static LoadResults<Program> importByUsingSpecificLoaderClassAndLcs(File file,
			Project project, String projectFolderPath, Class<? extends Loader> loaderClass,
			List<Pair<String, String>> loaderArgs, Language language, CompilerSpec compilerSpec,
			Object consumer, MessageLog messageLog, TaskMonitor monitor) throws IOException,
			CancelledException, DuplicateNameException, InvalidNameException, VersionException {
		return ProgramLoader.builder()
				.source(file)
				.project(project)
				.projectFolderPath(projectFolderPath)
				.loaders(loaderClass)
				.loaderArgs(loaderArgs)
				.language(language)
				.compiler(compilerSpec)
				.log(messageLog)
				.monitor(monitor)
				.load(consumer);
	}

	/**
	 * Automatically imports the given {@link FSRL} with the given type of {@link Loader}, language,
	 * and compiler specification.
	 * <p>
	 * Note that when the import completes, the returned {@link Loaded} {@link Program}s are not 
	 * saved to a project.  That is the responsibility of the caller (see 
	 * {@link LoadResults#save(TaskMonitor)}).
	 * <p>
	 * It is also the responsibility of the caller to close the returned {@link Loaded} 
	 * {@link Program}s with {@link LoadResults#close()} when they are no longer needed.
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
	 * @param consumer A reference to the object "consuming" the returned {@link LoadResults}, used
	 *   to ensure the underlying {@link Program}s are only closed when every consumer is done
	 *   with it (see {@link LoadResults#close()}).
	 * @param messageLog The log
	 * @param monitor A task monitor
	 * @return The {@link LoadResults} which contains one or more {@link Loaded} {@link Program}s 
	 *   (created but not saved)
	 * @throws IOException if there was an IO-related problem loading
	 * @throws CancelledException if the operation was cancelled 
	 * @throws DuplicateNameException if the load resulted in a {@link Program} naming conflict
	 * @throws InvalidNameException if an invalid {@link Program} name was used during load
	 * @throws VersionException if there was an issue with database versions, probably due to a 
	 *   failed language upgrade
	 * @deprecated Use {@link ProgramLoader}
	 */
	@Deprecated(since = "12.0", forRemoval = true)
	public static LoadResults<Program> importByUsingSpecificLoaderClassAndLcs(FSRL fsrl,
			Project project, String projectFolderPath, Class<? extends Loader> loaderClass,
			List<Pair<String, String>> loaderArgs, Language language, CompilerSpec compilerSpec,
			Object consumer, MessageLog messageLog, TaskMonitor monitor) throws IOException,
			CancelledException, DuplicateNameException, InvalidNameException, VersionException {
		return ProgramLoader.builder()
				.source(fsrl)
				.project(project)
				.projectFolderPath(projectFolderPath)
				.loaders(loaderClass)
				.loaderArgs(loaderArgs)
				.language(language)
				.compiler(compilerSpec)
				.log(messageLog)
				.monitor(monitor)
				.load(consumer);
	}

	/**
	 * Automatically imports the given {@link File} with the {@link BinaryLoader}, using the given
	 * language and compiler specification.
	 * <p>
	 * Note that when the import completes, the returned {@link Loaded} {@link Program} is 
	 * not saved to a project.  That is the responsibility of the caller (see 
	 * {@link Loaded#save(TaskMonitor)}).
	 * <p>
	 * It is also the responsibility of the caller to close the returned {@link Loaded} 
	 * {@link Program} with {@link Loaded#close()} when it is no longer needed.
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
	 * @param consumer A reference to the object "consuming" the returned {@link Loaded} 
	 *   {@link Program}, used to ensure the underlying {@link Program} is only closed when every 
	 *   consumer is done with it (see {@link Loaded#close()}).
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
	 * @deprecated Use {@link ProgramLoader}
	 */
	@Deprecated(since = "12.0", forRemoval = true)
	public static Loaded<Program> importAsBinary(File file, Project project,
			String projectFolderPath, Language language, CompilerSpec compilerSpec, Object consumer,
			MessageLog messageLog, TaskMonitor monitor) throws IOException, CancelledException,
			DuplicateNameException, InvalidNameException, VersionException, LoadException {
		LoadResults<Program> loadResults = ProgramLoader.builder()
				.source(file)
				.project(project)
				.projectFolderPath(projectFolderPath)
				.loaders(BinaryLoader.class)
				.language(language)
				.compiler(compilerSpec)
				.log(messageLog)
				.monitor(monitor)
				.load(consumer);
		loadResults.getNonPrimary().forEach(Loaded::close);
		return loadResults.getPrimary();
	}

	/**
	 * Automatically imports the given {@link ByteProvider} bytes with the {@link BinaryLoader}, 
	 * using the given language and compiler specification.
	 * <p>
	 * Note that when the import completes, the returned {@link Loaded} {@link Program} is 
	 * not saved to a project.  That is the responsibility of the caller (see 
	 * {@link Loaded#save(TaskMonitor)}).
	 * <p>
	 * It is also the responsibility of the caller to close the returned {@link Loaded} 
	 * {@link Program} with {@link Loaded#close()} when it is no longer needed.
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
	 * @param consumer A reference to the object "consuming" the returned {@link Loaded} 
	 *   {@link Program}, used to ensure the underlying {@link Program} is only closed when every 
	 *   consumer is done with it (see {@link Loaded#close()}).
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
	 * @deprecated Use {@link ProgramLoader}
	 */
	@Deprecated(since = "12.0", forRemoval = true)
	public static Loaded<Program> importAsBinary(ByteProvider bytes, Project project,
			String projectFolderPath, Language language, CompilerSpec compilerSpec,
			Object consumer, MessageLog messageLog, TaskMonitor monitor) throws IOException,
			CancelledException, DuplicateNameException, InvalidNameException, VersionException,
			LoadException {
		LoadResults<Program> loadResults = ProgramLoader.builder()
				.source(bytes)
				.project(project)
				.projectFolderPath(projectFolderPath)
				.loaders(BinaryLoader.class)
				.language(language)
				.compiler(compilerSpec)
				.log(messageLog)
				.monitor(monitor)
				.load(consumer);
		loadResults.getNonPrimary().forEach(Loaded::close);
		return loadResults.getPrimary();
	}

	/**
	 * Automatically imports the given {@link File} with advanced options.
	 * <p>
	 * Note that when the import completes, the returned {@link Loaded} {@link Program}s are not 
	 * saved to a project.  That is the responsibility of the caller (see 
	 * {@link LoadResults#save(TaskMonitor)}).
	 * <p>
	 * It is also the responsibility of the caller to release the returned {@link Loaded} 
	 * {@link Program}s with {@link LoadResults#close()} when they are no longer needed.
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
	 * @param consumer A reference to the object "consuming" the returned {@link LoadResults}, used
	 *   to ensure the underlying {@link Program}s are only closed when every consumer is done
	 *   with it (see {@link LoadResults#close()}).
	 * @param messageLog The log
	 * @param monitor A task monitor
	 * @return The {@link LoadResults} which contains one or more {@link Loaded} {@link Program}s 
	 *   (created but not saved)
	 * @throws IOException if there was an IO-related problem loading
	 * @throws CancelledException if the operation was cancelled 
	 * @throws DuplicateNameException if the load resulted in a {@link Program} naming conflict
	 * @throws InvalidNameException if an invalid {@link Program} name was used during load
	 * @throws VersionException if there was an issue with database versions, probably due to a 
	 *   failed language upgrade
	 * @throws LoadException if nothing was loaded
	 * @deprecated Use {@link ProgramLoader}
	 */
	@Deprecated(since = "12.0", forRemoval = true)
	public static LoadResults<Program> importFresh(File file, Project project,
			String projectFolderPath, Object consumer, MessageLog messageLog, TaskMonitor monitor,
			Predicate<Loader> loaderFilter, LoadSpecChooser loadSpecChooser,
			String importNameOverride, OptionChooser optionChooser) throws IOException,
			CancelledException, DuplicateNameException, InvalidNameException, VersionException,
			LoadException {
		return ProgramLoader.builder()
				.source(file)
				.project(project)
				.projectFolderPath(projectFolderPath)
				.name(importNameOverride)
				.loaders(loaderFilter)
				.loaderArgs(optionChooser.getArgs())
				.language(loadSpecChooser.getLanguageId())
				.compiler(loadSpecChooser.getCompilerSpecId())
				.log(messageLog)
				.monitor(monitor)
				.load(consumer);
	}

	/**
	 * Automatically imports the given {@link FSRL} with advanced options.
	 * <p>
	 * Note that when the import completes, the returned {@link Loaded} {@link Program}s are not 
	 * saved to a project.  That is the responsibility of the caller (see 
	 * {@link LoadResults#save(TaskMonitor)}).
	 * <p>
	 * It is also the responsibility of the caller to release the returned {@link Loaded} 
	 * {@link Program}s with {@link LoadResults#close()} when they are no longer needed.
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
	 * @param consumer A reference to the object "consuming" the returned {@link LoadResults}, used
	 *   to ensure the underlying {@link Program}s are only closed when every consumer is done
	 *   with it (see {@link LoadResults#close()}).
	 * @param messageLog The log
	 * @param monitor A task monitor
	 * @return The {@link LoadResults} which contains one or more {@link Loaded} {@link Program}s 
	 *   (created but not saved)
	 * @throws IOException if there was an IO-related problem loading
	 * @throws CancelledException if the operation was cancelled 
	 * @throws DuplicateNameException if the load resulted in a {@link Program} naming conflict
	 * @throws InvalidNameException if an invalid {@link Program} name was used during load
	 * @throws VersionException if there was an issue with database versions, probably due to a 
	 *   failed language upgrade
	 * @throws LoadException if nothing was loaded
	 * @deprecated Use {@link ProgramLoader}
	 */
	@Deprecated(since = "12.0", forRemoval = true)
	public static LoadResults<Program> importFresh(FSRL fsrl, Project project,
			String projectFolderPath, Object consumer, MessageLog messageLog, TaskMonitor monitor,
			Predicate<Loader> loaderFilter, LoadSpecChooser loadSpecChooser,
			String importNameOverride, OptionChooser optionChooser)
			throws IOException, CancelledException, DuplicateNameException, InvalidNameException,
			VersionException, LoadException {
		return ProgramLoader.builder()
				.source(fsrl)
				.project(project)
				.projectFolderPath(projectFolderPath)
				.name(importNameOverride)
				.loaders(loaderFilter)
				.loaderArgs(optionChooser.getArgs())
				.language(loadSpecChooser.getLanguageId())
				.compiler(loadSpecChooser.getCompilerSpecId())
				.log(messageLog)
				.monitor(monitor)
				.load(consumer);
	}

	/**
	 * Automatically imports the given {@link ByteProvider bytes} with advanced options.
	 * <p>
	 * Note that when the import completes, the returned {@link Loaded} {@link Program}s are not 
	 * saved to a project.  That is the responsibility of the caller (see 
	 * {@link LoadResults#save(TaskMonitor)}).
	 * <p>
	 * It is also the responsibility of the caller to release the returned {@link Loaded} 
	 * {@link Program}s with {@link LoadResults#close()} when they are no longer needed.
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
	 * @param consumer A reference to the object "consuming" the returned {@link LoadResults}, used
	 *   to ensure the underlying {@link Program}s are only closed when every consumer is done
	 *   with it (see {@link LoadResults#close()}).
	 * @param messageLog The log
	 * @param monitor A task monitor
	 * @return The {@link LoadResults} which contains one or more {@link Loaded} {@link Program}s 
	 *   (created but not saved)
	 * @throws IOException if there was an IO-related problem loading
	 * @throws CancelledException if the operation was cancelled 
	 * @throws DuplicateNameException if the load resulted in a {@link Program} naming conflict
	 * @throws InvalidNameException if an invalid {@link Program} name was used during load
	 * @throws VersionException if there was an issue with database versions, probably due to a 
	 *   failed language upgrade
	 * @throws LoadException if nothing was loaded
	 * @deprecated Use {@link ProgramLoader}
	 */
	@Deprecated(since = "12.0", forRemoval = true)
	public static LoadResults<Program> importFresh(ByteProvider provider, Project project,
			String projectFolderPath, Object consumer, MessageLog messageLog, TaskMonitor monitor,
			Predicate<Loader> loaderFilter, LoadSpecChooser loadSpecChooser,
			String importNameOverride, OptionChooser optionChooser) throws IOException,
			CancelledException, DuplicateNameException, InvalidNameException, VersionException,
			LoadException {
		return ProgramLoader.builder()
				.source(provider)
				.project(project)
				.projectFolderPath(projectFolderPath)
				.name(importNameOverride)
				.loaders(loaderFilter)
				.loaderArgs(optionChooser.getArgs())
				.language(loadSpecChooser.getLanguageId())
				.compiler(loadSpecChooser.getCompilerSpecId())
				.log(messageLog)
				.monitor(monitor)
				.load(consumer);
	}
}
