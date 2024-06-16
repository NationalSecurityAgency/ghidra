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
import java.util.Collection;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.framework.model.*;
import ghidra.program.model.listing.Program;
import ghidra.util.SystemUtilities;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.classfinder.ExtensionPoint;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * An interface that all loaders must implement. A particular loader implementation should be 
 * designed to identify one and only one file format.
 * <p>
 * NOTE:  ALL loader CLASSES MUST END IN "Loader".  If not, the {@link ClassSearcher} will not find 
 * them.
 */
public interface Loader extends ExtensionPoint, Comparable<Loader> {

	/**
	 * A string prefixed to each loader headless command line argument to avoid naming conflicts 
	 * with other headless command line argument names
	 */
	public static final String COMMAND_LINE_ARG_PREFIX = "-loader";

	/**
	 * Key used to lookup and store all loader options in the project's saved state
	 */
	public static final String OPTIONS_PROJECT_SAVE_STATE_KEY = "LOADER_OPTIONS";

	/**
	 * System property used to disable the loaders' message logs being echoed to the
	 * application.log file
	 */
	public static boolean loggingDisabled =
		SystemUtilities.getBooleanProperty("disable.loader.logging", false);

	/**
	 * If this {@link Loader} supports loading the given {@link ByteProvider}, this methods returns
	 * a {@link Collection} of all supported {@link LoadSpec}s that contain discovered load 
	 * specification information that this {@link Loader} will need to load.  If this {@link Loader}
	 * cannot support loading the given {@link ByteProvider}, an empty {@link Collection} is
	 * returned.
	 * 
	 * @param provider The bytes being loaded.
	 * @return A {@link Collection} of {@link LoadSpec}s that this {@link Loader} supports loading, 
	 *   or an empty {@link Collection} if this {@link Loader} doesn't support loading the given 
	 *   {@link ByteProvider}.
	 * @throws IOException if there was an IO-related issue finding the {@link LoadSpec}s.
	 */
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException;

	/**
	 * Loads bytes in a particular format as a new {@link Loaded} {@link DomainObject}. Multiple
	 * {@link DomainObject}s may end up getting created, depending on the nature of the format.
	 * The {@link Loaded} {@link DomainObject}s are bundled together in a {@link LoadResults}
	 * object which provides convenience methods to operate on the entire group of {@link Loaded}
	 * {@link DomainObject}s. 
	 * <p>
	 * Note that when the load completes, the returned {@link Loaded} {@link DomainObject}s are not 
	 * saved to a project.  That is the responsibility of the caller (see 
	 * {@link LoadResults#save(Project, Object, MessageLog, TaskMonitor)}).
	 * <p>
	 * It is also the responsibility of the caller to release the returned {@link Loaded} 
	 * {@link DomainObject}s with {@link LoadResults#release(Object)} when they are no longer
	 * needed.
	 *
	 * @param provider The bytes to load.
	 * @param loadedName A suggested name for the primary {@link Loaded} {@link DomainObject}. 
	 *   This is just a suggestion, and a {@link Loader} implementation reserves the right to change
	 *   it. The {@link LoadResults} should be queried for their true names using 
	 *   {@link Loaded#getName()}.
	 * @param project The {@link Project}.  Loaders can use this to take advantage of existing
	 *   {@link DomainFolder}s and {@link DomainFile}s to do custom behaviors such as loading
	 *   libraries. Could be null if there is no project.
	 * @param projectFolderPath A suggested project folder path for the {@link Loaded} 
	 *   {@link DomainObject}s. This is just a suggestion, and a {@link Loader} implementation 
	 *   reserves the right to change it for each {@link Loaded} result. The {@link LoadResults} 
	 *   should be queried for their true project folder paths using 
	 *   {@link Loaded#getProjectFolderPath()}.
	 * @param loadSpec The {@link LoadSpec} to use during load.
	 * @param options The load options.
	 * @param messageLog The message log.
	 * @param consumer A consumer object for generated {@link DomainObject}s.
	 * @param monitor A task monitor.
	 * @return The {@link LoadResults} which contains one or more {@link Loaded} 
	 *   {@link DomainObject}s (created but not saved).
	 * @throws LoadException if the load failed in an expected way
	 * @throws IOException if there was an IO-related problem loading.
	 * @throws CancelledException if the user cancelled the load.
	 * @throws VersionException if the load process tried to open an existing {@link DomainFile} 
	 *   which was created with a newer or unsupported version of Ghidra
	 */
	public LoadResults<? extends DomainObject> load(ByteProvider provider, String loadedName,
			Project project, String projectFolderPath, LoadSpec loadSpec, List<Option> options,
			MessageLog messageLog, Object consumer, TaskMonitor monitor) throws IOException,
			CancelledException, VersionException, LoadException;

	/**
	 * Loads bytes into the specified {@link Program}.  This method will not create any new 
	 * {@link Program}s.  It is only for adding to an existing {@link Program}.
	 *
	 * @param provider The bytes to load into the {@link Program}.
	 * @param loadSpec The {@link LoadSpec} to use during load.
	 * @param options The load options.
	 * @param messageLog The message log.
	 * @param program The {@link Program} to load into.
	 * @param monitor A cancelable task monitor.
	 * @throws LoadException if the load failed in an expected way.
	 * @throws IOException if there was an IO-related problem loading.
	 * @throws CancelledException if the user cancelled the load.
	 */
	public void loadInto(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			MessageLog messageLog, Program program, TaskMonitor monitor)
			throws IOException, LoadException, CancelledException;

	/**
	 * Gets the default {@link Loader} options.
	 * 
	 * @param provider The bytes of the thing being loaded.
	 * @param loadSpec The {@link LoadSpec}.
	 * @param domainObject The {@link DomainObject} being loaded.
	 * @param loadIntoProgram True if the load is adding to an existing {@link DomainObject}; 
	 *   otherwise, false.
	 * @return A list of the {@link Loader}'s default options.
	 */
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram);

	/**
	 * Validates the {@link Loader}'s options and returns null if all options are valid; otherwise, 
	 * an error message describing the problem is returned.
	 * 
	 * @param provider The bytes of the thing being loaded.
	 * @param loadSpec The proposed {@link LoadSpec}.
	 * @param options The list of {@link Option}s to validate.
	 * @param program existing program if the loader is adding to an existing program. If it is
	 * a fresh import, then this will be null. 
	 * @return null if all {@link Option}s are valid; otherwise, an error message describing the 
	 *   problem is returned.
	 */
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program);

	/**
	 * Gets the {@link Loader}'s name, which is used both for display purposes, and to identify the 
	 * {@link Loader} in the opinion files.
	 * 
	 * @return The {@link Loader}'s name.
	 */
	public String getName();

	/**
	 * For ordering purposes; lower tier numbers are more important (and listed
	 * first).
	 *
	 * @return the tier of the loader
	 */
	public LoaderTier getTier();

	/**
	 * For ordering purposes; lower numbers are more important (and listed
	 * first, within its tier).
	 *
	 * @return the ordering of the loader within its tier
	 */
	public int getTierPriority();

	/**
	 * The preferred file name to use when loading.
	 * <p>
	 * The default behavior of this method is to return the (cleaned up) name of the given 
	 *   {@link ByteProvider}.
	 * <p>
	 * NOTE: This method may get called frequently, so only parse the given {@link ByteProvider}
	 * if absolutely necessary.
	 * 
	 * @param provider The bytes to load.
	 * @return The preferred file name to use when loading.
	 */
	public default String getPreferredFileName(ByteProvider provider) {
		FSRL fsrl = provider.getFSRL();
		String name = (fsrl != null) ? fsrl.getName() : provider.getName();
		return name.replaceAll("[\\\\:|]+", "/");
	}

	/**
	 * Checks to see if this {@link Loader} supports loading into an existing {@link Program}.
	 * <p>
	 * The default behavior of this method is to return false.
	 * 
	 * @return True if this {@link Loader} supports loading into an existing {@link Program}; 
	 *   otherwise, false.
	 * @deprecated use {@link #supportsLoadIntoProgram(Program)} instead so you can restrict what
	 *   types of {@link Program}s can get loaded into other types of {@link Program}s
	 */
	@Deprecated(since = "10.4")
	public default boolean supportsLoadIntoProgram() {
		return false;
	}

	/**
	 * Checks to see if this {@link Loader} supports loading into the given {@link Program}.
	 * <p>
	 * The default behavior of this method is to return false.
	 * 
	 * @param program The {@link Program} to load into
	 * @return True if this {@link Loader} supports loading into the given {@link Program}; 
	 *   otherwise, false.
	 */
	public default boolean supportsLoadIntoProgram(Program program) {
		// We don't want to change the behavior of older implementations. They should update their
		// deprecated method usage and put in proper Program-specific checks
		return supportsLoadIntoProgram();
	}

	/**
	 * Checks to see if this {@link Loader} loads into a new {@link DomainFolder} instead of a new
	 * {@link DomainFile}
	 * 
	 * @return True if this {@link Loader} loads into a new {@link DomainFolder} instead of a new
	 *   {@link DomainFile}
	 */
	public default boolean loadsIntoNewFolder() {
		return false;
	}

	@Override
	public default int compareTo(Loader o) {
		int compareTiers = getTier().compareTo(o.getTier());
		if (compareTiers == 0) {
			int comparePriorities = getTierPriority() - o.getTierPriority();
			if (comparePriorities == 0) {
				return getName().compareTo(o.getName());
			}
			return comparePriorities;
		}
		return compareTiers;
	}
}
