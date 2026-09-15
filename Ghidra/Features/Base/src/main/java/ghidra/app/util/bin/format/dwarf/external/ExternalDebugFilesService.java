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
package ghidra.app.util.bin.format.dwarf.external;

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import ghidra.app.util.bin.format.dwarf.external.DebugStreamProvider.StreamInfo;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A collection of {@link DebugFileProvider providers} that can be queried to find a
 * DWARF external debug file.  Typically this will be an ELF binary that contains the debug
 * information that was stripped from the original ELF binary, but can also include ability
 * to fetch original binaries as well as source files.
 */
public class ExternalDebugFilesService {
	private static final String EXT_DEBUG_FILES_OPTION = "ExternalDebugFiles";
	private static final String STORAGE_OPTION = EXT_DEBUG_FILES_OPTION + ".storage";
	private static final String PROVIDERS_OPTION = EXT_DEBUG_FILES_OPTION + ".providers";

	private final DebugFileStorage storage;
	private List<DebugInfoProvider> providers = new ArrayList<>();

	/**
	 * Creates a new instance using a {@link DebugFileStorage}, and a list of providers.
	 * 
	 * @param storage {@link DebugFileStorage} 
	 * @param providers list of {@link DebugFileProvider providers} to search
	 */
	public ExternalDebugFilesService(DebugFileStorage storage, List<DebugInfoProvider> providers) {
		Objects.requireNonNull(storage);
		this.storage = storage;
		this.providers.add(storage);
		this.providers.addAll(providers);
	}

	public DebugFileStorage getStorage() {
		return storage;
	}

	/**
	 * Returns the configured providers.
	 * 
	 * @return list of providers
	 */
	public List<DebugInfoProvider> getProviders() {
		return List.copyOf(providers.subList(1, providers.size()));
	}

	/**
	 * Adds a {@link DebugInfoProvider} as a location to search.
	 * 
	 * @param provider {@link DebugInfoProvider} to add
	 */
	public void addProvider(DebugInfoProvider provider) {
		providers.add(provider);
	}

	/**
	 * Searches for the specified external debug file.
	 * 
	 * @param debugInfo information about the external debug file
	 * @param monitor {@link TaskMonitor}
	 * @return found file, or {@code null} if not found
	 * @throws IOException if error
	 */
	public File find(ExternalDebugInfo debugInfo, TaskMonitor monitor) throws IOException {
		try {
			for (DebugInfoProvider provider : providers) {
				monitor.checkCancelled();
				File result = null;
				if (provider instanceof DebugFileProvider fileProvider) {
					result = fileProvider.getFile(debugInfo, monitor);
				}
				else if (provider instanceof DebugStreamProvider streamProvider) {
					StreamInfo stream = streamProvider.getStream(debugInfo, monitor);
					if (stream != null) {
						result = storage.putStream(debugInfo, stream, monitor);
					}
				}
				if (result != null) {
					return result;
				}
			}
		}
		catch (CancelledException ce) {
			// fall thru, return null
		}
		return null;
	}

	//----------------------------------------
	/**
	 * {@return an ExternalDebugFilesService instance with no additional search locations}
	 */
	public static ExternalDebugFilesService getMinimal() {
		return new ExternalDebugFilesService(LocalDirDebugInfoDProvider.getGhidraCacheInstance(),
			List.of());
	}

	/**
	 * {@return an ExternalDebugFilesService instance with default search locations}
	 */
	public static ExternalDebugFilesService getDefault() {
		return new ExternalDebugFilesService(LocalDirDebugInfoDProvider.getGhidraCacheInstance(),
			List.of(new SameDirDebugInfoProvider(null),
				LocalDirDebugInfoDProvider.getUserHomeCacheInstance()));
	}

	/**
	 * Get a new instance of {@link ExternalDebugFilesService} using the previously saved 
	 * information (via {@link #saveToPrefs(ExternalDebugFilesService)}), for the specified program.
	 * 
	 * @param program {@link Program}
	 * @return new {@link ExternalDebugFilesService} instance
	 */
	public static ExternalDebugFilesService forProgram(Program program) {
		return fromPrefs(DebugInfoProviderRegistry.getInstance().newContext(program));
	}

	/**
	 * Get a new instance of {@link ExternalDebugFilesService} using the previously saved 
	 * information (via {@link #saveToPrefs(ExternalDebugFilesService)}).
	 *  
	 * @param context created via {@link DebugInfoProviderRegistry#newContext(ghidra.program.model.listing.Program)}
	 * @return new {@link ExternalDebugFilesService} instance
	 */
	public static ExternalDebugFilesService fromPrefs(DebugInfoProviderCreatorContext context) {
		DebugInfoProviderRegistry registry = DebugInfoProviderRegistry.getInstance();
		
		String storageStr = Preferences.getProperty(STORAGE_OPTION, "", true);
		DebugFileStorage storage = null;
		if ( storageStr != null ) {
			DebugInfoProvider storageProvider = registry.create(storageStr, context);
			storage = (storageProvider instanceof DebugFileStorage dfs) ? dfs : null;
		}
		if ( storage == null ) {
			storage = LocalDirDebugInfoDProvider.getGhidraCacheInstance();
		}
		
		String providersStr = Preferences.getProperty(PROVIDERS_OPTION, "", true);
		String[] providerNames = providersStr.split(";");
		List<DebugInfoProvider> providers = new ArrayList<>();
		for (String providerName : providerNames) {
			if (!providerName.isBlank()) {
				DebugInfoProvider provider = registry.create(providerName, context);
				if (provider != null) {
					providers.add(provider);
				}
			}
		}
		if (providers.isEmpty()) {
			// default to search the same directory as the program
			providers.add(SameDirDebugInfoProvider.create(null, context));
			providers.add(LocalDirDebugInfoDProvider.getUserHomeCacheInstance());
		}

		return new ExternalDebugFilesService(storage, providers);
	}

	/**
	 * Serializes an {@link ExternalDebugFilesService} to a string and writes to the Ghidra
	 * global preferences.
	 * 
	 * @param service the {@link ExternalDebugFilesService} to commit to preferences
	 */
	public static void saveToPrefs(ExternalDebugFilesService service) {
		if (service != null) {
			String serializedProviders = service.getProviders()
					.stream()
					.map(DebugInfoProvider::getName)
					.collect(Collectors.joining(";"));
			Preferences.setProperty(STORAGE_OPTION, service.getStorage().getName());
			Preferences.setProperty(PROVIDERS_OPTION, serializedProviders);
		}
		else {
			Preferences.setProperty(STORAGE_OPTION, null);
			Preferences.setProperty(PROVIDERS_OPTION, null);
		}
	}

}
