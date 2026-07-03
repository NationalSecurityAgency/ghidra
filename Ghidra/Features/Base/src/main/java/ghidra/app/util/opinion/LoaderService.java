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

import ghidra.app.util.bin.ByteProvider;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.task.TaskMonitor;
import util.CollectionUtils;

/**
 * Factory and utility methods for working with {@link Loader}s.
 */
public class LoaderService {

	public static Predicate<Loader> ACCEPT_ALL = loader -> true;

	/**
	 * Gets all supported {@link LoadSpec}s for loading the given {@link ByteProvider}.
	 * 
	 * @param provider The {@link ByteProvider} to load.
	 * @param loaderFilter A {@link Predicate} that will filter out undesired {@link Loader}s.
	 * @param monitor The {@link TaskMonitor}
	 * @return All supported {@link LoadSpec}s in the form of a {@link LoaderMap}.
	 */
	public static LoaderMap getSupportedLoadSpecs(ByteProvider provider,
			Predicate<Loader> loaderFilter, TaskMonitor monitor) {
		initializeLanguageService(monitor);
		LoaderMap loaderMap = new LoaderMap();
		List<Loader> fallback = new ArrayList<>();
		for (Loader loader : getAllLoaders()) {
			if (loaderFilter.test(loader)) {
				if (!loader.isFallback()) {
					tryLoadSpecs(loader, provider, loaderMap);
				}
				else {
					fallback.add(loader);
				}
			}
		}

		// Only try fallback loaders if no other loaders matched (ignoring the BinaryLoader)
		boolean matches = loaderMap.keySet()
				.stream()
				.map(Loader::getName)
				.anyMatch(Predicate.not(BinaryLoader.BINARY_NAME::equals));
		if (!matches) {
			fallback.forEach(loader -> tryLoadSpecs(loader, provider, loaderMap));
		}

		return loaderMap;
	}

	/**
	 * Gets all supported {@link LoadSpec}s for loading the given {@link ByteProvider}.
	 * 
	 * @param provider The {@link ByteProvider} to load.
	 * @param loaderFilter A {@link Predicate} that will filter out undesired {@link Loader}s.
	 * @return All supported {@link LoadSpec}s in the form of a {@link LoaderMap}.
	 * @deprecated Use {@link #getSupportedLoadSpecs(ByteProvider, Predicate, TaskMonitor)}
	 */
	@Deprecated(since = "12.2", forRemoval = true)
	public static LoaderMap getSupportedLoadSpecs(ByteProvider provider,
			Predicate<Loader> loaderFilter) {
		return getSupportedLoadSpecs(provider, loaderFilter, TaskMonitor.DUMMY);
	}

	/**
	 * Attempts to find and register supported {@link LoadSpec}s for the given {@link Loader}
	 * 
	 * @param loader The {@link Loader} to query
	 * @param provider The {@link ByteProvider} to load from
	 * @param loaderMap The {@link LoaderMap} to populate with discovered {@link LoadSpec}s
	 */
	private static void tryLoadSpecs(Loader loader, ByteProvider provider, LoaderMap loaderMap) {
		try {
			Collection<LoadSpec> loadSpecs = loader.findSupportedLoadSpecs(provider);
			if (!CollectionUtils.isBlank(loadSpecs)) {
				loaderMap.put(loader, loadSpecs);
			}
		}
		catch (IOException e) {
			// file not applicable for loader
		}
		catch (RuntimeException e) {
			Msg.error(LoaderService.class, "Unexpected Loader exception from " + loader.getName(),
				e);
		}
	}

	/**
	 * Gets all supported {@link LoadSpec}s for loading the given {@link ByteProvider}.
	 * 
	 * @param provider The {@link ByteProvider} to load.
	 * @param monitor The {@link TaskMonitor}
	 * @return All supported {@link LoadSpec}s in the form of a {@link LoaderMap}.
	 */
	public static LoaderMap getAllSupportedLoadSpecs(ByteProvider provider, TaskMonitor monitor) {
		return getSupportedLoadSpecs(provider, ACCEPT_ALL, monitor);
	}

	/**
	 * Gets all supported {@link LoadSpec}s for loading the given {@link ByteProvider}.
	 * 
	 * @param provider The {@link ByteProvider} to load.
	 * @return All supported {@link LoadSpec}s in the form of a {@link LoaderMap}.
	 * @deprecated Use {@link #getAllSupportedLoadSpecs(ByteProvider, TaskMonitor)}
	 */
	@Deprecated(since = "12.2", forRemoval = true)
	public static LoaderMap getAllSupportedLoadSpecs(ByteProvider provider) {
		return getAllSupportedLoadSpecs(provider, TaskMonitor.DUMMY);
	}

	/**
	 * Gets all known {@link Loader}s' names.
	 * 
	 * @return All known {@link Loader}s' names.  The {@link Loader} names are sorted
	 * according to their corresponding {@link Loader}s {@link Loader#compareTo(Loader) natural 
	 * ordering}. 
	 */
	public static Collection<String> getAllLoaderNames() {
		return getAllLoaders()
			.stream()
			.sorted()
			.map(loader -> loader.getName())
			.collect(Collectors.toList());
	}

	/**
	 * Gets the {@link Loader} {@link Class} that corresponds to the given simple {@link Class}
	 * name.
	 * 
	 * @param name The name of the {@link Loader} to get the {@link Class} of.
	 * @return The {@link Loader} {@link Class} that corresponds to the given simple {@link Class}
	 *   name, or {@code null} if it does not exist.
	 */
	public static Class<? extends Loader> getLoaderClassByName(String name) {
		return getAllLoaders()
			.stream()
			.filter(loader -> loader.getClass().getSimpleName().equals(name))
			.findFirst()
			.map(loader -> loader.getClass())
			.orElse(null);
	}

	/**
	 * Gets an instance of every known {@link Loader}.
	 * 
	 * @return An instance of every known {@link Loader}.  The {@link Loader} instances are sorted
	 *   according to their {@link Loader#compareTo(Loader) natural ordering}. 
	 */
	private synchronized static Collection<Loader> getAllLoaders() {
		List<Loader> loaders = new ArrayList<>(ClassSearcher.getInstances(Loader.class));
		Collections.sort(loaders);
		return loaders;
	}

	/**
	 * Gets the language service so we can show its slow progress with a monitor.
	 * <p>
	 * Typically the first time the language service is gotten is from within a call to
	 * {@link Loader#findSupportedLoadSpecs(ByteProvider)}, which doesn't have access to monitor
	 * (nor does {@link DefaultLanguageService#getLanguageService()}). This results in a stale
	 * monitor message being shown for several seconds.
	 * 
	 * @param monitor The {@link TaskMonitor}
	 */
	private static void initializeLanguageService(TaskMonitor monitor) {
		monitor.setMessage("Initializing language service...");
		monitor.setIndeterminate(true);
		monitor.setCancelEnabled(false);
		DefaultLanguageService.getLanguageService();
		monitor.setCancelEnabled(true);
	}
}
