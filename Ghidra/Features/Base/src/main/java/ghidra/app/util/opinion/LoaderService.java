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
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;

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
	 * @return A {@link Map} of {@link Loader}s to their respective {@link LoadSpec}s.  It is safe
	 *   to assume that every {@link Loader} in the {@link Map} will have at least one 
	 *   {@link LoadSpec}.    
	 */
	public static Map<Loader, Collection<LoadSpec>> getSupportedLoadSpecs(ByteProvider provider,
			Predicate<Loader> loaderFilter) {
		Map<Loader, Collection<LoadSpec>> loadMap = new LinkedHashMap<>(); // maintain loader order
		for (Loader loader : getAllLoaders()) {
			if (loaderFilter.test(loader)) {
				try {
					Collection<LoadSpec> loadSpecs = loader.findSupportedLoadSpecs(provider);
					if (loadSpecs != null && !loadSpecs.isEmpty()) { // shouldn't be null, but protect against rogue loaders
						loadMap.put(loader, loadSpecs);
					}
				}
				catch (IOException e) {
					// file not applicable for loader
				}
				catch (RuntimeException e) {
					Msg.error(LoaderService.class,
						"Unexpected Loader exception from " + loader.getName(), e);
				}
			}
		}
		return loadMap;
	}

	/**
	 * Gets all supported {@link LoadSpec}s for loading the given {@link ByteProvider}.
	 * 
	 * @param provider The {@link ByteProvider} to load.
	 * @return A {@link Map} of {@link Loader}s to their respective {@link LoadSpec}s.  It is safe
	 *   to assume that every {@link Loader} in the {@link Map} will have at least one 
	 *   {@link LoadSpec}.    
	 */
	public static Map<Loader, Collection<LoadSpec>> getAllSupportedLoadSpecs(
			ByteProvider provider) {
		return getSupportedLoadSpecs(provider, ACCEPT_ALL);
	}

	/**
	 * Gets all known {@link Loader}s' names.
	 * 
	 * @return All known {@link Loader}s' names.
	 */
	public static Collection<String> getAllLoaderNames() {
		//@formatter:off
		return getAllLoaders()
			.stream()
			.map(loader -> loader.getName())
			.collect(Collectors.toList());
		//@formatter:on
	}

	/**
	 * Gets the {@link Loader} {@link Class} that corresponds to the given simple {@link Class}
	 * name.
	 * 
	 * @param name The name of the {@link Loader} to get the {@link Class} of.
	 * @return The {@link Loader} {@link Class} that corresponds to the given simple {@link Class}
	 *   name.
	 */
	public static Class<? extends Loader> getLoaderClassByName(String name) {
		//@formatter:off
		return getAllLoaders()
			.stream()
			.filter(loader -> loader.getClass().getSimpleName().equals(name))
			.findFirst()
			.map(loader -> loader.getClass())
			.orElse(null);
		//@formatter:on
	}

	/**
	 * Gets an instance of every known {@link Loader}.
	 * 
	 * @return An instance of every known {@link Loader}.
	 */
	private synchronized static Collection<Loader> getAllLoaders() {
		List<Loader> loaders = new ArrayList<>(ClassSearcher.getInstances(Loader.class));
		Collections.sort(loaders);
		return loaders;
	}
}
