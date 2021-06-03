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
	 * @return All supported {@link LoadSpec}s in the form of a {@link LoaderMap}.
	 */
	public static LoaderMap getSupportedLoadSpecs(ByteProvider provider,
			Predicate<Loader> loaderFilter) {
		LoaderMap loaderMap = new LoaderMap();
		for (Loader loader : getAllLoaders()) {
			if (loaderFilter.test(loader)) {
				try {
					Collection<LoadSpec> loadSpecs = loader.findSupportedLoadSpecs(provider);
					if (loadSpecs != null && !loadSpecs.isEmpty()) { // shouldn't be null, but protect against rogue loaders
						loaderMap.put(loader, loadSpecs);
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
		return loaderMap;
	}

	/**
	 * Gets all supported {@link LoadSpec}s for loading the given {@link ByteProvider}.
	 * 
	 * @param provider The {@link ByteProvider} to load.
	 * @return All supported {@link LoadSpec}s in the form of a {@link LoaderMap}.
	 */
	public static LoaderMap getAllSupportedLoadSpecs(ByteProvider provider) {
		return getSupportedLoadSpecs(provider, ACCEPT_ALL);
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
	 *   name.
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
}
