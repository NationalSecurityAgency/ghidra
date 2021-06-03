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

import ghidra.app.util.opinion.*;

/**
 * Chooses a {@link LoadSpec} for a {@link Loader} to use based on some criteria
 */
@FunctionalInterface
public interface LoadSpecChooser {

	/**
	 * Chooses a {@link LoadSpec} for a {@link Loader} to use based on some criteria
	 * 
	 * @param loaderMap A {@link LoaderMap}
	 * @return The chosen {@link LoadSpec}, or null if one could not be found
	 */
	public LoadSpec choose(LoaderMap loaderMap);

	/**
	 * Chooses the first "preferred" {@link LoadSpec}
	 * 
	 * @see LoadSpec#isPreferred()
	 */
	public static final LoadSpecChooser CHOOSE_THE_FIRST_PREFERRED = loaderMap -> {
		return loaderMap.values()
				.stream()
				.flatMap(loadSpecs -> loadSpecs.stream())
				.filter(loadSpec -> loadSpec != null && loadSpec.isPreferred())
				.findFirst()
				.orElse(null);
	};
}
