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

import java.util.List;
import java.util.function.Predicate;

import generic.stl.Pair;
import ghidra.app.util.opinion.Loader;

public class SingleLoaderFilter implements Predicate<Loader> {
	private final Class<? extends Loader> single;
	private List<Pair<String, String>> loaderArgs;

	/**
	 * Create a new single loader filter from the given loader class.
	 * 
	 * @param single The loader class used for this filter.
	 */
	public SingleLoaderFilter(Class<? extends Loader> single) {
		this.single = single;
	}

	/**
	 * Create a new single loader filter from the given loader class and loader command line
	 * argument list.
	 * 
	 * @param single The loader class used for this filter.
	 * @param loaderArgs The loader arguments used for this filter.  Could be null if there
	 *                   are not arguments.
	 */
	public SingleLoaderFilter(Class<? extends Loader> single,
			List<Pair<String, String>> loaderArgs) {
		this.single = single;
		this.loaderArgs = loaderArgs;
	}

	/**
	 * Gets the loader arguments tied to the loader in this filter.
	 * 
	 * @return The loader arguments tied to the loader in this filter.  Could be null if there
	 *         are no arguments. 
	 */
	public List<Pair<String, String>> getLoaderArgs() {
		return loaderArgs;
	}

	@Override
	public boolean test(Loader loader) {
		if (loader.getClass().equals(single)) {
			return true;
		}
		return false;
	}
}
