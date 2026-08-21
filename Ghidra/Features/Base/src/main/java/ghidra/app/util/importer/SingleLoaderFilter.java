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

import java.util.function.Predicate;

import ghidra.app.util.opinion.Loader;

/**
 * Filters on one specific loader
 * 
 * @deprecated Use {@link ProgramLoader.Builder#loaders(Class)} instead
 */
@Deprecated(since = "12.0", forRemoval = true)
public class SingleLoaderFilter implements Predicate<Loader> {
	private final Class<? extends Loader> single;

	/**
	 * Create a new single loader filter from the given loader class.
	 * 
	 * @param single The loader class used for this filter.
	 * @deprecated Use {@link ProgramLoader.Builder#loaders(Class)} instead
	 */
	@Deprecated(since = "12.0", forRemoval = true)
	public SingleLoaderFilter(Class<? extends Loader> single) {
		this.single = single;
	}

	@Override
	public boolean test(Loader loader) {
		return loader.getClass().equals(single);
	}
}
