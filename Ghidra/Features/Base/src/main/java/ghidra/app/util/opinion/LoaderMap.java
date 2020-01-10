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

import java.util.*;

/**
 * A {@link Map} of {@link Loader}s to their respective {@link LoadSpec}s.
 * <p>
 * The {@link Loader} keys are sorted according to their {@link Loader#compareTo(Loader) natural 
 * ordering}.
 */
public class LoaderMap extends TreeMap<Loader, Collection<LoadSpec>> {

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		for (Loader loader : keySet()) {
			Collection<LoadSpec> loadSpecs = get(loader);
			sb.append(loader.getName() + " - " + loadSpecs.size() + " load specs\n");
		}
		return sb.toString();
	}
}
