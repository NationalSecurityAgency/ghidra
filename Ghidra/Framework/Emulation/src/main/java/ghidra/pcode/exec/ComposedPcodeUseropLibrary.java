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
package ghidra.pcode.exec;

import java.util.*;

/**
 * A p-code userop library composed of other libraries
 * 
 * @param <T> the type of values processed by the library
 */
public class ComposedPcodeUseropLibrary<T> implements PcodeUseropLibrary<T> {
	/**
	 * Obtain a map representing the composition of userops from all the given libraries
	 * 
	 * <p>
	 * Name collisions are not allowed. If any two libraries export the same symbol, even if the
	 * definitions happen to do the same thing, it is an error.
	 * 
	 * @param <T> the type of values processed by the libraries
	 * @param libraries the libraries whose userops to collect
	 * @return the resulting map
	 */
	public static <T> Map<String, PcodeUseropDefinition<T>> composeUserops(
			Collection<PcodeUseropLibrary<T>> libraries) {
		Map<String, PcodeUseropDefinition<T>> userops = new HashMap<>();
		for (PcodeUseropLibrary<T> lib : libraries) {
			for (PcodeUseropDefinition<T> def : lib.getUserops().values()) {
				if (userops.put(def.getName(), def) != null) {
					throw new IllegalArgumentException(
						"Cannot compose libraries with conflicting definitions on " +
							def.getName());
				}
			}
		}
		return userops;
	}

	private final Map<String, PcodeUseropDefinition<T>> userops;

	/**
	 * Construct a composed userop library from the given libraries
	 * 
	 * <p>
	 * This uses {@link #composeUserops(Collection)}, so its restrictions apply here, too.
	 * 
	 * @param libraries the libraries
	 */
	public ComposedPcodeUseropLibrary(Collection<PcodeUseropLibrary<T>> libraries) {
		this.userops = composeUserops(libraries);
	}

	@Override
	public Map<String, PcodeUseropDefinition<T>> getUserops() {
		return userops;
	}
}
