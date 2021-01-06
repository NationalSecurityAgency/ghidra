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

public class ComposedSleighUseropLibrary<T> implements SleighUseropLibrary<T> {
	public static <T> Map<String, SleighUseropDefinition<T>> composeUserops(
			Collection<SleighUseropLibrary<T>> libraries) {
		Map<String, SleighUseropDefinition<T>> userops = new HashMap<>();
		for (SleighUseropLibrary<T> lib : libraries) {
			for (SleighUseropDefinition<T> def : lib.getUserops().values()) {
				if (userops.put(def.getName(), def) != null) {
					throw new IllegalArgumentException(
						"Cannot compose libraries with conflicting definitions on " +
							def.getName());
				}
			}
		}
		return userops;
	}

	private final Map<String, SleighUseropDefinition<T>> userops;

	public ComposedSleighUseropLibrary(Collection<SleighUseropLibrary<T>> libraries) {
		this.userops = composeUserops(libraries);
	}

	@Override
	public Map<String, SleighUseropDefinition<T>> getUserops() {
		return userops;
	}
}
