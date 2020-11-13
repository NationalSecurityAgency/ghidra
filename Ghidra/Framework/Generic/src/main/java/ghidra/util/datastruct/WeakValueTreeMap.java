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
package ghidra.util.datastruct;

import java.util.*;

/**
 * Class to provide a tree map with weak values.
 */
public class WeakValueTreeMap<K, V> extends AbstractWeakValueNavigableMap<K, V> {
	protected final NavigableMap<K, WeakValueRef<K, V>> refMap;

	/**
	 * Constructs a new weak map
	 */
	public WeakValueTreeMap() {
		super();
		refMap = new TreeMap<>();
	}

	/**
	 * Constructs a new weak map with keys ordered according to the given comparator
	 * 
	 * @param comparator the comparator, or {@code null} for the natural ordering
	 */
	public WeakValueTreeMap(Comparator<K> comparator) {
		super();
		refMap = new TreeMap<>(comparator);
	}

	@Override
	protected NavigableMap<K, WeakValueRef<K, V>> getRefMap() {
		return refMap;
	}
}
