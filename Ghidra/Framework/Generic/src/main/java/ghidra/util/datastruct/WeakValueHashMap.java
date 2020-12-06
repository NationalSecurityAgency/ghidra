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

import java.util.HashMap;
import java.util.Map;

/**
 * Class to provide a hash map with weak values.
 */

public class WeakValueHashMap<K, V> extends AbstractWeakValueMap<K, V> {
	private Map<K, WeakValueRef<K, V>> refMap;

	/**
	 * Constructs a new weak map
	 */
	public WeakValueHashMap() {
		super();
		refMap = new HashMap<>();
	}

	/**
	 * Constructs a new weak map with the given initial size
	 * 
	 * @param initialSize the initial size of the backing map
	 */
	public WeakValueHashMap(int initialSize) {
		super();
		refMap = new HashMap<>(initialSize);
	}

	@Override
	protected Map<K, WeakValueRef<K, V>> getRefMap() {
		return refMap;
	}
}
