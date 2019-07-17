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

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A simple implementation of a LRU map that will throw away entries that exceed the given
 * maximum size.
 *
 * <P>If you would like a LRU based upon <i>access-order</i>, then use the {@link LRUMap}.
 *
 * @param <K> the key type
 * @param <V> the value type
 */
public class FixedSizeHashMap<K, V> extends LinkedHashMap<K, V> {
	private int maxSize;

	public FixedSizeHashMap(int maxSize) {
		this(16, maxSize);
	}

	public FixedSizeHashMap(int initialSize, int maxSize) {
		super(initialSize, 0.75f, true);
		this.maxSize = maxSize;
	}

	@Override
	protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
		return size() > maxSize;
	}
}
