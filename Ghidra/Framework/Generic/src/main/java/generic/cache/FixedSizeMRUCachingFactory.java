/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package generic.cache;

import ghidra.util.datastruct.LRUMap;

/**
 * An object that will cache values returned from the given factory.  This class lets you combine
 * the work of building items as needed with cache maintenance operations, such as get and put 
 * (and move, in the case of a sized cache).
 *   
 * <P>
 * The caching of this class
 * is bound by the size parameter of the constructor.   Further, the caching strategy is an 
 * Most Recently Used strategy, meaning that the least accessed cache items will fall off of the
 * cache.
 *
 * @param <K> the key used to get a value
 * @param <V> the value returned for the given key
 */
public class FixedSizeMRUCachingFactory<K, V> implements Factory<K, V> {

	private LRUMap<K, V> cache;
	private Factory<K, V> delegate;

	public FixedSizeMRUCachingFactory(Factory<K, V> factory, int size) {
		this.delegate = factory;
		this.cache = new LRUMap<K, V>(size);
	}

	@Override
	public V get(K key) {
		V value = cache.get(key);
		if (value != null) {
			return value;
		}

		value = delegate.get(key);
		cache.put(key, value);
		return value;
	}
}
