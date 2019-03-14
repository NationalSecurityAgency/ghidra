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

/**
 * A simple interface that can build, lookup or otherwise return a value <code>V</code> for a
 * key <code>K</code>.
 *
 * @param <K> the key used to get a value
 * @param <V> the value returned for the given key
 */
public interface Factory<K, V> {
	public V get(K key);
}
