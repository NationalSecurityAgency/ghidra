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
package ghidra.generic.util.datastruct;

import java.util.*;

import org.apache.commons.collections4.multimap.AbstractSetValuedMap;

/**
 * A multi-valued map using a tree map of tree sets
 * 
 * @param <K> the type of key
 * @param <V> the type of value
 */
public class TreeSetValuedTreeMap<K, V> extends AbstractSetValuedMap<K, V> {
	public TreeSetValuedTreeMap() {
		super(new TreeMap<>());
	}

	@Override
	protected Set<V> createCollection() {
		return new TreeSet<>();
	}
}
