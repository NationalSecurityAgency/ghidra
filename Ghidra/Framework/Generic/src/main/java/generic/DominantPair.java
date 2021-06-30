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
package generic;

import java.util.Objects;

import generic.stl.Pair;

/**
 * DominantPair is a pair where the key is responsible for equality and hashCode (and the value of
 * the pair doesn't matter at all).  This is useful when you need the pair itself to function as a
 * key in a Map or value in a Set.
 *
 * @param <K> the key type
 * @param <V> the value type
 */
public class DominantPair<K, V> extends Pair<K, V> {
	public DominantPair(K key, V value) {
		super(key, value);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((first == null) ? 0 : first.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		DominantPair<?, ?> other = (DominantPair<?, ?>) obj;
		return Objects.equals(first, other.first);
	}

	@Override
	public String toString() {
		return "(" + first + "," + second + ")";
	}
}
