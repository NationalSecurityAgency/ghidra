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
package ghidra.graph;

import java.util.HashSet;
import java.util.Set;

//TODO Do we need this class
public class GraphPathSet<V> {

	private Set<GraphPath<V>> paths = new HashSet<>();

	public boolean containSomePathStartingWith(GraphPath<V> otherPath) {
		for (GraphPath<V> path : paths) {
			if (path.startsWith(otherPath)) {
				return true;
			}
		}
		return false;
	}

	public void add(GraphPath<V> path) {
		paths.add(path);
	}

	public Set<GraphPath<V>> getPathsContaining(V v) {
		Set<GraphPath<V>> set = new HashSet<>();
		for (GraphPath<V> path : paths) {
			if (path.contains(v)) {
				set.add(path);
			}
		}
		return set;
	}

	public int size() {
		return paths.size();
	}

	@Override
	public String toString() {
		StringBuilder buf = new StringBuilder();
		for (GraphPath<V> path : paths) {
			buf.append(path.toString()).append('\n');
		}
		return buf.toString();
	}

}
