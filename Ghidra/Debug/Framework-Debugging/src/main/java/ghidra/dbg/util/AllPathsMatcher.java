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
package ghidra.dbg.util;

import java.util.List;
import java.util.Set;

public enum AllPathsMatcher implements PathPredicates {
	INSTANCE;

	@Override
	public PathPredicates or(PathPredicates that) {
		return this;
	}

	@Override
	public boolean matches(List<String> path) {
		return true;
	}

	@Override
	public boolean successorCouldMatch(List<String> path, boolean strict) {
		return true;
	}

	@Override
	public boolean ancestorMatches(List<String> path, boolean strict) {
		if (path.isEmpty() && strict) {
			return false;
		}
		return true;
	}

	@Override
	public Set<String> getNextKeys(List<String> path) {
		return Set.of("", "[]");
	}

	@Override
	public Set<String> getNextNames(List<String> path) {
		return Set.of("");
	}

	@Override
	public Set<String> getNextIndices(List<String> path) {
		return Set.of("");
	}

	@Override
	public List<String> getSingletonPath() {
		return null;
	}

	@Override
	public PathPattern getSingletonPattern() {
		return null;
	}

	@Override
	public PathPredicates applyKeys(List<String> keys) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isEmpty() {
		return false;
	}
}
