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

import java.util.*;
import java.util.function.Predicate;

public class PathMatcher implements PathPredicates {
	protected final Set<PathPattern> patterns = new HashSet<>();

	public void addPattern(List<String> pattern) {
		patterns.add(new PathPattern(pattern));
	}

	/**
	 * TODO: We could probably do a lot better, esp. for many patterns, by using a trie.
	 */
	protected boolean anyPattern(Predicate<PathPattern> pred) {
		for (PathPattern p : patterns) {
			if (pred.test(p)) {
				return true;
			}
		}
		return false;
	}

	@Override
	public boolean matches(List<String> path) {
		return anyPattern(p -> p.matches(path));
	}

	@Override
	public boolean successorCouldMatch(List<String> path) {
		return anyPattern(p -> p.successorCouldMatch(path));
	}

	@Override
	public boolean ancestorMatches(List<String> path) {
		return anyPattern(p -> p.ancestorMatches(path));
	}
}
