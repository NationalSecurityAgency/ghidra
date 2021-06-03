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

import org.apache.commons.lang3.StringUtils;

public class PathMatcher implements PathPredicates {
	protected static final Set<String> WILD_SINGLETON = Set.of("");

	protected final Set<PathPattern> patterns = new HashSet<>();

	public void addPattern(List<String> pattern) {
		patterns.add(new PathPattern(pattern));
	}

	public void addPattern(PathPattern pattern) {
		patterns.add(pattern);
	}

	@Override
	public String toString() {
		return String.format("<PathMatcher\n  %s\n>", StringUtils.join(patterns, "\n  "));
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
	public boolean successorCouldMatch(List<String> path, boolean strict) {
		return anyPattern(p -> p.successorCouldMatch(path, strict));
	}

	@Override
	public boolean ancestorMatches(List<String> path, boolean strict) {
		return anyPattern(p -> p.ancestorMatches(path, strict));
	}

	@Override
	public List<String> getSingletonPath() {
		if (patterns.size() != 1) {
			return null;
		}
		return patterns.iterator().next().getSingletonPath();
	}

	@Override
	public PathPattern getSingletonPattern() {
		if (patterns.size() != 1) {
			return null;
		}
		return patterns.iterator().next();
	}

	@Override
	public Set<String> getNextNames(List<String> path) {
		Set<String> result = new HashSet<>();
		for (PathPattern pattern : patterns) {
			result.addAll(pattern.getNextNames(path));
			if (result.contains("")) {
				return WILD_SINGLETON;
			}
		}
		return result;
	}

	@Override
	public Set<String> getNextIndices(List<String> path) {
		Set<String> result = new HashSet<>();
		for (PathPattern pattern : patterns) {
			result.addAll(pattern.getNextIndices(path));
			if (result.contains("")) {
				return WILD_SINGLETON;
			}
		}
		return result;
	}

	@Override
	public boolean isEmpty() {
		return patterns.isEmpty();
	}

	@Override
	public PathMatcher applyIndices(List<String> indices) {
		PathMatcher result = new PathMatcher();
		for (PathPattern pat : patterns) {
			result.addPattern(pat.applyIndices(indices));
		}
		return result;
	}
}
