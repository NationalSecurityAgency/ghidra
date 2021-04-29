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

public class PathPattern implements PathPredicates {
	private final List<String> pattern;

	/**
	 * TODO: This can get more sophisticated if needed, but for now, I don't think we even need
	 * regular expressions. Either we care about a path element, or we don't.
	 * 
	 * <p>
	 * This takes a list of path keys as a means of matching paths. The empty key serves as a
	 * wildcard accepting all keys in that position, e.g., the following matches all elements within
	 * {@code Processes}:
	 * 
	 * <p>
	 * {@code List.of("Processes", "[]")}
	 * 
	 * <p>
	 * This should still be compatible with {@link PathUtils#parse(String)} and
	 * {@link PathUtils#toString(List)} allowing the last example to be expressed as
	 * {@code PathUtils.parse("Processes[]")}.
	 * 
	 * @param pattern a list of path elements
	 */
	public PathPattern(List<String> pattern) {
		this.pattern = List.copyOf(pattern);
	}

	@Override
	public String toString() {
		return String.format("<PathPattern %s>", PathUtils.toString(pattern));
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof PathPattern)) {
			return false;
		}
		PathPattern that = (PathPattern) obj;
		return Objects.equals(this.pattern, that.pattern);
	}

	@Override
	public int hashCode() {
		return pattern.hashCode();
	}

	public static boolean isWildcard(String pat) {
		return "[]".equals(pat) || "".equals(pat);
	}

	public static boolean keyMatches(String pat, String key) {
		if (key.equals(pat)) {
			return true;
		}
		if ("[]".equals(pat) && PathUtils.isIndex(key)) {
			return true;
		}
		if ("".equals(pat) && PathUtils.isName(key)) {
			return true;
		}
		return false;
	}

	protected boolean matchesUpTo(List<String> path, int length) {
		for (int i = 0; i < length; i++) {
			if (!keyMatches(pattern.get(i), path.get(i))) {
				return false;
			}
		}
		return true;
	}

	@Override
	public boolean matches(List<String> path) {
		if (path.size() != pattern.size()) {
			return false;
		}
		return matchesUpTo(path, path.size());
	}

	@Override
	public boolean successorCouldMatch(List<String> path, boolean strict) {
		if (path.size() > pattern.size()) {
			return false;
		}
		if (strict && path.size() == pattern.size()) {
			return false;
		}
		return matchesUpTo(path, path.size());
	}

	@Override
	public boolean ancestorMatches(List<String> path, boolean strict) {
		if (path.size() < pattern.size()) {
			return false;
		}
		if (strict && path.size() == pattern.size()) {
			return false;
		}
		return matchesUpTo(path, pattern.size());
	}

	protected static boolean containsWildcards(List<String> pattern) {
		for (String pat : pattern) {
			if (isWildcard(pat)) {
				return true;
			}
		}
		return false;
	}

	@Override
	public List<String> getSingletonPath() {
		if (containsWildcards(pattern)) {
			return null;
		}
		return pattern;
	}

	public int countWildcards() {
		return (int) pattern.stream().filter(k -> isWildcard(k)).count();
	}

	@Override
	public PathPattern getSingletonPattern() {
		return this;
	}

	@Override
	public Set<String> getNextNames(List<String> path) {
		if (path.size() >= pattern.size()) {
			return Set.of();
		}
		String pat = pattern.get(path.size());
		if (PathUtils.isName(pat)) {
			return Set.of(pat);
		}
		return Set.of();
	}

	@Override
	public Set<String> getNextIndices(List<String> path) {
		if (path.size() >= pattern.size()) {
			return Set.of();
		}
		String pat = pattern.get(path.size());
		if (PathUtils.isIndex(pat)) {
			return Set.of(PathUtils.parseIndex(pat));
		}
		return Set.of();
	}

	@Override
	public boolean isEmpty() {
		return false;
	}

	@Override
	public PathPattern applyIndices(List<String> indices) {
		List<String> result = new ArrayList<>(pattern.size());
		Iterator<String> it = indices.iterator();
		for (String pat : pattern) {
			if (it.hasNext() && isWildcard(pat)) {
				String index = it.next();
				if (PathUtils.isIndex(pat)) {
					result.add(PathUtils.makeKey(index));
				}
				else {
					// NB. Rare for attribute wildcards, but just in case
					result.add(index);
				}
			}
			else {
				result.add(pat);
			}
		}
		return new PathPattern(result);
	}

	/**
	 * If the given path matches, extract indices where matched by wildcards
	 * 
	 * <p>
	 * This is essentially the inverse of {@link #applyIndices(List)}, but can only be asked of one
	 * pattern. The keys are returned from left to right, in the order matched by the pattern. Only
	 * those keys matched by a wildcard are included in the result. Indices are extracted with the
	 * brackets {@code []} removed.
	 * 
	 * @param path the path to match
	 * @return the list of matched indices or {@code null} if not matched
	 */
	public List<String> matchIndices(List<String> path) {
		int length = pattern.size();
		if (length != path.size()) {
			return null;
		}
		List<String> result = new ArrayList<>();
		for (int i = 0; i < length; i++) {
			String pat = pattern.get(i);
			String key = path.get(i);
			if (!keyMatches(pat, key)) {
				return null;
			}
			if (isWildcard(pat)) {
				if (PathUtils.isIndex(pat)) {
					result.add(PathUtils.parseIndex(key));
				}
				else {
					result.add(key);
				}
			}
		}
		return result;
	}
}
