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
package ghidra.trace.model.target.path;

import java.util.*;

public class PathPattern implements PathFilter {
	private final KeyPath pattern;

	/**
	 * TODO: This can get more sophisticated if needed, but for now, I don't think we even need
	 * regular expressions. Either we care about a path element, or we don't.
	 * 
	 * <p>
	 * This takes a keypath as a means of matching paths. The blank key serves as a wildcard
	 * accepting all keys in that position, e.g., the following matches all elements within
	 * {@code Processes}:
	 * 
	 * <pre>
	 * {@link PathFilter#parse(String) PathFilter.parse}("Processes[]");
	 * </pre>
	 * 
	 * @param pattern a list of path elements
	 */
	public PathPattern(KeyPath pattern) {
		this.pattern = pattern;
	}

	@Override
	public String toString() {
		return String.format("<PathPattern %s>", pattern);
	}

	/**
	 * Convert this pattern to a string.,
	 * 
	 * <p>
	 * This is the inverse of {@link PathFilter#parse(String)}.
	 * 
	 * @return the string
	 */
	public String toPatternString() {
		return pattern.toString();
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof PathPattern)) {
			return false;
		}
		PathPattern that = (PathPattern) obj;
		if (!Objects.equals(this.pattern, that.pattern)) {
			return false;
		}
		return true;
	}

	@Override
	public int hashCode() {
		return pattern.hashCode();
	}

	@Override
	public PathFilter or(PathFilter that) {
		if (this.equals(that)) {
			return this;
		}
		PathMatcher result = new PathMatcher();
		result.addPattern(this);
		if (that instanceof PathPattern) {
			result.addPattern(this);
		}
		else if (that instanceof PathMatcher) {
			PathMatcher matcher = (PathMatcher) that;
			result.patterns.addAll(matcher.patterns);
		}
		else {
			throw new AssertionError();
		}
		return result;
	}

	public static boolean isWildcard(String pat) {
		return "[]".equals(pat) || "".equals(pat);
	}

	protected boolean matchesUpTo(KeyPath path, int length) {
		for (int i = 0; i < length; i++) {
			if (!PathFilter.keyMatches(pattern.key(i), path.key(i))) {
				return false;
			}
		}
		return true;
	}

	protected boolean matchesBackTo(KeyPath path, int length) {
		int patternMax = pattern.size() - 1;
		int pathMax = path.size() - 1;
		for (int i = 0; i < length; i++) {
			if (!PathFilter.keyMatches(pattern.key(patternMax - i), path.key(pathMax - i))) {
				return false;
			}
		}
		return true;
	}

	@Override
	public boolean matches(KeyPath path) {
		if (path.size() != pattern.size()) {
			return false;
		}
		return matchesUpTo(path, path.size());
	}

	@Override
	public boolean successorCouldMatch(KeyPath path, boolean strict) {
		if (path.size() > pattern.size()) {
			return false;
		}
		if (strict && path.size() == pattern.size()) {
			return false;
		}
		return matchesUpTo(path, path.size());
	}

	@Override
	public boolean ancestorMatches(KeyPath path, boolean strict) {
		if (path.size() < pattern.size()) {
			return false;
		}
		if (strict && path.size() == pattern.size()) {
			return false;
		}
		return matchesUpTo(path, pattern.size());
	}

	@Override
	public boolean ancestorCouldMatchRight(KeyPath path, boolean strict) {
		if (path.size() > pattern.size()) {
			return false;
		}
		if (strict && path.size() == pattern.size()) {
			return false;
		}
		return matchesBackTo(path, path.size());
	}

	@Override
	public KeyPath getSingletonPath() {
		if (pattern.containsWildcard()) {
			return null;
		}
		return pattern;
	}

	/**
	 * Return the pattern as a key path of patterns
	 * 
	 * @return the list of key patterns
	 */
	public KeyPath asPath() {
		return pattern;
	}

	/**
	 * Count the number of wildcard keys in this pattern
	 * 
	 * @return the count
	 */
	public int countWildcards() {
		return pattern.countWildcards();
	}

	@Override
	public PathPattern getSingletonPattern() {
		return this;
	}

	@Override
	public Collection<PathPattern> getPatterns() {
		return List.of(this);
	}

	@Override
	public Set<String> getNextKeys(KeyPath path) {
		if (path.size() >= pattern.size()) {
			return Set.of();
		}
		if (!matchesUpTo(path, path.size())) {
			return Set.of();
		}
		return Set.of(pattern.key(path.size()));
	}

	@Override
	public Set<String> getNextNames(KeyPath path) {
		if (path.size() >= pattern.size()) {
			return Set.of();
		}
		if (!matchesUpTo(path, path.size())) {
			return Set.of();
		}
		String pat = pattern.key(path.size());
		if (KeyPath.isName(pat)) {
			return Set.of(pat);
		}
		return Set.of();
	}

	@Override
	public Set<String> getNextIndices(KeyPath path) {
		if (path.size() >= pattern.size()) {
			return Set.of();
		}
		if (!matchesUpTo(path, path.size())) {
			return Set.of();
		}
		String pat = pattern.key(path.size());
		if (KeyPath.isIndex(pat)) {
			return Set.of(KeyPath.parseIndex(pat));
		}
		return Set.of();
	}

	@Override
	public Set<String> getPrevKeys(KeyPath path) {
		if (path.size() >= pattern.size()) {
			return Set.of();
		}
		if (!matchesBackTo(path, path.size())) {
			return Set.of();
		}
		return Set.of(pattern.key(pattern.size() - 1 - path.size()));
	}

	@Override
	public boolean isNone() {
		return false;
	}

	@Override
	public PathPattern applyKeys(Align align, List<String> keys) {
		String[] result = new String[pattern.size()];
		ListIterator<String> kit = align.iterator(keys);
		ListIterator<String> pit = align.iterator(pattern.keys);

		while (pit.hasNext()) {
			int i = pit.nextIndex();
			String pat = pit.next();
			if (kit.hasNext() && isWildcard(pat)) {
				String index = kit.next();
				if (KeyPath.isIndex(pat)) {
					result[i] = KeyPath.makeKey(index);
				}
				else {
					// NB. Rare for attribute wildcards, but just in case
					result[i] = index;
				}
			}
			else {
				result[i] = pat;
			}
		}
		return new PathPattern(new KeyPath(result));
	}

	/**
	 * If the given path matches, extract keys where matched by wildcards
	 * 
	 * <p>
	 * This is essentially the inverse of {@link #applyKeys(String...)}, but can only be asked of
	 * one pattern. The keys are returned from left to right, in the order matched by the pattern.
	 * Only those keys matched by a wildcard are included in the result. Indices are extracted with
	 * the brackets {@code []} removed.
	 * 
	 * @param path the path to match
	 * @param matchLength true if the path must have the same number of keys as this pattern, or
	 *            false if the path is allowed to have more keys than this pattern
	 * @return the list of matched keys or {@code null} if not matched
	 */
	public List<String> matchKeys(KeyPath path, boolean matchLength) {
		int length = pattern.size();
		if (matchLength ? length != path.size() : length > path.size()) {
			return null;
		}
		List<String> result = new ArrayList<>();
		for (int i = 0; i < length; i++) {
			String pat = pattern.key(i);
			String key = path.key(i);
			if (!PathFilter.keyMatches(pat, key)) {
				return null;
			}
			if (isWildcard(pat)) {
				if (KeyPath.isIndex(pat)) {
					result.add(KeyPath.parseIndex(key));
				}
				else {
					result.add(key);
				}
			}
		}
		return result;
	}

	void doRemoveRight(int count, PathMatcher result) {
		KeyPath parent = pattern.parent(count);
		if (parent == null) {
			return;
		}
		result.addPattern(parent);
	}

	@Override
	public PathMatcher removeRight(int count) {
		PathMatcher result = new PathMatcher();
		doRemoveRight(count, result);
		return result;
	}
}
