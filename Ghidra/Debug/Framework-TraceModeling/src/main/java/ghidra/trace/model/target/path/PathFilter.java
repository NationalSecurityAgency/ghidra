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
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import ghidra.util.ReversedListIterator;

public interface PathFilter {
	PathFilter NONE = new PathFilter() {
		@Override
		public PathFilter or(PathFilter that) {
			return that;
		}

		@Override
		public boolean matches(KeyPath path) {
			return false;
		}

		@Override
		public boolean successorCouldMatch(KeyPath path, boolean strict) {
			return false;
		}

		@Override
		public boolean ancestorMatches(KeyPath path, boolean strict) {
			return false;
		}

		@Override
		public boolean ancestorCouldMatchRight(KeyPath path, boolean strict) {
			return false;
		}

		@Override
		public Set<String> getNextKeys(KeyPath path) {
			return Set.of();
		}

		@Override
		public Set<String> getNextNames(KeyPath path) {
			return Set.of();
		}

		@Override
		public Set<String> getNextIndices(KeyPath path) {
			return Set.of();
		}

		@Override
		public Set<String> getPrevKeys(KeyPath path) {
			return Set.of();
		}

		@Override
		public KeyPath getSingletonPath() {
			return null;
		}

		@Override
		public PathPattern getSingletonPattern() {
			return null;
		}

		@Override
		public Set<PathPattern> getPatterns() {
			return Set.of();
		}

		@Override
		public PathFilter removeRight(int count) {
			return this;
		}

		@Override
		public PathFilter applyKeys(Align align, List<String> keys) {
			return this;
		}

		@Override
		public boolean isNone() {
			return true;
		}
	};

	enum Align {
		LEFT {
			@Override
			<T> ListIterator<T> iterator(List<T> list) {
				return list.listIterator();
			}
		},
		RIGHT {
			@Override
			<T> ListIterator<T> iterator(List<T> list) {
				return new ReversedListIterator<>(list.listIterator(list.size()));
			}
		};

		abstract <T> ListIterator<T> iterator(List<T> list);

		<T> ListIterator<T> iterator(T[] arr) {
			return iterator(Arrays.asList(arr));
		};
	}

	static boolean keyMatches(String pat, String key) {
		if (key.equals(pat)) {
			return true;
		}
		if ("[]".equals(pat)) {
			return KeyPath.isIndex(key);
		}
		if ("".equals(pat)) {
			return KeyPath.isName(key);
		}
		return false;
	}

	static boolean anyMatches(Set<String> pats, String key) {
		return pats.stream().anyMatch(p -> keyMatches(p, key));
	}

	static PathFilter pattern(String... keyPatterns) {
		return new PathPattern(KeyPath.of(keyPatterns));
	}

	static PathFilter pattern(KeyPath keyPatterns) {
		return new PathPattern(keyPatterns);
	}

	static PathPattern parse(String pattern) {
		return new PathPattern(KeyPath.parse(pattern));
	}

	PathFilter or(PathFilter that);

	/**
	 * Check if the entire path passes
	 * 
	 * @param path the path to check
	 * @return true if it matches, false otherwise
	 */
	boolean matches(KeyPath path);

	/**
	 * Check if the given path <em>could</em> have a matching successor
	 * 
	 * <p>
	 * This essentially checks if the given path is a viable prefix to the matcher.
	 * 
	 * @implNote this method could become impractical for culling queries if we allow too
	 *           sophisticated of patterns. Notably, to allow an "any number of keys" pattern, e.g.,
	 *           akin to {@code /src/**{@literal /}*.c} in file system path matchers. Anything
	 *           starting with "src" could have a successor that matches.
	 * 
	 * 
	 * @param path the path (prefix) to check
	 * @param strict true to exclude the case where {@link #matches(KeyPath)} would return true
	 * @return true if a successor could match, false otherwise
	 */
	boolean successorCouldMatch(KeyPath path, boolean strict);

	/**
	 * Check if the given path has an ancestor that matches
	 * 
	 * @param path the path to check
	 * @param strict true to exclude the case where {@link #matches(KeyPath)} would return true
	 * @return true if an ancestor matches, false otherwise
	 */
	boolean ancestorMatches(KeyPath path, boolean strict);

	/**
	 * Check if the given path <em>could</em> have a matching ancestor, right to left
	 * 
	 * <p>
	 * This essentially checks if the given path is a viable postfix to the matcher.
	 * 
	 * @param path the path (postfix) to check
	 * @param strict true to exclude the case where {@link #matches(KeyPath)} would return true
	 * @return true if an ancestor could match, false otherwise
	 */
	boolean ancestorCouldMatchRight(KeyPath path, boolean strict);

	/**
	 * Get the patterns for the next possible key
	 * 
	 * <p>
	 * If a successor of the given path cannot match this pattern, the empty set is returned.
	 * 
	 * @param path the ancestor path
	 * @return a set of patterns where indices are enclosed in brackets {@code []}
	 */
	Set<String> getNextKeys(KeyPath path);

	/**
	 * Get the patterns for the next possible name
	 * 
	 * <p>
	 * If a successor of the given path cannot match this pattern, the empty set is returned. If the
	 * pattern could accept a name next, get all patterns describing those names
	 * 
	 * @param path the ancestor path
	 * @return a set of patterns
	 */
	Set<String> getNextNames(KeyPath path);

	/**
	 * Assuming a successor of path could match, get the patterns for the next possible index
	 * 
	 * <p>
	 * If a successor of the given path cannot match this pattern, the empty set is returned. If the
	 * pattern could accept an index next, get all patterns describing those indices
	 * 
	 * @param path the ancestor path
	 * @return a set of patterns, without brackets {@code []}
	 */
	Set<String> getNextIndices(KeyPath path);

	/**
	 * Get the patterns for the previous possible key (right-to-left matching)
	 * 
	 * <p>
	 * If an ancestor of the given path cannot match this pattern, the empty set is returned.
	 * 
	 * @param path the successor path
	 * @return a set of patterns where indices are enclosed in brackets {@code []}
	 */
	Set<String> getPrevKeys(KeyPath path);

	/**
	 * If this predicate is known to match only one path, i.e., no wildcards, get that path
	 * 
	 * @return the singleton path, or {@code null}
	 */
	KeyPath getSingletonPath();

	/**
	 * If this predicate consists of a single pattern, get that pattern
	 * 
	 * @return the singleton pattern, or {@code null}
	 */
	PathPattern getSingletonPattern();

	/**
	 * Get the patterns of this predicate
	 * 
	 * @return the patterns
	 */
	Set<PathPattern> getPatterns();

	/**
	 * Remove count elements from the right
	 * 
	 * @param count the number of elements to remove
	 * @return the resulting filter
	 */
	PathFilter removeRight(int count);

	/**
	 * Substitute wildcards from left to right for the given list of keys
	 * 
	 * <p>
	 * Takes each pattern and substitutes its wildcards for the given indices, according to the
	 * given alignment. This object is unmodified, and the result is returned.
	 * 
	 * <p>
	 * If there are fewer wildcards in a pattern than given, only the first keys are taken. If there
	 * are fewer keys than wildcards in a pattern, then the remaining wildcards are left in the
	 * resulting pattern. In this manner, the left-most wildcards are substituted for the left-most
	 * indices, or the right-most wildcards are substituted for the right-most indices, depending on
	 * the alignment.
	 * 
	 * @param align the end to align
	 * @param keys the keys to substitute
	 * @return the pattern or matcher with the applied substitutions
	 */
	PathFilter applyKeys(Align align, List<String> keys);

	default PathFilter applyKeys(Align align, String... keys) {
		return applyKeys(align, List.of(keys));
	}

	default PathFilter applyKeys(String... keys) {
		return applyKeys(Align.LEFT, keys);
	}

	default PathFilter applyIntKeys(int radix, Align align, List<Integer> keys) {
		return applyKeys(align,
			keys.stream().map(k -> Integer.toString(k, radix)).collect(Collectors.toList()));
	}

	default PathFilter applyIntKeys(int radix, Align align, int... keys) {
		return applyKeys(align,
			IntStream.of(keys)
					.mapToObj(k -> Integer.toString(k, radix))
					.collect(Collectors.toList()));
	}

	default PathFilter applyIntKeys(int... keys) {
		return applyIntKeys(10, Align.LEFT, keys);
	}

	/**
	 * Test if any patterns are contained here
	 * 
	 * <p>
	 * Note that the presence of a pattern does not guarantee the presence of a matching object.
	 * However, the absence of any pattern does guarantee no object can match.
	 * 
	 * @return true if equivalent to {@link #NONE}
	 */
	boolean isNone();
}
