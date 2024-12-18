/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.dbg.util;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import ghidra.async.AsyncFence;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.util.PathUtils.PathComparator;
import ghidra.util.ReversedListIterator;

/**
 * @deprecated This will be moved/refactored into trace database. In general, it will still exist,
 *             but things depending on it are now back on shifting sand.
 */
@Deprecated(since = "11.2")
public interface PathPredicates {
	PathPredicates EMPTY = new PathPredicates() {
		@Override
		public PathPredicates or(PathPredicates that) {
			return that;
		}

		@Override
		public boolean matches(List<String> path) {
			return false;
		}

		@Override
		public boolean successorCouldMatch(List<String> path, boolean strict) {
			return false;
		}

		@Override
		public boolean ancestorMatches(List<String> path, boolean strict) {
			return false;
		}

		@Override
		public boolean ancestorCouldMatchRight(List<String> path, boolean strict) {
			return false;
		}

		@Override
		public Set<String> getNextKeys(List<String> path) {
			return Set.of();
		}

		@Override
		public Set<String> getNextNames(List<String> path) {
			return Set.of();
		}

		@Override
		public Set<String> getNextIndices(List<String> path) {
			return Set.of();
		}

		@Override
		public Set<String> getPrevKeys(List<String> path) {
			return Set.of();
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
		public Collection<PathPattern> getPatterns() {
			return List.of();
		}

		@Override
		public PathPredicates removeRight(int count) {
			return this;
		}

		@Override
		public PathPredicates applyKeys(Align align, List<String> keys) {
			return this;
		}

		@Override
		public boolean isEmpty() {
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
	}

	static boolean keyMatches(String pat, String key) {
		if (key.equals(pat)) {
			return true;
		}
		if ("[]".equals(pat)) {
			return PathUtils.isIndex(key);
		}
		if ("".equals(pat)) {
			return PathUtils.isName(key);
		}
		return false;
	}

	static boolean anyMatches(Set<String> pats, String key) {
		return pats.stream().anyMatch(p -> keyMatches(p, key));
	}

	static PathPredicates pattern(String... keyPatterns) {
		return new PathPattern(List.of(keyPatterns));
	}

	static PathPredicates pattern(List<String> keyPatterns) {
		return new PathPattern(keyPatterns);
	}

	static PathPredicates parse(String pattern) {
		return new PathPattern(PathUtils.parse(pattern));
	}

	PathPredicates or(PathPredicates that);

	/**
	 * Check if the entire path passes
	 * 
	 * @param path the path to check
	 * @return true if it matches, false otherwise
	 */
	boolean matches(List<String> path);

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
	 * @param strict true to exclude the case where {@link #matches(List)} would return true
	 * @return true if a successor could match, false otherwise
	 */
	boolean successorCouldMatch(List<String> path, boolean strict);

	/**
	 * Check if the given path has an ancestor that matches
	 * 
	 * @param path the path to check
	 * @param strict true to exclude the case where {@link #matches(List)} would return true
	 * @return true if an ancestor matches, false otherwise
	 */
	boolean ancestorMatches(List<String> path, boolean strict);

	/**
	 * Check if the given path <em>could</em> have a matching ancestor, right to left
	 * 
	 * <p>
	 * This essentially checks if the given path is a viable postfix to the matcher.
	 * 
	 * @param path the path (postfix) to check
	 * @param strict true to exclude the case where {@link #matches(List)} would return true
	 * @return true if an ancestor could match, false otherwise
	 */
	boolean ancestorCouldMatchRight(List<String> path, boolean strict);

	/**
	 * Get the patterns for the next possible key
	 * 
	 * <p>
	 * If a successor of the given path cannot match this pattern, the empty set is returned.
	 * 
	 * @param path the ancestor path
	 * @return a set of patterns where indices are enclosed in brackets ({@code [])
	 */
	Set<String> getNextKeys(List<String> path);

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
	Set<String> getNextNames(List<String> path);

	/**
	 * Assuming a successor of path could match, get the patterns for the next possible index
	 * 
	 * <p>
	 * If a successor of the given path cannot match this pattern, the empty set is returned. If the
	 * pattern could accept an index next, get all patterns describing those indices
	 * 
	 * @param path the ancestor path
	 * @return a set of patterns, without brackets ({@code [])
	 */
	Set<String> getNextIndices(List<String> path);

	/**
	 * Get the patterns for the previous possible key (right-to-left matching)
	 * 
	 * <p>
	 * If an ancestor of the given path cannot match this pattern, the empty set is returned.
	 * 
	 * @param path the successor path
	 * @return a set of patterns where indices are enclosed in brackets ({@code [])
	 */
	Set<String> getPrevKeys(List<String> path);

	/**
	 * If this predicate is known to match only one path, i.e., no wildcards, get that path
	 * 
	 * @return the singleton path, or {@code null}
	 */
	List<String> getSingletonPath();

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
	Collection<PathPattern> getPatterns();

	/**
	 * Remove count elements from the right
	 * 
	 * @param count the number of elements to remove
	 * @return the resulting predicates
	 */
	PathPredicates removeRight(int count);

	default NavigableMap<List<String>, ?> getCachedValues(TargetObject seed) {
		return getCachedValues(List.of(), seed);
	}

	default NavigableMap<List<String>, ?> getCachedValues(List<String> path, Object val) {
		NavigableMap<List<String>, Object> result = new TreeMap<>(PathComparator.KEYED);
		getCachedValues(result, path, val);
		return result;
	}

	default void getCachedValues(Map<List<String>, Object> result, List<String> path, Object val) {
		if (matches(path)) {
			result.put(path, val);
		}
		if (val instanceof TargetObject && successorCouldMatch(path, true)) {
			TargetObject cur = (TargetObject) val;
			Set<String> nextNames = getNextNames(path);
			if (!nextNames.isEmpty()) {
				for (Map.Entry<String, ?> ent : cur.getCachedAttributes().entrySet()) {
					Object value = ent.getValue();
					String name = ent.getKey();
					if (!anyMatches(nextNames, name)) {
						continue;
					}
					getCachedValues(result, PathUtils.extend(path, name), value);
				}
			}
			Set<String> nextIndices = getNextIndices(path);
			if (!nextIndices.isEmpty()) {
				for (Map.Entry<String, ?> ent : cur.getCachedElements().entrySet()) {
					Object obj = ent.getValue();
					String index = ent.getKey();
					if (!anyMatches(nextIndices, index)) {
						continue;
					}
					getCachedValues(result, PathUtils.index(path, index), obj);
				}
			}
		}
	}

	default NavigableMap<List<String>, TargetObject> getCachedSuccessors(TargetObject seed) {
		NavigableMap<List<String>, TargetObject> result = new TreeMap<>(PathComparator.KEYED);
		getCachedSuccessors(result, List.of(), seed);
		return result;
	}

	default void getCachedSuccessors(Map<List<String>, TargetObject> result,
			List<String> path, TargetObject cur) {
		if (matches(path)) {
			result.put(path, cur);
		}
		if (successorCouldMatch(path, true)) {
			Set<String> nextNames = getNextNames(path);
			if (nextNames.equals(PathMatcher.WILD_SINGLETON)) {
				for (Map.Entry<String, ?> ent : cur.getCachedAttributes().entrySet()) {
					if (!(ent.getValue() instanceof TargetObject obj)) {
						continue;
					}
					String name = ent.getKey();
					getCachedSuccessors(result, PathUtils.extend(path, name), obj);
				}
			}
			else {
				for (String name : nextNames) {
					if (!(cur.getCachedAttribute(name) instanceof TargetObject obj)) {
						continue;
					}
					getCachedSuccessors(result, PathUtils.extend(path, name), obj);
				}
			}

			Set<String> nextIndices = getNextIndices(path);
			if (nextIndices.equals(PathMatcher.WILD_SINGLETON)) {
				for (Map.Entry<String, ? extends TargetObject> ent : cur.getCachedElements()
						.entrySet()) {
					TargetObject obj = ent.getValue();
					if (obj == null) {
						return;
					}
					String index = ent.getKey();
					getCachedSuccessors(result, PathUtils.index(path, index), obj);
				}
			}
			else {
				Map<String, ? extends TargetObject> elements = cur.getCachedElements();
				for (String index : nextIndices) {
					TargetObject obj = elements.get(index);
					if (obj == null) {
						return;
					}
					getCachedSuccessors(result, PathUtils.index(path, index), obj);
				}
			}
		}
	}

	default CompletableFuture<NavigableMap<List<String>, TargetObject>> fetchSuccessors(
			TargetObject seed) {
		NavigableMap<List<String>, TargetObject> result = new TreeMap<>(PathComparator.KEYED);
		return fetchSuccessors(result, List.of(), seed).thenApply(__ -> result);
	}

	default CompletableFuture<Void> fetchSuccessors(Map<List<String>, TargetObject> result,
			List<String> path, TargetObject cur) {
		AsyncFence fence = new AsyncFence();
		if (matches(path)) {
			synchronized (result) {
				result.put(path, cur);
			}
		}
		if (successorCouldMatch(path, true)) {
			Set<String> nextNames = getNextNames(path);
			if (!nextNames.isEmpty()) {
				fence.include(cur.fetchAttributes().thenCompose(attrs -> {
					AsyncFence aFence = new AsyncFence();
					for (Map.Entry<String, ?> ent : attrs.entrySet()) {
						Object value = ent.getValue();
						if (!(value instanceof TargetObject)) {
							continue;
						}
						String name = ent.getKey();
						if (!anyMatches(nextNames, name)) {
							continue;
						}
						TargetObject obj = (TargetObject) value;
						aFence.include(
							fetchSuccessors(result, PathUtils.extend(path, name), obj));
					}
					return aFence.ready();
				}));
			}
			Set<String> nextIndices = getNextIndices(path);
			if (!nextIndices.isEmpty()) {
				fence.include(cur.fetchElements().thenCompose(elems -> {
					AsyncFence eFence = new AsyncFence();
					for (Map.Entry<String, ? extends TargetObject> ent : elems.entrySet()) {
						TargetObject obj = ent.getValue();
						String index = ent.getKey();
						if (!anyMatches(nextIndices, index)) {
							continue;
						}
						eFence.include(
							fetchSuccessors(result, PathUtils.index(path, index), obj));
					}
					return eFence.ready();
				}));
			}
		}
		return fence.ready();
	}

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
	PathPredicates applyKeys(Align align, List<String> keys);

	default PathPredicates applyKeys(Align align, String... keys) {
		return applyKeys(align, List.of(keys));
	}

	default PathPredicates applyKeys(String... keys) {
		return applyKeys(Align.LEFT, keys);
	}

	default PathPredicates applyIntKeys(int radix, Align align, List<Integer> keys) {
		return applyKeys(align,
			keys.stream().map(k -> Integer.toString(k, radix)).collect(Collectors.toList()));
	}

	default PathPredicates applyIntKeys(int radix, Align align, int... keys) {
		return applyKeys(align,
			IntStream.of(keys)
					.mapToObj(k -> Integer.toString(k, radix))
					.collect(Collectors.toList()));
	}

	default PathPredicates applyIntKeys(int... keys) {
		return applyIntKeys(10, Align.LEFT, keys);
	}

	/**
	 * Test if any patterns are contained here
	 * 
	 * <p>
	 * Note that the presence of a pattern does not guarantee the presence of a matching object.
	 * However, the absence of any pattern does guarantee no object can match.
	 * 
	 * @return
	 */
	boolean isEmpty();
}
