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
package ghidra.trace.model.target;

import java.util.*;
import java.util.stream.Stream;

import ghidra.dbg.util.PathPredicates;
import ghidra.dbg.util.PathUtils;
import ghidra.dbg.util.PathUtils.PathComparator;

/**
 * An immutable path of keys leading from one object object to another
 * 
 * <p>
 * Often, the source is the root. These are often taken as a parameter when searching for values. In
 * essence, they simply wrap a list of string keys, but it provides convenience methods, sensible
 * comparison, and better typing.
 */
public final class TraceObjectKeyPath implements Comparable<TraceObjectKeyPath> {

	/**
	 * Create a path from the given list of keys
	 * 
	 * @param keyList the list of keys from source to destination
	 * @return the path
	 */
	public static TraceObjectKeyPath of(List<String> keyList) {
		return new TraceObjectKeyPath(List.copyOf(keyList));
	}

	/**
	 * Create a path from the given keys
	 * 
	 * @param keys the keys from source to destination
	 * @return the path
	 */
	public static TraceObjectKeyPath of(String... keys) {
		return new TraceObjectKeyPath(List.of(keys));
	}

	/**
	 * Parse a path from the given string
	 * 
	 * @param path the dot-separated keys from source to destinattion
	 * @return the path
	 */
	public static TraceObjectKeyPath parse(String path) {
		return new TraceObjectKeyPath(PathUtils.parse(path));
	}

	private final List<String> keyList;
	private final int hash;

	private TraceObjectKeyPath(List<String> keyList) {
		this.keyList = keyList;
		this.hash = Objects.hash(keyList);
	}

	@Override
	public int hashCode() {
		return hash;
	}

	@Override
	public int compareTo(TraceObjectKeyPath that) {
		if (this == that) {
			return 0;
		}
		return PathComparator.KEYED.compare(this.keyList, that.keyList);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof TraceObjectKeyPath)) {
			return false;
		}
		TraceObjectKeyPath that = (TraceObjectKeyPath) obj;
		return this.keyList.equals(that.keyList);
	}

	/**
	 * Get the (immutable) list of keys from source to destination
	 * 
	 * @return the key list
	 */
	public List<String> getKeyList() {
		return keyList;
	}

	/**
	 * Assuming the source is the root, check if this path refers to that root
	 * 
	 * @return true if the path is empty, false otherwise
	 */
	public boolean isRoot() {
		return keyList.isEmpty();
	}

	/**
	 * Create a new path by appending the given key
	 * 
	 * <p>
	 * For example, if this path is "{@code Processes[2]}" and {@code name} takes the value
	 * "{@code Threads}", the result will be "{@code Processes[2].Threads}".
	 * 
	 * @param name the new final key
	 * @return the resulting path
	 */
	public TraceObjectKeyPath key(String name) {
		return new TraceObjectKeyPath(PathUtils.extend(keyList, name));
	}

	/**
	 * Get the final key of this path
	 * 
	 * @return the final key
	 */
	public String key() {
		return PathUtils.getKey(keyList);
	}

	/**
	 * Create a new path by appending the given element index
	 * 
	 * <p>
	 * For example, if this path is "{@code Processes}" and {@code index} takes the value 2, the
	 * result will be "{@code Processes[2]}".
	 * 
	 * @param index the new final index
	 * @return the resulting path
	 */
	public TraceObjectKeyPath index(long index) {
		return index(PathUtils.makeIndex(index));
	}

	/**
	 * Create a new path by appending the given element index
	 * 
	 * <p>
	 * This does the same as {@link #key(String)} but uses brackets instead. For example, if this
	 * path is "{@code Processes[2].Threads[0].Registers}" and {@code index} takes the value
	 * "{@code RAX}", the result will be "{@code Processes[2].Threads[0].Registers[RAX]"}.
	 * 
	 * @param index the new final index
	 * @return the resulting path
	 */
	public TraceObjectKeyPath index(String index) {
		return new TraceObjectKeyPath(PathUtils.index(keyList, index));
	}

	/**
	 * Get the final index of this path
	 * 
	 * @return the final index
	 * @throws IllegalArgumentException if the final key is not an index, i.e., in brackets
	 */
	public String index() {
		return PathUtils.getIndex(keyList);
	}

	@Override
	public String toString() {
		return PathUtils.toString(keyList);
	}

	/**
	 * Create a new path by removing the final key
	 * 
	 * @return the resulting path, or null if this path is empty
	 */
	public TraceObjectKeyPath parent() {
		List<String> pkl = PathUtils.parent(keyList);
		return pkl == null ? null : new TraceObjectKeyPath(pkl);
	}

	/**
	 * Create a new path by appending the given list of keys
	 * 
	 * <p>
	 * For example, if this path is "{@code Processes[2]}" and {@code subKeyList} takes the value
	 * {@code List.of("Threads", "[0]")}, the result will be "{@code Processes[2].Threads[0]}".
	 * 
	 * @param subKeyList the list of keys to append
	 * @return the resulting path
	 */
	public TraceObjectKeyPath extend(List<String> subKeyList) {
		return new TraceObjectKeyPath(PathUtils.extend(keyList, subKeyList));
	}

	/**
	 * Create a new path by appending the given keys
	 * 
	 * @see #extend(List)
	 * @param subKeyList the keys to append
	 * @return the resulting path
	 */
	public TraceObjectKeyPath extend(String... subKeyList) {
		return extend(Arrays.asList(subKeyList));
	}

	/**
	 * Stream, starting with the longer paths, paths that match the given predicates
	 * 
	 * @param matcher
	 * @return
	 */
	public Stream<TraceObjectKeyPath> streamMatchingAncestry(PathPredicates predicates) {
		if (!predicates.ancestorMatches(keyList, false)) {
			return Stream.of();
		}
		Stream<TraceObjectKeyPath> ancestry =
			isRoot() ? Stream.of() : parent().streamMatchingAncestry(predicates);
		if (predicates.matches(keyList)) {
			return Stream.concat(Stream.of(this), ancestry);
		}
		return ancestry;
	}

	/**
	 * Check if this path is an ancestor of the given path
	 * 
	 * <p>
	 * Equivalently, check if the given path is a successor of this path. A path is considered an
	 * ancestor of itself. To check for a strict ancestor, use
	 * {@code this.isAncestor(that) && !this.equals(that)}.
	 * 
	 * @param that the supposed successor to this path
	 * @return true if the given path is in fact a successor
	 */
	public boolean isAncestor(TraceObjectKeyPath that) {
		return PathUtils.isAncestor(keyList, that.keyList);
	}
}
