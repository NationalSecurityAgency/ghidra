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
package ghidra.taint.model;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * An immutable set of multiple taint marks
 * 
 * <p>
 * A variable in an emulator could be tainted by multiple marks, so we must use vectors of sets, not
 * vectors of marks. Please see {@link TaintMark#equals(Object)} regarding the equality of tagged
 * marks.
 */
public class TaintSet {
	private static final String SEP = ";";
	/** The empty set, the default for all state variables */
	public static final TaintSet EMPTY = new TaintSet(Set.of());

	/**
	 * Parse a set of taint marks
	 * 
	 * <p>
	 * The form is a semicolon-separated list of taint marks, e.g.,
	 * "{@code myVar:tag1,tag2;anotherVar;yetAnother}".
	 * 
	 * @param string the string to parse
	 * @return the resulting set
	 */
	public static TaintSet parse(String string) {
		return new TaintSet(Stream.of(string.split(SEP))
				.map(TaintMark::parse)
				.collect(Collectors.toUnmodifiableSet()));
	}

	/**
	 * Create a taint set of the given marks
	 * 
	 * @param marks the marks
	 * @return the set
	 */
	public static TaintSet of(TaintMark... marks) {
		return new TaintSet(Set.of(marks));
	}

	/**
	 * Create a taint set of the given marks
	 * 
	 * @param marks the marks
	 * @return the set
	 */
	static TaintSet of(Set<TaintMark> marks) {
		return new TaintSet(Set.copyOf(marks));
	}

	final Set<TaintMark> marks;
	private final int hashCode;

	TaintSet(Set<TaintMark> marks) {
		this.marks = marks; // Must be immutable
		this.hashCode = Objects.hashCode(marks);
	}

	/**
	 * Convert the set to a string
	 * 
	 * @see #parse(String)
	 */
	@Override
	public String toString() {
		return marks.stream().map(TaintMark::toString).collect(Collectors.joining(SEP));
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof TaintSet)) {
			return false;
		}
		TaintSet that = (TaintSet) obj;
		return Objects.equals(this.marks, that.marks);
	}

	@Override
	public int hashCode() {
		return hashCode;
	}

	/**
	 * Get the marks in this set
	 * 
	 * @return the marks
	 */
	public Set<TaintMark> getMarks() {
		return marks;
	}

	/**
	 * Check if this set is empty
	 * 
	 * @return the marks
	 */
	public boolean isEmpty() {
		return marks.isEmpty();
	}

	/**
	 * Construct the taint set from the union of marks of this and the given taint set
	 * 
	 * @param that another taint set
	 * @return the union
	 */
	public TaintSet union(TaintSet that) {
		Set<TaintMark> marks = new HashSet<>();
		// TODO: What's the most efficient data structure here?
		marks.addAll(this.marks);
		marks.addAll(that.marks);
		return of(marks);
	}

	/**
	 * Construct the taint set formed by tagging each mark in this set
	 * 
	 * @param string the tag to add to each mark
	 * @return the new set
	 */
	public TaintSet tagged(String string) {
		int size = this.marks.size();
		Set<TaintMark> marks = new HashSet<>(size);
		for (TaintMark m : this.marks) {
			marks.add(m.tagged(string));
		}
		return of(marks);
	}
}
