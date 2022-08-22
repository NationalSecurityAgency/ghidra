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
import java.util.function.BinaryOperator;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * A mutable, but fixed-size, buffer of taint sets
 * 
 * <p>
 * This is the auxiliary type used by the Taint Analyzer's emulator.
 * 
 * <p>
 * Regarding serialization, we do not serialize the vector for storage, but only for display. For
 * storage, we instead serialize and store each taint set on an address-by-address basis. Thus, we
 * do not (yet) have a {@code parse(String)} method.
 */
public class TaintVec {
	/**
	 * Create a vector of empty taint sets
	 * 
	 * @param size the length of the vector
	 * @return the new vector
	 */
	public static TaintVec empties(int size) {
		return copies(TaintSet.EMPTY, size);
	}

	/**
	 * Broadcast the given set into a new vector or the given length
	 * 
	 * @param taint the taint set
	 * @param size the length of the vector
	 * @return the new vector
	 */
	public static TaintVec copies(TaintSet taint, int size) {
		return new TaintVec(size).setCopies(taint);
	}

	/**
	 * Create a taint vector representing a new tainted byte array, where each element is given a
	 * distinct name
	 * 
	 * <p>
	 * For example, the parameters {@code ("arr", 0, 4)} will produce the vector
	 * "{@code [arr_0][arr_1][arr_2][arr_3]}". Each element is a singleton set containing the mark
	 * for a byte in the tainted array.
	 * 
	 * @param name the base for naming each element
	 * @param start the starting index for naming each element
	 * @param size the number of bytes, i.e., the length of the vector
	 * @return the new vector
	 */
	public static TaintVec array(String name, long start, int size) {
		return new TaintVec(size).setArray(name, start);
	}

	private TaintSet[] sets;
	private List<TaintSet> setsView;
	public final int length;

	/**
	 * Create a new uninitialized taint vector of the given length
	 * 
	 * @param length the length
	 */
	public TaintVec(int length) {
		this.sets = new TaintSet[length];
		this.setsView = Collections.unmodifiableList(Arrays.asList(sets));
		this.length = sets.length;
	}

	@Override
	public String toString() {
		return String.format("<TaintVec: %s>", toDisplay());
	}

	/**
	 * Convert the vector to a string suitable for display in the UI
	 * 
	 * @return the string
	 */
	public String toDisplay() {
		return Stream.of(sets).map(e -> "[" + e + "]").collect(Collectors.joining());
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof TaintVec)) {
			return false;
		}
		TaintVec that = (TaintVec) obj;
		return Objects.equals(this.setsView, that.setsView);
	}

	@Override
	public int hashCode() {
		return Objects.hash(setsView);
	}

	/**
	 * Get the vector as a list
	 * 
	 * @return the list
	 */
	public List<TaintSet> getSets() {
		return setsView;
	}

	/**
	 * Get an element from the vector
	 * 
	 * @param i the index
	 * @return the taint set
	 */
	public TaintSet get(int i) {
		return sets[i];
	}

	/**
	 * Set an element in the vector
	 * 
	 * @param i the index
	 * @param s the taint set
	 */
	public void set(int i, TaintSet s) {
		sets[i] = s;
	}

	/**
	 * Set several elements in the vector
	 * 
	 * <p>
	 * This is essentially just an array copy. The entire source {@code vec} is copied into this
	 * vector such that the first element of the source is placed at the start index of the
	 * destination.
	 * 
	 * @param start the starting index
	 * @param vec the vector of sets
	 * @return this vector
	 */
	public TaintVec set(int start, TaintVec vec) {
		for (int i = 0; i < vec.length; i++) {
			sets[i + start] = vec.sets[i];
		}
		return this;
	}

	/**
	 * Perform an operation on each same-indexed element from this and another vector, forming a
	 * third result vector
	 * 
	 * <p>
	 * In essence return, a vector where {@code result[n] = this[n] op that[n]}. The two input
	 * vectors must match in length.
	 * 
	 * @param that the other vector
	 * @param op the operation to apply
	 * @return the result
	 */
	private TaintVec zip(TaintVec that, BinaryOperator<TaintSet> op) {
		final int length = this.sets.length;
		if (length != that.sets.length) {
			throw new IllegalArgumentException("TaintVecs must match in length");
		}
		TaintVec vec = new TaintVec(length);
		for (int i = 0; i < length; i++) {
			vec.sets[i] = op.apply(this.sets[i], that.sets[i]);
		}
		return vec;
	}

	/**
	 * Perform an operation on a given taint set and each element from this array, forming a result
	 * vector
	 * 
	 * <p>
	 * In essence, return a vector where {@code result[n] = this[n] op set}.
	 * 
	 * @param set the taint set
	 * @param op the operation to apply
	 * @return the result
	 */
	private TaintVec each(TaintSet set, BinaryOperator<TaintSet> op) {
		final int length = this.sets.length;
		TaintVec vec = new TaintVec(length);
		for (int i = 0; i < length; i++) {
			vec.sets[i] = op.apply(this.sets[i], set);
		}
		return vec;
	}

	/**
	 * Union each element with its corresponding element from another vector, forming a new result
	 * vector
	 * 
	 * @param that the other vector
	 * @return the result
	 */
	public TaintVec zipUnion(TaintVec that) {
		return zip(that, TaintSet::union);
	}

	/**
	 * Union each element with the given set, forming a new result vector
	 * 
	 * @param set the taint set
	 * @return the result
	 */
	public TaintVec eachUnion(TaintSet set) {
		return each(set, TaintSet::union);
	}

	/**
	 * Reduce this vector to a single taint set by union
	 * 
	 * @return the resulting taint set
	 */
	public TaintSet union() {
		Set<TaintMark> result = new HashSet<>();
		for (int i = 0; i < sets.length; i++) {
			result.addAll(sets[i].marks);
		}
		return TaintSet.of(result);
	}

	/**
	 * Combine this and another taint vector to represent a tainted indirect read
	 * 
	 * <p>
	 * Because the all bytes of the address offset "affect" the value read, we first union all the
	 * taint sets of the that offset. We then tag each mark in that union with "{@code indR}".
	 * Finally we union that result with each element of this vector (this vector representing the
	 * bytes read from memory).
	 * 
	 * @param offset the vector representing the bytes that encode the offset
	 * @return the vector representing the tainted bytes read from memory
	 */
	public TaintVec tagIndirectRead(TaintVec offset) {
		TaintSet taintOffset = offset.union().tagged("indR");
		return eachUnion(taintOffset);
	}

	/**
	 * Combine this and another taint vector to represent a tainted indirect write
	 * 
	 * <p>
	 * This works the same as {@link #tagIndirectRead(TaintVec)}, except with the tag "{@code indW}"
	 * and it occurs before the actual write.
	 * 
	 * @param offset the vector representing the bytes that encode the offset
	 * @return the vector representing the tainted bytes to be written to memory
	 */
	public TaintVec tagIndirectWrite(TaintVec offset) {
		TaintSet taintOffset = offset.union().tagged("indW");
		return eachUnion(taintOffset);
	}

	/**
	 * Broadcast the given set over this vector, modifying it in place
	 * 
	 * @param taint the taint set
	 * @return this vector
	 */
	public TaintVec setCopies(TaintSet taint) {
		for (int i = 0; i < length; i++) {
			sets[i] = taint;
		}
		return this;
	}

	/**
	 * Broadcast the empty taint set over this vector, modifying it in place
	 * 
	 * @return this vector
	 */
	public TaintVec setEmpties() {
		return setCopies(TaintSet.EMPTY);
	}

	/**
	 * Fill this vector as in {@link #array(String, long, int)}, modifying it in place
	 * 
	 * @param name the base for naming each element
	 * @param start the starting index for naming each element
	 * @return this vector
	 */
	public TaintVec setArray(String name, long start) {
		for (int i = 0; i < length; i++) {
			sets[i] = TaintSet.of(new TaintMark(name + "_" + (start + i), Set.of()));
		}
		return this;
	}

	/**
	 * Modify the vector so each element becomes the union of itself and all elements of lesser
	 * significance
	 * 
	 * <p>
	 * This should be used after {@link #zipUnion(TaintVec)} to model operations with carries.
	 * 
	 * @param isBigEndian true if smaller indices have greater significance
	 * @return this vector
	 */
	public TaintVec setCascade(boolean isBigEndian) {
		if (isBigEndian) {
			for (int i = length - 2; i >= 0; i--) {
				sets[i] = sets[i].union(sets[i + 1]);
			}
		}
		for (int i = 0; i < length - 1; i++) {
			sets[i + 1] = sets[i + 1].union(sets[i]);
		}
		return this;
	}

	/**
	 * Modify the vector so each element becomes the union of itself and its neighbor
	 * 
	 * <p>
	 * This should be used to model shift operations. Both the shift direction and the endianness
	 * must be considered.
	 * 
	 * @param right true to cause each greater index to be unioned in place with less-indexed
	 *            neighbor
	 * @return this vector
	 */
	public TaintVec setBlur(boolean right) {
		if (right) {
			for (int i = length - 2; i >= 0; i--) {
				sets[i + 1] = sets[i + 1].union(sets[i]);
			}
		}
		for (int i = 0; i < length - 1; i++) {
			sets[i] = sets[i].union(sets[i + 1]);
		}
		return this;
	}

	public enum ShiftMode {
		UNBOUNDED {
			@Override
			int adjustRight(int right, int length) {
				return right;
			}

			@Override
			int adjustSrc(int src, int length) {
				return src;
			}
		},
		REMAINDER {
			@Override
			int adjustRight(int right, int length) {
				return right % length;
			}

			@Override
			int adjustSrc(int src, int length) {
				return src;
			}
		},
		CIRCULAR {
			@Override
			int adjustRight(int right, int length) {
				return right % length;
			}

			@Override
			int adjustSrc(int src, int length) {
				int temp = src % length;
				if (temp < 0) {
					return temp + length;
				}
				return temp;
			}
		};

		abstract int adjustRight(int right, int length);

		abstract int adjustSrc(int src, int length);
	}

	/**
	 * Shift this vector some number of elements, in place
	 * 
	 * @param right the number of elements to shift right, or negative for left
	 * @return this vector
	 */
	public TaintVec setShifted(int right, ShiftMode mode) {
		right = mode.adjustRight(right, length);
		if (right > length || -right > length) {
			return setEmpties();
		}
		if (right < 0) {
			TaintSet start = sets[0];
			for (int i = 0; i < length; i++) {
				int src = mode.adjustSrc(i - right, length);
				if (src < 0 || src >= length) {
					break;
				}
				sets[i] = src == 0 ? start : sets[src];
			}
		}
		else {
			TaintSet start = sets[length - 1];
			for (int i = 0; i < length - 1; i++) {
				int src = mode.adjustSrc(i - right, length);
				if (src < 0 || src >= length) {
					break;
				}
				sets[i] = src == length - 1 ? start : sets[src];
			}
		}
		return this;
	}

	/**
	 * Drop all but length elements from this vector, creating a new vector
	 * 
	 * <p>
	 * Drops the most significant elements of this vector, as specified by the endianness
	 * 
	 * @param length the length fo the new vector
	 * @param isBigEndian true to drop lower-indexed elements, false to drop higher-indexed elements
	 * @return the truncated vector
	 */
	public TaintVec truncated(int length, boolean isBigEndian) {
		if (length > this.length) {
			throw new IllegalArgumentException();
		}
		TaintVec vec = new TaintVec(length);
		int diff = isBigEndian ? this.length - length : 0;
		for (int i = 0; i < length; i++) {
			vec.sets[i] = vec.sets[i + diff];
		}
		return vec;
	}

	/**
	 * Create a copy of this vector
	 * 
	 * @return the copy
	 */
	public TaintVec copy() {
		TaintVec vec = new TaintVec(length);
		for (int i = 0; i < length; i++) {
			vec.sets[i] = sets[i];
		}
		return vec;
	}

	/**
	 * Extend this vector to create a new vector of the given length
	 * 
	 * <p>
	 * Elements are appended at the most significant end, as specified by the endianness. If signed,
	 * the appended elements are copies of the most significant element in this vector. Otherwise,
	 * they are empty taint sets.
	 * 
	 * @param length the length of the new vector
	 * @param isBigEndian true to append to the lower-indexed end, false to append to the
	 *            higher-indexed end
	 * @param isSigned true to append copies of the most significant element, false to append empty
	 *            sets
	 * @return the new vector
	 */
	public TaintVec extended(int length, boolean isBigEndian, boolean isSigned) {
		if (length < this.length) {
			return truncated(length, isBigEndian);
		}
		TaintVec vec = new TaintVec(length);
		int diff = isBigEndian ? length - this.length : 0;
		for (int i = 0; i < this.length; i++) {
			vec.sets[i + diff] = vec.sets[i];
		}
		TaintSet ext = isSigned ? isBigEndian ? sets[0] : sets[this.length - 1] : TaintSet.EMPTY;
		int start = isBigEndian ? 0 : this.length;
		for (int i = 0; i < diff; i++) {
			vec.sets[start + i] = ext;
		}
		return vec;
	}
}
