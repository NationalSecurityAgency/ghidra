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
package ghidra.generic.util.datastruct;

import java.nio.BufferOverflowException;
import java.nio.BufferUnderflowException;
import java.util.*;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import generic.ULongSpan;
import generic.ULongSpan.*;
import ghidra.util.MathUtilities;

/**
 * A sparse byte array characterized by contiguous dense regions
 * 
 * <p>
 * Notionally, the array is 2 to the power 64 bytes in size. Only the initialized values are
 * actually stored. Uninitialized indices are assumed to have the value 0. Naturally, this
 * implementation works best when the array is largely uninitialized. For efficient use, isolated
 * initialized values should be avoided. Rather, an entire range should be initialized at the same
 * time.
 * 
 * <p>
 * On a number line, the initialized indices of a semisparse array might be depicted:
 * 
 * <pre>
 * -----   --------- - ------         ---
 * </pre>
 * 
 * <p>
 * In contrast, the same for a sparse array might be depicted:
 * 
 * <pre>
 * -    --  -  - -    ---     --     -         -
 * </pre>
 * 
 * <p>
 * This implementation is well-suited for memory caches where the memory is accessed by reading
 * ranges instead of individual bytes. Because consecutive reads and writes tend to occur in a
 * common locality, caches using a semisparse array may perform well.
 * 
 * <p>
 * This implementation is also thread-safe. Any thread needing exclusive access for multiple reads
 * and/or writes, e.g., to implement a compare-and-set operation, must apply additional
 * synchronization.
 */
public class SemisparseByteArray {
	/** The size of blocks used internally to store array values */
	public static final int BLOCK_SIZE = 0x1000;

	private final Map<Long, byte[]> blocks;
	private final MutableULongSpanSet defined;

	public SemisparseByteArray() {
		this.blocks = new HashMap<>();
		this.defined = new DefaultULongSpanSet();
	}

	protected SemisparseByteArray(Map<Long, byte[]> blocks, MutableULongSpanSet defined) {
		this.blocks = blocks;
		this.defined = defined;
	}

	static byte[] copyArr(Map.Entry<?, byte[]> ent) {
		byte[] b = ent.getValue();
		return Arrays.copyOf(b, b.length);
	}

	public synchronized SemisparseByteArray fork() {
		// TODO Could use some copy-on-write optimization here and in parents
		Map<Long, byte[]> copyBlocks = blocks.entrySet()
				.stream()
				.collect(Collectors.toMap(Entry::getKey, SemisparseByteArray::copyArr));
		MutableULongSpanSet copyDefined = new DefaultULongSpanSet();
		copyDefined.addAll(defined);
		return new SemisparseByteArray(copyBlocks, copyDefined);
	}

	/**
	 * Clear the array
	 * 
	 * <p>
	 * All indices will be uninitialized after this call, just as it was immediately after
	 * construction
	 */
	public synchronized void clear() {
		defined.clear();
		blocks.clear();
	}

	/**
	 * Copy a range of data from the semisparse array into the given byte array
	 * 
	 * @see #getData(long, byte[], int, int)
	 * @param loc the index to begin copying data out
	 * @param data the array to copy data into
	 */
	public synchronized void getData(long loc, byte[] data) {
		getData(loc, data, 0, data.length);
	}

	/**
	 * Copy a range of data from the semisparse array into a portion of the given byte array
	 * 
	 * <p>
	 * Copies {@code length} bytes of data from the semisparse array starting at index {@code loc}
	 * into {@code data} starting at index {@code} offset. All initialized portions within the
	 * requested region are copied. The uninitialized portions may be treated as zeroes or not
	 * copied at all. Typically, the destination array has been initialized to zero by the caller,
	 * such that all uninitialized portions are zero. To avoid fetching uninitialized data, use
	 * {@link #contiguousAvailableAfter(long)} as an upper bound on the length.
	 * 
	 * @param loc the index to begin copying data out
	 * @param data the array to copy data into
	 * @param offset the offset into the destination array
	 * @param length the length of data to read
	 */
	public synchronized void getData(final long loc, final byte[] data, final int offset,
			final int length) {
		if (length < 0) {
			throw new IllegalArgumentException("length: " + length);
		}
		// Read in portion of first block (could be full block)
		long blockNum = Long.divideUnsigned(loc, BLOCK_SIZE);
		int blockOffset = (int) Long.remainderUnsigned(loc, BLOCK_SIZE);
		byte[] block = blocks.get(blockNum);
		int amt = Math.min(length, BLOCK_SIZE - blockOffset);
		if (block != null) {
			System.arraycopy(block, blockOffset, data, offset, amt);
		}

		// Read in each following block
		int cur = amt;
		while (cur < length) {
			blockNum++;
			if (blockNum == 0) {
				throw new BufferUnderflowException();
			}
			block = blocks.get(blockNum);
			amt = Math.min(length - cur, BLOCK_SIZE);
			if (block != null) {
				System.arraycopy(block, 0, data, cur + offset, amt);
			}
			cur += amt;
		}
	}

	/**
	 * Enumerate the initialized ranges within the given range
	 * 
	 * <p>
	 * The given range is interpreted as closed, i.e., [a, b].
	 * 
	 * @param a the lower-bound, inclusive, of the range
	 * @param b the upper-bound, inclusive, of the range
	 * @return the set of initialized ranges
	 */
	public synchronized ULongSpanSet getInitialized(long a, long b) {
		MutableULongSpanSet result = new DefaultULongSpanSet();
		ULongSpan query = ULongSpan.span(a, b);
		for (ULongSpan span : defined.intersecting(query)) {
			result.add(query.intersect(span));
		}
		return result;
	}

	/**
	 * Check if a range is completely initialized
	 * 
	 * <p>
	 * The given range is interpreted as closed, i.e., [a, b].
	 * 
	 * @param a the lower-bound, inclusive, of the range
	 * @param b the upper-bound, inclusive, of the range
	 * @return true if all indices in the range are initialized, false otherwise
	 */
	public synchronized boolean isInitialized(long a, long b) {
		return defined.encloses(ULongSpan.span(a, b));
	}

	/**
	 * Check if an index is initialized
	 * 
	 * @param a the index to check
	 * @return true if the index is initialized, false otherwise
	 */
	public synchronized boolean isInitialized(long a) {
		return defined.contains(a);
	}

	/**
	 * Enumerate the uninitialized ranges within the given range
	 * 
	 * <p>
	 * The given range is interpreted as closed, i.e., [a, b].
	 * 
	 * @param a the lower-bound, inclusive, of the range
	 * @param b the upper-bound, inclusive, of the range
	 * @return the set of uninitialized ranges
	 */
	public synchronized ULongSpanSet getUninitialized(long a, long b) {
		MutableULongSpanSet result = new DefaultULongSpanSet();
		for (ULongSpan s : defined.complement(ULongSpan.span(a, b))) {
			result.add(s);
		}
		return result;
	}

	/**
	 * Initialize or modify a range of the array by copying from a given array
	 * 
	 * @see #putData(long, byte[], int, int)
	 * @param loc the index of the semisparse array to begin copying into
	 * @param data the data to copy
	 */
	public synchronized void putData(long loc, byte[] data) {
		putData(loc, data, 0, data.length);
	}

	/**
	 * Initialize or modify a range of the array by copying a portion from a given array
	 * 
	 * @param loc the index of the semisparse array to begin copying into
	 * @param data the source array to copy from
	 * @param offset the offset of the source array to begin copying from
	 * @param length the length of data to copy
	 */
	public synchronized void putData(final long loc, final byte[] data, final int offset,
			final int length) {
		if (length < 0) {
			throw new IllegalArgumentException("length: " + length);
		} else if (length == 0) {
			return;
		}
		defined.add(ULongSpan.extent(loc, length));

		// Write out portion of first block (could be full block)
		long blockNum = Long.divideUnsigned(loc, BLOCK_SIZE);
		int blockOffset = (int) Long.remainderUnsigned(loc, BLOCK_SIZE);
		byte[] block = blocks.computeIfAbsent(blockNum, n -> new byte[BLOCK_SIZE]);
		int amt = Math.min(length, BLOCK_SIZE - blockOffset);
		System.arraycopy(data, offset, block, blockOffset, amt);

		// Write out each following block
		int cur = amt;
		while (cur < length) {
			blockNum++;
			if (blockNum == 0) {
				throw new BufferOverflowException();
			}
			block = blocks.computeIfAbsent(blockNum, n -> new byte[BLOCK_SIZE]);
			amt = Math.min(length - cur, BLOCK_SIZE);
			System.arraycopy(data, cur + offset, block, 0, amt);
			cur += amt;
		}
	}

	/**
	 * Copy the contents on another semisparse array into this one
	 * 
	 * @param from the source array
	 */
	public synchronized void putAll(SemisparseByteArray from) {
		byte[] temp = new byte[4096];
		for (ULongSpan span : from.defined.spans()) {
			long lower = span.min();
			long length = span.length();
			for (long i = 0; Long.compareUnsigned(i, length) < 0;) {
				int l = MathUtilities.unsignedMin(temp.length, length - i);
				from.getData(lower + i, temp, 0, l);
				this.putData(lower + i, temp, 0, l);
				i += l;
			}
		}
	}

	/**
	 * Check how many contiguous bytes are available starting at the given address
	 * 
	 * @param loc the starting offset
	 * @return the number of contiguous defined bytes following
	 */
	public synchronized int contiguousAvailableAfter(long loc) {
		ULongSpan span = defined.spanContaining(loc);
		if (span == null) {
			return 0;
		}
		long diff = span.max() - loc + 1;
		return MathUtilities.unsignedMin(Integer.MAX_VALUE, diff);
	}
}
