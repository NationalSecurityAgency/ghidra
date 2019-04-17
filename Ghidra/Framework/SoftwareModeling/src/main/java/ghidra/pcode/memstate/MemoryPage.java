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
package ghidra.pcode.memstate;

import java.util.Arrays;

/**
 * <code>MemoryPage</code> is allows the contents/data of a memory page
 * to be maintained along with an initializedMask.  Each bit within the
 * initializedMask corresponds to a data byte within the page.  A null
 * mask indicates that all data within the page is initialized.  A one-bit
 * within the mask indicates that the corresponding data byte is initialized.
 */
public class MemoryPage {

	public final byte[] data;
	private byte[] initializedMask;

	/**
	 * Construct a new fully initialized page containing
	 * all zero (0) byte data.
	 */
	public MemoryPage(int pageSize) {
		data = new byte[pageSize];
	}

	/**
	 * Construct a memory page with an existing data bytes buffer
	 * @param bytes buffer
	 */
	public MemoryPage(byte[] bytes) {
		data = bytes;
	}

	public byte[] getInitializedMask() {
		return initializedMask;
	}

	/**
	 * Mark entire page as uninitialized
	 */
	public void setUninitialized() {
		initializedMask = getInitializedMask(data.length, false);
	}

	/**
	 * Mark entire page as uninitialized
	 */
	public void setInitialized() {
		initializedMask = getInitializedMask(data.length, true);
	}

	/**
	 * Update initialization mask
	 * @param pageOffset
	 * @param size
	 * @param maskUpdate
	 */
	public void setInitialized(int pageOffset, int size, byte[] maskUpdate) {
		int maskOffset = pageOffset / 8;
		int firstBit = pageOffset % 8;
		while (size > 0) {
			int s = Math.min(size, 8 - firstBit);
			size -= s;
			int mask = (0xff << firstBit) & ((1 << (firstBit + s)) - 1);
			int val = mask;
			if (maskUpdate != null) {
				val &= maskUpdate[maskOffset];
			}
			if (initializedMask == null) {
				// allocate mask if needed
				byte test = (byte) (val | ~mask);
				if (test == (byte) -1) {
					++maskOffset;
					firstBit = 0;
					continue;
				}
				initializedMask = getInitializedMask(data.length, true);
			}
			initializedMask[maskOffset] = (byte) ((initializedMask[maskOffset] & ~mask) | val);
			++maskOffset;
			firstBit = 0;
		}
	}

	/**
	 * Mark specified page region as initialized.
	 * @param pageOffset
	 * @param size
	 */
	public void setInitialized(int pageOffset, int size) {
		if (initializedMask == null) {
			return;
		}
		if (pageOffset == 0 && size == data.length) {
			initializedMask = null;
			return;
		}
		setInitialized(initializedMask, pageOffset, size);
	}

	/**
	 * Mark specified page region as uninitialized.
	 * @param pageOffset
	 * @param size
	 */
	public void setUninitialized(int pageOffset, int size) {
		if (initializedMask == null) {
			initializedMask = getInitializedMask(data.length, true);
		}
		setUninitialized(initializedMask, pageOffset, size);
	}

	/**
	 * Get number of leading bytes within page range which have been 
	 * initialized.
	 * @param pageOffset
	 * @param size
	 * @return number of leading bytes within page range which have been 
	 * initialized.
	 */
	public int getInitializedByteCount(int pageOffset, int size) {
		return getInitializedByteCount(initializedMask, pageOffset, size);
	}

	/**
	 * Generate an initialized mask for the specified page size
	 * @param pageSize
	 * @param initialized
	 * @return
	 */
	public static byte[] getInitializedMask(int pageSize, boolean initialized) {
		byte[] mask = new byte[(pageSize + 7) / 8];
		if (initialized) {
			Arrays.fill(mask, (byte) -1);
		}
		return mask;
	}

	/**
	 * Generate an initialized mask for the specified page size.
	 * The region is identified by offset and size.  The remaining portions
	 * of the mask will be set based upon !initialized.
	 * @param pageSize
	 * @param offset
	 * @param size
	 * @param initialized
	 * @return
	 */
	public static byte[] getInitializedMask(int pageSize, int offset, int size,
			boolean initialized) {
		byte[] mask = getInitializedMask(pageSize, true);
		if (initialized) {
			if (offset != 0) {
				setUninitialized(mask, 0, offset);
			}
			int end = offset + size;
			if (end < pageSize) {
				setUninitialized(mask, end, pageSize - end);
			}
		}
		else if (size != 0) {
			setUninitialized(mask, offset, size);
		}
		return mask;
	}

	/**
	 * Mark specified page region as initialized.
	 * @param initializedMask
	 * @param pageOffset
	 * @param size
	 */
	public static void setInitialized(byte[] initializedMask, int pageOffset, int size) {
		int maskOffset = pageOffset / 8;
		int firstBit = pageOffset % 8;
		while (size > 0) {
			int s = Math.min(size, 8 - firstBit);
			size -= s;
			int mask = (0xff << firstBit) & ((1 << (firstBit + s)) - 1);
			initializedMask[maskOffset] |= (byte) mask;
			++maskOffset;
			firstBit = 0;
		}
	}

	/**
	 * Mark specified page region as uninitialized.
	 * @param initializedMask
	 * @param pageOffset
	 * @param size
	 */
	public static void setUninitialized(byte[] initializedMask, int pageOffset, int size) {
		int maskOffset = pageOffset / 8;
		int firstBit = pageOffset % 8;
		while (size > 0) {
			int s = Math.min(size, 8 - firstBit);
			size -= s;
			int mask = (0xff << firstBit) & ((1 << (firstBit + s)) - 1);
			initializedMask[maskOffset] &= (byte) ~mask;
			++maskOffset;
			firstBit = 0;
		}
	}

	/**
	 * Determine how many leading bytes of a specified page region is marked as
	 * initialized.  Valid page region defined by pageOffset and size is assumed.
	 * @param initializedMask
	 * @param pageOffset
	 * @param size 
	 * @return number of leading bytes at pageOffset (upto size) are initialized.
	 */
	public static int getInitializedByteCount(byte[] initializedMask, int pageOffset, int size) {
		if (initializedMask == null) {
			return size;
		}
		int initializedSize = 0;
		int maskOffset = pageOffset / 8;
		int firstBit = pageOffset % 8;
		while (size > 0) {
			int s = Math.min(size, 8 - firstBit); // number of bytes represented by mask
			size -= s;
			int mask = (0xff << firstBit) & ((1 << (firstBit + s)) - 1);
			int result = initializedMask[maskOffset] & mask;
			if (result != mask) {
				// count leading bits
				for (result >>= firstBit; (result & 1) != 0; result >>= 1) {
					++initializedSize;
				}
				return initializedSize;
			}
			initializedSize += s;
			++maskOffset;
			firstBit = 0;
		}
		return initializedSize;
	}
}
