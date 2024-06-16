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
package ghidra.trace.database.program;

import java.nio.ByteBuffer;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.MathUtilities;

public abstract class ByteCache {
	public static final int BITS = 12;
	public static final long OFFSET_MASK = -1L << BITS;
	public static final int SIZE = 1 << BITS;

	private class Page {
		private volatile boolean valid = false;
		private Address start = null;
		private final byte[] bytes = new byte[SIZE];
		private final ByteBuffer buf = ByteBuffer.wrap(bytes);
		private int len;

		public final boolean contains(Address address, int length) {
			if (!valid || start == null) {
				return false;
			}
			long offset = address.subtract(start);
			return Long.compareUnsigned(offset + length, len) < 0;
		}

		public final int load(Address address, int length) throws MemoryAccessException {
			valid = false;
			start = address.getNewAddress(address.getOffset() & OFFSET_MASK);
			long offset = address.subtract(start);
			buf.clear(); // NB. Do not limit. Cache what we can.
			len = doLoad(address, buf);
			if (len < offset + length) {
				throw new MemoryAccessException();
			}
			valid = true;
			return (int) offset;
		}

		public void invalidate(AddressRange range) {
			// TODO: Is it worth it to check for intersection?
			valid = false;
		}
	}

	private final int pageCount;
	private final Page[] pages;

	public ByteCache(int pageCount) {
		this.pageCount = pageCount;
		pages = new Page[pageCount];
		for (int i = 0; i < pageCount; i++) {
			pages[i] = newPage();
		}
	}

	protected Page newPage() {
		return new Page();
	}

	public boolean canCache(Address address, int len) {
		long cacheBufOff = address.getOffset() & ~OFFSET_MASK;
		return cacheBufOff + len < pageCount * SIZE;
	}

	public byte read(Address address) throws MemoryAccessException {
		Address pageStart = address.getNewAddress(address.getOffset() & OFFSET_MASK);
		Page page = ensurePageCached(pageStart, 1);
		int cacheBufOff = (int) address.subtract(pageStart);
		return page.bytes[cacheBufOff];
	}

	public int read(Address address, ByteBuffer buf) throws MemoryAccessException {
		long startOff = address.getOffset();
		long startPage = startOff & OFFSET_MASK;
		int bufStart = buf.position();

		long memOffset = startPage;
		int cacheBufOff = (int) (startOff - startPage);
		while (buf.hasRemaining()) {
			int required = MathUtilities.unsignedMin(SIZE - cacheBufOff, buf.remaining());
			Page page = ensurePageCached(address.getNewAddress(memOffset), required);
			buf.put(page.bytes, cacheBufOff, required);
			memOffset += SIZE;
			cacheBufOff = 0;
		}
		return buf.position() - bufStart;
	}

	protected int choosePage(Address address, int len) {
		for (int i = 0; i < pageCount; i++) {
			Page page = pages[i];
			if (page.contains(address, len)) {
				return i;
			}
		}
		return -1;
	}

	/**
	 * Ensure a page is cached
	 * 
	 * @param address the start address of the page
	 * @param len the minimum number of bytes required from the page
	 * @return the chosen cache page
	 * @throws MemoryAccessException if the required bytes cannot be read
	 */
	private Page ensurePageCached(Address address, int len) throws MemoryAccessException {
		int chosen = choosePage(address, len);
		if (chosen == -1) {
			pages[pageCount - 1].load(address, len);
			chosen = pageCount - 1;
		}
		if (chosen == 0) {
			return pages[0];
		}
		synchronized (pages) {
			Page temp = pages[chosen];
			pages[chosen] = pages[0];
			pages[0] = temp;
			return temp;
		}
	}

	protected abstract int doLoad(Address address, ByteBuffer buf) throws MemoryAccessException;

	public void invalidate(AddressRange range) {
		synchronized (pages) {
			for (Page p : pages) {
				p.invalidate(range);
			}
		}
	}
}
