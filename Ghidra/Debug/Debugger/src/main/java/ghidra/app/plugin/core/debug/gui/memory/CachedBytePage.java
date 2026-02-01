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
package ghidra.app.plugin.core.debug.gui.memory;

import java.nio.ByteBuffer;
import java.util.*;

import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.program.model.address.Address;

public class CachedBytePage {
	private static final int PAGE_SIZE = 4096;
	/**
	 * There seem to be a handful of layout indices which are routinely gathered:
	 * <ol>
	 * <li>The visible layout, to paint it.</li>
	 * <li>Layout[0], to get measurements for scrolling amounts.</li>
	 * <li>The layout containing the cursor, for accessibility.</li>
	 * </ol>
	 * <p>
	 * We include an extra slack entry so that when a new address is accessed, we don't necessarily
	 * invalidate an entry that is about to be used. Since the entries often are accessed in a
	 * cycle, the entry about to be used is often the least-recently used.
	 * <p>
	 * NOTE: We already instantiate a separate cache for previous vs current coordinates, so no need
	 * to multiply this by 2.
	 */
	private static final int CACHE_SIZE = 4;

	private static boolean coordsEqualForMemory(DebuggerCoordinates c1, DebuggerCoordinates c2) {
		return c1.getTrace() == c2.getTrace() && c1.getViewSnap() == c2.getViewSnap();
	}

	record CacheKey(DebuggerCoordinates coordinates, Address start) {
		int computeOffset(DebuggerCoordinates coordinates, Address address) {
			if (coordsEqualForMemory(this.coordinates, coordinates)) {
				long offset = address.subtract(start);
				if (0 <= offset && offset < PAGE_SIZE) {
					return (int) offset;
				}
			}
			return -1;
		}
	}

	record CacheEntry(byte[] page, ByteBuffer buf) {
		public CacheEntry(byte[] page) {
			this(page, ByteBuffer.wrap(page));
		}

		public CacheEntry() {
			this(new byte[PAGE_SIZE]);
		}

		CacheKey refresh(DebuggerCoordinates coordinates, Address address) {
			buf.clear();
			Address min = address.getAddressSpace().getMinAddress();
			Address start = address.subtractWrap(page.length / 2);

			if (start.compareTo(min) < 0 || start.compareTo(address) > 0) {
				start = min;
			}
			coordinates.getTrace()
					.getMemoryManager()
					.getViewBytes(coordinates.getViewSnap(), start, buf);
			return new CacheKey(coordinates, start);
		}
	}

	private final SequencedMap<CacheKey, CacheEntry> map = new LinkedHashMap<>();

	public byte getByte(DebuggerCoordinates coordinates, Address address) {
		for (Map.Entry<CacheKey, CacheEntry> ent : map.entrySet()) {
			int offset = ent.getKey().computeOffset(coordinates, address);
			if (offset != -1) {
				// LRU logic: Reset the hit entry's age.
				map.remove(ent.getKey());
				map.put(ent.getKey(), ent.getValue());
				return ent.getValue().page[offset];
			}
		}

		CacheEntry entry =
			map.size() >= CACHE_SIZE ? map.pollFirstEntry().getValue() : new CacheEntry();
		CacheKey key = entry.refresh(coordinates, address);
		int offset = key.computeOffset(coordinates, address);
		assert offset != -1;
		map.put(key, entry);
		return entry.page[offset];
	}

	public void invalidate() {
		map.clear();
	}
}
