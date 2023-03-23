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

import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.program.model.address.Address;

public class CachedBytePage {
	private boolean valid = true;
	private DebuggerCoordinates coordinates;
	private Address start;
	private byte[] page = new byte[4096];
	private ByteBuffer buf = ByteBuffer.wrap(page);

	public byte getByte(DebuggerCoordinates coordinates, Address address) {
		long offset;
		if (!valid || this.coordinates == null || !this.coordinates.equals(coordinates) ||
			start == null || !start.hasSameAddressSpace(address)) {
			offset = refresh(coordinates, address);
		}
		else {
			offset = address.subtract(start);
			if (offset < 0 || 4096 <= offset) {
				offset = refresh(coordinates, address);
			}
		}
		return page[(int) offset];
	}

	public void invalidate() {
		valid = false;
	}

	private long refresh(DebuggerCoordinates coordinates, Address address) {
		valid = false;
		buf.clear();
		Address min = address.getAddressSpace().getMinAddress();
		start = address.subtractWrap(page.length / 2);

		if (start.compareTo(min) < 0 || start.compareTo(address) > 0) {
			start = min;
		}
		coordinates.getTrace()
				.getMemoryManager()
				.getViewBytes(coordinates.getViewSnap(), start, buf);
		valid = true;
		return address.subtract(start);
	}
}
