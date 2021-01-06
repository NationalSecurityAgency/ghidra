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
package ghidra.trace.database.memory;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.mem.Memory;
import ghidra.trace.util.MemBufferAdapter;

public class DBTraceMemBuffer implements MemBufferAdapter {
	private final DBTraceMemorySpace space;
	private final long snap;
	private final Address start;
	private final ByteOrder byteOrder;

	public DBTraceMemBuffer(DBTraceMemorySpace space, long snap, Address start,
			ByteOrder byteOrder) {
		this.space = space;
		this.snap = snap;
		this.start = start;
		this.byteOrder = byteOrder;
	}

	@Override
	public Address getAddress() {
		return start;
	}

	@Override
	public Memory getMemory() {
		// TODO: This may be problematic for non-canonical views
		return space.trace.getProgramView().getMemory();
	}

	@Override
	public boolean isBigEndian() {
		return byteOrder == ByteOrder.BIG_ENDIAN;
	}

	@Override
	public int getBytes(ByteBuffer buffer, int offset) {
		try {
			return space.getViewBytes(snap, start.addNoWrap(offset), buffer);
		}
		catch (AddressOverflowException e) {
			return 0;
		}
	}
}
