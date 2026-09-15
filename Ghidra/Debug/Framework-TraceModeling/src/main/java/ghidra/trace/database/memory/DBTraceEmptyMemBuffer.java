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
import java.util.Arrays;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.mem.MemBufferMixin;
import ghidra.program.model.mem.Memory;
import ghidra.trace.database.DBTrace;
import ghidra.util.MathUtilities;

public class DBTraceEmptyMemBuffer implements MemBufferMixin {
	private final DBTrace trace;
	private final Address start;
	private final ByteOrder byteOrder;

	public DBTraceEmptyMemBuffer(DBTrace trace, Address start, ByteOrder byteOrder) {
		this.trace = trace;
		this.start = start;
		this.byteOrder = byteOrder;
	}

	@Override
	public Address getAddress() {
		return start;
	}

	@Override
	public Memory getMemory() {
		// NOTE: This may be problematic for non-canonical views
		return trace.getProgramView().getMemory();
	}

	@Override
	public boolean isBigEndian() {
		return byteOrder == ByteOrder.BIG_ENDIAN;
	}

	@Override
	public int getBytes(ByteBuffer buffer, int offset) {
		try {
			long toRead =
				start.getAddressSpace().getMaxAddress().subtract(start.addNoWrap(offset)) + 1;
			toRead = MathUtilities.unsignedMin(toRead, buffer.remaining());
			toRead = MathUtilities.unsignedMin(toRead, Integer.MAX_VALUE);
			int result = (int) toRead;
			int end = buffer.position() + result;
			Arrays.fill(buffer.array(), buffer.position(), end, (byte) 0);
			return result;
		}
		catch (AddressOverflowException e) {
			return 0;
		}
	}
}
