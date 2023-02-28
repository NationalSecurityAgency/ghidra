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

import static org.junit.Assert.*;

import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

import org.junit.Test;

import db.Transaction;
import db.DBHandle;
import ghidra.program.model.address.*;
import ghidra.trace.database.DBTrace;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.util.database.DBOpenMode;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractDBTraceMemoryManagerMemoryTest
		extends AbstractDBTraceMemoryManagerTest {

	@Test
	public void testSetState() {
		try (Transaction tx = b.startTransaction()) {
			memory.setState(0, b.addr(0x4000), b.addr(0x5000), TraceMemoryState.KNOWN);

			// +1 Overflow
			memory.setState(0, b.range(0x4000, 0x7fffffffffffffffL), TraceMemoryState.KNOWN);
			memory.setState(0, b.range(0x4000, 0xffffffffffffffffL), TraceMemoryState.KNOWN);

			// NOP
			memory.setState(0, b.addr(0x4500), b.addr(0x5000), TraceMemoryState.KNOWN);

			AddressSet set = new AddressSet();
			set.add(b.addr(0x2000), b.addr(0x2500));
			set.add(b.addr(0x4000), b.addr(0x5000)); // NOP when set
			memory.setState(0, set, TraceMemoryState.KNOWN);

			// ERR
			AddressSpace regs = b.trace.getBaseAddressFactory().getRegisterSpace();
			try {
				memory.setState(0, regs.getAddress(0x4000), TraceMemoryState.KNOWN);
				fail();
			}
			catch (IllegalArgumentException e) {
				// pass;
			}

			try {
				memory.setState(0,
					new AddressRangeImpl(regs.getAddress(0x4000), regs.getAddress(0x5000)),
					TraceMemoryState.KNOWN);
				fail();
			}
			catch (IllegalArgumentException e) {
				// pass;
			}
		}
	}

	@Test
	public void testSetGetStateOneByte() {
		assertEquals(null, memory.getState(3, b.addr(0x4000)));

		try (Transaction tx = b.startTransaction()) {
			memory.setState(3, b.addr(0x4000), TraceMemoryState.KNOWN);
		}

		assertEquals(TraceMemoryState.KNOWN, memory.getState(3, b.addr(0x4000)));
		assertEquals(TraceMemoryState.UNKNOWN, memory.getState(3, b.addr(0x4001)));
		assertEquals(TraceMemoryState.UNKNOWN, memory.getState(3, b.addr(0x3fff)));
		assertEquals(TraceMemoryState.UNKNOWN, memory.getState(2, b.addr(0x4000)));
		assertEquals(TraceMemoryState.UNKNOWN, memory.getState(4, b.addr(0x4000)));

		try (Transaction tx = b.startTransaction()) {
			memory.setState(3, b.addr(0x4000), TraceMemoryState.ERROR);
		}

		assertEquals(TraceMemoryState.ERROR, memory.getState(3, b.addr(0x4000)));
		assertEquals(TraceMemoryState.UNKNOWN, memory.getState(3, b.addr(0x4001)));
		assertEquals(TraceMemoryState.UNKNOWN, memory.getState(3, b.addr(0x3fff)));
		assertEquals(TraceMemoryState.UNKNOWN, memory.getState(2, b.addr(0x4000)));
		assertEquals(TraceMemoryState.UNKNOWN, memory.getState(4, b.addr(0x4000)));
	}

	@Test
	public void testSetRangeGetState() {
		try (Transaction tx = b.startTransaction()) {
			memory.setState(3, b.addr(0x4000), b.addr(0x5000), TraceMemoryState.KNOWN);
		}

		assertEquals(TraceMemoryState.KNOWN, memory.getState(3, b.addr(0x4800)));
		assertEquals(TraceMemoryState.KNOWN, memory.getState(3, b.addr(0x4000)));
		assertEquals(TraceMemoryState.KNOWN, memory.getState(3, b.addr(0x5000)));
		assertEquals(TraceMemoryState.UNKNOWN, memory.getState(3, b.addr(0x3fff)));
		assertEquals(TraceMemoryState.UNKNOWN, memory.getState(3, b.addr(0x5001)));
		assertEquals(TraceMemoryState.UNKNOWN, memory.getState(2, b.addr(0x4800)));
		assertEquals(TraceMemoryState.UNKNOWN, memory.getState(4, b.addr(0x4800)));
	}

	@Test
	public void testGetMostRecentStateSingleRange() {
		try (Transaction tx = b.startTransaction()) {
			memory.setState(3, b.addr(0x4000), b.addr(0x5000), TraceMemoryState.KNOWN);
		}

		assertEquals(null, memory.getMostRecentStateEntry(2, b.addr(0)));
		assertEquals(null, memory.getMostRecentStateEntry(2, b.addr(0x3fff)));
		assertEquals(null, memory.getMostRecentStateEntry(2, b.addr(0x4000)));
		assertEquals(null, memory.getMostRecentStateEntry(2, b.addr(0x5000)));
		assertEquals(null, memory.getMostRecentStateEntry(2, b.addr(0x5001)));

		assertEquals(null, memory.getMostRecentStateEntry(3, b.addr(0)));
		assertEquals(null, memory.getMostRecentStateEntry(3, b.addr(0x3fff)));
		assertSnapState(3, TraceMemoryState.KNOWN,
			memory.getMostRecentStateEntry(3, b.addr(0x4000)));
		assertSnapState(3, TraceMemoryState.KNOWN,
			memory.getMostRecentStateEntry(3, b.addr(0x5000)));
		assertEquals(null, memory.getMostRecentStateEntry(3, b.addr(0x5001)));

		assertEquals(null, memory.getMostRecentStateEntry(4, b.addr(0)));
		assertEquals(null, memory.getMostRecentStateEntry(4, b.addr(0x3fff)));
		assertSnapState(3, TraceMemoryState.KNOWN,
			memory.getMostRecentStateEntry(4, b.addr(0x4000)));
		assertSnapState(3, TraceMemoryState.KNOWN,
			memory.getMostRecentStateEntry(4, b.addr(0x5000)));
		assertEquals(null, memory.getMostRecentStateEntry(4, b.addr(0x5001)));
	}

	@Test
	public void testGetMostRecentStateSameSnap() {
		try (Transaction tx = b.startTransaction()) {
			memory.setState(3, b.addr(0x4000), b.addr(0x5000), TraceMemoryState.KNOWN);
			memory.setState(3, b.addr(0x4020), b.addr(0x4080), TraceMemoryState.ERROR);
		}

		assertEquals(null, memory.getMostRecentStateEntry(2, b.addr(0)));
		assertEquals(null, memory.getMostRecentStateEntry(2, b.addr(0x3fff)));
		assertEquals(null, memory.getMostRecentStateEntry(2, b.addr(0x4000)));
		assertEquals(null, memory.getMostRecentStateEntry(2, b.addr(0x401f)));
		assertEquals(null, memory.getMostRecentStateEntry(2, b.addr(0x4020)));
		assertEquals(null, memory.getMostRecentStateEntry(2, b.addr(0x4080)));
		assertEquals(null, memory.getMostRecentStateEntry(2, b.addr(0x4081)));
		assertEquals(null, memory.getMostRecentStateEntry(2, b.addr(0x5000)));
		assertEquals(null, memory.getMostRecentStateEntry(2, b.addr(0x5001)));

		assertEquals(null, memory.getMostRecentStateEntry(3, b.addr(0)));
		assertEquals(null, memory.getMostRecentStateEntry(3, b.addr(0x3fff)));
		assertSnapState(3, TraceMemoryState.KNOWN,
			memory.getMostRecentStateEntry(3, b.addr(0x4000)));
		assertSnapState(3, TraceMemoryState.KNOWN,
			memory.getMostRecentStateEntry(3, b.addr(0x401f)));
		assertSnapState(3, TraceMemoryState.ERROR,
			memory.getMostRecentStateEntry(3, b.addr(0x4020)));
		assertSnapState(3, TraceMemoryState.ERROR,
			memory.getMostRecentStateEntry(3, b.addr(0x4080)));
		assertSnapState(3, TraceMemoryState.KNOWN,
			memory.getMostRecentStateEntry(3, b.addr(0x4081)));
		assertSnapState(3, TraceMemoryState.KNOWN,
			memory.getMostRecentStateEntry(3, b.addr(0x5000)));
		assertEquals(null, memory.getMostRecentStateEntry(3, b.addr(0x5001)));

		assertEquals(null, memory.getMostRecentStateEntry(5, b.addr(0)));
		assertEquals(null, memory.getMostRecentStateEntry(5, b.addr(0x3fff)));
		assertSnapState(3, TraceMemoryState.KNOWN,
			memory.getMostRecentStateEntry(5, b.addr(0x4000)));
		assertSnapState(3, TraceMemoryState.KNOWN,
			memory.getMostRecentStateEntry(5, b.addr(0x401f)));
		assertSnapState(3, TraceMemoryState.ERROR,
			memory.getMostRecentStateEntry(5, b.addr(0x4020)));
		assertSnapState(3, TraceMemoryState.ERROR,
			memory.getMostRecentStateEntry(5, b.addr(0x4080)));
		assertSnapState(3, TraceMemoryState.KNOWN,
			memory.getMostRecentStateEntry(5, b.addr(0x4081)));
		assertSnapState(3, TraceMemoryState.KNOWN,
			memory.getMostRecentStateEntry(5, b.addr(0x5000)));
		assertEquals(null, memory.getMostRecentStateEntry(5, b.addr(0x5001)));
	}

	@Test
	public void testGetMostRecentStateLaterBefore() {
		try (Transaction tx = b.startTransaction()) {
			memory.setState(3, b.addr(0x4000), b.addr(0x5000), TraceMemoryState.KNOWN);
			memory.setState(4, b.addr(0x3000), b.addr(0x3500), TraceMemoryState.ERROR);
		}

		assertEquals(null, memory.getMostRecentStateEntry(2, b.addr(0)));
		assertEquals(null, memory.getMostRecentStateEntry(2, b.addr(0x2fff)));
		assertEquals(null, memory.getMostRecentStateEntry(2, b.addr(0x3000)));
		assertEquals(null, memory.getMostRecentStateEntry(2, b.addr(0x3500)));
		assertEquals(null, memory.getMostRecentStateEntry(2, b.addr(0x3501)));
		assertEquals(null, memory.getMostRecentStateEntry(2, b.addr(0x3fff)));
		assertEquals(null, memory.getMostRecentStateEntry(2, b.addr(0x4000)));
		assertEquals(null, memory.getMostRecentStateEntry(2, b.addr(0x5000)));
		assertEquals(null, memory.getMostRecentStateEntry(2, b.addr(0x5001)));

		assertEquals(null, memory.getMostRecentStateEntry(3, b.addr(0)));
		assertEquals(null, memory.getMostRecentStateEntry(3, b.addr(0x2fff)));
		assertEquals(null, memory.getMostRecentStateEntry(3, b.addr(0x3000)));
		assertEquals(null, memory.getMostRecentStateEntry(3, b.addr(0x3500)));
		assertEquals(null, memory.getMostRecentStateEntry(3, b.addr(0x3501)));
		assertEquals(null, memory.getMostRecentStateEntry(3, b.addr(0x3fff)));
		assertSnapState(3, TraceMemoryState.KNOWN,
			memory.getMostRecentStateEntry(3, b.addr(0x4000)));
		assertSnapState(3, TraceMemoryState.KNOWN,
			memory.getMostRecentStateEntry(3, b.addr(0x5000)));
		assertEquals(null, memory.getMostRecentStateEntry(3, b.addr(0x5001)));

		assertEquals(null, memory.getMostRecentStateEntry(4, b.addr(0)));
		assertEquals(null, memory.getMostRecentStateEntry(4, b.addr(0x2fff)));
		assertSnapState(4, TraceMemoryState.ERROR,
			memory.getMostRecentStateEntry(4, b.addr(0x3000)));
		assertSnapState(4, TraceMemoryState.ERROR,
			memory.getMostRecentStateEntry(4, b.addr(0x3500)));
		assertEquals(null, memory.getMostRecentStateEntry(4, b.addr(0x3501)));
		assertEquals(null, memory.getMostRecentStateEntry(4, b.addr(0x3fff)));
		assertSnapState(3, TraceMemoryState.KNOWN,
			memory.getMostRecentStateEntry(4, b.addr(0x4000)));
		assertSnapState(3, TraceMemoryState.KNOWN,
			memory.getMostRecentStateEntry(4, b.addr(0x5000)));
		assertEquals(null, memory.getMostRecentStateEntry(4, b.addr(0x5001)));

		assertEquals(null, memory.getMostRecentStateEntry(5, b.addr(0)));
		assertEquals(null, memory.getMostRecentStateEntry(5, b.addr(0x2fff)));
		assertSnapState(4, TraceMemoryState.ERROR,
			memory.getMostRecentStateEntry(5, b.addr(0x3000)));
		assertSnapState(4, TraceMemoryState.ERROR,
			memory.getMostRecentStateEntry(5, b.addr(0x3500)));
		assertEquals(null, memory.getMostRecentStateEntry(5, b.addr(0x3501)));
		assertEquals(null, memory.getMostRecentStateEntry(5, b.addr(0x3fff)));
		assertSnapState(3, TraceMemoryState.KNOWN,
			memory.getMostRecentStateEntry(5, b.addr(0x4000)));
		assertSnapState(3, TraceMemoryState.KNOWN,
			memory.getMostRecentStateEntry(5, b.addr(0x5000)));
		assertEquals(null, memory.getMostRecentStateEntry(5, b.addr(0x5001)));
	}

	@Test
	public void testGetMostRecentStateLaterOverStart() {
		try (Transaction tx = b.startTransaction()) {
			memory.setState(3, b.addr(0x4000), b.addr(0x5000), TraceMemoryState.KNOWN);
			memory.setState(4, b.addr(0x3000), b.addr(0x4500), TraceMemoryState.ERROR);
		}

		assertEquals(null, memory.getMostRecentStateEntry(2, b.addr(0)));
		assertEquals(null, memory.getMostRecentStateEntry(2, b.addr(0x2fff)));
		assertEquals(null, memory.getMostRecentStateEntry(2, b.addr(0x3000)));
		assertEquals(null, memory.getMostRecentStateEntry(2, b.addr(0x3fff)));
		assertEquals(null, memory.getMostRecentStateEntry(2, b.addr(0x4000)));
		assertEquals(null, memory.getMostRecentStateEntry(2, b.addr(0x4500)));
		assertEquals(null, memory.getMostRecentStateEntry(2, b.addr(0x4501)));
		assertEquals(null, memory.getMostRecentStateEntry(2, b.addr(0x5000)));
		assertEquals(null, memory.getMostRecentStateEntry(2, b.addr(0x5001)));

		assertEquals(null, memory.getMostRecentStateEntry(3, b.addr(0)));
		assertEquals(null, memory.getMostRecentStateEntry(3, b.addr(0x2fff)));
		assertEquals(null, memory.getMostRecentStateEntry(3, b.addr(0x3000)));
		assertEquals(null, memory.getMostRecentStateEntry(3, b.addr(0x3fff)));
		assertSnapState(3, TraceMemoryState.KNOWN,
			memory.getMostRecentStateEntry(3, b.addr(0x4000)));
		assertSnapState(3, TraceMemoryState.KNOWN,
			memory.getMostRecentStateEntry(3, b.addr(0x4500)));
		assertSnapState(3, TraceMemoryState.KNOWN,
			memory.getMostRecentStateEntry(3, b.addr(0x4501)));
		assertSnapState(3, TraceMemoryState.KNOWN,
			memory.getMostRecentStateEntry(3, b.addr(0x5000)));
		assertEquals(null, memory.getMostRecentStateEntry(3, b.addr(0x5001)));

		assertEquals(null, memory.getMostRecentStateEntry(4, b.addr(0)));
		assertEquals(null, memory.getMostRecentStateEntry(4, b.addr(0x2fff)));
		assertSnapState(4, TraceMemoryState.ERROR,
			memory.getMostRecentStateEntry(4, b.addr(0x3000)));
		assertSnapState(4, TraceMemoryState.ERROR,
			memory.getMostRecentStateEntry(4, b.addr(0x3fff)));
		assertSnapState(4, TraceMemoryState.ERROR,
			memory.getMostRecentStateEntry(4, b.addr(0x4000)));
		assertSnapState(4, TraceMemoryState.ERROR,
			memory.getMostRecentStateEntry(4, b.addr(0x4500)));
		assertSnapState(3, TraceMemoryState.KNOWN,
			memory.getMostRecentStateEntry(4, b.addr(0x4501)));
		assertSnapState(3, TraceMemoryState.KNOWN,
			memory.getMostRecentStateEntry(4, b.addr(0x5000)));
		assertEquals(null, memory.getMostRecentStateEntry(4, b.addr(0x5001)));

		assertEquals(null, memory.getMostRecentStateEntry(5, b.addr(0)));
		assertEquals(null, memory.getMostRecentStateEntry(5, b.addr(0x2fff)));
		assertSnapState(4, TraceMemoryState.ERROR,
			memory.getMostRecentStateEntry(5, b.addr(0x3000)));
		assertSnapState(4, TraceMemoryState.ERROR,
			memory.getMostRecentStateEntry(5, b.addr(0x3fff)));
		assertSnapState(4, TraceMemoryState.ERROR,
			memory.getMostRecentStateEntry(5, b.addr(0x4000)));
		assertSnapState(4, TraceMemoryState.ERROR,
			memory.getMostRecentStateEntry(5, b.addr(0x4500)));
		assertSnapState(3, TraceMemoryState.KNOWN,
			memory.getMostRecentStateEntry(5, b.addr(0x4501)));
		assertSnapState(3, TraceMemoryState.KNOWN,
			memory.getMostRecentStateEntry(5, b.addr(0x5000)));
		assertEquals(null, memory.getMostRecentStateEntry(5, b.addr(0x5001)));
	}

	@Test
	public void testGetMostRecentStates() {
		try (Transaction tx = b.startTransaction()) {
			memory.setState(3, b.addr(0x4000), b.addr(0x7000), TraceMemoryState.KNOWN);
			memory.setState(3, b.addr(0x5000), b.addr(0x6000), TraceMemoryState.ERROR);
			memory.setState(4, b.addr(0x3000), b.addr(0x4800), TraceMemoryState.KNOWN);
		}

		Map<TraceAddressSnapRange, TraceMemoryState> expected;

		expected = new HashMap<>();
		assertEquals(expected,
			collectAsMap(memory.getMostRecentStates(2, b.range(0x2800, 0x9000))));

		expected = new HashMap<>();
		expected.put(b.srange(3, 0x4000, 0x4fff), TraceMemoryState.KNOWN);
		expected.put(b.srange(3, 0x5000, 0x6000), TraceMemoryState.ERROR);
		expected.put(b.srange(3, 0x6001, 0x7000), TraceMemoryState.KNOWN);
		assertEquals(expected,
			collectAsMap(memory.getMostRecentStates(3, b.range(0x2800, 0x9000))));

		expected = new HashMap<>();
		expected.put(b.srange(4, 0x3000, 0x4800), TraceMemoryState.KNOWN);
		expected.put(b.srange(3, 0x4801, 0x4fff), TraceMemoryState.KNOWN);
		expected.put(b.srange(3, 0x5000, 0x6000), TraceMemoryState.ERROR);
		expected.put(b.srange(3, 0x6001, 0x7000), TraceMemoryState.KNOWN);
		assertEquals(expected,
			collectAsMap(memory.getMostRecentStates(4, b.range(0x2800, 0x9000))));
		assertEquals(expected,
			collectAsMap(memory.getMostRecentStates(5, b.range(0x2800, 0x9000))));
	}

	@Test
	public void testGetAddressesWithState() {
		try (Transaction tx = b.startTransaction()) {
			memory.setState(3, b.addr(0x4000), b.addr(0x7000), TraceMemoryState.KNOWN);
			memory.setState(3, b.addr(0x5000), b.addr(0x6000), TraceMemoryState.ERROR);
			memory.setState(4, b.addr(0x3000), b.addr(0x4800), TraceMemoryState.KNOWN);
		}

		AddressSet set = new AddressSet();
		set.add(b.range(0x2800, 0x3800));
		set.add(b.range(0x3c00, 0x4800));
		set.add(b.range(0x4c00, 0x6100));
		set.add(b.range(0x8000, 0x9000));

		AddressSet expected;
		AddressSetView result;

		expected = new AddressSet();
		expected.add(b.range(0x3000, 0x3800));
		expected.add(b.range(0x3c00, 0x4800));
		result = memory.getAddressesWithState(4, set, state -> state == TraceMemoryState.KNOWN);
		assertEquals(expected, set.intersect(result));

		expected = new AddressSet();
		expected.add(b.range(0x4000, 0x4800));
		expected.add(b.range(0x4c00, 0x4fff));
		expected.add(b.range(0x6001, 0x6100));
		result = memory.getAddressesWithState(3, set, state -> state == TraceMemoryState.KNOWN);
		assertEquals(expected, set.intersect(result));

		// Test gaps
		expected = new AddressSet();
		expected.add(b.range(0x2800, 0x3800));
		expected.add(b.range(0x3c00, 0x3fff));
		expected.add(b.range(0x8000, 0x9000));
		result = memory.getAddressesWithState(3, set, state -> true);
		assertEquals(expected, set.subtract(result));
	}

	@Test
	public void testGetStates() {
		try (Transaction tx = b.startTransaction()) {
			memory.setState(3, b.addr(0x4000), b.addr(0x7000), TraceMemoryState.KNOWN);
			memory.setState(3, b.addr(0x5000), b.addr(0x6000), TraceMemoryState.ERROR);
		}

		Map<TraceAddressSnapRange, TraceMemoryState> expected;

		expected = new HashMap<>();
		expected.put(b.srange(3, 0x4000, 0x4fff), TraceMemoryState.KNOWN);
		expected.put(b.srange(3, 0x5000, 0x6000), TraceMemoryState.ERROR);
		expected.put(b.srange(3, 0x6001, 0x7000), TraceMemoryState.KNOWN);
		assertEquals(expected, collectAsMap(memory.getStates(3, b.range(0x3000, 0x8000))));
	}

	@Test
	public void testBytes0Length() {
		try (Transaction tx = b.startTransaction()) {
			assertEquals(0, memory.putBytes(3, b.addr(0x4000), b.buf()));
			assertEquals(0, getBlockRecordCount());
			assertEquals(0, getBufferRecordCount());
		}

		assertEquals(0, memory.getBytes(3, b.addr(0x4000), b.buf()));

		ByteBuffer read = b.buf(-1, -2, -3, -4);
		assertEquals(4, memory.getBytes(3, b.addr(0x3ffe), read));
		assertEquals(0, read.remaining());
		// NOTE: I think this is OK, because the state ought to be UNKNOWN anyway.
		assertArrayEquals(b.arr(-1, -2, -3, -4), read.array());
	}

	@Test
	public void testBytesSimple4Zeros() {
		try (Transaction tx = b.startTransaction()) {
			assertEquals(4, memory.putBytes(3, b.addr(0x4000), b.buf(0, 0, 0, 0)));
			assertEquals(4, memory.putBytes(3, b.addr(0x4000), b.buf(0, 0, 0, 0))); // Should have no effect
			assertEquals(1, getBlockRecordCount());
			// Zeros do not require buffer backing
			assertEquals(0, getBufferRecordCount());
		}

		// verify the corresponding change in state;
		Map<TraceAddressSnapRange, TraceMemoryState> expected;
		expected = new HashMap<>();
		expected.put(b.srange(3, 0x4000, 0x4003), TraceMemoryState.KNOWN);
		assertEquals(expected, collectAsMap(memory.getStates(3, b.range(0x3000, 0x5000))));

		ByteBuffer read = b.buf(-1, -2, -3, -4); // Verify zeros actually written
		assertEquals(4, memory.getBytes(3, b.addr(0x4000), read));
		assertArrayEquals(b.arr(0, 0, 0, 0), read.array());
	}

	@Test
	public void testBytesSimple4Bytes() {
		try (Transaction tx = b.startTransaction()) {
			assertEquals(4, memory.putBytes(3, b.addr(0x4000), b.buf(1, 2, 3, 4)));
			assertEquals(1, getBlockRecordCount());
			assertEquals(1, getBufferRecordCount());
		}
		DBTraceMemoryBufferEntry bufEnt = getBufferStore().getObjectAt(0);
		assertFalse(bufEnt.isCompressed());

		// verify the corresponding change in state;
		Map<TraceAddressSnapRange, TraceMemoryState> expected;
		expected = new HashMap<>();
		expected.put(b.srange(3, 0x4000, 0x4003), TraceMemoryState.KNOWN);
		assertEquals(expected, collectAsMap(memory.getStates(3, b.range(0x3000, 0x5000))));

		ByteBuffer read = ByteBuffer.allocate(4);
		assertEquals(4, memory.getBytes(3, b.addr(0x4000), read));
		assertArrayEquals(b.arr(1, 2, 3, 4), read.array());
	}

	@Test
	public void testBytesSpan4Bytes() {
		try (Transaction tx = b.startTransaction()) {
			assertEquals(4, memory.putBytes(3, b.addr(0x3ffe), b.buf(1, 2, 3, 4)));
			assertEquals(2, getBlockRecordCount());
			assertEquals(2, getBufferRecordCount());
		}

		ByteBuffer read = ByteBuffer.allocate(4);
		assertEquals(4, memory.getBytes(3, b.addr(0x3ffe), read));
		assertArrayEquals(b.arr(1, 2, 3, 4), read.array());
	}

	@Test
	public void testBytesSpan12BytesInChunks() {
		try (Transaction tx = b.startTransaction()) {
			assertEquals(4, memory.putBytes(3, b.addr(0x3ffa), b.buf(1, 2, 3, 4)));
			assertEquals(1, getBlockRecordCount());
			assertEquals(4, memory.putBytes(3, b.addr(0x3ffe), b.buf(5, 6, 7, 8)));
			assertEquals(2, getBlockRecordCount());
			assertEquals(4, memory.putBytes(3, b.addr(0x4002), b.buf(9, 10, 11, 12)));
			assertEquals(2, getBlockRecordCount());
			assertEquals(2, getBufferRecordCount());
		}

		ByteBuffer read = ByteBuffer.allocate(12);
		assertEquals(12, memory.getBytes(3, b.addr(0x3ffa), read));
		assertArrayEquals(b.arr(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12), read.array());
	}

	@Test
	public void testBytesOverflow() {
		try (Transaction tx = b.startTransaction()) {
			ByteBuffer write = b.buf(1, 2, 3, 4);
			assertEquals(2, memory.putBytes(3, b.addr(0xfffffffffffffffeL), write));
			assertEquals(2, write.remaining());
			assertEquals(1, getBlockRecordCount());
			assertEquals(1, getBufferRecordCount());
		}

		ByteBuffer read = b.buf(-1, -1, -1, -1);
		assertEquals(2, memory.getBytes(3, b.addr(0xfffffffffffffffeL), read));
		assertEquals(2, read.remaining());
		assertArrayEquals(b.arr(1, 2, -1, -1), read.array());
	}

	@Test
	public void testBytesWriteSameLater() {
		try (Transaction tx = b.startTransaction()) {
			assertEquals(4, memory.putBytes(3, b.addr(0x4000), b.buf(1, 2, 3, 4)));
			assertEquals(1, getBlockRecordCount());
			assertEquals(1, getBufferRecordCount());

			assertEquals(4, memory.putBytes(5, b.addr(0x4000), b.buf(1, 2, 3, 4)));
			assertEquals(1, getBlockRecordCount()); // Should not require a new block
			assertEquals(1, getBufferRecordCount()); // Definitely not another buffer
		}

		// verify the corresponding change in state;
		Map<TraceAddressSnapRange, TraceMemoryState> expected;

		expected = new HashMap<>();
		assertEquals(expected, collectAsMap(memory.getStates(2, b.range(0x3000, 0x5000))));
		assertEquals(expected, collectAsMap(memory.getStates(4, b.range(0x3000, 0x5000))));
		assertEquals(expected, collectAsMap(memory.getStates(6, b.range(0x3000, 0x5000))));

		expected = new HashMap<>();
		expected.put(b.srange(3, 0x4000, 0x4003), TraceMemoryState.KNOWN);
		assertEquals(expected, collectAsMap(memory.getStates(3, b.range(0x3000, 0x5000))));
		expected = new HashMap<>();
		expected.put(b.srange(5, 0x4000, 0x4003), TraceMemoryState.KNOWN);
		assertEquals(expected, collectAsMap(memory.getStates(5, b.range(0x3000, 0x5000))));

		ByteBuffer read = b.buf(0, 0, 0, 0);
		assertEquals(4, memory.getBytes(5, b.addr(0x4000), read));
		assertArrayEquals(b.arr(1, 2, 3, 4), read.array());
	}

	@Test
	public void testBytesArrayOffset() {
		try (Transaction tx = b.startTransaction()) {
			byte[] array = new byte[20];
			array[9] = -1;
			array[10] = 1;
			array[11] = 2;
			array[12] = 3;
			array[13] = 4;
			array[14] = -1;
			assertEquals(4, memory.putBytes(3, b.addr(0x4000), ByteBuffer.wrap(array, 10, 4)));
		}

		byte[] array = new byte[20];
		array[9] = -2;
		array[16] = -2;
		ByteBuffer read = ByteBuffer.wrap(array, 10, 6);
		assertEquals(6, memory.getBytes(3, b.addr(0x3fff), read));
		assertArrayEquals(b.arr(-2, 0, 1, 2, 3, 4, 0, -2), Arrays.copyOfRange(array, 9, 17));
	}

	@Test
	public void testGetBytesMostRecent() {
		try (Transaction tx = b.startTransaction()) {
			assertEquals(4, memory.putBytes(3, b.addr(0x4000), b.buf(1, 2, 3, 4)));
			assertEquals(4, memory.putBytes(4, b.addr(0x4002), b.buf(5, 6, 7, 8)));
			assertEquals(1, memory.putBytes(5, b.addr(0x4003), b.buf(0)));
			assertEquals(3, getBlockRecordCount());
			assertEquals(1, getBufferRecordCount());
		}

		ByteBuffer read = b.buf(-1, -1, -1, -1);
		assertEquals(4, memory.getBytes(2, b.addr(0x4000), read));
		assertArrayEquals(b.arr(-1, -1, -1, -1), read.array());

		read.position(0);
		assertEquals(4, memory.getBytes(3, b.addr(0x4000), read));
		assertArrayEquals(b.arr(1, 2, 3, 4), read.array());

		read.position(0);
		assertEquals(4, memory.getBytes(4, b.addr(0x4002), read));
		assertArrayEquals(b.arr(5, 6, 7, 8), read.array());

		read.position(0);
		assertEquals(4, memory.getBytes(4, b.addr(0x4000), read));
		assertArrayEquals(b.arr(1, 2, 5, 6), read.array());

		read = ByteBuffer.allocate(10);
		assertEquals(10, memory.getBytes(5, b.addr(0x3ffe), read));
		assertArrayEquals(b.arr(0, 0, 1, 2, 5, 0, 7, 8, 0, 0), read.array());
	}

	@Test
	public void testPutBytesIntoPastGetBytesMostRecent() {
		try (Transaction tx = b.startTransaction()) {
			assertEquals(4, memory.putBytes(4, b.addr(0x4800), b.buf(5, 6, 7, 8)));
			assertEquals(4, memory.putBytes(3, b.addr(0x4802), b.buf(1, 2, 3, 4)));
			assertEquals(10,
				memory.putBytes(2, b.addr(0x47fe), b.buf(9, 10, 11, 12, 13, 14, 15, 16, 17, 18)));
			assertEquals(3, getBlockRecordCount());
			assertEquals(1, getBufferRecordCount());
		}

		ByteBuffer read = b.buf(-1, -1, -1, -1);
		assertEquals(4, memory.getBytes(1, b.addr(0x4802), read));
		assertArrayEquals(b.arr(-1, -1, -1, -1), read.array());

		read.position(0);
		assertEquals(4, memory.getBytes(3, b.addr(0x4802), read));
		assertArrayEquals(b.arr(1, 2, 3, 4), read.array());

		read.position(0);
		assertEquals(4, memory.getBytes(4, b.addr(0x4800), read));
		assertArrayEquals(b.arr(5, 6, 7, 8), read.array());

		read.position(0);
		assertEquals(4, memory.getBytes(4, b.addr(0x4802), read));
		assertArrayEquals(b.arr(7, 8, 3, 4), read.array());

		read = ByteBuffer.allocate(14);
		assertEquals(14, memory.getBytes(4, b.addr(0x47fc), read));
		assertArrayEquals(b.arr(0, 0, 9, 10, 5, 6, 7, 8, 3, 4, 17, 18, 0, 0), read.array());
	}

	@Test
	public void testGetBytesCrossScratch() {
		try (Transaction tx = b.startTransaction()) {
			assertEquals(4, memory.putBytes(Long.MIN_VALUE, b.addr(0x4000), b.buf(1, 2, 3, 4)));
		}

		ByteBuffer read = b.buf(-1, -1, -1, -1);
		assertEquals(4, memory.getBytes(1, b.addr(0x4000), read));
		assertArrayEquals(b.arr(-1, -1, -1, -1), read.array());

		read.position(0);
		assertEquals(4, memory.getBytes(-1, b.addr(0x4000), read));
		assertArrayEquals(b.arr(1, 2, 3, 4), read.array());
	}

	@Test
	public void testPutBytesPackGetBytes() {
		try (Transaction tx = b.startTransaction()) {
			assertEquals(4, memory.putBytes(3, b.addr(0x4000), b.buf(1, 2, 3, 4)));
			memory.pack();
			assertEquals(1, getBlockRecordCount());
			assertEquals(1, getBufferRecordCount());
		}
		DBTraceMemoryBufferEntry bufEnt = getBufferStore().getObjectAt(0);
		assertTrue(bufEnt.isCompressed());

		ByteBuffer read = ByteBuffer.allocate(4);
		assertEquals(4, memory.getBytes(3, b.addr(0x4000), read));
		assertArrayEquals(b.arr(1, 2, 3, 4), read.array());

		assertTrue(bufEnt.isCompressed());
	}

	@Test
	public void testPutBytesPackPutBytes() {
		try (Transaction tx = b.startTransaction()) {
			assertEquals(4, memory.putBytes(3, b.addr(0x4000), b.buf(1, 2, 3, 4)));
			memory.pack();
			assertEquals(1, getBlockRecordCount());
			assertEquals(1, getBufferRecordCount());
			DBTraceMemoryBufferEntry bufEnt = getBufferStore().getObjectAt(0);
			assertTrue(bufEnt.isCompressed());
			assertEquals(4, memory.putBytes(3, b.addr(0x4000), b.buf(1, 2, 3, 4)));
			assertFalse(bufEnt.isCompressed()); // TODO: This is an implementation quirk. Do I care?
		}

		ByteBuffer read = ByteBuffer.allocate(4);
		assertEquals(4, memory.getBytes(3, b.addr(0x4000), read));
		assertArrayEquals(b.arr(1, 2, 3, 4), read.array());
	}

	@Test
	public void testFindBytes() {
		try (Transaction tx = b.startTransaction()) {
			assertEquals(5, memory.putBytes(3, b.addr(0x4000), b.buf(1, 2, 3, 4, 5)));
		}

		try {
			memory.findBytes(3, b.range(0x4000, 0x4003), b.buf(1, 2, 3, 4), b.buf(-1, -1, -1),
				true, TaskMonitor.DUMMY);
		}
		catch (IllegalArgumentException e) {
			// pass
		}

		// Degenerate
		assertNull(
			memory.findBytes(2, b.range(0x4000, 0x4003), b.buf(), b.buf(),
				true, TaskMonitor.DUMMY));

		// Too soon
		assertNull(
			memory.findBytes(2, b.range(0x4000, 0x4003), b.buf(1, 2, 3, 4), b.buf(-1, -1, -1, -1),
				true, TaskMonitor.DUMMY));

		// Too small
		assertNull(
			memory.findBytes(3, b.range(0x4000, 0x4002), b.buf(1, 2, 3, 4), b.buf(-1, -1, -1, -1),
				true, TaskMonitor.DUMMY));

		// Too high
		assertNull(
			memory.findBytes(3, b.range(0x4001, 0x4004), b.buf(1, 2, 3, 4), b.buf(-1, -1, -1, -1),
				true, TaskMonitor.DUMMY));

		// Too high, into unknown
		assertNull(
			memory.findBytes(3, b.range(0x4001, 0x4005), b.buf(1, 2, 3, 4, 5),
				b.buf(-1, -1, -1, -1, -1), true, TaskMonitor.DUMMY));

		// Too low
		assertNull(
			memory.findBytes(3, b.range(0x3fff, 0x4002), b.buf(1, 2, 3, 4), b.buf(-1, -1, -1, -1),
				true, TaskMonitor.DUMMY));

		// Perfect match
		assertEquals(b.addr(0x4000),
			memory.findBytes(3, b.range(0x4000, 0x4003), b.buf(1, 2, 3, 4), b.buf(-1, -1, -1, -1),
				true, TaskMonitor.DUMMY));

		// Make it work for the match
		assertEquals(b.addr(0x4000),
			memory.findBytes(3, b.range(0x0, -1), b.buf(1, 2, 3, 4), b.buf(-1, -1, -1, -1),
				true, TaskMonitor.DUMMY));

		// Make it work for the match
		assertEquals(b.addr(0x4000),
			memory.findBytes(3, b.range(0x0, -1), b.buf(1), b.buf(-1),
				true, TaskMonitor.DUMMY));

		// Sub match
		assertEquals(b.addr(0x4001),
			memory.findBytes(3, b.range(0x4000, 0x4003), b.buf(2, 3, 4), b.buf(-1, -1, -1),
				true, TaskMonitor.DUMMY));
	}

	@Test
	public void testRemoveBytes() {
		try (Transaction tx = b.startTransaction()) {
			assertEquals(10,
				memory.putBytes(2, b.addr(0x47fe), b.buf(9, 10, 11, 12, 13, 14, 15, 16, 17, 18)));
			assertEquals(4, memory.putBytes(4, b.addr(0x4800), b.buf(5, 6, 7, 8)));
			assertEquals(4, memory.putBytes(3, b.addr(0x4802), b.buf(1, 2, 3, 4)));
			assertEquals(3, getBlockRecordCount());
			assertEquals(1, getBufferRecordCount());
			/* 0x fe ff 00 01 02 03 04 05 06 07
			 * 
			 * 4:        5  6  7  8
			 * 3:              1  2  3  4
			 * 2:  9 10 11 12 13 14 15 16 17 18
			 */

			memory.removeBytes(2, b.addr(0x47ff), 14);
			/* 0x fe ff 00 01 02 03 04 05 06 07
			 * 
			 * 4:        5  6  7  8
			 * 3:              1  2  3  4
			 * 2:  9 .. .. .. .. .. .. .. .. ..
			 */
		}

		ByteBuffer read = ByteBuffer.allocate(4);
		assertEquals(4, memory.getBytes(1, b.addr(0x4802), read));
		assertArrayEquals(b.arr(0, 0, 0, 0), read.array());

		read.position(0);
		assertEquals(4, memory.getBytes(3, b.addr(0x4802), read));
		assertArrayEquals(b.arr(1, 2, 3, 4), read.array());

		read.position(0);
		assertEquals(4, memory.getBytes(4, b.addr(0x4800), read));
		assertArrayEquals(b.arr(5, 6, 7, 8), read.array());

		read.position(0);
		assertEquals(4, memory.getBytes(4, b.addr(0x4802), read));
		assertArrayEquals(b.arr(7, 8, 3, 4), read.array());

		read = ByteBuffer.allocate(14);
		assertEquals(14, memory.getBytes(4, b.addr(0x47fc), read));
		assertArrayEquals(b.arr(0, 0, 9, 0, 5, 6, 7, 8, 3, 4, 0, 0, 0, 0), read.array());

		// Check overall effect on state
		Map<TraceAddressSnapRange, TraceMemoryState> expected;
		expected = new HashMap<>();
		expected.put(b.srange(2, 0x47fe, 0x47fe), TraceMemoryState.KNOWN);
		expected.put(b.srange(4, 0x4800, 0x4803), TraceMemoryState.KNOWN);
		expected.put(b.srange(3, 0x4804, 0x4805), TraceMemoryState.KNOWN);
		assertEquals(expected,
			collectAsMap(memory.getMostRecentStates(6, b.range(0x4700, 0x4900))));
	}

	@Test
	public void testSaveAndLoad() throws Exception {
		try (Transaction tx = b.startTransaction()) {
			assertEquals(4, memory.putBytes(3, b.addr(0x4000), b.buf(1, 2, 3, 4)));
			assertEquals(1, getBlockRecordCount());
			assertEquals(1, getBufferRecordCount());
		}

		Path tmp = Files.createTempFile("test", ".db");
		Files.delete(tmp); // saveAs must create the file
		b.trace.getDBHandle().saveAs(tmp.toFile(), false, new ConsoleTaskMonitor());

		DBHandle opened = new DBHandle(tmp.toFile());
		DBTrace restored = null;
		try {
			restored = new DBTrace(opened, DBOpenMode.UPDATE, new ConsoleTaskMonitor(), this);

			DBTraceMemorySpace rSpace =
				restored.getMemoryManager().getMemorySpace(b.language.getDefaultDataSpace(), true);
			assertEquals(1, rSpace.bufferStore.getRecordCount());

			// verify the corresponding change in state;
			Map<TraceAddressSnapRange, TraceMemoryState> expected;
			expected = new HashMap<>();
			expected.put(b.srange(3, 0x4000, 0x4003), TraceMemoryState.KNOWN);
			assertEquals(expected, collectAsMap(memory.getStates(3, b.range(0x3000, 0x5000))));

			ByteBuffer read = ByteBuffer.allocate(4);
			assertEquals(4, rSpace.getBytes(3, b.addr(0x4000), read));
			assertArrayEquals(b.arr(1, 2, 3, 4), read.array());
		}
		finally {
			if (restored != null) {
				restored.release(this);
			}
		}
	}

	@Test
	public void testAddButAbortedStillEmpty() throws Exception {
		try (Transaction tx = b.startTransaction()) {
			assertEquals(4, memory.putBytes(3, b.addr(0x4000), b.buf(1, 2, 3, 4)));
			assertEquals(1, getBlockRecordCount());
			assertEquals(1, getBufferRecordCount());

			// verify the corresponding change in state;
			Map<TraceAddressSnapRange, TraceMemoryState> expected;
			expected = new HashMap<>();
			expected.put(b.srange(3, 0x4000, 0x4003), TraceMemoryState.KNOWN);
			assertEquals(expected, collectAsMap(memory.getStates(3, b.range(0x3000, 0x5000))));

			tx.abort();
		}
		assertEquals(0, getBlockRecordCount());
		assertEquals(0, getBufferRecordCount());

		// verify the corresponding change in state;
		Map<AddressRange, TraceMemoryState> expected;
		expected = new HashMap<>();
		assertEquals(expected, collectAsMap(memory.getStates(3, b.range(0x3000, 0x5000))));

		ByteBuffer read = ByteBuffer.allocate(4);
		assertEquals(4, memory.getBytes(3, b.addr(0x4000), read));
		assertArrayEquals(b.arr(0, 0, 0, 0), read.array());
	}

	@Test
	public void testAddThenUndo() throws Exception {
		try (Transaction tx = b.startTransaction()) {
			assertEquals(4, memory.putBytes(3, b.addr(0x4000), b.buf(1, 2, 3, 4)));
			assertEquals(1, getBlockRecordCount());
			assertEquals(1, getBufferRecordCount());

			// verify the corresponding change in state;
			Map<TraceAddressSnapRange, TraceMemoryState> expected;
			expected = new HashMap<>();
			expected.put(b.srange(3, 0x4000, 0x4003), TraceMemoryState.KNOWN);
			assertEquals(expected, collectAsMap(memory.getStates(3, b.range(0x3000, 0x5000))));
		}
		b.trace.undo();

		assertEquals(0, getBlockRecordCount());
		assertEquals(0, getBufferRecordCount());

		// verify the corresponding change in state;
		Map<AddressRange, TraceMemoryState> expected;
		expected = new HashMap<>();
		assertEquals(expected, collectAsMap(memory.getStates(3, b.range(0x3000, 0x5000))));

		ByteBuffer read = ByteBuffer.allocate(4);
		assertEquals(4, memory.getBytes(3, b.addr(0x4000), read));
		assertArrayEquals(b.arr(0, 0, 0, 0), read.array());
	}

	@Test
	public void testAddThenUndoThenRedo() throws Exception {
		try (Transaction tx = b.startTransaction()) {
			assertEquals(4, memory.putBytes(3, b.addr(0x4000), b.buf(1, 2, 3, 4)));
			assertEquals(1, getBlockRecordCount());
			assertEquals(1, getBufferRecordCount());

			// verify the corresponding change in state;
			Map<TraceAddressSnapRange, TraceMemoryState> expected;
			expected = new HashMap<>();
			expected.put(b.srange(3, 0x4000, 0x4003), TraceMemoryState.KNOWN);
			assertEquals(expected, collectAsMap(memory.getStates(3, b.range(0x3000, 0x5000))));
		}
		b.trace.undo();

		assertEquals(0, getBlockRecordCount());
		assertEquals(0, getBufferRecordCount());

		// verify the corresponding change in state;
		Map<TraceAddressSnapRange, TraceMemoryState> expected;
		expected = new HashMap<>();
		assertEquals(expected, collectAsMap(memory.getStates(3, b.range(0x3000, 0x5000))));

		ByteBuffer read = ByteBuffer.allocate(4);
		assertEquals(4, memory.getBytes(3, b.addr(0x4000), read));
		assertArrayEquals(b.arr(0, 0, 0, 0), read.array());

		b.trace.redo();

		assertEquals(1, getBlockRecordCount());
		assertEquals(1, getBufferRecordCount());

		expected = new HashMap<>();
		expected.put(b.srange(3, 0x4000, 0x4003), TraceMemoryState.KNOWN);
		assertEquals(expected, collectAsMap(memory.getStates(3, b.range(0x3000, 0x5000))));

		read.position(0);
		assertEquals(4, memory.getBytes(3, b.addr(0x4000), read));
		assertArrayEquals(b.arr(1, 2, 3, 4), read.array());
	}

	@Test
	public void testHighBlockNumbers() throws Exception {
		/**
		 * This test gets down into the block buffer implementation. If the block number exceeds
		 * 127, if might (accidentally) get treated as negative. Thanks Java! We can create this
		 * situation by writing to the same b.address at more than 127 different snaps.
		 */

		try (Transaction tx = b.startTransaction()) {
			for (int i = 0; i < 300; i++) {
				memory.putBytes(i, b.addr(0x4000), b.buf(1, 2, 3, i % 256));
			}
		}

		for (int i = 0; i < 300; i++) {
			ByteBuffer buf = ByteBuffer.allocate(4);
			memory.getBytes(i, b.addr(0x4000), buf);
			assertArrayEquals(b.arr(1, 2, 3, i % 256), buf.array());
		}
	}

	@Test
	public void testOverlaySpaces() throws Exception {
		try (Transaction tx = b.startTransaction()) {
			AddressSpace os = memory.createOverlayAddressSpace("test",
				b.trace.getBaseAddressFactory().getDefaultAddressSpace());
			DBTraceMemorySpace space = memory.getMemorySpace(os, true);
			assertEquals(4, space.putBytes(0, os.getAddress(0x4000), b.buf(1, 2, 3, 4)));

			ByteBuffer read = ByteBuffer.allocate(4);
			// This is from original space, not overlay, so should be 0s
			assertEquals(4, memory.getBytes(0, b.addr(0x4000), read));
			assertArrayEquals(b.arr(0, 0, 0, 0), read.array());
			read.clear();

			assertEquals(4, space.getBytes(0, os.getAddress(0x4000), read));
			assertArrayEquals(b.arr(1, 2, 3, 4), read.array());
		}
	}
}
