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

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.Map.Entry;

import org.junit.*;

import com.google.common.collect.Range;

import db.DBHandle;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.util.DefaultLanguageService;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.stack.DBTraceStack;
import ghidra.trace.database.thread.DBTraceThread;
import ghidra.trace.model.ImmutableTraceAddressSnapRange;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.util.database.*;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractDBTraceMemoryManagerTest
		extends AbstractGhidraHeadlessIntegrationTest {
	protected Language toyLanguage;
	protected DBTrace trace;
	protected DBTraceMemoryManager memory;

	protected abstract LanguageID getLanguageID();

	@Before
	public void setUp() throws IOException {
		toyLanguage = DefaultLanguageService.getLanguageService()
				.getLanguage(getLanguageID());
		trace = new DBTrace("Testing", toyLanguage.getDefaultCompilerSpec(), this);
		memory = trace.getMemoryManager();
	}

	@After
	public void tearDown() {
		trace.release(this);
	}

	protected Address addr(long offset) {
		return toyLanguage.getDefaultDataSpace().getAddress(offset);
	}

	protected AddressRange range(long start, long end) {
		return new AddressRangeImpl(addr(start), addr(end));
	}

	protected TraceAddressSnapRange srange(long snap, long minOff, long maxOff) {
		return new ImmutableTraceAddressSnapRange(addr(minOff), addr(maxOff), snap, snap);
	}

	protected AddressSetView set(AddressRange... ranges) {
		AddressSet result = new AddressSet();
		for (AddressRange rng : ranges) {
			result.add(rng);
		}
		return result;
	}

	@Test
	public void testSetState() {
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			memory.setState(0, addr(0x4000), addr(0x5000), TraceMemoryState.KNOWN);

			// +1 Overflow
			memory.setState(0, range(0x4000, 0x7fffffffffffffffL), TraceMemoryState.KNOWN);
			memory.setState(0, range(0x4000, 0xffffffffffffffffL), TraceMemoryState.KNOWN);

			// NOP
			memory.setState(0, addr(0x4500), addr(0x5000), TraceMemoryState.KNOWN);

			AddressSet set = new AddressSet();
			set.add(addr(0x2000), addr(0x2500));
			set.add(addr(0x4000), addr(0x5000)); // NOP when set
			memory.setState(0, set, TraceMemoryState.KNOWN);

			// ERR
			AddressSpace regs = trace.getBaseAddressFactory().getRegisterSpace();
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
		assertEquals(null, memory.getState(3, addr(0x4000)));

		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			memory.setState(3, addr(0x4000), TraceMemoryState.KNOWN);
		}

		assertEquals(TraceMemoryState.KNOWN, memory.getState(3, addr(0x4000)));
		assertEquals(TraceMemoryState.UNKNOWN, memory.getState(3, addr(0x4001)));
		assertEquals(TraceMemoryState.UNKNOWN, memory.getState(3, addr(0x3fff)));
		assertEquals(TraceMemoryState.UNKNOWN, memory.getState(2, addr(0x4000)));
		assertEquals(TraceMemoryState.UNKNOWN, memory.getState(4, addr(0x4000)));

		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			memory.setState(3, addr(0x4000), TraceMemoryState.ERROR);
		}

		assertEquals(TraceMemoryState.ERROR, memory.getState(3, addr(0x4000)));
		assertEquals(TraceMemoryState.UNKNOWN, memory.getState(3, addr(0x4001)));
		assertEquals(TraceMemoryState.UNKNOWN, memory.getState(3, addr(0x3fff)));
		assertEquals(TraceMemoryState.UNKNOWN, memory.getState(2, addr(0x4000)));
		assertEquals(TraceMemoryState.UNKNOWN, memory.getState(4, addr(0x4000)));
	}

	@Test
	public void testSetRangeGetState() {
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			memory.setState(3, addr(0x4000), addr(0x5000), TraceMemoryState.KNOWN);
		}

		assertEquals(TraceMemoryState.KNOWN, memory.getState(3, addr(0x4800)));
		assertEquals(TraceMemoryState.KNOWN, memory.getState(3, addr(0x4000)));
		assertEquals(TraceMemoryState.KNOWN, memory.getState(3, addr(0x5000)));
		assertEquals(TraceMemoryState.UNKNOWN, memory.getState(3, addr(0x3fff)));
		assertEquals(TraceMemoryState.UNKNOWN, memory.getState(3, addr(0x5001)));
		assertEquals(TraceMemoryState.UNKNOWN, memory.getState(2, addr(0x4800)));
		assertEquals(TraceMemoryState.UNKNOWN, memory.getState(4, addr(0x4800)));
	}

	protected static void assertSnapState(long snap, TraceMemoryState state,
			Entry<TraceAddressSnapRange, TraceMemoryState> entry) {
		assertEquals(snap, entry.getKey().getY1().longValue());
		assertEquals(state, entry.getValue());
	}

	@Test
	public void testGetMostRecentStateSingleRange() {
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			memory.setState(3, addr(0x4000), addr(0x5000), TraceMemoryState.KNOWN);
		}

		assertEquals(null, memory.getMostRecentStateEntry(2, addr(0)));
		assertEquals(null, memory.getMostRecentStateEntry(2, addr(0x3fff)));
		assertEquals(null, memory.getMostRecentStateEntry(2, addr(0x4000)));
		assertEquals(null, memory.getMostRecentStateEntry(2, addr(0x5000)));
		assertEquals(null, memory.getMostRecentStateEntry(2, addr(0x5001)));

		assertEquals(null, memory.getMostRecentStateEntry(3, addr(0)));
		assertEquals(null, memory.getMostRecentStateEntry(3, addr(0x3fff)));
		assertSnapState(3, TraceMemoryState.KNOWN, memory.getMostRecentStateEntry(3, addr(0x4000)));
		assertSnapState(3, TraceMemoryState.KNOWN, memory.getMostRecentStateEntry(3, addr(0x5000)));
		assertEquals(null, memory.getMostRecentStateEntry(3, addr(0x5001)));

		assertEquals(null, memory.getMostRecentStateEntry(4, addr(0)));
		assertEquals(null, memory.getMostRecentStateEntry(4, addr(0x3fff)));
		assertSnapState(3, TraceMemoryState.KNOWN, memory.getMostRecentStateEntry(4, addr(0x4000)));
		assertSnapState(3, TraceMemoryState.KNOWN, memory.getMostRecentStateEntry(4, addr(0x5000)));
		assertEquals(null, memory.getMostRecentStateEntry(4, addr(0x5001)));
	}

	@Test
	public void testGetMostRecentStateSameSnap() {
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			memory.setState(3, addr(0x4000), addr(0x5000), TraceMemoryState.KNOWN);
			memory.setState(3, addr(0x4020), addr(0x4080), TraceMemoryState.ERROR);
		}

		assertEquals(null, memory.getMostRecentStateEntry(2, addr(0)));
		assertEquals(null, memory.getMostRecentStateEntry(2, addr(0x3fff)));
		assertEquals(null, memory.getMostRecentStateEntry(2, addr(0x4000)));
		assertEquals(null, memory.getMostRecentStateEntry(2, addr(0x401f)));
		assertEquals(null, memory.getMostRecentStateEntry(2, addr(0x4020)));
		assertEquals(null, memory.getMostRecentStateEntry(2, addr(0x4080)));
		assertEquals(null, memory.getMostRecentStateEntry(2, addr(0x4081)));
		assertEquals(null, memory.getMostRecentStateEntry(2, addr(0x5000)));
		assertEquals(null, memory.getMostRecentStateEntry(2, addr(0x5001)));

		assertEquals(null, memory.getMostRecentStateEntry(3, addr(0)));
		assertEquals(null, memory.getMostRecentStateEntry(3, addr(0x3fff)));
		assertSnapState(3, TraceMemoryState.KNOWN, memory.getMostRecentStateEntry(3, addr(0x4000)));
		assertSnapState(3, TraceMemoryState.KNOWN, memory.getMostRecentStateEntry(3, addr(0x401f)));
		assertSnapState(3, TraceMemoryState.ERROR, memory.getMostRecentStateEntry(3, addr(0x4020)));
		assertSnapState(3, TraceMemoryState.ERROR, memory.getMostRecentStateEntry(3, addr(0x4080)));
		assertSnapState(3, TraceMemoryState.KNOWN, memory.getMostRecentStateEntry(3, addr(0x4081)));
		assertSnapState(3, TraceMemoryState.KNOWN, memory.getMostRecentStateEntry(3, addr(0x5000)));
		assertEquals(null, memory.getMostRecentStateEntry(3, addr(0x5001)));

		assertEquals(null, memory.getMostRecentStateEntry(5, addr(0)));
		assertEquals(null, memory.getMostRecentStateEntry(5, addr(0x3fff)));
		assertSnapState(3, TraceMemoryState.KNOWN, memory.getMostRecentStateEntry(5, addr(0x4000)));
		assertSnapState(3, TraceMemoryState.KNOWN, memory.getMostRecentStateEntry(5, addr(0x401f)));
		assertSnapState(3, TraceMemoryState.ERROR, memory.getMostRecentStateEntry(5, addr(0x4020)));
		assertSnapState(3, TraceMemoryState.ERROR, memory.getMostRecentStateEntry(5, addr(0x4080)));
		assertSnapState(3, TraceMemoryState.KNOWN, memory.getMostRecentStateEntry(5, addr(0x4081)));
		assertSnapState(3, TraceMemoryState.KNOWN, memory.getMostRecentStateEntry(5, addr(0x5000)));
		assertEquals(null, memory.getMostRecentStateEntry(5, addr(0x5001)));
	}

	@Test
	public void testGetMostRecentStateLaterBefore() {
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			memory.setState(3, addr(0x4000), addr(0x5000), TraceMemoryState.KNOWN);
			memory.setState(4, addr(0x3000), addr(0x3500), TraceMemoryState.ERROR);
		}

		assertEquals(null, memory.getMostRecentStateEntry(2, addr(0)));
		assertEquals(null, memory.getMostRecentStateEntry(2, addr(0x2fff)));
		assertEquals(null, memory.getMostRecentStateEntry(2, addr(0x3000)));
		assertEquals(null, memory.getMostRecentStateEntry(2, addr(0x3500)));
		assertEquals(null, memory.getMostRecentStateEntry(2, addr(0x3501)));
		assertEquals(null, memory.getMostRecentStateEntry(2, addr(0x3fff)));
		assertEquals(null, memory.getMostRecentStateEntry(2, addr(0x4000)));
		assertEquals(null, memory.getMostRecentStateEntry(2, addr(0x5000)));
		assertEquals(null, memory.getMostRecentStateEntry(2, addr(0x5001)));

		assertEquals(null, memory.getMostRecentStateEntry(3, addr(0)));
		assertEquals(null, memory.getMostRecentStateEntry(3, addr(0x2fff)));
		assertEquals(null, memory.getMostRecentStateEntry(3, addr(0x3000)));
		assertEquals(null, memory.getMostRecentStateEntry(3, addr(0x3500)));
		assertEquals(null, memory.getMostRecentStateEntry(3, addr(0x3501)));
		assertEquals(null, memory.getMostRecentStateEntry(3, addr(0x3fff)));
		assertSnapState(3, TraceMemoryState.KNOWN, memory.getMostRecentStateEntry(3, addr(0x4000)));
		assertSnapState(3, TraceMemoryState.KNOWN, memory.getMostRecentStateEntry(3, addr(0x5000)));
		assertEquals(null, memory.getMostRecentStateEntry(3, addr(0x5001)));

		assertEquals(null, memory.getMostRecentStateEntry(4, addr(0)));
		assertEquals(null, memory.getMostRecentStateEntry(4, addr(0x2fff)));
		assertSnapState(4, TraceMemoryState.ERROR, memory.getMostRecentStateEntry(4, addr(0x3000)));
		assertSnapState(4, TraceMemoryState.ERROR, memory.getMostRecentStateEntry(4, addr(0x3500)));
		assertEquals(null, memory.getMostRecentStateEntry(4, addr(0x3501)));
		assertEquals(null, memory.getMostRecentStateEntry(4, addr(0x3fff)));
		assertSnapState(3, TraceMemoryState.KNOWN, memory.getMostRecentStateEntry(4, addr(0x4000)));
		assertSnapState(3, TraceMemoryState.KNOWN, memory.getMostRecentStateEntry(4, addr(0x5000)));
		assertEquals(null, memory.getMostRecentStateEntry(4, addr(0x5001)));

		assertEquals(null, memory.getMostRecentStateEntry(5, addr(0)));
		assertEquals(null, memory.getMostRecentStateEntry(5, addr(0x2fff)));
		assertSnapState(4, TraceMemoryState.ERROR, memory.getMostRecentStateEntry(5, addr(0x3000)));
		assertSnapState(4, TraceMemoryState.ERROR, memory.getMostRecentStateEntry(5, addr(0x3500)));
		assertEquals(null, memory.getMostRecentStateEntry(5, addr(0x3501)));
		assertEquals(null, memory.getMostRecentStateEntry(5, addr(0x3fff)));
		assertSnapState(3, TraceMemoryState.KNOWN, memory.getMostRecentStateEntry(5, addr(0x4000)));
		assertSnapState(3, TraceMemoryState.KNOWN, memory.getMostRecentStateEntry(5, addr(0x5000)));
		assertEquals(null, memory.getMostRecentStateEntry(5, addr(0x5001)));
	}

	@Test
	public void testGetMostRecentStateLaterOverStart() {
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			memory.setState(3, addr(0x4000), addr(0x5000), TraceMemoryState.KNOWN);
			memory.setState(4, addr(0x3000), addr(0x4500), TraceMemoryState.ERROR);
		}

		assertEquals(null, memory.getMostRecentStateEntry(2, addr(0)));
		assertEquals(null, memory.getMostRecentStateEntry(2, addr(0x2fff)));
		assertEquals(null, memory.getMostRecentStateEntry(2, addr(0x3000)));
		assertEquals(null, memory.getMostRecentStateEntry(2, addr(0x3fff)));
		assertEquals(null, memory.getMostRecentStateEntry(2, addr(0x4000)));
		assertEquals(null, memory.getMostRecentStateEntry(2, addr(0x4500)));
		assertEquals(null, memory.getMostRecentStateEntry(2, addr(0x4501)));
		assertEquals(null, memory.getMostRecentStateEntry(2, addr(0x5000)));
		assertEquals(null, memory.getMostRecentStateEntry(2, addr(0x5001)));

		assertEquals(null, memory.getMostRecentStateEntry(3, addr(0)));
		assertEquals(null, memory.getMostRecentStateEntry(3, addr(0x2fff)));
		assertEquals(null, memory.getMostRecentStateEntry(3, addr(0x3000)));
		assertEquals(null, memory.getMostRecentStateEntry(3, addr(0x3fff)));
		assertSnapState(3, TraceMemoryState.KNOWN, memory.getMostRecentStateEntry(3, addr(0x4000)));
		assertSnapState(3, TraceMemoryState.KNOWN, memory.getMostRecentStateEntry(3, addr(0x4500)));
		assertSnapState(3, TraceMemoryState.KNOWN, memory.getMostRecentStateEntry(3, addr(0x4501)));
		assertSnapState(3, TraceMemoryState.KNOWN, memory.getMostRecentStateEntry(3, addr(0x5000)));
		assertEquals(null, memory.getMostRecentStateEntry(3, addr(0x5001)));

		assertEquals(null, memory.getMostRecentStateEntry(4, addr(0)));
		assertEquals(null, memory.getMostRecentStateEntry(4, addr(0x2fff)));
		assertSnapState(4, TraceMemoryState.ERROR, memory.getMostRecentStateEntry(4, addr(0x3000)));
		assertSnapState(4, TraceMemoryState.ERROR, memory.getMostRecentStateEntry(4, addr(0x3fff)));
		assertSnapState(4, TraceMemoryState.ERROR, memory.getMostRecentStateEntry(4, addr(0x4000)));
		assertSnapState(4, TraceMemoryState.ERROR, memory.getMostRecentStateEntry(4, addr(0x4500)));
		assertSnapState(3, TraceMemoryState.KNOWN, memory.getMostRecentStateEntry(4, addr(0x4501)));
		assertSnapState(3, TraceMemoryState.KNOWN, memory.getMostRecentStateEntry(4, addr(0x5000)));
		assertEquals(null, memory.getMostRecentStateEntry(4, addr(0x5001)));

		assertEquals(null, memory.getMostRecentStateEntry(5, addr(0)));
		assertEquals(null, memory.getMostRecentStateEntry(5, addr(0x2fff)));
		assertSnapState(4, TraceMemoryState.ERROR, memory.getMostRecentStateEntry(5, addr(0x3000)));
		assertSnapState(4, TraceMemoryState.ERROR, memory.getMostRecentStateEntry(5, addr(0x3fff)));
		assertSnapState(4, TraceMemoryState.ERROR, memory.getMostRecentStateEntry(5, addr(0x4000)));
		assertSnapState(4, TraceMemoryState.ERROR, memory.getMostRecentStateEntry(5, addr(0x4500)));
		assertSnapState(3, TraceMemoryState.KNOWN, memory.getMostRecentStateEntry(5, addr(0x4501)));
		assertSnapState(3, TraceMemoryState.KNOWN, memory.getMostRecentStateEntry(5, addr(0x5000)));
		assertEquals(null, memory.getMostRecentStateEntry(5, addr(0x5001)));
	}

	@Test
	public void testGetAddressesWithState() {
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			memory.setState(3, addr(0x4000), addr(0x7000), TraceMemoryState.KNOWN);
			memory.setState(3, addr(0x5000), addr(0x6000), TraceMemoryState.ERROR);
			memory.setState(4, addr(0x3000), addr(0x4800), TraceMemoryState.KNOWN);
		}

		AddressSet set = new AddressSet();
		set.add(range(0x2800, 0x3800));
		set.add(range(0x3c00, 0x4800));
		set.add(range(0x4c00, 0x6100));
		set.add(range(0x8000, 0x9000));

		AddressSet expected;
		AddressSetView result;

		expected = new AddressSet();
		expected.add(range(0x3000, 0x3800));
		expected.add(range(0x3c00, 0x4800));
		result = memory.getAddressesWithState(4, set, state -> state == TraceMemoryState.KNOWN);
		assertEquals(expected, set.intersect(result));

		expected = new AddressSet();
		expected.add(range(0x4000, 0x4800));
		expected.add(range(0x4c00, 0x4fff));
		expected.add(range(0x6001, 0x6100));
		result = memory.getAddressesWithState(3, set, state -> state == TraceMemoryState.KNOWN);
		assertEquals(expected, set.intersect(result));

		// Test gaps
		expected = new AddressSet();
		expected.add(range(0x2800, 0x3800));
		expected.add(range(0x3c00, 0x3fff));
		expected.add(range(0x8000, 0x9000));
		result = memory.getAddressesWithState(3, set, state -> true);
		assertEquals(expected, set.subtract(result));
	}

	@Test
	public void testGetStates() {
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			memory.setState(3, addr(0x4000), addr(0x7000), TraceMemoryState.KNOWN);
			memory.setState(3, addr(0x5000), addr(0x6000), TraceMemoryState.ERROR);
		}

		Map<TraceAddressSnapRange, TraceMemoryState> expected;

		expected = new HashMap<>();
		expected.put(srange(3, 0x4000, 0x4fff), TraceMemoryState.KNOWN);
		expected.put(srange(3, 0x5000, 0x6000), TraceMemoryState.ERROR);
		expected.put(srange(3, 0x6001, 0x7000), TraceMemoryState.KNOWN);
		assertEquals(expected, collectAsMap(memory.getStates(3, range(0x3000, 0x8000))));
	}

	protected static Map<TraceAddressSnapRange, TraceMemoryState> collectAsMap(
			Iterable<Entry<TraceAddressSnapRange, TraceMemoryState>> it) {
		Map<TraceAddressSnapRange, TraceMemoryState> result = new HashMap<>();
		for (Entry<TraceAddressSnapRange, TraceMemoryState> entry : it) {
			assertNotNull(entry.getValue());
			TraceMemoryState old = result.put(entry.getKey(), entry.getValue());
			assertNull(old);
		}
		return result;
	}

	@Test
	public void testGetMostRecentStates() {
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			memory.setState(3, addr(0x4000), addr(0x7000), TraceMemoryState.KNOWN);
			memory.setState(3, addr(0x5000), addr(0x6000), TraceMemoryState.ERROR);
			memory.setState(4, addr(0x3000), addr(0x4800), TraceMemoryState.KNOWN);
		}

		Map<TraceAddressSnapRange, TraceMemoryState> expected;

		expected = new HashMap<>();
		assertEquals(expected, collectAsMap(memory.getMostRecentStates(2, range(0x2800, 0x9000))));

		expected = new HashMap<>();
		expected.put(srange(3, 0x4000, 0x4fff), TraceMemoryState.KNOWN);
		expected.put(srange(3, 0x5000, 0x6000), TraceMemoryState.ERROR);
		expected.put(srange(3, 0x6001, 0x7000), TraceMemoryState.KNOWN);
		assertEquals(expected, collectAsMap(memory.getMostRecentStates(3, range(0x2800, 0x9000))));

		expected = new HashMap<>();
		expected.put(srange(4, 0x3000, 0x4800), TraceMemoryState.KNOWN);
		expected.put(srange(3, 0x4801, 0x4fff), TraceMemoryState.KNOWN);
		expected.put(srange(3, 0x5000, 0x6000), TraceMemoryState.ERROR);
		expected.put(srange(3, 0x6001, 0x7000), TraceMemoryState.KNOWN);
		assertEquals(expected, collectAsMap(memory.getMostRecentStates(4, range(0x2800, 0x9000))));
		assertEquals(expected, collectAsMap(memory.getMostRecentStates(5, range(0x2800, 0x9000))));
	}

	protected byte[] arr(int... e) {
		byte[] result = new byte[e.length];
		for (int i = 0; i < e.length; i++) {
			result[i] = (byte) e[i];
		}
		return result;
	}

	protected ByteBuffer buf(int... e) {
		return ByteBuffer.wrap(arr(e));
	}

	protected int getBlockRecordCount() {
		DBTraceMemorySpace space = memory.getForSpace(toyLanguage.getDefaultSpace(), false);
		if (space == null) {
			return 0;
		}
		return space.blockStore.getRecordCount();
	}

	protected DBCachedObjectStore<DBTraceMemoryBufferEntry> getBufferStore() {
		DBTraceMemorySpace space = memory.getForSpace(toyLanguage.getDefaultSpace(), false);
		if (space == null) {
			return null;
		}
		return space.bufferStore;
	}

	protected int getBufferRecordCount() {
		DBCachedObjectStore<DBTraceMemoryBufferEntry> bufferStore = getBufferStore();
		if (bufferStore == null) {
			return 0;
		}
		return bufferStore.getRecordCount();
	}

	@Test
	public void testBytes0Length() {
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			assertEquals(0, memory.putBytes(3, addr(0x4000), buf()));
			assertEquals(0, getBlockRecordCount());
			assertEquals(0, getBufferRecordCount());
		}

		assertEquals(0, memory.getBytes(3, addr(0x4000), buf()));

		ByteBuffer read = buf(-1, -2, -3, -4);
		assertEquals(4, memory.getBytes(3, addr(0x3ffe), read));
		assertEquals(0, read.remaining());
		// NOTE: I think this is OK, because the state ought to be UNKNOWN anyway.
		assertArrayEquals(arr(-1, -2, -3, -4), read.array());
	}

	@Test
	public void testBytesSimple4Zeros() {
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			assertEquals(4, memory.putBytes(3, addr(0x4000), buf(0, 0, 0, 0)));
			assertEquals(4, memory.putBytes(3, addr(0x4000), buf(0, 0, 0, 0))); // Should have no effect
			assertEquals(1, getBlockRecordCount());
			// Zeros do not require buffer backing
			assertEquals(0, getBufferRecordCount());
		}

		// verify the corresponding change in state;
		Map<TraceAddressSnapRange, TraceMemoryState> expected;
		expected = new HashMap<>();
		expected.put(srange(3, 0x4000, 0x4003), TraceMemoryState.KNOWN);
		assertEquals(expected, collectAsMap(memory.getStates(3, range(0x3000, 0x5000))));

		ByteBuffer read = buf(-1, -2, -3, -4); // Verify zeros actually written
		assertEquals(4, memory.getBytes(3, addr(0x4000), read));
		assertArrayEquals(arr(0, 0, 0, 0), read.array());
	}

	@Test
	public void testBytesSimple4Bytes() {
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			assertEquals(4, memory.putBytes(3, addr(0x4000), buf(1, 2, 3, 4)));
			assertEquals(1, getBlockRecordCount());
			assertEquals(1, getBufferRecordCount());
		}
		DBTraceMemoryBufferEntry bufEnt = getBufferStore().getObjectAt(0);
		assertFalse(bufEnt.isCompressed());

		// verify the corresponding change in state;
		Map<TraceAddressSnapRange, TraceMemoryState> expected;
		expected = new HashMap<>();
		expected.put(srange(3, 0x4000, 0x4003), TraceMemoryState.KNOWN);
		assertEquals(expected, collectAsMap(memory.getStates(3, range(0x3000, 0x5000))));

		ByteBuffer read = ByteBuffer.allocate(4);
		assertEquals(4, memory.getBytes(3, addr(0x4000), read));
		assertArrayEquals(arr(1, 2, 3, 4), read.array());
	}

	@Test
	public void testBytesSpan4Bytes() {
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			assertEquals(4, memory.putBytes(3, addr(0x3ffe), buf(1, 2, 3, 4)));
			assertEquals(2, getBlockRecordCount());
			assertEquals(2, getBufferRecordCount());
		}

		ByteBuffer read = ByteBuffer.allocate(4);
		assertEquals(4, memory.getBytes(3, addr(0x3ffe), read));
		assertArrayEquals(arr(1, 2, 3, 4), read.array());
	}

	@Test
	public void testBytesSpan12BytesInChunks() {
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			assertEquals(4, memory.putBytes(3, addr(0x3ffa), buf(1, 2, 3, 4)));
			assertEquals(1, getBlockRecordCount());
			assertEquals(4, memory.putBytes(3, addr(0x3ffe), buf(5, 6, 7, 8)));
			assertEquals(2, getBlockRecordCount());
			assertEquals(4, memory.putBytes(3, addr(0x4002), buf(9, 10, 11, 12)));
			assertEquals(2, getBlockRecordCount());
			assertEquals(2, getBufferRecordCount());
		}

		ByteBuffer read = ByteBuffer.allocate(12);
		assertEquals(12, memory.getBytes(3, addr(0x3ffa), read));
		assertArrayEquals(arr(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12), read.array());
	}

	@Test
	public void testBytesOverflow() {
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			ByteBuffer write = buf(1, 2, 3, 4);
			assertEquals(2, memory.putBytes(3, addr(0xfffffffffffffffeL), write));
			assertEquals(2, write.remaining());
			assertEquals(1, getBlockRecordCount());
			assertEquals(1, getBufferRecordCount());
		}

		ByteBuffer read = buf(-1, -1, -1, -1);
		assertEquals(2, memory.getBytes(3, addr(0xfffffffffffffffeL), read));
		assertEquals(2, read.remaining());
		assertArrayEquals(arr(1, 2, -1, -1), read.array());
	}

	@Test
	public void testBytesWriteSameLater() {
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			assertEquals(4, memory.putBytes(3, addr(0x4000), buf(1, 2, 3, 4)));
			assertEquals(1, getBlockRecordCount());
			assertEquals(1, getBufferRecordCount());

			assertEquals(4, memory.putBytes(5, addr(0x4000), buf(1, 2, 3, 4)));
			assertEquals(1, getBlockRecordCount()); // Should not require a new block
			assertEquals(1, getBufferRecordCount()); // Definitely not another buffer
		}

		// verify the corresponding change in state;
		Map<TraceAddressSnapRange, TraceMemoryState> expected;

		expected = new HashMap<>();
		assertEquals(expected, collectAsMap(memory.getStates(2, range(0x3000, 0x5000))));
		assertEquals(expected, collectAsMap(memory.getStates(4, range(0x3000, 0x5000))));
		assertEquals(expected, collectAsMap(memory.getStates(6, range(0x3000, 0x5000))));

		expected = new HashMap<>();
		expected.put(srange(3, 0x4000, 0x4003), TraceMemoryState.KNOWN);
		assertEquals(expected, collectAsMap(memory.getStates(3, range(0x3000, 0x5000))));
		expected = new HashMap<>();
		expected.put(srange(5, 0x4000, 0x4003), TraceMemoryState.KNOWN);
		assertEquals(expected, collectAsMap(memory.getStates(5, range(0x3000, 0x5000))));

		ByteBuffer read = buf(0, 0, 0, 0);
		assertEquals(4, memory.getBytes(5, addr(0x4000), read));
		assertArrayEquals(arr(1, 2, 3, 4), read.array());
	}

	@Test
	public void testBytesArrayOffset() {
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			byte[] array = new byte[20];
			array[9] = -1;
			array[10] = 1;
			array[11] = 2;
			array[12] = 3;
			array[13] = 4;
			array[14] = -1;
			assertEquals(4, memory.putBytes(3, addr(0x4000), ByteBuffer.wrap(array, 10, 4)));
		}

		byte[] array = new byte[20];
		array[9] = -2;
		array[16] = -2;
		ByteBuffer read = ByteBuffer.wrap(array, 10, 6);
		assertEquals(6, memory.getBytes(3, addr(0x3fff), read));
		assertArrayEquals(arr(-2, 0, 1, 2, 3, 4, 0, -2), Arrays.copyOfRange(array, 9, 17));
	}

	@Test
	public void testGetBytesMostRecent() {
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			assertEquals(4, memory.putBytes(3, addr(0x4000), buf(1, 2, 3, 4)));
			assertEquals(4, memory.putBytes(4, addr(0x4002), buf(5, 6, 7, 8)));
			assertEquals(1, memory.putBytes(5, addr(0x4003), buf(0)));
			assertEquals(3, getBlockRecordCount());
			assertEquals(1, getBufferRecordCount());
		}

		ByteBuffer read = buf(-1, -1, -1, -1);
		assertEquals(4, memory.getBytes(2, addr(0x4000), read));
		assertArrayEquals(arr(-1, -1, -1, -1), read.array());

		read.position(0);
		assertEquals(4, memory.getBytes(3, addr(0x4000), read));
		assertArrayEquals(arr(1, 2, 3, 4), read.array());

		read.position(0);
		assertEquals(4, memory.getBytes(4, addr(0x4002), read));
		assertArrayEquals(arr(5, 6, 7, 8), read.array());

		read.position(0);
		assertEquals(4, memory.getBytes(4, addr(0x4000), read));
		assertArrayEquals(arr(1, 2, 5, 6), read.array());

		read = ByteBuffer.allocate(10);
		assertEquals(10, memory.getBytes(5, addr(0x3ffe), read));
		assertArrayEquals(arr(0, 0, 1, 2, 5, 0, 7, 8, 0, 0), read.array());
	}

	@Test
	public void testPutBytesIntoPastGetBytesMostRecent() {
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			assertEquals(4, memory.putBytes(4, addr(0x4800), buf(5, 6, 7, 8)));
			assertEquals(4, memory.putBytes(3, addr(0x4802), buf(1, 2, 3, 4)));
			assertEquals(10,
				memory.putBytes(2, addr(0x47fe), buf(9, 10, 11, 12, 13, 14, 15, 16, 17, 18)));
			assertEquals(3, getBlockRecordCount());
			assertEquals(1, getBufferRecordCount());
		}

		ByteBuffer read = buf(-1, -1, -1, -1);
		assertEquals(4, memory.getBytes(1, addr(0x4802), read));
		assertArrayEquals(arr(-1, -1, -1, -1), read.array());

		read.position(0);
		assertEquals(4, memory.getBytes(3, addr(0x4802), read));
		assertArrayEquals(arr(1, 2, 3, 4), read.array());

		read.position(0);
		assertEquals(4, memory.getBytes(4, addr(0x4800), read));
		assertArrayEquals(arr(5, 6, 7, 8), read.array());

		read.position(0);
		assertEquals(4, memory.getBytes(4, addr(0x4802), read));
		assertArrayEquals(arr(7, 8, 3, 4), read.array());

		read = ByteBuffer.allocate(14);
		assertEquals(14, memory.getBytes(4, addr(0x47fc), read));
		assertArrayEquals(arr(0, 0, 9, 10, 5, 6, 7, 8, 3, 4, 17, 18, 0, 0), read.array());
	}

	@Test
	public void testPutBytesPackGetBytes() {
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			assertEquals(4, memory.putBytes(3, addr(0x4000), buf(1, 2, 3, 4)));
			memory.pack();
			assertEquals(1, getBlockRecordCount());
			assertEquals(1, getBufferRecordCount());
		}
		DBTraceMemoryBufferEntry bufEnt = getBufferStore().getObjectAt(0);
		assertTrue(bufEnt.isCompressed());

		ByteBuffer read = ByteBuffer.allocate(4);
		assertEquals(4, memory.getBytes(3, addr(0x4000), read));
		assertArrayEquals(arr(1, 2, 3, 4), read.array());

		assertTrue(bufEnt.isCompressed());
	}

	@Test
	public void testPutBytesPackPutBytes() {
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			assertEquals(4, memory.putBytes(3, addr(0x4000), buf(1, 2, 3, 4)));
			memory.pack();
			assertEquals(1, getBlockRecordCount());
			assertEquals(1, getBufferRecordCount());
			DBTraceMemoryBufferEntry bufEnt = getBufferStore().getObjectAt(0);
			assertTrue(bufEnt.isCompressed());
			assertEquals(4, memory.putBytes(3, addr(0x4000), buf(1, 2, 3, 4)));
			assertFalse(bufEnt.isCompressed()); // TODO: This is an implementation quirk. Do I care?
		}

		ByteBuffer read = ByteBuffer.allocate(4);
		assertEquals(4, memory.getBytes(3, addr(0x4000), read));
		assertArrayEquals(arr(1, 2, 3, 4), read.array());
	}

	@Test
	public void testFindBytes() {
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			assertEquals(5, memory.putBytes(3, addr(0x4000), buf(1, 2, 3, 4, 5)));
		}

		try {
			memory.findBytes(3, range(0x4000, 0x4003), buf(1, 2, 3, 4), buf(-1, -1, -1),
				true, TaskMonitor.DUMMY);
		}
		catch (IllegalArgumentException e) {
			// pass
		}

		// Degenerate
		assertNull(
			memory.findBytes(2, range(0x4000, 0x4003), buf(), buf(),
				true, TaskMonitor.DUMMY));

		// Too soon
		assertNull(
			memory.findBytes(2, range(0x4000, 0x4003), buf(1, 2, 3, 4), buf(-1, -1, -1, -1),
				true, TaskMonitor.DUMMY));

		// Too small
		assertNull(
			memory.findBytes(3, range(0x4000, 0x4002), buf(1, 2, 3, 4), buf(-1, -1, -1, -1),
				true, TaskMonitor.DUMMY));

		// Too high
		assertNull(
			memory.findBytes(3, range(0x4001, 0x4004), buf(1, 2, 3, 4), buf(-1, -1, -1, -1),
				true, TaskMonitor.DUMMY));

		// Too high, into unknown
		assertNull(
			memory.findBytes(3, range(0x4001, 0x4005), buf(1, 2, 3, 4, 5), buf(-1, -1, -1, -1, -1),
				true, TaskMonitor.DUMMY));

		// Too low
		assertNull(
			memory.findBytes(3, range(0x3fff, 0x4002), buf(1, 2, 3, 4), buf(-1, -1, -1, -1),
				true, TaskMonitor.DUMMY));

		// Perfect match
		assertEquals(addr(0x4000),
			memory.findBytes(3, range(0x4000, 0x4003), buf(1, 2, 3, 4), buf(-1, -1, -1, -1),
				true, TaskMonitor.DUMMY));

		// Make it work for the match
		assertEquals(addr(0x4000),
			memory.findBytes(3, range(0x0, -1), buf(1, 2, 3, 4), buf(-1, -1, -1, -1),
				true, TaskMonitor.DUMMY));

		// Make it work for the match
		assertEquals(addr(0x4000),
			memory.findBytes(3, range(0x0, -1), buf(1), buf(-1),
				true, TaskMonitor.DUMMY));

		// Sub match
		assertEquals(addr(0x4001),
			memory.findBytes(3, range(0x4000, 0x4003), buf(2, 3, 4), buf(-1, -1, -1),
				true, TaskMonitor.DUMMY));
	}

	@Test
	public void testRemoveBytes() {
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			assertEquals(10,
				memory.putBytes(2, addr(0x47fe), buf(9, 10, 11, 12, 13, 14, 15, 16, 17, 18)));
			assertEquals(4, memory.putBytes(4, addr(0x4800), buf(5, 6, 7, 8)));
			assertEquals(4, memory.putBytes(3, addr(0x4802), buf(1, 2, 3, 4)));
			assertEquals(3, getBlockRecordCount());
			assertEquals(1, getBufferRecordCount());
			/* 0x fe ff 00 01 02 03 04 05 06 07
			 * 
			 * 4:        5  6  7  8
			 * 3:              1  2  3  4
			 * 2:  9 10 11 12 13 14 15 16 17 18
			 */

			memory.removeBytes(2, addr(0x47ff), 14);
			/* 0x fe ff 00 01 02 03 04 05 06 07
			 * 
			 * 4:        5  6  7  8
			 * 3:              1  2  3  4
			 * 2:  9 .. .. .. .. .. .. .. .. ..
			 */
		}

		ByteBuffer read = ByteBuffer.allocate(4);
		assertEquals(4, memory.getBytes(1, addr(0x4802), read));
		assertArrayEquals(arr(0, 0, 0, 0), read.array());

		read.position(0);
		assertEquals(4, memory.getBytes(3, addr(0x4802), read));
		assertArrayEquals(arr(1, 2, 3, 4), read.array());

		read.position(0);
		assertEquals(4, memory.getBytes(4, addr(0x4800), read));
		assertArrayEquals(arr(5, 6, 7, 8), read.array());

		read.position(0);
		assertEquals(4, memory.getBytes(4, addr(0x4802), read));
		assertArrayEquals(arr(7, 8, 3, 4), read.array());

		read = ByteBuffer.allocate(14);
		assertEquals(14, memory.getBytes(4, addr(0x47fc), read));
		assertArrayEquals(arr(0, 0, 9, 0, 5, 6, 7, 8, 3, 4, 0, 0, 0, 0), read.array());

		// Check overall effect on state
		Map<TraceAddressSnapRange, TraceMemoryState> expected;
		expected = new HashMap<>();
		expected.put(srange(2, 0x47fe, 0x47fe), TraceMemoryState.KNOWN);
		expected.put(srange(4, 0x4800, 0x4803), TraceMemoryState.KNOWN);
		expected.put(srange(3, 0x4804, 0x4805), TraceMemoryState.KNOWN);
		assertEquals(expected, collectAsMap(memory.getMostRecentStates(6, range(0x4700, 0x4900))));
	}

	@Test
	public void testSaveAndLoad() throws Exception {
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			assertEquals(4, memory.putBytes(3, addr(0x4000), buf(1, 2, 3, 4)));
			assertEquals(1, getBlockRecordCount());
			assertEquals(1, getBufferRecordCount());
		}

		Path tmp = Files.createTempFile("test", ".db");
		Files.delete(tmp); // saveAs must create the file
		trace.getDBHandle().saveAs(tmp.toFile(), false, new ConsoleTaskMonitor());

		DBHandle opened = new DBHandle(tmp.toFile());
		DBTrace restored = null;
		try {
			restored = new DBTrace(opened, DBOpenMode.UPDATE, new ConsoleTaskMonitor(), this);

			DBTraceMemorySpace rSpace =
				restored.getMemoryManager().getMemorySpace(toyLanguage.getDefaultDataSpace(), true);
			assertEquals(1, rSpace.bufferStore.getRecordCount());

			// verify the corresponding change in state;
			Map<TraceAddressSnapRange, TraceMemoryState> expected;
			expected = new HashMap<>();
			expected.put(srange(3, 0x4000, 0x4003), TraceMemoryState.KNOWN);
			assertEquals(expected, collectAsMap(memory.getStates(3, range(0x3000, 0x5000))));

			ByteBuffer read = ByteBuffer.allocate(4);
			assertEquals(4, rSpace.getBytes(3, addr(0x4000), read));
			assertArrayEquals(arr(1, 2, 3, 4), read.array());
		}
		finally {
			if (restored != null) {
				restored.release(this);
			}
		}
	}

	@Test
	public void testAddButAbortedStillEmpty() throws Exception {
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			assertEquals(4, memory.putBytes(3, addr(0x4000), buf(1, 2, 3, 4)));
			assertEquals(1, getBlockRecordCount());
			assertEquals(1, getBufferRecordCount());

			// verify the corresponding change in state;
			Map<TraceAddressSnapRange, TraceMemoryState> expected;
			expected = new HashMap<>();
			expected.put(srange(3, 0x4000, 0x4003), TraceMemoryState.KNOWN);
			assertEquals(expected, collectAsMap(memory.getStates(3, range(0x3000, 0x5000))));

			tid.abort();
		}
		assertEquals(0, getBlockRecordCount());
		assertEquals(0, getBufferRecordCount());

		// verify the corresponding change in state;
		Map<AddressRange, TraceMemoryState> expected;
		expected = new HashMap<>();
		assertEquals(expected, collectAsMap(memory.getStates(3, range(0x3000, 0x5000))));

		ByteBuffer read = ByteBuffer.allocate(4);
		assertEquals(4, memory.getBytes(3, addr(0x4000), read));
		assertArrayEquals(arr(0, 0, 0, 0), read.array());
	}

	@Test
	public void testAddThenUndo() throws Exception {
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			assertEquals(4, memory.putBytes(3, addr(0x4000), buf(1, 2, 3, 4)));
			assertEquals(1, getBlockRecordCount());
			assertEquals(1, getBufferRecordCount());

			// verify the corresponding change in state;
			Map<TraceAddressSnapRange, TraceMemoryState> expected;
			expected = new HashMap<>();
			expected.put(srange(3, 0x4000, 0x4003), TraceMemoryState.KNOWN);
			assertEquals(expected, collectAsMap(memory.getStates(3, range(0x3000, 0x5000))));
		}
		trace.undo();

		assertEquals(0, getBlockRecordCount());
		assertEquals(0, getBufferRecordCount());

		// verify the corresponding change in state;
		Map<AddressRange, TraceMemoryState> expected;
		expected = new HashMap<>();
		assertEquals(expected, collectAsMap(memory.getStates(3, range(0x3000, 0x5000))));

		ByteBuffer read = ByteBuffer.allocate(4);
		assertEquals(4, memory.getBytes(3, addr(0x4000), read));
		assertArrayEquals(arr(0, 0, 0, 0), read.array());
	}

	@Test
	public void testAddThenUndoThenRedo() throws Exception {
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			assertEquals(4, memory.putBytes(3, addr(0x4000), buf(1, 2, 3, 4)));
			assertEquals(1, getBlockRecordCount());
			assertEquals(1, getBufferRecordCount());

			// verify the corresponding change in state;
			Map<TraceAddressSnapRange, TraceMemoryState> expected;
			expected = new HashMap<>();
			expected.put(srange(3, 0x4000, 0x4003), TraceMemoryState.KNOWN);
			assertEquals(expected, collectAsMap(memory.getStates(3, range(0x3000, 0x5000))));
		}
		trace.undo();

		assertEquals(0, getBlockRecordCount());
		assertEquals(0, getBufferRecordCount());

		// verify the corresponding change in state;
		Map<TraceAddressSnapRange, TraceMemoryState> expected;
		expected = new HashMap<>();
		assertEquals(expected, collectAsMap(memory.getStates(3, range(0x3000, 0x5000))));

		ByteBuffer read = ByteBuffer.allocate(4);
		assertEquals(4, memory.getBytes(3, addr(0x4000), read));
		assertArrayEquals(arr(0, 0, 0, 0), read.array());

		trace.redo();

		assertEquals(1, getBlockRecordCount());
		assertEquals(1, getBufferRecordCount());

		expected = new HashMap<>();
		expected.put(srange(3, 0x4000, 0x4003), TraceMemoryState.KNOWN);
		assertEquals(expected, collectAsMap(memory.getStates(3, range(0x3000, 0x5000))));

		read.position(0);
		assertEquals(4, memory.getBytes(3, addr(0x4000), read));
		assertArrayEquals(arr(1, 2, 3, 4), read.array());
	}

	@Test
	public void testHighBlockNumbers() throws Exception {
		/**
		 * This test gets down into the block buffer implementation. If the block number exceeds
		 * 127, if might (accidentally) get treated as negative. Thanks Java! We can create this
		 * situation by writing to the same address at more than 127 different snaps.
		 */

		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			for (int i = 0; i < 300; i++) {
				memory.putBytes(i, addr(0x4000), buf(1, 2, 3, i % 256));
			}
		}

		for (int i = 0; i < 300; i++) {
			ByteBuffer buf = ByteBuffer.allocate(4);
			memory.getBytes(i, addr(0x4000), buf);
			assertArrayEquals(arr(1, 2, 3, i % 256), buf.array());
		}
	}

	@Test
	public void testRegisters() throws Exception {
		Register r0 = toyLanguage.getRegister("r0");
		Register r0h = toyLanguage.getRegister("r0h");
		Register r0l = toyLanguage.getRegister("r0l");

		DBTraceThread thread;
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			thread = trace.getThreadManager().addThread("Thread1", Range.atLeast(0L));
			DBTraceMemoryRegisterSpace regs = memory.getMemoryRegisterSpace(thread, true);

			regs.setValue(0, new RegisterValue(r0, new BigInteger("0123456789ABCDEF", 16)));
			assertEquals(new BigInteger("0123456789ABCDEF", 16),
				regs.getValue(0, r0).getUnsignedValue());

			regs.setValue(0, new RegisterValue(r0h, new BigInteger("76543210", 16)));
			assertEquals(new BigInteger("7654321089ABCDEF", 16),
				regs.getValue(0, r0).getUnsignedValue());
			assertEquals(new BigInteger("76543210", 16), regs.getValue(0, r0h).getUnsignedValue());
			assertEquals(new BigInteger("89ABCDEF", 16), regs.getValue(0, r0l).getUnsignedValue());

			regs.setValue(0, new RegisterValue(r0l, new BigInteger("FEDCBA98", 16)));
			assertEquals(new BigInteger("76543210FEDCBA98", 16),
				regs.getValue(0, r0).getUnsignedValue());
			assertEquals(new BigInteger("76543210", 16), regs.getValue(0, r0h).getUnsignedValue());
			assertEquals(new BigInteger("FEDCBA98", 16), regs.getValue(0, r0l).getUnsignedValue());

			DBTraceStack stack = trace.getStackManager().getStack(thread, 0, true);
			stack.setDepth(2, true);
			assertEquals(regs, memory.getMemoryRegisterSpace(stack.getFrame(0, false), false));
			DBTraceMemoryRegisterSpace frame =
				memory.getMemoryRegisterSpace(stack.getFrame(1, false), true);
			assertNotEquals(regs, frame);

			frame.setValue(0, new RegisterValue(r0, new BigInteger("1032547698BADCFE", 16)));
			assertEquals(new BigInteger("1032547698BADCFE", 16),
				frame.getValue(0, r0).getUnsignedValue());
		}
	}

	/**
	 * This test is based on the MWE submitted in GitHub issue #2760.
	 */
	@Test
	public void testManyStateEntries() throws Exception {
		Register pc = toyLanguage.getRegister("pc");
		DBTraceThread thread;
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			thread = trace.getThreadManager().addThread("Thread1", Range.atLeast(0L));
			DBTraceMemoryRegisterSpace regs = memory.getMemoryRegisterSpace(thread, true);

			for (int i = 1; i < 2000; i++) {
				//System.err.println("Snap " + i);
				regs.setState(i, pc, TraceMemoryState.KNOWN);
				//regs.stateMapSpace.checkIntegrity();
			}
		}
	}
}
