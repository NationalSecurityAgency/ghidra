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

import static org.junit.Assert.*;

import java.io.IOException;

import org.junit.*;

import db.Transaction;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.database.memory.DBTraceMemoryManager;
import ghidra.trace.database.memory.DBTraceMemoryRegion;
import ghidra.trace.model.memory.TraceMemoryFlag;

public class DBTraceProgramViewMemoryTest extends AbstractGhidraHeadlessIntegrationTest {

	ToyDBTraceBuilder tb;

	DBTraceVariableSnapProgramView view;
	DBTraceProgramViewMemory vmem;
	DBTraceMemoryManager memory;

	@Before
	public void setUpTraceProgramViewMemoryTest() throws LanguageNotFoundException, IOException {
		tb = new ToyDBTraceBuilder("Testing", ProgramBuilder._TOY64_BE);
		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getTimeManager().createSnapshot("Created");
		}
		memory = tb.trace.getMemoryManager();
		// NOTE: First snap has to exist first
		view = tb.trace.getProgramView();
		vmem = view.getMemory();
	}

	@After
	public void tearDownTraceProgramViewListingTest() {
		if (tb != null) {
			tb.close();
		}
	}

	@Test
	public void testBlockInOverlay() throws Throwable {
		AddressSpace os;
		DBTraceMemoryRegion io;
		try (Transaction tx = tb.startTransaction()) {
			os = memory.createOverlayAddressSpace("test",
				tb.trace.getBaseAddressFactory().getDefaultAddressSpace());
			io = (DBTraceMemoryRegion) memory.createRegion(".io", 0, tb.range(os, 0x1000, 0x1fff),
				TraceMemoryFlag.READ, TraceMemoryFlag.WRITE, TraceMemoryFlag.VOLATILE);
		}

		AddressSet asSet = new AddressSet(vmem);
		assertEquals(tb.set(tb.range(os, 0x1000, 0x1fff)), asSet);

		MemoryBlock[] blocks = vmem.getBlocks();
		assertEquals(1, blocks.length);

		MemoryBlock blk = blocks[0];
		assertSame(blk, vmem.getRegionBlock(io));
		assertEquals(".io", blk.getName());
		assertEquals(tb.addr(os, 0x1000), blk.getStart());
		assertEquals(tb.addr(os, 0x1fff), blk.getEnd());
	}

	@Test
	public void testBytesInTwoViews() throws Throwable {
		try (Transaction tx = tb.startTransaction()) {
			memory.putBytes(0, tb.addr(0x00400000), tb.buf(1, 2, 3, 4, 5, 6, 7, 8));
			memory.putBytes(1, tb.addr(0x00400000), tb.buf(8, 7, 6, 5, 4, 3, 2, 1));
		}

		view.setSnap(1);
		DBTraceProgramView view0 = tb.trace.getFixedProgramView(0);

		byte[] actual = new byte[8];

		view0.getMemory().getBytes(tb.addr(0x00400000), actual);
		assertArrayEquals(tb.arr(1, 2, 3, 4, 5, 6, 7, 8), actual);

		view.getMemory().getBytes(tb.addr(0x00400000), actual);
		assertArrayEquals(tb.arr(8, 7, 6, 5, 4, 3, 2, 1), actual);
	}
}
