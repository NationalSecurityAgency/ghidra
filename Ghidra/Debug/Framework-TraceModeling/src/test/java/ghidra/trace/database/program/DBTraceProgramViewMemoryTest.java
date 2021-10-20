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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;

import java.io.IOException;

import org.junit.*;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.database.memory.DBTraceMemoryManager;
import ghidra.trace.database.memory.DBTraceMemoryRegion;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.memory.TraceOverlappedRegionException;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.exception.DuplicateNameException;

public class DBTraceProgramViewMemoryTest extends AbstractGhidraHeadlessIntegrationTest {

	ToyDBTraceBuilder b;

	DBTraceProgramView view;
	DBTraceProgramViewMemory vmem;
	DBTraceMemoryManager memory;

	@Before
	public void setUpTraceProgramViewMemoryTest() throws LanguageNotFoundException, IOException {
		b = new ToyDBTraceBuilder("Testing", ProgramBuilder._TOY64_BE);
		try (UndoableTransaction tid = b.startTransaction()) {
			b.trace.getTimeManager().createSnapshot("Created");
		}
		memory = b.trace.getMemoryManager();
		// NOTE: First snap has to exist first
		view = b.trace.getProgramView();
		vmem = view.getMemory();
	}

	@After
	public void tearDownTraceProgramViewListingTest() {
		if (b != null) {
			b.close();
		}
	}

	@Test
	public void testBlockInOverlay() throws DuplicateNameException, TraceOverlappedRegionException,
			AddressOutOfBoundsException {
		AddressSpace os;
		DBTraceMemoryRegion io;
		try (UndoableTransaction tid = b.startTransaction()) {
			os = memory.createOverlayAddressSpace("test",
				b.trace.getBaseAddressFactory().getDefaultAddressSpace());
			io = (DBTraceMemoryRegion) memory.createRegion(".io", 0, b.range(os, 0x1000, 0x1fff),
				TraceMemoryFlag.READ, TraceMemoryFlag.WRITE, TraceMemoryFlag.VOLATILE);
		}

		AddressSet asSet = new AddressSet(vmem);
		assertEquals(b.set(b.range(os, 0x1000, 0x1fff)), asSet);

		MemoryBlock[] blocks = vmem.getBlocks();
		assertEquals(1, blocks.length);

		MemoryBlock blk = blocks[0];
		assertSame(blk, vmem.getBlock(io));
		assertEquals(".io", blk.getName());
		assertEquals(b.addr(os, 0x1000), blk.getStart());
		assertEquals(b.addr(os, 0x1fff), blk.getEnd());
	}
}
