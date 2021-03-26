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
package ghidra.program.database.code;

import static org.junit.Assert.*;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.test.ToyProgramBuilder;
import ghidra.util.task.TaskMonitor;

/**
 * Test the code manager portion of listing.
 *
 *
 */
public class DefaultDataCacheTest extends AbstractGenericTest {

	private ToyProgramBuilder builder;

	private Listing listing;
	private AddressSpace space;
	private Program program;
	private Memory mem;
	private int transactionID;

	/**
	 * Constructor for CodeManagerTest.
	 * @param arg0
	 */
	public DefaultDataCacheTest() {
		super();
	}

	/*
	 * @see TestCase#setUp()
	 */
	@Before
	public void setUp() throws Exception {

		builder = new ToyProgramBuilder("Test", true, this);
		builder.createMemory("B1", "1000", 0x2000);
		builder.addBytesNOP("1000", 4);
		program = builder.getProgram();
		space = program.getAddressFactory().getDefaultAddressSpace();
		listing = program.getListing();
		mem = program.getMemory();
		transactionID = program.startTransaction("Test");

	}

	@After
	public void tearDown() throws Exception {
		program.endTransaction(transactionID, true);
		program.release(this);
	}

	@Test
	public void testDefaultCodeUnitsGetInvalidated() {
		CodeUnit cu = listing.getCodeUnitAt(addr(0x1001));
		assertTrue(cu instanceof Data);
		DataDB data = (DataDB) cu;
		assertTrue(!data.isDefined());
		assertTrue(!((Boolean) invokeInstanceMethod("isInvalid", data)));
		AddressSet restrictedSet = new AddressSet(addr(0x1000), addr(0x1003));
		Disassembler disassembler = Disassembler.getDisassembler(program, TaskMonitor.DUMMY, null);
		AddressSetView disAddrs = disassembler.disassemble(addr(0x1000), restrictedSet);
		assertTrue(!disAddrs.isEmpty());
		assertTrue(!((Boolean) invokeInstanceMethod("checkIsValid", data)));
		assertNull(listing.getCodeUnitAt(addr(0x1001)));
	}

	private Address addr(long l) {
		return space.getAddress(l);
	}

}
