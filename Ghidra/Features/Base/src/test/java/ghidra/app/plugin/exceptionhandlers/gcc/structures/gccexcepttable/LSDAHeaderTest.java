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
package ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable;

import static org.junit.Assert.*;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.app.plugin.exceptionhandlers.gcc.RegionDescriptor;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Tests that the LSDA header locates the type table correctly however many bytes the TType
 * offset ULEB128 occupies. Each LSDA below runs LPStart encoding (omitted), TType encoding
 * (pcrel|sdata4), TType offset, call site encoding (uleb128) and table length, call site
 * records, action table, then a single type table entry ending at the type table base.
 */
public class LSDAHeaderTest extends AbstractGenericTest {

	private ProgramBuilder builder;
	private Program program;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("lsda", ProgramBuilder._X64);
		builder.createMemory("lsda", "0x1000", 0x400);
		program = builder.getProgram();
	}

	@After
	public void tearDown() {
		builder.dispose();
	}

	@Test
	public void testSingleByteTTypeOffset() throws Exception {
		builder.setBytes("0x1000", "ff 1b 0d 01 04 00 02 02 01 01 00 00 f4 02 00 00");

		LSDATable table = createTable();

		assertEquals(addr(0x100f), table.getHeader().getTTypeBaseAddress());
		assertEquals(addr(0x1300), table.getTypeTable().getTypeInfoAddress(1));
	}

	@Test
	public void testTwoByteTTypeOffset() throws Exception {
		builder.setBytes("0x1000",
			"ff 1b 80 01 01 78 " + "00 02 02 01 ".repeat(30) + "01 00 80 02 00 00");

		LSDATable table = createTable();

		assertEquals(addr(0x1083), table.getHeader().getTTypeBaseAddress());
		assertEquals(addr(0x1300), table.getTypeTable().getTypeInfoAddress(1));
	}

	@Test
	public void testThreeByteTTypeOffset() throws Exception {
		builder.setBytes("0x1000", "ff 1b 80 80 01 01 00");

		LSDAHeader header = new LSDAHeader(TaskMonitor.DUMMY, program, region());
		int id = program.startTransaction("lsda");
		try {
			header.create(addr(0x1000));
		}
		finally {
			program.endTransaction(id, true);
		}

		assertEquals(addr(0x5004), header.getTTypeBaseAddress());
	}

	private LSDATable createTable() throws Exception {
		RegionDescriptor region = region();
		region.setLSDAAddress(addr(0x1000));

		int id = program.startTransaction("lsda");
		try {
			LSDATable table = new LSDATable(TaskMonitor.DUMMY, program);
			table.create(addr(0x1000), region);
			return table;
		}
		finally {
			program.endTransaction(id, true);
		}
	}

	private RegionDescriptor region() {
		RegionDescriptor region = new RegionDescriptor(program.getMemory().getBlock(addr(0x1000)));
		region.setIPRange(new AddressRangeImpl(addr(0x1000), addr(0x1100)));
		return region;
	}

	private Address addr(long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}
}
