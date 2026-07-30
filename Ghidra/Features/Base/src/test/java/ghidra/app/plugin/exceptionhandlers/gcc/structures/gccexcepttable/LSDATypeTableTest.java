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
 * Tests that an entry the type table cannot resolve costs only that entry. The type table is
 * built last, so an exception escaping it would discard the call site and action tables that
 * {@link LSDATable#create} has already finished.
 */
public class LSDATypeTableTest extends AbstractGenericTest {

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
	public void testUnresolvableTypeEntryKeepsCallSiteTable() throws Exception {
		// the sole type table entry is a pc-relative displacement that leaves the address space
		builder.setBytes("0x1000", "ff 1b 0d 01 04 00 02 02 01 01 00 00 01 00 00 80");

		Address lsda = addr(0x1000);
		RegionDescriptor region = new RegionDescriptor(program.getMemory().getBlock(lsda));
		region.setIPRange(new AddressRangeImpl(lsda, addr(0x1100)));
		region.setLSDAAddress(lsda);

		LSDATable table = new LSDATable(TaskMonitor.DUMMY, program);
		int id = program.startTransaction("lsda");
		try {
			table.create(lsda, region);
		}
		finally {
			program.endTransaction(id, true);
		}

		assertEquals(1, table.getCallSiteTable().getCallSiteRecords().size());
	}

	private Address addr(long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}
}
