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
package ghidra.util.table.field;

import static ghidra.program.model.symbol.RefType.DATA;
import static ghidra.program.model.symbol.SourceType.ANALYSIS;
import static ghidra.util.task.TaskMonitor.DUMMY;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.util.Arrays;

import org.junit.*;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.CodeUnitFormatOptions.ShowBlockName;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

public class AddressBasedLocationTest extends AbstractGhidraHeadlessIntegrationTest {

	private Program program;

	private AddressBasedLocation[] locations;

	private Address addr(String addrStr) {
		return program.getAddressFactory().getAddress(addrStr);
	}

	@Before
	public void setUp() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("Test", ProgramBuilder._8051, this);
		program = builder.getProgram();

		int txId = program.startTransaction("Add Stuff");

		Memory memory = program.getMemory();
		memory.createInitializedBlock("A", addr("OTHER:0"), 0x300, (byte) 0, DUMMY, true);
		memory.createInitializedBlock("B", addr("CODE:0"), 0x300, (byte) 0, DUMMY, true);
		memory.createInitializedBlock("C", addr("OTHER:0"), 0x300, (byte) 0, DUMMY, true);

		memory.createUninitializedBlock("BLOCK1", addr("CODE:100"), 100, false);
		memory.createUninitializedBlock("BLOCK2", addr("CODE:200"), 100, false);

		AddressFactory addressFactory = program.getAddressFactory();
		AddressSpace stackSpace = addressFactory.getStackSpace();
		AddressSpace constSpace = addressFactory.getConstantSpace();

		program.getFunctionManager().createFunction("testFunc", addr("CODE:0"),
			new AddressSet(addr("CODE:0"), addr("CODE:20")), ANALYSIS);

		ReferenceManager rm = program.getReferenceManager();

		Reference offsetRef1 =
			rm.addOffsetMemReference(addr("CODE:0"), addr("CODE:110"), 0x10, DATA, ANALYSIS, 0);
		Reference offsetRef2 =
			rm.addOffsetMemReference(addr("CODE:1"), addr("CODE:f0"), -0x10, DATA, ANALYSIS, 0);
		Reference offsetRef3 =
			rm.addOffsetMemReference(addr("CODE:2"), addr("CODE:120"), 0x20, DATA, ANALYSIS, 0);

		Reference stackRef1 = rm.addStackReference(addr("CODE:3"), 0, 0x10, DATA, ANALYSIS);
		Reference stackRef2 = rm.addStackReference(addr("CODE:4"), 0, -0x10, DATA, ANALYSIS);
		Reference stackRef3 = rm.addStackReference(addr("CODE:5"), 0, 0x20, DATA, ANALYSIS);

		Reference regRef1 =
			rm.addRegisterReference(addr("CODE:6"), 0, program.getRegister("R4"), DATA, ANALYSIS);
		Reference regRef2 =
			rm.addRegisterReference(addr("CODE:7"), 0, program.getRegister("DPTR"), DATA, ANALYSIS);
		Reference regRef3 =
			rm.addRegisterReference(addr("CODE:8"), 0, program.getRegister("ACC"), DATA, ANALYSIS);

		Reference shiftRef1 =
			rm.addShiftedMemReference(addr("CODE:9"), addr("CODE:200"), 2, DATA, ANALYSIS, 0);
		Reference shiftRef2 =
			rm.addShiftedMemReference(addr("CODE:10"), addr("CODE:200"), 4, DATA, ANALYSIS, 0);
		Reference shiftRef3 =
			rm.addShiftedMemReference(addr("CODE:11"), addr("CODE:200"), 3, DATA, ANALYSIS, 0);

		Reference extRef1 =
			rm.addExternalReference(addr("CODE:12"), "LIBA.DLL", "LAB1", null, ANALYSIS, 0, DATA);
		Reference extRef2 = rm.addExternalReference(addr("CODE:13"), "LIBA.DLL", "LAB2",
			addr("INTMEM:10"), ANALYSIS, 0, DATA);
		Reference extRef3 = rm.addExternalReference(addr("CODE:14"), "LIBA.DLL", "LAB3",
			addr("EXTMEM:1000"), ANALYSIS, 0, DATA);

		program.endTransaction(txId, true);

		locations = new AddressBasedLocation[] {
			new AddressBasedLocation(program, stackSpace.getAddress(-2)),
			new AddressBasedLocation(program, addr("CODE:200")),
			new AddressBasedLocation(program, AddressSpace.HASH_SPACE.getAddress(0x12345678)),
			new AddressBasedLocation(program, shiftRef1, ShowBlockName.ALWAYS),
			new AddressBasedLocation(program, addr("CODE:120")),
			new AddressBasedLocation(program, extRef2, ShowBlockName.ALWAYS),
			new AddressBasedLocation(program, regRef1, ShowBlockName.ALWAYS),
			new AddressBasedLocation(program, addr("CODE:210")),
			new AddressBasedLocation(program, constSpace.getAddress(-6)),
			new AddressBasedLocation(program, offsetRef1, ShowBlockName.ALWAYS),
			new AddressBasedLocation(program, addr("A:210")),
			new AddressBasedLocation(program, addr("B:210")),
			new AddressBasedLocation(program, addr("C:210")),
			new AddressBasedLocation(program, Address.NO_ADDRESS),
			new AddressBasedLocation(program, extRef1, ShowBlockName.ALWAYS),
			new AddressBasedLocation(program, addr("CODE:90")),
			new AddressBasedLocation(program, stackRef1, ShowBlockName.ALWAYS),
			new AddressBasedLocation(program, addr("CODE:110")),
			new AddressBasedLocation(program, shiftRef2, ShowBlockName.ALWAYS),
			new AddressBasedLocation(program, null),
			new AddressBasedLocation(program, regRef2, ShowBlockName.ALWAYS),
			new AddressBasedLocation(program, addr("CODE:100")),
			new AddressBasedLocation(program, addr("C:100")),
			new AddressBasedLocation(program, addr("B:100")),
			new AddressBasedLocation(program, addr("A:100")),
			new AddressBasedLocation(program, offsetRef2, ShowBlockName.ALWAYS),
			new AddressBasedLocation(program, AddressSpace.HASH_SPACE.getAddress(0x87654321L)),
			new AddressBasedLocation(program, extRef3, ShowBlockName.ALWAYS),
			new AddressBasedLocation(program, addr("CODE:80")),
			new AddressBasedLocation(program, stackRef2, ShowBlockName.ALWAYS),
			new AddressBasedLocation(program, addr("A:80")),
			new AddressBasedLocation(program, addr("C:80")),
			new AddressBasedLocation(program, addr("B:80")),
			new AddressBasedLocation(program, addr("CODE:125")),
			new AddressBasedLocation(program, shiftRef3, ShowBlockName.ALWAYS),
			new AddressBasedLocation(program, regRef3, ShowBlockName.ALWAYS),
			new AddressBasedLocation(program, addr("CODE:115")),
			new AddressBasedLocation(program, offsetRef3, ShowBlockName.ALWAYS),
			new AddressBasedLocation(),
			new AddressBasedLocation(program, stackRef3, ShowBlockName.ALWAYS),
			new AddressBasedLocation(program, constSpace.getAddress(3)), };
	}

	@After
	public void tearDown() {
		if (program != null) {
			program.release(this);
		}
	}

	@Test
	public void testCompareToAndToString() {
		Arrays.sort(locations);

// Useful snippet when adding more address cases for code generation
//		for (int i = 0; i < locations.length; i++) {
//			System.out.println("assertEquals(\"" + locations[i].toString() + "\", locations[" + i +
//				"].toString());");
//		}

		assertNull(locations[0].getAddress());
		assertNull(locations[1].getAddress());

		assertEquals("<NULL>", locations[0].toString());
		assertEquals("<NULL>", locations[1].toString());
		assertEquals("A::00000080", locations[2].toString());
		assertEquals("A::00000100", locations[3].toString());
		assertEquals("A::00000210", locations[4].toString());
		assertEquals("B::0080", locations[5].toString());
		assertEquals("B::0100", locations[6].toString());
		assertEquals("B::0210", locations[7].toString());
		assertEquals("C::00000080", locations[8].toString());
		assertEquals("C::00000100", locations[9].toString());
		assertEquals("C::00000210", locations[10].toString());
		assertEquals("CODE:0080", locations[11].toString());
		assertEquals("CODE:0090", locations[12].toString());
		assertEquals("CODE:0100-0x10", locations[13].toString());
		assertEquals("CODE:0100", locations[14].toString());
		assertEquals("CODE:0110", locations[15].toString());
		assertEquals("BLOCK1::CODE:0100+0x10", locations[16].toString());
		assertEquals("CODE:0115", locations[17].toString());
		assertEquals("CODE:0120", locations[18].toString());
		assertEquals("BLOCK1::CODE:0100+0x20", locations[19].toString());
		assertEquals("CODE:0125", locations[20].toString());
		assertEquals("CODE:0200", locations[21].toString());
		assertEquals("BLOCK2::CODE:0200(0x20<<4)", locations[22].toString());
		assertEquals("BLOCK2::CODE:0200(0x40<<3)", locations[23].toString());
		assertEquals("BLOCK2::CODE:0200(0x80<<2)", locations[24].toString());
		assertEquals("CODE:0210", locations[25].toString());
		assertEquals("External[ ? ]", locations[26].toString());
		assertEquals("External[EXTMEM:1000]", locations[27].toString());
		assertEquals("External[INTMEM:10]", locations[28].toString());
		assertEquals("HASH:12345678", locations[29].toString());
		assertEquals("HASH:87654321", locations[30].toString());
		assertEquals("", locations[31].toString());
		assertEquals("Constant[-0x6]", locations[32].toString());
		assertEquals("Constant[+0x3]", locations[33].toString());
		assertEquals("Register[ACC]", locations[34].toString());
		assertEquals("Register[DPTR]", locations[35].toString());
		assertEquals("Register[R4R5R6R7]", locations[36].toString());
		assertEquals("Stack[-0x10]", locations[37].toString());
		assertEquals("Stack[-0x2]", locations[38].toString());
		assertEquals("Stack[+0x10]", locations[39].toString());
		assertEquals("Stack[+0x20]", locations[40].toString());

		assertEquals(Address.NO_ADDRESS, locations[31].getAddress());
	}
}
