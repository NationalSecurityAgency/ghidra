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
package ghidra.app.util.demangler;

import static org.junit.Assert.*;

import org.junit.*;

import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.*;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.test.ToyProgramBuilder;
import ghidra.util.task.TaskMonitor;

public class DemangledAddressTableTest extends AbstractGhidraHeadlessIntegrationTest {

	private ProgramDB program;
	private int txID;

	@Before
	public void setUp() throws Exception {
		ToyProgramBuilder builder = new ToyProgramBuilder("test", true);
		builder.createMemory(".text", "0x0100", 0x100);

		// Extent of Address Table determined by one of the following in order of precedence:
		// 1. Size of undefined array at start of table
		// 2. Next label beyond start which resides within current block
		// 3. End of block containing table

		// Address Pointers will only be created if extent of table contains only
		// Undefined types or pointers

		//@formatter:off
		builder.setBytes("0x0110", new byte[] {
			0, 0, 1, 0x40,
			0, 0, 1, 0x41,
			0, 0, 1, 0x42,
			0, 0, 1, 0x43,
			0, 0, 1, 0x44,
			0, 0, 1, 0x45,
			0, 0, 1, 0x46,
			0, 0, 0, 0,    // should be skipped
			0, 0, 1, 0x48,
			0, 0, 2, 0x49, // should stop table (no memory)
			0, 0, 1, 0x4a,
			0, 0, 1, 0x4b
		});
		//@formatter:on

		program = builder.getProgram();
		txID = program.startTransaction("Test");
	}

	@After
	public void tearDown() throws Exception {
		program.endTransaction(txID, false);
	}

	/**
	 * Test that the DemangledAddressTable will properly create a sequence of data 
	 * pointers.  This test deals with the simple case where no existing data
	 * is present. End of block considered end of address table.
	 */
	@Test
	public void testApply_NoNextSymbol_NoData() throws Exception {

		// this is: vtable for UnqiueSpace
		String mangled = "_ZTV11UniqueSpace";
		Address addr = addr("0x0110");

		SymbolTable symbolTable = program.getSymbolTable();
		symbolTable.createLabel(addr, mangled, SourceType.IMPORTED);

		DemangledObject demangled = DemanglerUtil.demangle(mangled);
		assertTrue(demangled instanceof DemangledAddressTable);

		assertTrue(demangled.applyTo(program, addr, new DemanglerOptions(), TaskMonitor.DUMMY));

		// expected: UniqueSpace::vtable
		Symbol[] symbols = symbolTable.getSymbols(addr);
		assertEquals(2, symbols.length);
		assertEquals("vtable", symbols[0].getName());
		assertEquals(mangled, symbols[1].getName());

		Namespace ns = symbols[0].getParentNamespace();
		assertEquals("UniqueSpace", ns.getName(false));

		assertPointersAt(0, 0, "0x110", "0x114", "0x118", "0x11c", "0x120", "0x124", "0x128",
			/* skip 0 */ "0x130");
	}

	/**
	 * Test that the DemangledAddressTable will not create a sequence of data 
	 * pointers due to a data collision.  This test deals with the case where primitive types have been 
	 * previously created. End of block considered end of address table.
	 */
	@Test
	public void testApply_NoNextSymbol_DataCollision() throws Exception {

		// this is: vtable for UnqiueSpace
		String mangled = "_ZTV11UniqueSpace";
		Address addr = addr("0x0110");

		SymbolTable symbolTable = program.getSymbolTable();
		symbolTable.createLabel(addr, mangled, SourceType.IMPORTED);

		Listing listing = program.getListing();
		listing.createData(addr("0x114"), Undefined4DataType.dataType);
		listing.createData(addr("0x118"), Undefined4DataType.dataType);
		listing.createData(addr("0x120"), DWordDataType.dataType);

		DemangledObject demangled = DemanglerUtil.demangle(mangled);
		assertTrue(demangled instanceof DemangledAddressTable);

		assertTrue(demangled.applyTo(program, addr, new DemanglerOptions(), TaskMonitor.DUMMY));

		// expected: UniqueSpace::vtable
		Symbol[] symbols = symbolTable.getSymbols(addr);
		assertEquals(2, symbols.length);
		assertEquals("vtable", symbols[0].getName());
		assertEquals(mangled, symbols[1].getName());

		Namespace ns = symbols[0].getParentNamespace();
		assertEquals("UniqueSpace", ns.getName(false));

		// should fail to create pointers since table region (to end of block) contains
		// data other than pointer or undefined
		assertPointersAt(3, 0);
	}

	/**
	 * Test that the DemangledAddressTable will properly create a sequence of data 
	 * pointers.  This test deals with the case where primitive types have been 
	 * previously created. Next label considered end of address table.
	 */
	@Test
	public void testApply_WithNextSymbol_UndefinedData() throws Exception {

		// this is: vtable for UnqiueSpace
		String mangled = "_ZTV11UniqueSpace";
		Address addr = addr("0x0110");

		SymbolTable symbolTable = program.getSymbolTable();
		symbolTable.createLabel(addr, mangled, SourceType.IMPORTED);

		Listing listing = program.getListing();
		listing.createData(addr("0x114"), Undefined4DataType.dataType);
		listing.createData(addr("0x118"), Undefined4DataType.dataType);
		listing.createData(addr("0x120"), DWordDataType.dataType);

		symbolTable.createLabel(addr("0x120"), "NextLabel", SourceType.IMPORTED);

		DemangledObject demangled = DemanglerUtil.demangle(mangled);
		assertTrue(demangled instanceof DemangledAddressTable);

		assertTrue(demangled.applyTo(program, addr, new DemanglerOptions(), TaskMonitor.DUMMY));

		// expected: UniqueSpace::vtable
		Symbol[] symbols = symbolTable.getSymbols(addr);
		assertEquals(2, symbols.length);
		assertEquals("vtable", symbols[0].getName());
		assertEquals(mangled, symbols[1].getName());

		Namespace ns = symbols[0].getParentNamespace();
		assertEquals("UniqueSpace", ns.getName(false));

		assertPointersAt(1, 0, "0x110", "0x114", "0x118", "0x11c");
	}

	/**
	 * Test that the DemangledAddressTable will properly create a sequence of data 
	 * pointers.  This test deals with the case where primitive types have been 
	 * previously created where the first is an undefined array which dictates the 
	 * extent of the address table. Next label beyond end of address table.
	 */
	@Test
	public void testApply_WithUndefinedArray() throws Exception {

		// this is: vtable for UnqiueSpace
		String mangled = "_ZTV11UniqueSpace";
		Address addr = addr("0x0110");

		SymbolTable symbolTable = program.getSymbolTable();
		symbolTable.createLabel(addr, mangled, SourceType.IMPORTED);

		Listing listing = program.getListing();
		listing.createData(addr("0x110"), Undefined.getUndefinedDataType(12));
		listing.createData(addr("0x11c"), Undefined4DataType.dataType);
		listing.createData(addr("0x120"), DWordDataType.dataType);

		symbolTable.createLabel(addr("0x120"), "NextLabel", SourceType.IMPORTED);

		DemangledObject demangled = DemanglerUtil.demangle(mangled);
		assertTrue(demangled instanceof DemangledAddressTable);

		assertTrue(demangled.applyTo(program, addr, new DemanglerOptions(), TaskMonitor.DUMMY));

		// expected: UniqueSpace::vtable
		Symbol[] symbols = symbolTable.getSymbols(addr);
		assertEquals(2, symbols.length);
		assertEquals("vtable", symbols[0].getName());
		assertEquals(mangled, symbols[1].getName());

		Namespace ns = symbols[0].getParentNamespace();
		assertEquals("UniqueSpace", ns.getName(false));

		assertPointersAt(2, 0, "0x110", "0x114", "0x118");
	}

	private void assertPointersAt(int totalNonPointerData, int totalInstructions, String... addrs) {
		Listing listing = program.getListing();
		int index = 0;
		for (Data d : listing.getDefinedData(true)) {
			if (d.isPointer()) {
				assertTrue("too many pointers found, expected only " + addrs.length,
					index < addrs.length);
				assertEquals("unexpected pointer at " + d.getAddress(), addr(addrs[index++]),
					d.getAddress());
			}
		}
		assertEquals("insufficient pointers created", addrs.length, index);
		assertEquals("missing expected non-pointer data", totalNonPointerData,
			listing.getNumDefinedData() - index);
		assertEquals("missing expected instructions", totalInstructions,
			listing.getNumInstructions());
	}

	private Address addr(String addr) {
		return program.getAddressFactory().getAddress(addr);
	}
}
