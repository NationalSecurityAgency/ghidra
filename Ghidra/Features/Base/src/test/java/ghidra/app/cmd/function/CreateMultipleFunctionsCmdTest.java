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
package ghidra.app.cmd.function;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;

/**
 * Test for the {@link CreateMultipleFunctionsCmd}.
 */
public class CreateMultipleFunctionsCmdTest extends AbstractGenericTest {

	private Program program;
	private ProgramBuilder builder;

	@Before
	public void setUp() throws Exception {

		builder = new ProgramBuilder("notepad.exe", ProgramBuilder._TOY);
		builder.createMemory("test", "0x0", 50);
		program = builder.getProgram();

		//
		// Create some functions (byte patterns, not Ghidra objects) with varying separation
		//
		createFunctionBytes(0x0, 5);

		// immediately following
		createFunctionBytes(0x5, 5);

		// a gap between
		createFunctionBytes(0xe, 10);

		createFunctionBytes(0x18, 4);

		createFunctionBytes(0x1d, 4);
	}

	@Test
    public void testCreateMultipleFunctionsWithSingleRangeSelection() {

		// a selection that covers the functions we are seeking
		AddressSet selection = new AddressSet(addr(0x0), addr(0x20));

		int transactionID = program.startTransaction("Perform the TEST");

		CreateMultipleFunctionsCmd createCmd =
			new CreateMultipleFunctionsCmd(selection, SourceType.USER_DEFINED);
		createCmd.applyTo(program);

		program.endTransaction(transactionID, true);

		// Verify the functions were created.
		assertNotNull(func(addr(0x0)));
		assertNotNull(func(addr(0x5)));
		assertNotNull(func(addr(0xe)));
		assertNotNull(func(addr(0x18)));
		assertNotNull(func(addr(0x1d)));
	}

	@Test
    public void testCreateMultipleFunctionsWithMultipleEntryPointSelection() {

		// put each entry point in the selection
		AddressSet selection = new AddressSet();
		selection.add(addr(0x0));
		selection.add(addr(0x5));
		selection.add(addr(0xe));
		selection.add(addr(0x18));
		selection.add(addr(0x1d));

		int transactionID = program.startTransaction("Perform the TEST");

		CreateMultipleFunctionsCmd createCmd =
			new CreateMultipleFunctionsCmd(selection, SourceType.USER_DEFINED);
		createCmd.applyTo(program);

		program.endTransaction(transactionID, true);

		// Verify the functions were created.
		assertNotNull(func(addr(0x0)));
		assertNotNull(func(addr(0x5)));
		assertNotNull(func(addr(0xe)));
		assertNotNull(func(addr(0x18)));
		assertNotNull(func(addr(0x1d)));
	}

	@Test
    public void testCreateMultipleFunctionsWithMultipleOffsetRangeSelection() {

		// create a selection that starts inside functions and ends inside a follow-up function
		AddressSet selection = new AddressSet();
		selection.addRange(addr(0x2), addr(0x7));
		selection.addRange(addr(0xf), addr(0x1a));

		int transactionID = program.startTransaction("Perform the TEST");

		CreateMultipleFunctionsCmd createCmd =
			new CreateMultipleFunctionsCmd(selection, SourceType.USER_DEFINED);
		createCmd.applyTo(program);

		program.endTransaction(transactionID, true);

		// Verify where the functions were created.
		assertNotNull(func(addr(0x2)));// manually created
		assertNotNull(func(addr(0x5)));// next function
		assertNotNull(func(addr(0xf)));// manually created
		assertNotNull(func(addr(0x18)));// next function

		// Verify where the functions were not created.
		assertNull(func(addr(0x0)));
		assertNull(func(addr(0xe)));
		assertNull(func(addr(0x1d)));
	}

	private void createFunctionBytes(long addr, int size) throws Exception {
		long returnAddr = addr + size;
		builder.setBytes(Long.toString(returnAddr), "0e");// ret instruction pattern in 'toy'
	}

	private Address addr(long l) {
		AddressSpace addressSpace = program.getAddressFactory().getDefaultAddressSpace();
		return addressSpace.getAddress(l);
	}

	private Function func(Address a) {
		FunctionManager fm = program.getFunctionManager();
		return fm.getFunctionAt(a);
	}

}
