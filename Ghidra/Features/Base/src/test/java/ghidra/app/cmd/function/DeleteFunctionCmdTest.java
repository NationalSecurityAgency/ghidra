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

import static org.junit.Assert.*;

import java.io.PrintWriter;
import java.io.StringWriter;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

/**
 * Test for the {@link DeleteFunctionCmd}.
 * 
 * 
 * @since  Tracker Id 268
 */
public class DeleteFunctionCmdTest extends AbstractGenericTest {

	private Program program;

	/**
	 * Constructs this test class with the given test method name.
	 * 
	 */
	public DeleteFunctionCmdTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		ProgramBuilder builder = new ProgramBuilder("Test", ProgramBuilder._TOY);
		builder.createMemory("test", "0", 0x100);

		program = builder.getProgram();
	}

	/**
	 * Tests the deleting of functions via the {@link DeleteFunctionCmd}.
	 */
	@Test
	public void testDeleteFunction() {

		// create a function at an address that has a valid code unit
		Address address = addr(0x0);

		// get a function from the program with a default name        
		String defaultName = SymbolUtilities.getDefaultFunctionName(address);

		int transactionID = program.startTransaction("TEST");

		Function function =
			createFunction(defaultName, address, new AddressSet(address, address.add(200L)));

		assertNotNull("The test function was not created as expected.", function);

		// create and call the delete the command to remove the function
		DeleteFunctionCmd deleteFunctionCmd = new DeleteFunctionCmd(address);
		deleteFunctionCmd.applyTo(program);

		// ensure the function is deleted
		function = program.getListing().getFunctionAt(address);
		assertNull("The function was not deleted as expected.", function);

		// make sure that there is no label where that function existed
		Symbol[] symbols = program.getSymbolTable().getSymbols(address);
		assertTrue(
			"The symbol where the function was removed has the " +
				"default name of the function when it should not.",
			!containsMatchingSymbolName(symbols, defaultName));

		//
		// repeat above steps for another function that has a user-defined name
		// 
		String customName = "CustomFunctionName";
		function = createFunction(customName, address, new AddressSet(address, address.add(200L)));

		assertNotNull("The test function was not created as expected.", function);

		// create and call the delete the command to remove the function
		deleteFunctionCmd = new DeleteFunctionCmd(address);
		deleteFunctionCmd.applyTo(program);

		// make sure that after the function is deleted that there is a symbol
		// at that address with the same name as the function
		function = program.getListing().getFunctionAt(address);
		assertNull("The function was not deleted as expected.", function);

		symbols = program.getSymbolTable().getSymbols(address);
		assertTrue(
			"A label with the same name as the function was not " +
				"created when that function was deleted.",
			containsMatchingSymbolName(symbols, customName));

		program.endTransaction(transactionID, false);
	}

	// looks through the given symbol array to see if any have the same name 
	// as the provided string
	private boolean containsMatchingSymbolName(Symbol[] symbols, String name) {
		for (Symbol symbol : symbols) {
			System.err.println("checking: " + symbol + " against " + name);
			if (symbol.getName().equals(name)) {
				return true;
			}
		}

		return false;
	}

	private Address addr(long l) {
		AddressSpace addressSpace = program.getAddressFactory().getDefaultAddressSpace();
		return addressSpace.getAddress(l);
	}

	private Function createFunction(String name, Address entryPt, AddressSetView body) {
		try {
			FunctionManager functionManager = program.getFunctionManager();
			functionManager.createFunction(name, entryPt, body, SourceType.USER_DEFINED);
			return functionManager.getFunctionAt(entryPt);
		}
		catch (Exception exc) {
			StringWriter stringWriter = new StringWriter();
			PrintWriter writer = new PrintWriter(stringWriter);
			exc.printStackTrace(writer);
			Assert.fail("Unable to create function \"" + name + "\" at address: " + entryPt +
				". Exception info: " + stringWriter);
		}

		return null;
	}
}
