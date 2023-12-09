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
package sarif;

import static org.junit.Assert.assertEquals;

import org.junit.Assert;
import org.junit.Test;

import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.util.ProgramDiff;
import ghidra.util.exception.InvalidInputException;

public class FunctionSarifTest extends AbstractSarifTest {

	public FunctionSarifTest() {
		super();
	}

	@Test
	public void testCreateFunction() throws Exception {
		FunctionManager functionManager = program.getFunctionManager();
		SymbolTable symbolTable = program.getSymbolTable();
		symbolTable.createLabel(addr(100), "foo", SourceType.USER_DEFINED);

		createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));

		Symbol[] symbols = symbolTable.getSymbols(addr(100));
		assertEquals(1, symbols.length); // label should be converted to function

		Symbol s = symbolTable.createLabel(addr(100), "foo", SourceType.USER_DEFINED);
		assertEquals(SymbolType.FUNCTION, s.getSymbolType());
		symbols = symbolTable.getSymbols(addr(100));
		assertEquals(1, symbols.length); // should still be just a function

		// Overlapping functions - not allowed
		try {
			functionManager.createFunction("foo1", addr(50), new AddressSet(addr(50), addr(100)),
				SourceType.USER_DEFINED);
			Assert.fail();
		}
		catch (OverlappingFunctionException e) {
			// Expected
		}
		try {
			functionManager.createFunction("foo2", addr(200), new AddressSet(addr(200), addr(250)),
				SourceType.USER_DEFINED);
			Assert.fail();
		}
		catch (OverlappingFunctionException e) {
			// Expected
		}
		try {
			functionManager.createFunction("foo3", addr(150), new AddressSet(addr(150), addr(250)),
				SourceType.USER_DEFINED);
			Assert.fail();
		}
		catch (OverlappingFunctionException e) {
			// Expected
		}

		// Invalid entry address
		try {
			createFunction("foo4", addr(250), new AddressSet(addr(300), addr(350)));
			Assert.fail();
		}
		catch (IllegalArgumentException e) {
			// expected
		}

		createFunction("foo4", addr(50), new AddressSet(addr(50), addr(99)));
		createFunction("foo5", addr(201), new AddressSet(addr(201), addr(250)));

		//  try duplicate name
		createFunction("foo5", addr(500), new AddressSet(addr(500), addr(600)));

		ProgramDiff programDiff = readWriteCompare();
		
		AddressSetView differences = programDiff.getDifferences(monitor);
		assert(differences.isEmpty());
	}

	@Test
	public void testCreateVarArgFunction() throws Exception {
		Function f = createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));
		f.setVarArgs(true);
		
		ProgramDiff programDiff = readWriteCompare();
		
		AddressSetView differences = programDiff.getDifferences(monitor);
		assert(differences.isEmpty());
	}

	@Test
	public void testCreateInlineFunction() throws Exception {
		Function f = createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));
		f.setInline(true);

		ProgramDiff programDiff = readWriteCompare();
		
		AddressSetView differences = programDiff.getDifferences(monitor);
		assert(differences.isEmpty());
	}

	@Test
	public void testCreateNoReturnFunction() throws Exception {
		Function f = createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));
		assertEquals(false, f.hasNoReturn());
		f.setNoReturn(true);
		
		ProgramDiff programDiff = readWriteCompare();
		
		AddressSetView differences = programDiff.getDifferences(monitor);
		assert(differences.isEmpty());
	}
	
	private Function createFunction(String name, Address entryPt, AddressSetView body)
			throws InvalidInputException, OverlappingFunctionException {

		FunctionManager functionManager = program.getFunctionManager();
		functionManager.createFunction(name, entryPt, body, SourceType.USER_DEFINED);
		Function f = functionManager.getFunctionAt(entryPt);
		assertEquals(name, f.getName());
		assertEquals(entryPt, f.getEntryPoint());
		assertEquals(body, f.getBody());
		return f;
	}
}
