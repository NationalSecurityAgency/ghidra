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
package ghidra.program.model.listing;

import static org.junit.Assert.*;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.InvalidInputException;

public class VariableUtilitiesTest extends AbstractGenericTest {

	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		Language language = getLanguage("Toy:BE:64:default");
		CompilerSpec compilerSpec = language.getDefaultCompilerSpec();
		program = new ProgramDB("Test", language, compilerSpec, this);
	}

	@After
	public void tearDown() {
		program.release(this);
	}

	private static Language getLanguage(String languageName) throws LanguageNotFoundException {
		LanguageService languageService = DefaultLanguageService.getLanguageService();
		return languageService.getLanguage(new LanguageID(languageName));
	}

	@Test
	public void testCheckDataType() throws Exception {

		DataType dt = new TypedefDataType("Foo", new PointerDataType()); // point size will be 8 in program
		assertEquals(4, dt.getLength());

		dt = VariableUtilities.checkDataType(dt, false, -1, program);
		assertEquals(8, dt.getLength());

		dt = new ArrayDataType(new PointerDataType(), 5, -1); // point size will be 8 in program
		assertEquals(20, dt.getLength());

		dt = VariableUtilities.checkDataType(dt, false, -1, program);
		assertEquals(40, dt.getLength());
	}

	@Test
	public void testResizeStackWithoutFunction() throws Exception {
		VariableStorage original = new VariableStorage(program, -16, 4);
		VariableStorage resized =
			VariableUtilities.resizeStorage(original, new QWordDataType(), true, null);
		assertEquals(-16, resized.getStackOffset());
		assertEquals(8, resized.size());
		assertEquals(4, original.size());
	}

	@Test
	public void testShrinkRegisterWithoutFunction() throws Exception {
		VariableStorage original = new VariableStorage(program, program.getRegister("r0"));
		VariableStorage resized =
			VariableUtilities.resizeStorage(original, new DWordDataType(), false, null);
		assertEquals(program.getRegister("r0l").getAddress(), resized.getFirstVarnode().getAddress());
		assertEquals(4, resized.size());
		assertEquals(8, original.size());
	}

	@Test
	public void testVariableImplGrowsStackStorage() throws Exception {
		LocalVariableImpl variable = new LocalVariableImpl("local", new DWordDataType(), -16, program);
		VariableStorage original = variable.getVariableStorage();
		variable.setDataType(new QWordDataType(), SourceType.USER_DEFINED);
		assertEquals(8, variable.getVariableStorage().size());
		assertEquals(-16, variable.getStackOffset());
		assertEquals(4, original.size());
	}

	@Test
	public void testResizeWithoutFunctionRejectsStackBoundaryCrossing() throws Exception {
		VariableStorage original = new VariableStorage(program, -4, 4);
		try {
			VariableUtilities.resizeStorage(original, new QWordDataType(), false, null);
			fail("Storage must not grow across stack offset zero");
		}
		catch (InvalidInputException expected) {
			assertEquals(-4, original.getStackOffset());
			assertEquals(4, original.size());
		}
	}

	@Test
	public void testVariableImplGrowsToBigEndianParentRegister() throws Exception {
		Register lowHalf = program.getRegister("r0l");
		LocalVariableImpl variable =
			new LocalVariableImpl("local", 0, new DWordDataType(), lowHalf, program);
		VariableStorage original = variable.getVariableStorage();
		variable.setDataType(new QWordDataType(), SourceType.USER_DEFINED);
		assertEquals(program.getRegister("r0").getAddress(),
			variable.getVariableStorage().getFirstVarnode().getAddress());
		assertEquals(8, variable.getVariableStorage().size());
		assertEquals(lowHalf.getAddress(), original.getFirstVarnode().getAddress());
	}

	@Test
	public void testResizeStackWithFunction() throws Exception {
		int transaction = program.startTransaction("Create function");
		try {
			Address entry = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
			Function function = program.getFunctionManager()
				.createFunction("function", entry, new AddressSet(entry), SourceType.USER_DEFINED);
			VariableStorage original = new VariableStorage(program, -16, 4);
			VariableStorage resized =
				VariableUtilities.resizeStorage(original, new QWordDataType(), false, function);
			assertEquals(-16, resized.getStackOffset());
			assertEquals(8, resized.size());
			assertEquals(4, original.size());
		}
		finally {
			program.endTransaction(transaction, false);
		}
	}
}
