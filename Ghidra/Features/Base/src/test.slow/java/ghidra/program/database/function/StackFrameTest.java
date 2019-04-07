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
package ghidra.program.database.function;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.After;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * 
 */
public class StackFrameTest extends AbstractGhidraHeadedIntegrationTest {

	private ProgramDB program;
	private AddressSpace space;
	private FunctionManager functionManager;
	private int transactionID;

	public StackFrameTest() {
		super();
	}

	@After
	public void tearDown() throws Exception {
		if (program != null) {
			program.endTransaction(transactionID, true);
			program.release(this);
		}

	}

	private Address addr(long l) {
		return space.getAddress(l);
	}

	private Function createFunction(String name, Address entryPt, AddressSetView body)
			throws DuplicateNameException, InvalidInputException, OverlappingFunctionException {

		functionManager.createFunction(name, entryPt, body, SourceType.USER_DEFINED);
		Function f = functionManager.getFunctionAt(entryPt);
		assertEquals(entryPt, f.getEntryPoint());
		assertEquals(body, f.getBody());
		return f;
	}

	@Test
    public void testCreateVariableNegativeStack() throws Exception {

		program =
			createDefaultProgram(testName.getMethodName(), ProgramBuilder._TOY, "default", this);
		space = program.getAddressFactory().getDefaultAddressSpace();
		functionManager = program.getFunctionManager();
		transactionID = program.startTransaction("Test");

		doCreateVariableTest(4);
	}

	@Test
    public void testCreateVariablePositiveStack() throws Exception {

		program = createDefaultProgram(testName.getMethodName(), ProgramBuilder._TOY_BE_POSITIVE,
			"posStack", this);
//		program = createDefaultProgram("TestPos", TestProcessorConstants.PROCESSOR_TMS320C3x, this);
		space = program.getAddressFactory().getDefaultAddressSpace();
		functionManager = program.getFunctionManager();
		transactionID = program.startTransaction("Test");

		doCreateVariableTest(-4);
	}

	private void doCreateVariableTest(int baseParamOffset) throws Exception {

		Function f = createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));
		f.setCustomVariableStorage(true);

		StackFrame frame = f.getStackFrame();
		boolean growsNeg = frame.growsNegative();
		DataType dt = new ByteDataType();

		String names[] = new String[16];

		for (int i = 0; i < 16; i++) {
			int offset = i - 8;

			if (growsNeg) {
				if (offset < baseParamOffset) {
					names[i] = "local_test" + offset;
				}
				else {
					names[i] = "myParam_" + offset;
				}
			}
			else {
				if (offset < baseParamOffset) {
					names[i] = "myParam_" + offset;
				}
				else {
					names[i] = "local_test" + offset;
				}
			}

			Variable var = frame.createVariable(names[i], offset, dt, SourceType.USER_DEFINED);
			var.setComment("My Comment" + i);
		}

		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(addr(100));
		frame = f.getStackFrame();

		Variable[] vars = frame.getStackVariables();
		for (int i = 0; i < vars.length; i++) {
			System.out.println(vars[i].getName() + ": " + vars[i].getVariableStorage());
		}
		assertEquals(8, frame.getParameters().length);

		assertEquals(8, frame.getParameterSize());
		assertEquals(8, frame.getLocalSize());

		vars = frame.getParameters();
		assertEquals(8, vars.length);
		int n = growsNeg ? 8 : 0;
		for (int i = 0; i < vars.length; i++) {
			Variable var = vars[i];
			System.out.println(
				"  Stack Var: " + var.getName() + " " + vars[i].getVariableStorage());
			assertTrue(var.isStackVariable());
			assertEquals(n - 8, var.getStackOffset());
			assertEquals(names[n], var.getName());
			assertEquals(1, var.getLength());
			assertTrue(dt.isEquivalent(var.getDataType()));
			assertEquals("My Comment" + n, var.getComment());
			++n;
		}

		vars = frame.getLocals();
		assertEquals(8, vars.length);
		n = growsNeg ? 0 : 8;
		for (int i = 0; i < vars.length; i++) {
			Variable var = vars[i];
			//System.out.println("  Stack Var: " + var.getName() + " " + vars[i].getVariableStorage());
			assertTrue(var.isStackVariable());
			assertEquals(n - 8, var.getStackOffset());
			assertEquals(names[n], var.getName());
			assertEquals(1, var.getLength());
			assertTrue(dt.isEquivalent(var.getDataType()));
			assertEquals("My Comment" + n, var.getComment());
			++n;
		}

	}
	//TODO

//	public void testSetLocalSize() {
//		Assert.fail();
//	}
//
//	public void testGetParameterCount() {
//	}
//
//	public void testClearVariable() {
//	}
//
//	public void testSetParameterOffset() {
//	}
//
//	public void testSetReturnAddressOffset() {
//	}
//
//	public void testGetVariableContaining() {
//	}
//
//	public void testIsParameterOffset() {
//	}

}
