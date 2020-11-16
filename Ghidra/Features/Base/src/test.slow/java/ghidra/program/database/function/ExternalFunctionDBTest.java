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

import static org.junit.Assert.*;

import org.junit.*;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 *
 */
public class ExternalFunctionDBTest extends AbstractGhidraHeadedIntegrationTest {

	private ProgramDB program;
	private FunctionManager functionManager;
	private ExternalManager extMgr;
	private int transactionID;

	/**
	 * Constructor for FunctionDataDBTest.
	 * 
	 * @param arg0
	 */
	public ExternalFunctionDBTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		program = createDefaultProgram(testName.getMethodName(), ProgramBuilder._TOY, this);
		transactionID = program.startTransaction("Test");
		functionManager = program.getFunctionManager();
		extMgr = program.getExternalManager();
	}

	@After
	public void tearDown() throws Exception {
		if (program != null) {
			program.endTransaction(transactionID, true);
			program.release(this);
		}

	}

	private Function createExternalFunction(String name)
			throws DuplicateNameException, InvalidInputException {

		ExternalLocation extLoc =
			extMgr.addExtLocation("TestLibrary", name, null, SourceType.USER_DEFINED);
		Symbol extSym = extLoc.getSymbol();
		assertNotNull(extSym);
		assertEquals(SymbolType.LABEL, extSym.getSymbolType());
		assertEquals(extLoc, extSym.getObject());
		assertNull(extLoc.getFunction());

		Namespace parentNamespace = extLoc.getParentNameSpace();
		assertEquals(SymbolType.LIBRARY, parentNamespace.getSymbol().getSymbolType());
		assertTrue(parentNamespace.isExternal());

		assertNull(functionManager.getFunction(extSym.getID()));

		Function function = extLoc.createFunction();
		assertNotNull(function);
		assertTrue(function.isExternal());
		assertEquals(extLoc.getExternalSpaceAddress(), function.getEntryPoint());
		assertEquals(extLoc, function.getExternalLocation());

		Symbol s = program.getSymbolTable().getPrimarySymbol(function.getEntryPoint());
		assertNotNull(s);
		assertEquals(SymbolType.FUNCTION, s.getSymbolType());

		return function;
	}

	@Test
	public void testGetName() throws Exception {
		Function f = createExternalFunction("foo");
		String name = f.getName();
		assertTrue(name.indexOf("foo") == 0);
	}

	@Test
	public void testSetNameUser() throws Exception {
		Function f = createExternalFunction("foo");
		String name = "MyFunction";
		f.setName(name, SourceType.USER_DEFINED);
		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(f.getEntryPoint());
		assertEquals(name, f.getName());
		assertEquals(SourceType.USER_DEFINED, f.getSymbol().getSource());
	}

	@Test
	public void testSetComment() throws Exception {
		Function f = createExternalFunction("foo");
		String comment = "Test Comment\nLine 2";
		f.setComment(comment);
		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(f.getEntryPoint());
		assertEquals(comment, f.getComment());
		assertEquals(2, f.getCommentAsArray().length);
	}

	@Test
	public void testSetRepeatable() throws Exception {
		Function f = createExternalFunction("foo");
		String comment = "Test Repeatable Comment\nRepeatable Line 2";
		f.setRepeatableComment(comment);
		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(f.getEntryPoint());
		assertEquals(comment, f.getRepeatableComment());
		assertEquals(2, f.getRepeatableCommentAsArray().length);
	}

	@Test
	public void testSetBody() throws Exception {
		try {
			Function f = createExternalFunction("foo");
			assertTrue(f.getBody().isEmpty());
			f.setBody(new AddressSet(f.getEntryPoint()));
			Assert.fail("Setting body on external function should throw exception");
		}
		catch (UnsupportedOperationException e) {
			// expected
		}
	}

	@Test
	public void testFunctionIterator() throws Exception {

		Function f = createExternalFunction("foo");

		// External functions should not be returned by normal function iterators
		assertTrue(!functionManager.getFunctions(true).hasNext());
		assertTrue(!functionManager.getFunctions(f.getEntryPoint(), true).hasNext());

		assertTrue(!functionManager.getFunctionsNoStubs(true).hasNext());
		assertTrue(!functionManager.getFunctionsNoStubs(f.getEntryPoint(), true).hasNext());
		assertTrue(!functionManager.getFunctionsNoStubs(
			new AddressSet(AddressSpace.EXTERNAL_SPACE.getMinAddress(),
				AddressSpace.EXTERNAL_SPACE.getMaxAddress()),
			true).hasNext());

	}

	@Test
	public void testExternalFunctionIterator() throws Exception {

		Function f = createExternalFunction("foo");

		FunctionIterator it =
			functionManager.getFunctions(new AddressSet(AddressSpace.EXTERNAL_SPACE.getMinAddress(),
				AddressSpace.EXTERNAL_SPACE.getMaxAddress()), true);
		assertTrue(it.hasNext());
		Function extFunc = it.next();
		assertEquals(f, extFunc);

		it = functionManager.getExternalFunctions();
		assertTrue(it.hasNext());
		extFunc = it.next();
		assertEquals(f, extFunc);
	}

	@Test
	public void testSetRegisterParameter() throws Exception {
		Function f = createExternalFunction("foo");
		f.setCustomVariableStorage(true);

		DataType[] dt =
			new DataType[] { new LongDataType(), new WordDataType(), new Pointer16DataType() };

		Register[] regs =
			new Register[] { functionManager.getProgram().getProgramContext().getRegister("r1"),
				functionManager.getProgram().getProgramContext().getRegister("r0l"),
				functionManager.getProgram().getProgramContext().getRegister("spl") };

		LocalVariableImpl regVar = new LocalVariableImpl("TestReg0", 0, dt[0], regs[0], program);
		regVar.setComment("My Comment0");
		f.addParameter(regVar, SourceType.USER_DEFINED);
		regVar = new LocalVariableImpl("TestReg1", 0, dt[1], regs[1], program);
		regVar.setComment("My Comment1");
		f.addParameter(regVar, SourceType.USER_DEFINED);
		regVar = new LocalVariableImpl("TestReg2", 0, dt[2], regs[2], program);
		regVar.setComment("My Comment2");
		f.addParameter(regVar, SourceType.USER_DEFINED);

		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(f.getEntryPoint());
		Parameter[] params = f.getParameters();
		assertEquals(3, params.length);
		for (int i = 0; i < 3; i++) {
			Parameter param = params[i];
			assertEquals("TestReg" + i, param.getName());
			assertEquals(i, param.getOrdinal());
			assertEquals("My Comment" + i, param.getComment());
			assertEquals(f, param.getFunction());
			assertTrue(param.isRegisterVariable());
			assertEquals(regs[i], param.getRegister());
			assertTrue(dt[i].isEquivalent(param.getDataType()));
		}
	}

	@Test
	public void testCodeSymbolRestore() throws Exception {
		Function f = createExternalFunction("foo");
		Namespace parentNamespace = f.getSymbol().getParentNamespace();

		program.getFunctionManager().removeFunction(f.getEntryPoint());
		ExternalLocation externalLocation =
			program.getExternalManager().getUniqueExternalLocation(parentNamespace, "foo");
		assertNotNull(externalLocation);
		assertTrue(!externalLocation.isFunction());
		assertEquals(SymbolType.LABEL, externalLocation.getSymbol().getSymbolType());
	}

	@Test
	public void testCodeSymbolRestoreDefaultName() throws Exception {
		ExternalLocation extLoc =
			extMgr.addExtLocation("TestLibrary", null, addr(0x1000), SourceType.USER_DEFINED);
		Function f = extLoc.createFunction();

		Namespace parentNamespace = f.getSymbol().getParentNamespace();

		program.getFunctionManager().removeFunction(f.getEntryPoint());
		ExternalLocation externalLocation =
			program.getExternalManager().getUniqueExternalLocation(parentNamespace, "EXT_00001000");
		assertNotNull(externalLocation);
		assertTrue(!externalLocation.isFunction());
		assertEquals(SymbolType.LABEL, externalLocation.getSymbol().getSymbolType());
	}

	private Address addr(long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}
}
