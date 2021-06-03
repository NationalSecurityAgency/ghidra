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
package ghidra.program.database.symbol;

import static org.junit.Assert.*;

import org.junit.*;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitorAdapter;

public class SymbolManagerSourceTest extends AbstractGhidraHeadedIntegrationTest {

	private ProgramDB program;
	private SymbolTable st;
	private AddressSpace space;
	private ReferenceManager refMgr;
	private int transactionID;
	private Namespace globalScope;

	public SymbolManagerSourceTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		program = createDefaultProgram(testName.getMethodName(), ProgramBuilder._TOY, this);
		globalScope = program.getGlobalNamespace();
		space = program.getAddressFactory().getDefaultAddressSpace();
		Memory memory = program.getMemory();
		transactionID = program.startTransaction("Test");
		memory.createInitializedBlock("test", addr(0), 5000, (byte) 0,
			TaskMonitorAdapter.DUMMY_MONITOR, false);
		st = program.getSymbolTable();
		refMgr = program.getReferenceManager();
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

	private Symbol createSymbol(Address addr, String name, Namespace namespace, SourceType source)
			throws InvalidInputException {
		return st.createLabel(addr, name, namespace, source);
	}

	private void createDataReference(Address fromAddr, Address toAddr) {
		refMgr.addMemoryReference(fromAddr, toAddr, RefType.DATA, SourceType.USER_DEFINED, 0);
	}

	private void createDefaultFunction(Address entryPoint, AddressSet addrSet)
			throws DuplicateNameException, InvalidInputException, OverlappingFunctionException {
		FunctionManager functionMgr = program.getFunctionManager();
		Function f = functionMgr.createFunction(SymbolUtilities.getDefaultFunctionName(entryPoint),
			entryPoint, addrSet, SourceType.DEFAULT);
		assertNotNull(f);
	}

	/* ***** TEST CASES ***** */

	@Test
	public void testCreateUserSymbol() throws Exception {
		Symbol s = createSymbol(addr(0x0100), "UserSymbol", globalScope, SourceType.USER_DEFINED);
		assertEquals("UserSymbol", s.getName());
		assertEquals(true, s.getSource() == SourceType.USER_DEFINED);
	}

	@Test
	public void testCreateImportedSymbol() throws Exception {
		Symbol s = createSymbol(addr(0x0100), "ImportedSymbol", globalScope, SourceType.IMPORTED);
		assertEquals("ImportedSymbol", s.getName());
		assertEquals(true, s.getSource() == SourceType.IMPORTED);
	}

	@Test
	public void testCreateAnalysisSymbol() throws Exception {
		Symbol s = createSymbol(addr(0x0100), "AnalysisSymbol", globalScope, SourceType.ANALYSIS);
		assertEquals("AnalysisSymbol", s.getName());
		assertEquals(true, s.getSource() == SourceType.ANALYSIS);
	}

	@Test
	public void testCreateDefaultSymbol() throws Exception {
		Address endAddr = addr(0x0200);
		Address entryPoint = addr(0x0100);
		AddressSet addrSet = new AddressSet(entryPoint, endAddr);
		createDefaultFunction(entryPoint, addrSet);
		Function f = program.getFunctionManager().getFunctionAt(addr(0x0100));
		assertNotNull(f);
		assertEquals("FUN_00000100", f.getName());
		Symbol[] symbols = st.getSymbols(addr(0x0100));
		assertEquals(1, symbols.length);
		Symbol s = symbols[0];
		assertEquals("FUN_00000100", s.getName());
		assertEquals(true, s.getSource() == SourceType.DEFAULT);
		assertEquals(false, s.isDynamic());
	}

	@Test
	public void testCreateDynamicSymbol() throws Exception {
		Address fromAddr = addr(0x0200);
		Address toAddr = addr(0x0100);
		createDataReference(fromAddr, toAddr);
		Symbol[] symbols = st.getSymbols(addr(0x0100));
		assertEquals(1, symbols.length);
		Symbol s = symbols[0];
		assertEquals("DAT_00000100", s.getName());
		assertEquals(true, s.getSource() == SourceType.DEFAULT);
		assertEquals(true, s.isDynamic());
	}

	@Test
	public void testSetSymbolSource() throws Exception {
		Symbol s = createSymbol(addr(0x0100), "MySymbol", globalScope, SourceType.USER_DEFINED);
		assertEquals(SourceType.USER_DEFINED, s.getSource());

		s.setSource(SourceType.ANALYSIS);
		assertEquals(SourceType.ANALYSIS, s.getSource());

		s.setSource(SourceType.IMPORTED);
		assertEquals(SourceType.IMPORTED, s.getSource());

		try {
			s.setSource(SourceType.DEFAULT);
			Assert.fail("Shouldn't be able to set source on a Label symbol.");
		}
		catch (IllegalArgumentException e) {
		}
		assertEquals(SourceType.IMPORTED, s.getSource());

		s.setSource(SourceType.USER_DEFINED);
		assertEquals(SourceType.USER_DEFINED, s.getSource());
	}

	@Test
	public void testSetFunctionSource() throws Exception {
		Listing listing = program.getListing();

		AddressSet set = new AddressSet();
		set.addRange(addr(100), addr(150));
		set.addRange(addr(300), addr(310));
		set.addRange(addr(320), addr(330));
		listing.createFunction("fredFunc", addr(100), set, SourceType.USER_DEFINED);

		Symbol s1 = st.getPrimarySymbol(addr(100));
		assertNotNull(s1);
		assertEquals("fredFunc", s1.getName());
		assertTrue(s1.isPrimary());

		try {
			s1.setSource(SourceType.DEFAULT);
			Assert.fail("Shouldn't be able to set function source to DEFAULT.");
		}
		catch (IllegalArgumentException e) {
		}
		s1.setName("FUN_00000064", SourceType.DEFAULT);
		Symbol s2 = st.getPrimarySymbol(addr(100));
		assertNotNull(s2);
		assertEquals("FUN_00000064", s2.getName());
	}

	@Test
	public void testSetSymbolPinned() throws Exception {
		Symbol s = createSymbol(addr(0x0100), "MySymbol", globalScope, SourceType.USER_DEFINED);
		assertEquals(false, s.isPinned());

		s.setPinned(true);
		assertEquals(true, s.isPinned());

		s.setPinned(false);
		assertEquals(false, s.isPinned());
	}

	@Test
	public void testSetDefaultSymbolToNewName() throws Exception {
		Address fromAddr = addr(0x0200);
		Address toAddr = addr(0x0100);
		createDataReference(fromAddr, toAddr);
		Symbol[] symbols = st.getSymbols(addr(0x0100));
		assertEquals(1, symbols.length);
		Symbol s = symbols[0];
		assertEquals("DAT_00000100", s.getName());
		assertEquals(true, s.getSource() == SourceType.DEFAULT);

		s.setName("MySymbol", SourceType.USER_DEFINED);

		symbols = st.getSymbols(addr(0x0100));
		assertEquals(1, symbols.length);
		s = symbols[0];
		assertEquals("MySymbol", s.getName());
		assertEquals(true, s.getSource() == SourceType.USER_DEFINED);
	}

	@Test
	public void testSetNonDefaultToDefault() throws Exception {
		Symbol s = createSymbol(addr(0x0100), "UserSymbol", globalScope, SourceType.USER_DEFINED);
		assertEquals("UserSymbol", s.getName());
		assertEquals(true, s.getSource() == SourceType.USER_DEFINED);
		try {
			s.setSource(SourceType.DEFAULT);
			Assert.fail("Shouldn't be able to set source to default.");
		}
		catch (IllegalArgumentException e) {
			// Success
		}

		Symbol[] symbols = st.getSymbols(addr(0x0100));
		assertEquals(1, symbols.length);
		s = symbols[0];
		assertEquals("UserSymbol", s.getName());
		assertEquals(SourceType.USER_DEFINED, s.getSource());
		assertEquals(false, s.getSource() == SourceType.DEFAULT);
	}

	@Test
	public void testSetDefaultToNonDefault() throws Exception {
		createDataReference(addr(0x0120), addr(0x0100));// Should cause default label at 0x0120
		Symbol[] symbols = st.getSymbols(addr(0x0100));
		assertEquals(1, symbols.length);
		Symbol s = symbols[0];
		assertEquals("DAT_00000100", s.getName());
		assertEquals(true, s.getSource() == SourceType.DEFAULT);
		assertEquals(true, s.isDynamic());

		try {
			s.setSource(SourceType.USER_DEFINED);
			Assert.fail("Shouldn't be able to change from default to non-default.");
		}
		catch (IllegalArgumentException e) {
		}

		try {
			s.setName("blue", SourceType.USER_DEFINED);
		}
		catch (IllegalArgumentException e) {
			Assert.fail(e.getMessage());
		}

		symbols = st.getSymbols(addr(0x0100));
		assertEquals(1, symbols.length);
		s = symbols[0];
		assertEquals("blue", s.getName());
		assertEquals(SourceType.USER_DEFINED, s.getSource());

		try {
			s.setSource(SourceType.DEFAULT);
			Assert.fail("Shouldn't be able to set symbol source to default");
		}
		catch (IllegalArgumentException e) {
			// expected
		}
	}

	@Test
	public void testSetSymbolName() throws Exception {
		Symbol s = createSymbol(addr(0x0100), "UserSymbol", globalScope, SourceType.USER_DEFINED);
		assertEquals("UserSymbol", s.getName());
		assertEquals(true, s.getSource() == SourceType.USER_DEFINED);

		s.setName("MyAnalysis", SourceType.ANALYSIS);

		Symbol[] symbols = st.getSymbols(addr(0x0100));
		assertEquals(1, symbols.length);
		s = symbols[0];
		assertEquals("MyAnalysis", s.getName());
		assertEquals(true, s.getSource() == SourceType.ANALYSIS);

		s.setName("IMPORTED", SourceType.IMPORTED);

		symbols = st.getSymbols(addr(0x0100));
		assertEquals(1, symbols.length);
		s = symbols[0];
		assertEquals("IMPORTED", s.getName());
		assertEquals(true, s.getSource() == SourceType.IMPORTED);

		s.setName("NewStuff", SourceType.USER_DEFINED);

		symbols = st.getSymbols(addr(0x0100));
		assertEquals(1, symbols.length);
		s = symbols[0];
		assertEquals("NewStuff", s.getName());
		assertEquals(true, s.getSource() == SourceType.USER_DEFINED);
	}

	@Test
	public void testCreateMultipleSymbols() throws Exception {
		createSymbol(addr(0x0100), "UserSymbol", globalScope, SourceType.USER_DEFINED);
		Symbol[] symbols = st.getSymbols(addr(0x0100));
		assertEquals(1, symbols.length);
		assertEquals("UserSymbol", symbols[0].getName());
		assertEquals(true, symbols[0].getSource() == SourceType.USER_DEFINED);
		assertEquals(true, symbols[0].isPrimary());

		createSymbol(addr(0x0100), "AnalysisSymbol", globalScope, SourceType.ANALYSIS);
		symbols = st.getSymbols(addr(0x0100));
		assertEquals(2, symbols.length);
		assertEquals("UserSymbol", symbols[0].getName());
		assertEquals(true, symbols[0].getSource() == SourceType.USER_DEFINED);
		assertEquals(true, symbols[0].isPrimary());
		assertEquals("AnalysisSymbol", symbols[1].getName());
		assertEquals(true, symbols[1].getSource() == SourceType.ANALYSIS);

		createSymbol(addr(0x0100), "ImportedSymbol", globalScope, SourceType.IMPORTED);
		symbols = st.getSymbols(addr(0x0100));
		assertEquals(3, symbols.length);
		assertEquals("UserSymbol", symbols[0].getName());
		assertEquals(true, symbols[0].getSource() == SourceType.USER_DEFINED);
		assertEquals(true, symbols[0].isPrimary());
		assertEquals("AnalysisSymbol", symbols[1].getName());
		assertEquals(true, symbols[1].getSource() == SourceType.ANALYSIS);
		assertEquals("ImportedSymbol", symbols[2].getName());
		assertEquals(true, symbols[2].getSource() == SourceType.IMPORTED);

		createSymbol(addr(0x0100), "espresso", globalScope, SourceType.USER_DEFINED);
		symbols = st.getSymbols(addr(0x0100));
		assertEquals(4, symbols.length);
		assertEquals("UserSymbol", symbols[0].getName());
		assertEquals(true, symbols[0].getSource() == SourceType.USER_DEFINED);
		assertEquals(true, symbols[0].isPrimary());
		assertEquals("AnalysisSymbol", symbols[1].getName());
		assertEquals(true, symbols[1].getSource() == SourceType.ANALYSIS);
		assertEquals("ImportedSymbol", symbols[2].getName());
		assertEquals(true, symbols[2].getSource() == SourceType.IMPORTED);
		assertEquals("espresso", symbols[3].getName());
		assertEquals(true, symbols[3].getSource() == SourceType.USER_DEFINED);
	}

	@Test
	public void testCreateClass() throws Exception {
		GhidraClass c = st.createClass(globalScope, "MyClass", SourceType.USER_DEFINED);
		Symbol s = c.getSymbol();
		assertEquals("MyClass", c.getName());
		assertEquals("MyClass", s.getName());
		assertEquals(true, s.getSource() == SourceType.USER_DEFINED);
		assertEquals(globalScope.getSymbol(), s.getParentSymbol());

		c = st.createClass(globalScope, "YourImportedSymbol", SourceType.IMPORTED);
		s = c.getSymbol();
		assertEquals("YourImportedSymbol", c.getName());
		assertEquals("YourImportedSymbol", s.getName());
		assertEquals(true, s.getSource() == SourceType.IMPORTED);
		assertEquals(globalScope.getSymbol(), s.getParentSymbol());

		c = st.createClass(globalScope, "AnalysisClass", SourceType.ANALYSIS);
		s = c.getSymbol();
		assertEquals("AnalysisClass", c.getName());
		assertEquals("AnalysisClass", s.getName());
		assertEquals(true, s.getSource() == SourceType.ANALYSIS);
		assertEquals(globalScope.getSymbol(), s.getParentSymbol());

		try {
			c = st.createClass(globalScope, "Class1", SourceType.DEFAULT);
			Assert.fail("Shouldn't be able to create default Class.");
		}
		catch (IllegalArgumentException e) {
		}
	}

	@Test
	public void testCreateExternalLibrary() throws Exception {
		Library lib = st.createExternalLibrary("UserLib", SourceType.USER_DEFINED);
		Symbol s = lib.getSymbol();
		assertEquals("UserLib", lib.getName());
		assertEquals("UserLib", s.getName());
		assertEquals(true, s.getSource() == SourceType.USER_DEFINED);
		assertEquals(globalScope.getSymbol(), s.getParentSymbol());

		lib = st.createExternalLibrary("ImportedLib", SourceType.IMPORTED);
		s = lib.getSymbol();
		assertEquals("ImportedLib", lib.getName());
		assertEquals("ImportedLib", s.getName());
		assertEquals(true, s.getSource() == SourceType.IMPORTED);
		assertEquals(globalScope.getSymbol(), s.getParentSymbol());

		lib = st.createExternalLibrary("AnalysisLib", SourceType.ANALYSIS);
		s = lib.getSymbol();
		assertEquals("AnalysisLib", lib.getName());
		assertEquals("AnalysisLib", s.getName());
		assertEquals(true, s.getSource() == SourceType.ANALYSIS);
		assertEquals(globalScope.getSymbol(), s.getParentSymbol());

		try {
			lib = st.createExternalLibrary("DefaultLib", SourceType.DEFAULT);
			Assert.fail("Shouldn't be able to create default External Library.");
		}
		catch (IllegalArgumentException e) {
		}
	}

	@Test
	public void testCreateNamespace() throws Exception {
		Namespace n = st.createNameSpace(globalScope, "MyNamespace", SourceType.USER_DEFINED);
		Symbol s = n.getSymbol();
		assertEquals("MyNamespace", n.getName());
		assertEquals("MyNamespace", s.getName());
		assertEquals(true, s.getSource() == SourceType.USER_DEFINED);
		assertEquals(globalScope.getSymbol(), s.getParentSymbol());

		n = st.createNameSpace(globalScope, "YourImportedSymbol", SourceType.IMPORTED);
		s = n.getSymbol();
		assertEquals("YourImportedSymbol", n.getName());
		assertEquals("YourImportedSymbol", s.getName());
		assertEquals(true, s.getSource() == SourceType.IMPORTED);
		assertEquals(globalScope.getSymbol(), s.getParentSymbol());

		n = st.createNameSpace(globalScope, "AnalysisNamespace", SourceType.ANALYSIS);
		s = n.getSymbol();
		assertEquals("AnalysisNamespace", n.getName());
		assertEquals("AnalysisNamespace", s.getName());
		assertEquals(true, s.getSource() == SourceType.ANALYSIS);
		assertEquals(globalScope.getSymbol(), s.getParentSymbol());

		try {
			n = st.createNameSpace(globalScope, "Namespace1", SourceType.DEFAULT);
			Assert.fail("Shouldn't be able to create default Namespace.");
		}
		catch (IllegalArgumentException e) {
		}
	}

}
