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

import java.util.Arrays;

import org.junit.*;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.test.ToyProgramBuilder;
import ghidra.util.task.TaskMonitor;

public class DemangledFunctionTest extends AbstractGhidraHeadlessIntegrationTest {

	private ProgramBuilder programBuilder;
	private ProgramDB program;
	private int txID;

	@Before
	public void setUp() throws Exception {
		programBuilder = new ToyProgramBuilder("test", true);
		programBuilder.createMemory(".text", "0x0100", 0x100);
		program = programBuilder.getProgram();
		txID = program.startTransaction("Test");
	}

	@After
	public void tearDown() throws Exception {
		program.endTransaction(txID, false);
	}

	/*
	 * Test that the DemangledFunction will properly create a cascade of namespaces for
	 * functions that live inside of a class that lives inside of a namespace.
	 * This test applies a demangled name where the mangled name does NOT exist.
	 */
	@Test
	public void testApply_FunctionInClassInNamespace() throws Exception {

		// this is: public long __thiscall ATL::CRegKey::Close(void)
		String mangled = "?CloseM@CRegKeyM@ATL@@QAEJXZ";
		DemangledObject demangled = DemanglerUtil.demangle(mangled);
		assertTrue(demangled instanceof DemangledFunction);

		Address addr = addr("0x0101");
		assertTrue(demangled.applyTo(program, addr, new DemanglerOptions(), TaskMonitor.DUMMY));

		assertFunction("CloseM", addr);

		SymbolTable symbolTable = program.getSymbolTable();

		// expected: ATL::CRegKey::Close
		Symbol[] symbols = symbolTable.getSymbols(addr);
		assertEquals(1, symbols.length);
		assertEquals("CloseM", symbols[0].getName());

		Namespace ns = symbols[0].getParentNamespace();
		assertEquals("CRegKeyM", ns.getName(false));

		ns = ns.getParentNamespace();
		assertEquals("ATL", ns.getName(false));
	}

	/*
	 * Test that the DemangledFunction will properly update a thunk function
	 * with its namespace, and ripple through to the underlying default thunked
	 * function.  The thunk 'this' parameter should utilize the Class 
	 * within which the thunk resides.
	 */
	@Test
	public void testApplyToThunk_FunctionInClassInNamespace() throws Exception {

		// this is: public long __thiscall ATL::CRegKey::Close(void)
		String mangled = "?Close@CRegKey@ATL@@QAEJXZ";
		DemangledObject demangled = DemanglerUtil.demangle(mangled);
		assertTrue(demangled instanceof DemangledFunction);

		FunctionManager functionMgr = program.getFunctionManager();
		Function f1 = functionMgr.createFunction(null, addr("0x0110"),
			new AddressSet(addr("0x0110")), SourceType.DEFAULT);
		Function f2 = functionMgr.createFunction(mangled, addr("0x0100"),
			new AddressSet(addr("0x0100")), SourceType.IMPORTED);
		f2.setThunkedFunction(f1);

		Address addr = addr("0x0100");
		demangled.applyTo(program, addr, new DemanglerOptions(), TaskMonitor.DUMMY);

		assertFunction("Close", addr);
		assertNoBookmarkAt(addr);

		SymbolTable symbolTable = program.getSymbolTable();

		// expected: ATL::CRegKey::Close
		Symbol[] symbols = symbolTable.getSymbols(addr);
		assertEquals(2, symbols.length); // both mangled and demangled
		assertTrue(symbols[0].isPrimary());
		assertEquals("Close", symbols[0].getName());

		Namespace ns = symbols[0].getParentNamespace();
		assertEquals("CRegKey", ns.getName(false));

		ns = ns.getParentNamespace();
		assertEquals("ATL", ns.getName(false));

		Parameter[] parameters = f2.getParameters();
		assertEquals("Missing parameter", 1, parameters.length);
		assertTrue(parameters[0].isAutoParameter());
		assertEquals("The 'this' param has incorrect type", "CRegKey *",
			parameters[0].getDataType().getDisplayName());

	}

	/*
	 * Test that the DemangledFunction will properly create a cascade of namespaces for
	 * functions that live inside of a class that lives inside of a namespace.
	 * This test applies a demangled name where the mangled name exists.
	 */
	@Test
	public void testApply_FunctionInClassInNamespace2() throws Exception {

		// this is: public long __thiscall ATL::CRegKey::Close(void)
		String mangled = "?Close@CRegKey@ATL@@QAEJXZ";
		Address addr = addr("0x0101");

		SymbolTable symbolTable = program.getSymbolTable();
		symbolTable.createLabel(addr, mangled, SourceType.IMPORTED);

		DemangledObject demangled = DemanglerUtil.demangle(mangled);
		assertTrue(demangled instanceof DemangledFunction);

		assertTrue(demangled.applyTo(program, addr, new DemanglerOptions(), TaskMonitor.DUMMY));

		assertFunction("Close", addr);
		assertNoBookmarkAt(addr);

		// expected: ATL::CRegKey::Close
		Symbol[] symbols = symbolTable.getSymbols(addr);
		assertEquals(2, symbols.length);
		assertEquals("Close", symbols[0].getName());
		assertEquals(mangled, symbols[1].getName());

		Namespace ns = symbols[0].getParentNamespace();
		assertEquals("CRegKey", ns.getName(false));

		ns = ns.getParentNamespace();
		assertEquals("ATL", ns.getName(false));
	}

	/*
	 * Test that the DemangledFunction will properly create a cascade of namespaces for
	 * functions that live inside of a class that lives inside of a namespace.
	 * This test applies a demangled name where the mangled name exists with address suffix.
	 */
	@Test
	public void testApply_FunctionInClassInNamespace3() throws Exception {

		// this is: public long __thiscall ATL::CRegKey::Close(void)
		String mangled = "?Close@CRegKey@ATL@@QAEJXZ";
		Address addr = addr("0x0101");

		SymbolTable symbolTable = program.getSymbolTable();
		String mangledWithAddr = SymbolUtilities.getAddressAppendedName(mangled, addr);
		symbolTable.createLabel(addr, mangledWithAddr, SourceType.IMPORTED);

		DemangledObject demangled = DemanglerUtil.demangle(mangled);
		assertTrue(demangled instanceof DemangledFunction);

		assertTrue(demangled.applyTo(program, addr, new DemanglerOptions(), TaskMonitor.DUMMY));

		assertFunction("Close", addr);
		assertNoBookmarkAt(addr);

		// expected: ATL::CRegKey::Close
		Symbol[] symbols = symbolTable.getSymbols(addr);
		assertEquals(2, symbols.length);
		assertEquals("Close", symbols[0].getName());
		assertEquals(mangledWithAddr, symbols[1].getName());

		Namespace ns = symbols[0].getParentNamespace();
		assertEquals("CRegKey", ns.getName(false));

		ns = ns.getParentNamespace();
		assertEquals("ATL", ns.getName(false));
	}

	/*
	 * Test that the DemangledFunction will properly create a cascade of namespaces for
	 * functions that live inside of a class that lives inside of a namespace.
	 * This test applies a demangled name where both the mangled name exists and
	 * the simple demangled name exists in the global space.
	 */
	@Test
	public void testApply_FunctionInClassInNamespace4() throws Exception {

		// this is: public long __thiscall ATL::CRegKey::Close(void)
		String mangled = "?Close@CRegKey@ATL@@QAEJXZ";
		Address addr = addr("0x0101");

		SymbolTable symbolTable = program.getSymbolTable();
		symbolTable.createLabel(addr, "Close", SourceType.IMPORTED);
		symbolTable.createLabel(addr, mangled, SourceType.IMPORTED);

		DemangledObject demangled = DemanglerUtil.demangle(mangled);
		assertTrue(demangled instanceof DemangledFunction);

		assertTrue(demangled.applyTo(program, addr, new DemanglerOptions(), TaskMonitor.DUMMY));

		assertFunction("Close", addr);
		assertNoBookmarkAt(addr);

		// expected: ATL::CRegKey::Close
		Symbol[] symbols = symbolTable.getSymbols(addr);
		assertEquals(2, symbols.length);
		assertEquals("Close", symbols[0].getName());
		assertEquals(mangled, symbols[1].getName());

		Namespace ns = symbols[0].getParentNamespace();
		assertEquals("CRegKey", ns.getName(false));

		ns = ns.getParentNamespace();
		assertEquals("ATL", ns.getName(false));
	}

	@Test
	public void testFunctionThisPointer() throws Exception {

		//
		// Test a function within a class that has a 'this' pointer
		//

		String mangled =
			"??$?0V?$A@_NABW4B@C@@@D@E@@@?$F@V?$G@U?$H@Q6A_NABW4B@C@@@Z$0A@@D@E@@_NABW4B@C@@@D@E@@@E@@QAE@ABV?$F@V?$A@_NABW4B@C@@@D@E@@@1@@Z";
		Address addr = addr("0x0101");

		SymbolTable symbolTable = program.getSymbolTable();
		symbolTable.createLabel(addr, mangled, SourceType.IMPORTED);

		DemangledObject demangled = DemanglerUtil.demangle(mangled);
		assertTrue(demangled instanceof DemangledFunction);
		assertTrue(demangled.applyTo(program, addr, new DemanglerOptions(), TaskMonitor.DUMMY));

		String className =
			"F<class_E::D::G<struct_E::D::H<bool_(__cdecl*const)(enum_C::B_const&),0>,bool,enum_C::B_const&>_>";
		String functionName = className + "<class_E::D::A<bool,enum_C::B_const&>_>";

		Function function = assertFunction(functionName, addr);
		assertNoBookmarkAt(addr);

		Symbol[] symbols = symbolTable.getSymbols(addr);
		assertEquals(2, symbols.length);
		assertEquals(functionName, symbols[0].getName());
		assertEquals(mangled, symbols[1].getName());

		// Check for the Class 'this' pointer
		Parameter[] parameters = function.getParameters();
		assertEquals(2, parameters.length);
		Parameter p1 = parameters[0];
		assertEquals("this", p1.getName());
		assertEquals(className + " *", p1.getDataType().toString());

		Namespace ns = symbols[0].getParentNamespace();
		assertEquals(className, ns.getName(false));
		ns = ns.getParentNamespace();
		assertEquals("E", ns.getName(false));
	}

	/*
	 * Test that the DemangledFunction will properly create a cascade of namespaces for
	 * functions that live inside of a class that lives inside of a namespace.
	 * This test applies a demangled name where the mangled name exists on an external
	 * location symbol.
	 */
	@Test
	public void testApply_ExternalFunctionInClassInNamespace() throws Exception {

		// this is: public long __thiscall ATL::CRegKey::Close(void)
		String mangled = "?Close@CRegKey@ATL@@QAEJXZ";

		ExternalManager externalManager = program.getExternalManager();
		Library lib = externalManager.addExternalLibraryName("MY.DLL", SourceType.IMPORTED);
		ExternalLocation extLoc =
			externalManager.addExtLocation(lib, mangled, null, SourceType.IMPORTED);

		Address addr = extLoc.getExternalSpaceAddress();

		DemangledObject demangled = DemanglerUtil.demangle(mangled);
		assertTrue(demangled instanceof DemangledFunction);

		assertTrue(demangled.applyTo(program, addr, new DemanglerOptions(), TaskMonitor.DUMMY));

		assertFunction("Close", addr);
		assertNoBookmarkAt(addr);

		SymbolTable symbolTable = program.getSymbolTable();

		// expected: ATL::CRegKey::Close
		Symbol[] symbols = symbolTable.getSymbols(addr);
		assertEquals(1, symbols.length);
		assertEquals("Close", symbols[0].getName());

		Namespace ns = symbols[0].getParentNamespace();
		assertEquals("CRegKey", ns.getName(false));

		ns = ns.getParentNamespace();
		assertEquals("ATL", ns.getName(false));

		extLoc = externalManager.getExternalLocation(symbols[0]);
		assertNotNull(extLoc);

		assertEquals("Close", extLoc.getLabel());
		assertEquals(mangled, extLoc.getOriginalImportedName());

	}

	@Test
	public void testFunctionVariable() throws Exception {

		//
		// This makes sure that a variable inside of a function namespace prevents a class 
		// namespace object from being created when a function does not exist.  Instead it should
		// create a simple namespace.
		//

		String mangled = "_ZZ18__gthread_active_pvE20__gthread_active_ptr";
		String functionName = "__gthread_active_p";
		programBuilder.createEmptyFunction(functionName, "0x0101", 10, new VoidDataType());

		programBuilder.createLabel("0x0103", mangled);

		DemangledObject demangled = DemanglerUtil.demangle(program, mangled);
		assertNotNull(demangled);
		assertTrue(demangled instanceof DemangledVariable);

		assertEquals("__gthread_active_p()::__gthread_active_ptr", demangled.getSignature(false));

		Address addr = addr("0x0103");
		demangled.applyTo(program, addr, new DemanglerOptions(), TaskMonitor.DUMMY);

		assertSimpleNamespaceExists("__gthread_active_p()");
		assertNoBookmarkAt(addr);

		SymbolTable symbolTable = program.getSymbolTable();
		Symbol[] symbols = symbolTable.getSymbols(addr);
		assertEquals(2, symbols.length);
		assertEquals("_ZZ18__gthread_active_pvE20__gthread_active_ptr", symbols[1].getName());
		assertEquals("__gthread_active_ptr", symbols[0].getName());

		Namespace ns = symbols[0].getParentNamespace();
		assertEquals("__gthread_active_p()", ns.getName(false));
	}

	private void assertNoBookmarkAt(Address addr) {
		BookmarkManager bm = program.getBookmarkManager();
		Bookmark[] bookmarks = bm.getBookmarks(addr);
		if (bookmarks.length > 0) {
			fail("Expected no bookmark; found " + Arrays.toString(bookmarks));
		}
	}

	private void assertSimpleNamespaceExists(String name) {
		SymbolTable symbolTable = program.getSymbolTable();
		Namespace ns = symbolTable.getNamespace(name, program.getGlobalNamespace());
		assertNotNull("Namespace not created: " + name, ns);
		assertEquals(SymbolType.NAMESPACE, ns.getSymbol().getSymbolType());
	}

	private Function assertFunction(String name, Address addr) {
		FunctionManager fm = program.getFunctionManager();
		Function function = fm.getFunctionAt(addr);
		assertNotNull("Expected function to get created at " + addr, function);
		assertEquals(name, function.getName());
		return function;
	}

	private Address addr(String addr) {
		return program.getAddressFactory().getAddress(addr);
	}
}
