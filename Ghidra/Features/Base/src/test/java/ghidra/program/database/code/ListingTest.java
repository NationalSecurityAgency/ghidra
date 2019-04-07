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
package ghidra.program.database.code;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.List;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;
import ghidra.test.ToyProgramBuilder;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Test the code manager portion of listing.
 *
 *
 */
public class ListingTest extends AbstractGenericTest {

	private ToyProgramBuilder builder;

	private Listing listing;
	private AddressSpace space;
	private Program program;
	private Memory mem;
	private int transactionID;

	/**
	 * Constructor for CodeManagerTest.
	 * @param arg0
	 */
	public ListingTest() {
		super();
	}

	/*
	 * @see TestCase#setUp()
	 */
	@Before
	public void setUp() throws Exception {

		builder = new ToyProgramBuilder("Test", true, this);
		builder.createMemory("B1", "1000", 0x2000);

		program = builder.getProgram();
		space = program.getAddressFactory().getDefaultAddressSpace();
		listing = program.getListing();
		mem = program.getMemory();
		transactionID = program.startTransaction("Test");

	}

	@After
	public void tearDown() throws Exception {
		program.endTransaction(transactionID, true);
		program.release(this);
	}

	@Test
	public void testGetFunctionWithNamespace()
			throws DuplicateNameException, InvalidInputException, OverlappingFunctionException {

		listing.createFunction("bob", addr(0x1000), new AddressSet(addr(0x1000), addr(0x1100)),
			SourceType.USER_DEFINED);

		SymbolTable symbolTable = program.getSymbolTable();
		Namespace namespace1 = symbolTable.createNameSpace(program.getGlobalNamespace(), "foo",
			SourceType.USER_DEFINED);
		Namespace namespace2 =
			symbolTable.createNameSpace(namespace1, "bar", SourceType.USER_DEFINED);

		listing.createFunction("bob", namespace2, addr(0x2000),
			new AddressSet(addr(0x2000), addr(0x2100)), SourceType.USER_DEFINED);

		List<Function> functions = listing.getFunctions("foo::bar", "bob");
		assertEquals(1, functions.size());
	}

	@Test
	public void testGetFunctionWithColonInNameAndWithNamespace()
			throws DuplicateNameException, InvalidInputException, OverlappingFunctionException {

		listing.createFunction("bob::sis", addr(0x1000), new AddressSet(addr(0x1000), addr(0x1100)),
			SourceType.USER_DEFINED);

		SymbolTable symbolTable = program.getSymbolTable();
		Namespace namespace1 = symbolTable.createNameSpace(program.getGlobalNamespace(), "foo::bar",
			SourceType.USER_DEFINED);
		Namespace namespace2 =
			symbolTable.createNameSpace(namespace1, "baz", SourceType.USER_DEFINED);

		listing.createFunction("bob::sis", namespace2, addr(0x2000),
			new AddressSet(addr(0x2000), addr(0x2100)), SourceType.USER_DEFINED);

		List<Function> functions = listing.getFunctions("foo::bar::baz", "bob::sis");
		assertEquals(1, functions.size());
		Function f = functions.get(0);
		assertNotNull(f);
		assertEquals("bob::sis", f.getName());
		assertEquals("foo::bar::baz::bob::sis", f.getName(true));
		assertEquals("bob::sis", f.getName(false));
		assertEquals("baz", f.getParentNamespace().getName());
		assertEquals("foo::bar", f.getParentNamespace().getParentNamespace().getName());
		assertEquals(Namespace.GLOBAL_NAMESPACE_ID,
			f.getParentNamespace().getParentNamespace().getParentNamespace().getID());
	}

	private Address addr(long l) {
		return space.getAddress(l);
	}

//	private void parseStatic(Address startAddr, Address endAddr) throws Exception {
//
//		Address addr;
//
//		for (addr = startAddr; addr.compareTo(endAddr) <= 0;) {
//			parseOne(addr);
//			CodeUnit unit = listing.getCodeUnitAt(addr);
//			addr = addr.add(unit.getLength());
//		}
//	}

//	private void parseOne(Address atAddr) throws Exception {
//
//		MemBuffer buf = new DumbMemBufferImpl(mem, atAddr);
//		ProcessorContext context = new ProgramProcessorContext(program.getProgramContext(), atAddr);
//		InstructionPrototype proto = program.getLanguage().parse(buf, context, false);
//		listing.createInstruction(atAddr, proto, buf, context);
//
//	}
}
