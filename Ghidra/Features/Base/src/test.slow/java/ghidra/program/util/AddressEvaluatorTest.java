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
package ghidra.program.util;

import static org.junit.Assert.*;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;

public class AddressEvaluatorTest extends AbstractGenericTest {

	private Program program;
	private ProgramBuilder builder;
	private Symbol entry;
	private Symbol entryInFoo;

	public AddressEvaluatorTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", ProgramBuilder._TOY_LE, this);
		builder.createMemory("TestBlock", "0x100", 100);
		program = builder.getProgram();
		entry = builder.createLabel("0x100", "entry");
		builder.createNamespace("foo");
		entryInFoo = builder.createLabel("0x103", "entry", "foo");
	}

	@After
	public void tearDown() {
		program.release(this);
	}

	@Test
	public void testLongValueExpression() {
		assertEval(addr("0x19"), "(2+3)*5");
		assertEval(addr("0x11"), "2+3*5");
		assertEval(addr("0x11"), "2+(3*5)");
		assertEval(addr("0x3"), "0-5+8");
		assertEval(addr("0x3"), "-5+8");
		assertEval(addr("0xfffffffB"), "-5");
		assertEval(addr("0x11"), "3+(5+(3*2)+(3))");
	}

	@Test
	public void testAssumesHex() {
		assertEval(addr("0x30"), "20 + 10");
		assertEval(addr("0xf1"), "e1+10");
	}

	@Test
	public void testAcceptsHexPrefix() {
		assertEval(addr("0x16"), "0x11+5");
		assertEval(addr("0x35"), "20+0x15");
	}

	@Test
	public void testBitWiseExpressions() {

		assertEval(addr("0xff00"), "0xffff ^ 0xff");
		assertEval(addr("0x123f"), "0xffff & 0x123f");
		assertEval(addr("0x1234"), "0x1200 | 0x0034");
		assertEval(addr("0xffffffff"), "~ 0x0");
		assertEval(addr("0x1201"), "0x1200 | ~(0xfffffffe)");
		assertEval(addr("0x480"), "0x1200 >> 2");
		assertEval(addr("0x1200"), "0x480 << 2");
		assertEval(addr("0x103"), "0x100 | 0x1 | ~(~0x2)");
	}

	@Test
	public void testLogicalExpressions() {
		assertEval(addr("0x1"), "(((0x1 | 0x2) & 0x2) == 0x2)");
		assertEval(addr("0x0"), "(((0x1 | 0x2) & 0x2) == 0x1)");
		assertEval(addr("0x0"), "(((0x1 | 0x2) & 0x2) == 0x1)");

		assertEval(addr("0x1"), "(((0x1 | 0x2) & 0x2) >= 0x1)");
		assertEval(addr("0x0"), "(((0x1 | 0x2) & 0x2) <= 0x1)");

	}

	@Test
	public void testAlternateNumberDecorations() {
		assertEval(addr("0x4"), "(4ul)");
		assertEval(addr("0x4"), "(4UL)");
		assertEval(addr("0x4"), "( 4l )");
		assertEval(addr("0x4"), "(4L)");
		assertEval(addr("0x4"), "(4u )");
		assertEval(addr("0x4"), "( 4U)");
	}

	@Test
	public void testInvalidInput() {
		assertEval(null, "( 4P)");
	}

	@Test
	public void testShift() {
		assertEval(addr("0x80"), "0x100 >> 1");
		assertEval(addr("0x400"), "0x100 << 2");
	}

	@Test
	public void testSymbolLookup() {
		assertEval(entry.getAddress(), "entry");
		assertEval(entry.getAddress().add(10), "entry+5*2");
		assertEval(addr("0x101"), "entry + (entry == 0x100)");
		assertEval(addr("0x500"), "entry + (entry == 0x100) * 0x400 + (entry < 0x100) * 0x500");
		assertEval(addr("0x600"), "entry + (entry > 0x100) * 0x400 + (entry <= 0x100) * 0x500");
	}

	@Test
	public void testSymbolInNamespaceLookup() {
		assertEval(entryInFoo.getAddress(), "foo::entry");
		assertEval(entryInFoo.getAddress().add(10), "foo::entry+5*2");
		assertEval(null, "bar::entry");
	}

	@Test
	public void testSymbolShift() {
		assertEval(addr("0x80"), "entry >> 1");
		assertEval(addr("0x400"), "entry << 2");
	}

	@Test
	public void testMemoryBlockOffset() {
		assertEval(addr("0x110"), "TestBlock+10");
	}

	@Test
	public void testMultiAddrSpace() throws Exception {
		assertEval(addr("0x15"), "ram:2 + 0x13");
		assertEval(addr("register:0x15"), "register:2 + 0x13");
	}

	private void assertEval(Address addr, String input) {
		assertEquals(addr, AddressEvaluator.evaluate(program, input));
	}

	private Address addr(String address) {
		return program.getAddressFactory().getAddress(address);
	}
}
