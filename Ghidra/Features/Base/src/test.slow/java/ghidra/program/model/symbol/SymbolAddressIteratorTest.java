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
package ghidra.program.model.symbol;

import static org.junit.Assert.*;

import org.junit.*;

import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.test.ToyProgramBuilder;

public class SymbolAddressIteratorTest extends AbstractGhidraHeadlessIntegrationTest {

	private ToyProgramBuilder builder;
	private ProgramDB program;
	private AddressSpace space;

	@Before
	public void setup() throws Exception {
		builder = new ToyProgramBuilder();
		builder.createMemory("RAM", "0", 10000, "");
		program = builder.getProgram();
		space = program.getAddressFactory().getDefaultAddressSpace();

	}

	@After
	public void tearDown() {
		builder.dispose();
	}

	@Test
	public void testNoSymbols() {

		SymbolAddressIterator it = new SymbolAddressIterator(program, 10);
		assertAddresses(it);
	}

	@Test
	public void testOneChunk() {
		createLabels(100, 200, 200, 300, 300, 300, 400);

		SymbolAddressIterator it = new SymbolAddressIterator(program, 10);
		assertAddresses(it, 100, 200, 300, 400);
	}

	@Test
	public void testTwoChunk() {
		createLabels(100, 200, 200, 300, 300, 300, 400);

		SymbolAddressIterator it = new SymbolAddressIterator(program, 2);
		assertAddresses(it, 100, 200, 300, 400);
	}

	@Test
	public void testFourChunks() {
		createLabels(100, 200, 200, 300, 300, 300, 400);

		SymbolAddressIterator it = new SymbolAddressIterator(program, 1);
		assertAddresses(it, 100, 200, 300, 400);
	}

	@Test
	public void testJustCallingNext() {
		createLabels(100, 100, 100, 200, 200);

		SymbolAddressIterator it = new SymbolAddressIterator(program, 1);
		assertEquals(addr(100), it.next());
		assertEquals(addr(200), it.next());
		assertNull(it.next());

	}

	@Test
	public void testLimitedBySet() {
		createLabels(100, 200, 200, 300, 300, 300, 400, 500);

		AddressSet set = new AddressSet(addr(200), addr(400));
		SymbolAddressIterator it = new SymbolAddressIterator(program, set, 2);
		assertAddresses(it, 200, 300, 400);
	}

	private void assertAddresses(AddressIterator it, Integer... addresses) {
		for (int i = 0; i < addresses.length; i++) {
			assertTrue("No address: " + addresses[i], it.hasNext());
			assertEquals(addr(addresses[i]), it.next());
		}
		assertFalse(it.hasNext());
	}

	private void createLabels(Integer... addresses) {
		for (Integer address : addresses) {
			builder.createLabel(Integer.toString(address, 16), "XXX+address");
		}

	}

	private Address addr(int address) {
		return space.getAddress(address);
	}

}
