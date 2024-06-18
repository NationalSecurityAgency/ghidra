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
package ghidra.app.util.viewer.listingpanel;

import static ghidra.util.datastruct.Duo.Side.*;
import static org.junit.Assert.*;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.*;
import ghidra.test.ToyProgramBuilder;
import ghidra.util.datastruct.Duo.Side;

public class ProgramLocationTranslatorTest extends AbstractGenericTest {
	private static long PROGRAM1_BASE = 0x100000;
	private static long PROGRAM2_BASE = 0x200000;

	private Program program1;
	private Program program2;
	private Function function1;
	private Function functionA;
	private TestAddressCorrelation correlator;
	private ProgramLocationTranslator translator;

	@Before
	public void setUp() throws Exception {
		program1 = createProgram1();
		program2 = createProgram2();
		function1 = program1.getListing().getFunctionAt(addr(program1, PROGRAM1_BASE));
		functionA = program1.getListing().getFunctionAt(addr(program2, PROGRAM2_BASE));
		correlator = new TestAddressCorrelation();
		translator = new ProgramLocationTranslator(correlator);
	}

	@After
	public void tearDown() {
		program1.release(this);
		program2.release(this);
	}

	@Test
	public void testBasicProgramLocation() {
		ProgramLocation location = new ProgramLocation(program1, program1.getMinAddress());
		ProgramLocation otherLocation = translator.getProgramLocation(RIGHT, location);
		assertEquals(program2, otherLocation.getProgram());
		assertEquals(program2.getMinAddress(), otherLocation.getAddress());

		ProgramLocation roundTripLocation = translator.getProgramLocation(LEFT, otherLocation);
		assertEquals(location, roundTripLocation);
	}

	@Test
	public void testBytesLocation() {
		Address minAddress = program1.getMinAddress();
		Address byteAddress = minAddress.add(1);
		ProgramLocation location =
			new BytesFieldLocation(program1, minAddress, byteAddress, null, 2);

		ProgramLocation otherLocation = translator.getProgramLocation(RIGHT, location);
		assertTrue(otherLocation instanceof BytesFieldLocation);
		assertEquals(program2, otherLocation.getProgram());
		assertEquals(program2.getMinAddress(), otherLocation.getAddress());
		assertEquals(program2.getMinAddress().add(1), otherLocation.getByteAddress());
		assertEquals(2, otherLocation.getCharOffset());

		ProgramLocation roundTripLocation = translator.getProgramLocation(LEFT, otherLocation);
		assertEquals(location, roundTripLocation);

	}

	@Test
	public void testVariableLocation() {
		Function f = program1.getListing().getFunctionAt(addr(program1, PROGRAM1_BASE));
		Variable[] variables = f.getAllVariables();
		VariableLocation location = new VariableLocation(program1, variables[0], 0, 1);

		ProgramLocation otherLocation = translator.getProgramLocation(RIGHT, location);
		assertTrue(otherLocation instanceof VariableLocation);

		ProgramLocation roundTripLocation = translator.getProgramLocation(LEFT, otherLocation);
		assertEquals(location, roundTripLocation);

	}

	@Test
	public void testLableFieldLocation() {
		Symbol[] symbols = program1.getSymbolTable().getSymbols(addr(program1, PROGRAM1_BASE));
		assertEquals(1, symbols.length);
		LabelFieldLocation location = new LabelFieldLocation(symbols[0], 0, 3);
		ProgramLocation otherLocation = translator.getProgramLocation(RIGHT, location);
		assertTrue(otherLocation instanceof LabelFieldLocation);

		ProgramLocation roundTripLocation = translator.getProgramLocation(LEFT, otherLocation);
		assertEquals(location, roundTripLocation);
	}

	private Address addr(Program program, long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	private Program createProgram1() throws Exception {
		ToyProgramBuilder builder = new ToyProgramBuilder("program1", true, this);

		builder.createMemory("text", Long.toHexString(PROGRAM1_BASE), 0x5000);
		buildFunction(builder, "fun1", PROGRAM1_BASE);
		buildFunction(builder, "fun2", PROGRAM1_BASE + 0x1000);
		buildFunction(builder, "fun3", PROGRAM1_BASE + 0x2000);

		Program program = builder.getProgram();

		builder.dispose();
		return program;
	}

	private Program createProgram2() throws Exception {
		ToyProgramBuilder builder = new ToyProgramBuilder("program2", true, this);

		builder.createMemory("text", Long.toHexString(PROGRAM2_BASE), 5000);
		buildFunction(builder, "funA", PROGRAM2_BASE);
		buildFunction(builder, "funB", PROGRAM2_BASE + 0x1000);

		Program program = builder.getProgram();

		builder.dispose();
		return program;
	}

	private void buildFunction(ToyProgramBuilder builder, String name, long address)
			throws Exception {
		builder.addBytesFallthrough(address);
		builder.addBytesReturn(address + 2);

		String functionStart = Long.toHexString(address);
		builder.disassemble(functionStart, 3, true);
		Function function = builder.createFunction(functionStart);
		Variable var =
			new LocalVariableImpl("i", new IntegerDataType(), -0x4, builder.getProgram());
		builder.addFunctionVariable(function, var);

		builder.createLabel(functionStart, name);// function label
	}

	private class TestAddressCorrelation implements ListingAddressCorrelation {

		@Override
		public Program getProgram(Side side) {
			return side == LEFT ? program1 : program2;
		}

		@Override
		public Function getFunction(Side side) {
			return side == LEFT ? function1 : functionA;
		}

		@Override
		public AddressSetView getAddresses(Side side) {
			return side == LEFT ? program1.getMemory() : program2.getMemory();
		}

		@Override
		public Address getAddress(Side side, Address otherSideAddress) {
			if (side == LEFT) {
				long offset = otherSideAddress.getOffset() - PROGRAM2_BASE;
				return addr(program1, PROGRAM1_BASE + offset);
			}
			long offset = otherSideAddress.getOffset() - PROGRAM1_BASE;
			return addr(program2, PROGRAM2_BASE + offset);

		}

	}
}
