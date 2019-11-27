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
package ghidra.program.model.data;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.*;

import generic.test.AbstractGTest;
import ghidra.program.model.ProgramTestDouble;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;

public class DataUtilitiesTest extends AbstractGTest {

	private Program program;
	private AddressSpace space;
	private AddressFactory addressFactory;
	private MyListing listing;
	private MyMemory memory;

	public DataUtilitiesTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		space = new GenericAddressSpace("Test1", 16, AddressSpace.TYPE_RAM, 0);
		addressFactory = new DefaultAddressFactory(new AddressSpace[] { space }, space);
		program = createProgram();
		listing = new MyListing();
		memory = new MyMemory();
	}

	/**
	 * Memory: 0x00 - 0xff
	 * 
	 * 00 ??
	 * .
	 * .
	 * .
	 * e7 ??
	 * e8 ??
	 * e9 ??
	 * ea ??
	 * eb Undefined4
	 * ef ??
	 * f0 ??
	 * f1 JZ LABEL
	 * f3 ??
	 * f4 Undefined2
	 * f6 ??
	 * f7 float
	 * fb ??
	 * fc Undefined4
	 */

	@Test
	public void testUndefinedRange1() { // undefineds
		assertTrue(DataUtilities.isUndefinedRange(program, addr(0xe7), addr(0xe8)));
	}

	@Test
	public void testUndefinedRange2() { // undefineds and Undefined4
		assertTrue(DataUtilities.isUndefinedRange(program, addr(0xe7), addr(0xeb)));
	}

	@Test
	public void testUndefinedRange3() { // undefineds and Undefined4
		assertTrue(DataUtilities.isUndefinedRange(program, addr(0xe7), addr(0xec)));
	}

	@Test
	public void testUndefinedRange4() { // undefineds and Undefined4
		assertTrue(DataUtilities.isUndefinedRange(program, addr(0xe7), addr(0xee)));
	}

	@Test
	public void testUndefinedRange5() { // undefineds and Undefined4 and undefineds
		assertTrue(DataUtilities.isUndefinedRange(program, addr(0xe7), addr(0xf0)));
	}

	@Test
	public void testUndefinedRange6() { // Undefined4
		assertTrue(DataUtilities.isUndefinedRange(program, addr(0xeb), addr(0xeb)));
	}

	@Test
	public void testUndefinedRange7() { // Undefined4 and undefineds
		assertTrue(DataUtilities.isUndefinedRange(program, addr(0xeb), addr(0xef)));
	}

	@Test
	public void testUndefinedRange8() { // undefineds and Undefined4 and JZ instruction
		assertFalse(DataUtilities.isUndefinedRange(program, addr(0xe7), addr(0xf1)));
	}

	@Test
	public void testUndefinedRange9() { // contains JZ instruction
		assertFalse(DataUtilities.isUndefinedRange(program, addr(0xe7), addr(0xf5)));
	}

	@Test
	public void testUndefinedRange10() { // JZ instruction
		assertFalse(DataUtilities.isUndefinedRange(program, addr(0xf1), addr(0xf1)));
	}

	@Test
	public void testUndefinedRange11() { // JZ instruction and undefined
		assertFalse(DataUtilities.isUndefinedRange(program, addr(0xf1), addr(0xf3)));
	}

	@Test
	public void testUndefinedRange12() { // JZ instruction and undefined
		assertFalse(DataUtilities.isUndefinedRange(program, addr(0xf2), addr(0xf3)));
	}

	@Test
	public void testUndefinedRange13() { // undefined and float
		assertFalse(DataUtilities.isUndefinedRange(program, addr(0xf6), addr(0xf7)));
	}

	@Test
	public void testUndefinedRange14() { // undefined and Undefined2
		assertTrue(DataUtilities.isUndefinedRange(program, addr(0xf3), addr(0xf6)));
	}

	@Test
	public void testUndefinedRange15() { // float
		assertFalse(DataUtilities.isUndefinedRange(program, addr(0xf7), addr(0xfa)));
	}

	@Test
	public void testUndefinedRange16() { // overlaps float
		assertFalse(DataUtilities.isUndefinedRange(program, addr(0xf8), addr(0xff)));
	}

	@Test
	public void testUndefinedRange17() { // undefined and Undefined4
		assertTrue(DataUtilities.isUndefinedRange(program, addr(0xfb), addr(0xff)));
	}

	@Test
	public void testUndefinedRange18() { // Undefined4
		assertTrue(DataUtilities.isUndefinedRange(program, addr(0xfc), addr(0xff)));
	}

	@Test
	public void testUndefinedRange19() { // start > end
		assertFalse(DataUtilities.isUndefinedRange(program, addr(0xe9), addr(0xe8)));
	}

	@Test
	public void testUndefinedRange20() { // start == end
		assertTrue(DataUtilities.isUndefinedRange(program, addr(0xe9), addr(0xe9)));
	}

	@Test
	public void testUndefinedRange21() throws Exception { // from one block into another
		assertFalse(DataUtilities.isUndefinedRange(program, addr(0xfe), addr(0x100)));
	}

	@Test
	public void testUndefinedRange22() throws Exception { // off the back end of a block
		assertFalse(DataUtilities.isUndefinedRange(program, addr(0x10d), addr(0x200)));
	}

	@Test
	public void testUndefinedRange23() throws Exception { // off the front end of a block
		assertFalse(DataUtilities.isUndefinedRange(program, addr(0x20d), addr(0x300)));
	}

	@Test
	public void testUndefinedRange24() throws Exception { // from one block into another with gap
		assertFalse(DataUtilities.isUndefinedRange(program, addr(0x10d), addr(0x300)));
	}

	@Test
	public void testUndefinedRange25() throws Exception { // in non-defined block
		assertFalse(DataUtilities.isUndefinedRange(program, addr(0x209), addr(0x20c)));
	}

	@Test
	public void testMaxUndefined1() { // undefineds and Undefined4
		Assert.assertEquals(addr(0xf0),
			DataUtilities.getMaxAddressOfUndefinedRange(program, addr(0xe7)));
	}

	@Test
	public void testMaxUndefined2() { // JZ LABEL
		Assert.assertEquals(null, DataUtilities.getMaxAddressOfUndefinedRange(program, addr(0xf1)));
	}

	@Test
	public void testMaxUndefined3() { // JZ LABEL
		Assert.assertEquals(null, DataUtilities.getMaxAddressOfUndefinedRange(program, addr(0xf2)));
	}

	@Test
	public void testMaxUndefined4() { // float
		Assert.assertEquals(null, DataUtilities.getMaxAddressOfUndefinedRange(program, addr(0xf7)));
	}

	@Test
	public void testMaxUndefined5() { // float
		Assert.assertEquals(null, DataUtilities.getMaxAddressOfUndefinedRange(program, addr(0xf9)));
	}

	@Test
	public void testMaxUndefined6() { // Undefined4
		Assert.assertEquals(addr(0xff),
			DataUtilities.getMaxAddressOfUndefinedRange(program, addr(0xfc)));
	}

	@Test
	public void testMaxUndefined7() { // Undefined4
		Assert.assertEquals(addr(0xff),
			DataUtilities.getMaxAddressOfUndefinedRange(program, addr(0xfd)));
	}

	@Test
	public void testMaxUndefined8() { // undefineds and Undefined2
		Assert.assertEquals(addr(0xf6),
			DataUtilities.getMaxAddressOfUndefinedRange(program, addr(0xf3)));
	}

	@Test
	public void testMaxUndefined9() { // Undefined4 and undefineds
		Assert.assertEquals(addr(0xf0),
			DataUtilities.getMaxAddressOfUndefinedRange(program, addr(0xed)));
	}

	//================================================================

	private Program createProgram() {
		return new ProgramTestDouble() {

			@Override
			public AddressFactory getAddressFactory() {
				return addressFactory;
			}

			@Override
			public Listing getListing() {
				return listing;
			}

			@Override
			public Memory getMemory() {
				return memory;
			}
		};
	}

	private class MyMemory extends MemoryStub {

		@Override
		public MemoryBlock getBlock(Address addr) {
			return new MyMemoryBlock(addr);
		}

	}

	private class MyMemoryBlock extends MemoryBlockStub {

		Address address;

		MyMemoryBlock(Address addr) {
			address = addr;
		}

		@Override
		public Address getStart() {
			long offset = address.getOffset();
			if (offset >= 0x0 && offset <= 0xff) {
				return addr(0x0);
			}
			else if (offset >= 0x100 && offset <= 0x1ff) {
				return addr(0x100);
			}
			else if (offset >= 0x300 && offset <= 0x3ff) {
				return addr(0x300);
			}
			return null;
		}

		@Override
		public Address getEnd() {
			long offset = address.getOffset();
			if (offset >= 0x0 && offset <= 0xff) {
				return addr(0xff);
			}
			else if (offset >= 0x100 && offset <= 0x1ff) {
				return addr(0x1ff);
			}
			else if (offset >= 0x300 && offset <= 0x3ff) {
				return addr(0x3ff);
			}
			return null;
		}

		@Override
		public boolean contains(Address addr) {
			long addressOffset = address.getOffset();
			long addrOffset = addr.getOffset();
			if ((addressOffset >= 0x0 && addressOffset <= 0xff) &&
				(addrOffset >= 0x0 && addrOffset <= 0xff)) {
				return true;
			}
			else if ((addressOffset >= 0x100 && addressOffset <= 0x1ff) &&
				(addrOffset >= 0x100 && addrOffset <= 0x1ff)) {
				return true;
			}
			else if ((addressOffset >= 0x300 && addressOffset <= 0x3ff) &&
				(addrOffset >= 0x300 && addrOffset <= 0x3ff)) {
				return true;
			}
			return false;
		}
	}

	private class MyListing extends ListingStub {

		@Override
		public Data getDataContaining(Address address) {
			long offset = address.getOffset();
			if (offset < 0x0 || offset > 0xff || offset == 0xf1 || offset == 0xf2) {
				return null; // outside our test memory or at instruction.
			}
			return new MyData(address);
		}

		@Override
		public Data getDataAt(Address addr) {

			long offset = addr.getOffset();
			if (offset > 0xff) { // outside our test memory.
				return null;
			}
			else if (offset == 0xec || offset == 0xed || offset == 0xee || offset == 0xf1 ||
				offset == 0xf2 || offset == 0xf5 || offset == 0xf8 || offset == 0xf9 ||
				offset == 0xfa || offset == 0xfd || offset == 0xfe || offset == 0xff) {
				return null; // These are not minimum address of any data.
			}
			// The rest are starts of defined or undefined data.
			return new MyData(addr);
		}

		@Override
		public CodeUnit getDefinedCodeUnitAfter(Address addr) {
			long offset = addr.getOffset();
			if (offset > 0x0 && offset <= 0xeb) {
				return new MyData(addr(0xeb));
			}
			else if (offset > 0xeb && offset <= 0xf1) {
				return new MyInstruction(addr(0xf1));
			}
			else if (offset > 0xf1 && offset <= 0xf4) {
				return new MyData(addr(0xf4));
			}
			else if (offset > 0xf4 && offset <= 0xf7) {
				return new MyData(addr(0xf7));
			}
			else if (offset > 0xf7 && offset <= 0xfc) {
				return new MyData(addr(0xfc));
			}
			return null;
		}

		@Override
		public CodeUnit getDefinedCodeUnitBefore(Address addr) {
			long offset = addr.getOffset();
			if (offset > 0xeb && offset <= 0xf1) {
				return new MyData(addr(0xeb));
			}
			else if (offset > 0xf1 && offset <= 0xf4) {
				return new MyInstruction(addr(0xf1));
			}
			else if (offset > 0xf4 && offset <= 0xf7) {
				return new MyData(addr(0xf4));
			}
			else if (offset > 0xf7 && offset <= 0xfc) {
				return new MyData(addr(0xf7));
			}
			else if (offset > 0xfc && offset <= 0xff) {
				return new MyData(addr(0xfc));
			}
			return null;
		}

	}

	private class MyInstruction extends InstructionStub {

		Address address;

		MyInstruction(Address addr) {
			address = addr;
		}

		@Override
		public Address getAddress() {
			return getMinAddress();
		}

		@Override
		public Address getMinAddress() {
			long offset = address.getOffset();
			if (offset == 0xf1 || offset == 0xf2) {
				return addr(0xf1);
			}
			return null;
		}

		@Override
		public Address getMaxAddress() {
			long offset = address.getOffset();
			if (offset == 0xf1 || offset == 0xf2) {
				return addr(0xf2);
			}
			return null;
		}
	}

	private class MyData extends DataStub {

		Address address;

		MyData(Address addr) {
			address = addr;
		}

		@Override
		public Address getAddress() {
			return getMinAddress();
		}

		@Override
		public Address getMinAddress() {
			long offset = address.getOffset();
			if (offset > 0xff) {
				return null;
			}
			else if (offset >= 0xeb && offset <= 0xee) {
				return addr(0xeb); // Undefined4
			}
			else if (offset >= 0xf1 && offset <= 0xf2) {
				return null; // JZ LABEL
			}
			else if (offset >= 0xf4 && offset <= 0xf5) {
				return addr(0xf4); // Undefined2
			}
			else if (offset >= 0xf7 && offset <= 0xfa) {
				return addr(0xf7); // float
			}
			else if (offset >= 0xfc && offset <= 0xff) {
				return addr(0xfc); // Undefined4
			}
			else {
				return address;
			}
		}

		@Override
		public Address getMaxAddress() {
			long offset = address.getOffset();
			if (offset > 0xff) {
				return null;
			}
			else if (offset >= 0xeb && offset <= 0xee) {
				return addr(0xee); // Undefined4
			}
			else if (offset >= 0xf1 && offset <= 0xf2) {
				return null; // JZ LABEL
			}
			else if (offset >= 0xf4 && offset <= 0xf5) {
				return addr(0xf5); // Undefined2
			}
			else if (offset >= 0xf7 && offset <= 0xfa) {
				return addr(0xfa); // float
			}
			else if (offset >= 0xfc && offset <= 0xff) {
				return addr(0xff); // Undefined4
			}
			else {
				return address;
			}
		}

		@Override
		public DataType getDataType() {
			long offset = address.getOffset();
			if (offset > 0xff) {
				return null;
			}
			else if (offset >= 0xeb && offset <= 0xee) {
				return new Undefined4DataType();
			}
			else if (offset >= 0xf1 && offset <= 0xf2) {
				return null; // JZ LABEL
			}
			else if (offset >= 0xf4 && offset <= 0xf5) {
				return new Undefined2DataType();
			}
			else if (offset >= 0xf7 && offset <= 0xfa) {
				return new FloatDataType();
			}
			else if (offset >= 0xfc && offset <= 0xff) {
				return new Undefined4DataType();
			}
			else {
				return DataType.DEFAULT;
			}
		}
	}

	private Address addr(int offset) {
		return addressFactory.getDefaultAddressSpace().getAddress(offset);
	}
}
