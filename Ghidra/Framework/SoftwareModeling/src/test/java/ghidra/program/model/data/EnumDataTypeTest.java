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

import static org.junit.Assert.*;

import org.junit.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.util.BigEndianDataConverter;
import ghidra.util.UniversalIdGenerator;

public class EnumDataTypeTest {

	@Before
	public void setUp() {
		UniversalIdGenerator.initialize();
	}

	@Test
	public void testNegativeValue() {

		EnumDataType enumDt = new EnumDataType("Test", 4);
		enumDt.add("bob", 0xffffffffL);

		ByteMemBufferImpl memBuffer = new ByteMemBufferImpl(Address.NO_ADDRESS,
			BigEndianDataConverter.INSTANCE.getBytes(-1), true);

		Assert.assertEquals("bob", enumDt.getRepresentation(memBuffer, null, 0));

	}

	@Test
	public void testUpperBitLongValue() {

		EnumDataType enumDt = new EnumDataType("Test", 4);
		enumDt.add("bob", 0x80000000L);

		ByteMemBufferImpl memBuffer = new ByteMemBufferImpl(Address.NO_ADDRESS,
			BigEndianDataConverter.INSTANCE.getBytes(Integer.MIN_VALUE), true);

		Assert.assertEquals("bob", enumDt.getRepresentation(memBuffer, null, 0));
	}

	@Test
	public void testCanAddHighUnsignedValue() {
		EnumDataType enumDt = new EnumDataType("Test", 1);
		enumDt.add("a", 0xff);
		assertEquals(0xff, enumDt.getValue("a"));
	}

	@Test
	public void testCanAddNegativeValue() {
		EnumDataType enumDt = new EnumDataType("Test", 1);
		enumDt.add("a", -1);
		assertEquals(-1, enumDt.getValue("a"));
	}

	@Test
	public void testCantAddNegativeAndHighUnsignedValue() {
		EnumDataType enumDt = new EnumDataType("Test", 1);
		enumDt.add("a", -1);
		try {
			enumDt.add("b", 0xff);
			fail("Expected Illegal ArgumentException");
		}
		catch (IllegalArgumentException e) {
			// expected
		}
	}

	@Test
	public void testCantAddHighUnsignedAndNegativeValue() {
		EnumDataType enumDt = new EnumDataType("Test", 1);
		enumDt.add("a", 0xff);
		try {
			enumDt.add("b", -1);
			fail("Expected Illegal ArgumentException");
		}
		catch (IllegalArgumentException e) {
			// expected
		}
	}

	@Test
	public void testCanAddNegativeAfterAddingThenRemovingHighUnsignedValue() {
		EnumDataType enumDt = new EnumDataType("Test", 1);
		enumDt.add("a", 0xff);
		enumDt.remove("a");
		enumDt.add("a", -1);
		assertEquals(-1, enumDt.getValue("a"));
	}

	@Test
	public void testGetMinPossibleWidthUnsigned() {
		EnumDataType enumDt = new EnumDataType("Test", 4);
		assertEquals(1, enumDt.getMinimumPossibleLength());

		enumDt.add("a", 0);
		assertEquals(1, enumDt.getMinimumPossibleLength());

		enumDt.add("b", 0xff);
		assertEquals(1, enumDt.getMinimumPossibleLength());

		enumDt.add("c", 0x100);
		assertEquals(2, enumDt.getMinimumPossibleLength());

		enumDt.add("d", 0xffff);
		assertEquals(2, enumDt.getMinimumPossibleLength());

		enumDt.add("e", 0x1ffff);
		assertEquals(4, enumDt.getMinimumPossibleLength());

		enumDt.add("f", 0xffffffffL);
		assertEquals(4, enumDt.getMinimumPossibleLength());

	}

	@Test
	public void testGetMinPossibleLengthFor8ByteEnum() {
		EnumDataType enumDt = new EnumDataType("Test", 8);
		enumDt.add("a", -1);
		assertEquals(1, enumDt.getMinimumPossibleLength());

	}

	@Test
	public void test8ByteEnums() {
		EnumDataType enumDt = new EnumDataType("Test", 8);
		enumDt.add("a", 0);
		assertEquals(Long.MIN_VALUE, enumDt.getMinPossibleValue());
		assertEquals(Long.MAX_VALUE, enumDt.getMaxPossibleValue());
		assertFalse(enumDt.isSigned());
		enumDt.add("b", -1);
		assertTrue(enumDt.isSigned());
	}

	@Test
	public void testGetMinPossibleWidthSigned() {
		EnumDataType enumDt = new EnumDataType("Test", 4);
		assertEquals(1, enumDt.getMinimumPossibleLength());

		enumDt.add("a", 0);
		assertEquals(1, enumDt.getMinimumPossibleLength());

		enumDt.add("b", -0x1);
		assertEquals(1, enumDt.getMinimumPossibleLength());

		enumDt.add("c", 0xff);
		assertEquals(2, enumDt.getMinimumPossibleLength());

		enumDt.add("d", 0xffff);
		assertEquals(4, enumDt.getMinimumPossibleLength());

		enumDt.add("e", 0x1ffff);
		assertEquals(4, enumDt.getMinimumPossibleLength());

	}

	@Test
	public void testGetMinPossibleWidthSignedWithBigNegatives() {
		EnumDataType enumDt = new EnumDataType("Test", 4);
		assertEquals(1, enumDt.getMinimumPossibleLength());

		enumDt.add("a", 0);
		assertEquals(1, enumDt.getMinimumPossibleLength());

		enumDt.add("b", -0x1);
		assertEquals(1, enumDt.getMinimumPossibleLength());

		enumDt.add("c", -0xff);
		assertEquals(2, enumDt.getMinimumPossibleLength());

		enumDt.add("d", -0xffff);
		assertEquals(4, enumDt.getMinimumPossibleLength());

		enumDt.add("e", -0x1ffff);
		assertEquals(4, enumDt.getMinimumPossibleLength());

	}

	@Test
	public void testMinMaxPossibleValuesNoSignednessSize1() {
		EnumDataType enumDt = new EnumDataType("Test", 1);
		assertEquals(-0x80, enumDt.getMinPossibleValue());
		assertEquals(0xff, enumDt.getMaxPossibleValue());
	}

	@Test
	public void testMinMaxPossibleValuesNoSignednessSize2() {
		EnumDataType enumDt = new EnumDataType("Test", 2);
		assertEquals(-0x8000, enumDt.getMinPossibleValue());
		assertEquals(0xffff, enumDt.getMaxPossibleValue());
	}

	@Test
	public void testMinMaxPossibleValuesNoSignednessSize4() {
		EnumDataType enumDt = new EnumDataType("Test", 4);
		assertEquals(-0x80000000L, enumDt.getMinPossibleValue());
		assertEquals(0xffffffffL, enumDt.getMaxPossibleValue());
	}

	@Test
	public void testMinMaxPossibleValuesNoSignednessSize8() {
		EnumDataType enumDt = new EnumDataType("Test", 8);
		assertEquals(Long.MIN_VALUE, enumDt.getMinPossibleValue());
		assertEquals(Long.MAX_VALUE, enumDt.getMaxPossibleValue());
	}

	public void testMinMaxPossibleValuesSignedSize1() {
		EnumDataType enumDt = new EnumDataType("Test", 1);
		enumDt.add("a", -1);	// this makes it an signed enum
		assertEquals(-0x80, enumDt.getMinPossibleValue());
		assertEquals(0x7f, enumDt.getMaxPossibleValue());
	}

	@Test
	public void testMinMaxPossibleValuesSignedSize2() {
		EnumDataType enumDt = new EnumDataType("Test", 2);
		enumDt.add("a", -1);	// this makes it an signed enum
		assertEquals(-0x8000, enumDt.getMinPossibleValue());
		assertEquals(0x7fff, enumDt.getMaxPossibleValue());
	}

	@Test
	public void testMinMaxPossibleValuesSignedSize4() {
		EnumDataType enumDt = new EnumDataType("Test", 4);
		enumDt.add("a", -1);	// this makes it an signed enum
		assertEquals(-0x80000000L, enumDt.getMinPossibleValue());
		assertEquals(0x7fffffffL, enumDt.getMaxPossibleValue());
	}

	@Test
	public void testMinMaxPossibleValuesSignedSize8() {
		EnumDataType enumDt = new EnumDataType("Test", 8);
		enumDt.add("a", -1);	// this makes it an signed enum
		assertEquals(Long.MIN_VALUE, enumDt.getMinPossibleValue());
		assertEquals(Long.MAX_VALUE, enumDt.getMaxPossibleValue());
	}

	public void testMinMaxPossibleValuesUnsignedSize1() {
		EnumDataType enumDt = new EnumDataType("Test", 1);
		enumDt.add("a", 0xff);	// this makes it an unsigned enum
		assertEquals(0, enumDt.getMinPossibleValue());
		assertEquals(0xff, enumDt.getMaxPossibleValue());
	}

	@Test
	public void testMinMaxPossibleValuesUnsignedSize2() {
		EnumDataType enumDt = new EnumDataType("Test", 2);
		enumDt.add("a", 0xffff);	// this makes it an signed enum
		assertEquals(0, enumDt.getMinPossibleValue());
		assertEquals(0xffff, enumDt.getMaxPossibleValue());
	}

	@Test
	public void testMinMaxPossibleValuesUnsignedSize4() {
		EnumDataType enumDt = new EnumDataType("Test", 4);
		enumDt.add("a", 0xffffffffL);	// this makes it an signed enum
		assertEquals(0, enumDt.getMinPossibleValue());
		assertEquals(0xffffffffL, enumDt.getMaxPossibleValue());
	}

	@Test
	public void testContainsName() {
		EnumDataType enumDt = new EnumDataType("Test", 4);
		enumDt.add("a", 0x1);
		enumDt.add("b", -1);
		assertTrue(enumDt.contains("a"));
		assertTrue(enumDt.contains("b"));
		assertFalse(enumDt.contains("c"));
	}

	@Test
	public void testContainsValue() {
		EnumDataType enumDt = new EnumDataType("Test", 4);
		enumDt.add("a", 0x1);
		enumDt.add("b", -1);
		assertTrue(enumDt.contains(-1));
		assertTrue(enumDt.contains(1));
		assertFalse(enumDt.contains(3));
	}
}
