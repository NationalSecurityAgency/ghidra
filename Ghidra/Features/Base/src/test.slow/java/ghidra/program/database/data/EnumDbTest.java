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
package ghidra.program.database.data;

import static org.junit.Assert.*;

import org.junit.*;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.EnumDataType;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;

/**
 * Tests for Enum data types.
 */
public class EnumDbTest extends AbstractGhidraHeadedIntegrationTest {

	private ProgramDB program;
	private DataTypeManagerDB dataMgr;
	private int transactionID;
	private Enum enum1;
	private Enum enum2;
	private Enum enum4;
	private Enum enum8;

	@Before
	public void setUp() throws Exception {
		program = createDefaultProgram("Test", ProgramBuilder._TOY, this);

		dataMgr = program.getDataTypeManager();
		transactionID = program.startTransaction("Test");
		enum1 = new EnumDataType("Test", 1);
		enum2 = new EnumDataType("Test", 2);
		enum4 = new EnumDataType("Test", 4);
		enum8 = new EnumDataType("Test", 8);

		enum1 = (Enum) dataMgr.resolve(enum1, null);
		enum2 = (Enum) dataMgr.resolve(enum2, null);
		enum4 = (Enum) dataMgr.resolve(enum4, null);
		enum8 = (Enum) dataMgr.resolve(enum8, null);
	}

	@After
	public void tearDown() throws Exception {
		program.endTransaction(transactionID, false);
		program.release(this);
	}

	@Test
	public void testCanAddHighUnsignedValue() {
		enum1.add("a", 0xff);
		assertEquals(0xff, enum1.getValue("a"));
	}

	@Test
	public void testCanAddNegativeValue() {
		enum1.add("a", -1);
		assertEquals(-1, enum1.getValue("a"));
	}

	@Test
	public void testCantAddNegativeAndHighUnsignedValue() {
		enum1.add("a", -1);
		try {
			enum1.add("b", 0xff);
			fail("Expected Illegal ArgumentException");
		}
		catch (IllegalArgumentException e) {
			// expected
		}
	}

	@Test
	public void testCantAddHighUnsignedAndNegativeValue() {
		enum1.add("a", 0xff);
		try {
			enum1.add("b", -1);
			fail("Expected Illegal ArgumentException");
		}
		catch (IllegalArgumentException e) {
			// expected
		}
	}

	@Test
	public void testCanAddNegativeAfterAddingThenRemovingHighUnsignedValue() {
		enum1.add("a", 0xff);
		enum1.remove("a");
		enum1.add("a", -1);
		assertEquals(-1, enum1.getValue("a"));
	}

	@Test
	public void testGetMinPossibleWidthUnsigned() {
		assertEquals(1, enum4.getMinimumPossibleLength());

		enum4.add("a", 0);
		assertEquals(1, enum4.getMinimumPossibleLength());

		enum4.add("b", 0xff);
		assertEquals(1, enum4.getMinimumPossibleLength());

		enum4.add("c", 0x100);
		assertEquals(2, enum4.getMinimumPossibleLength());

		enum4.add("d", 0xffff);
		assertEquals(2, enum4.getMinimumPossibleLength());

		enum4.add("e", 0x1ffff);
		assertEquals(4, enum4.getMinimumPossibleLength());

		enum4.add("f", 0xffffffffL);
		assertEquals(4, enum4.getMinimumPossibleLength());

	}

	@Test
	public void testGetMinPossibleWidthSigned() {
		assertEquals(1, enum4.getMinimumPossibleLength());

		enum4.add("a", 0);
		assertEquals(1, enum4.getMinimumPossibleLength());

		enum4.add("b", -0x1);
		assertEquals(1, enum4.getMinimumPossibleLength());

		enum4.add("c", 0xff);
		assertEquals(2, enum4.getMinimumPossibleLength());

		enum4.add("d", 0xffff);
		assertEquals(4, enum4.getMinimumPossibleLength());

		enum4.add("e", 0x1ffff);
		assertEquals(4, enum4.getMinimumPossibleLength());

	}

	@Test
	public void testGetMinPossibleWidthSignedWithBigNegatives() {
		assertEquals(1, enum4.getMinimumPossibleLength());

		enum4.add("a", 0);
		assertEquals(1, enum4.getMinimumPossibleLength());

		enum4.add("b", -0x1);
		assertEquals(1, enum4.getMinimumPossibleLength());

		enum4.add("c", -0xff);
		assertEquals(2, enum4.getMinimumPossibleLength());

		enum4.add("d", -0xffff);
		assertEquals(4, enum4.getMinimumPossibleLength());

		enum4.add("e", -0x1ffff);
		assertEquals(4, enum4.getMinimumPossibleLength());

	}

	@Test
	public void testMinMaxPossibleValuesNoSignednessSize1() {
		assertEquals(-0x80, enum1.getMinPossibleValue());
		assertEquals(0xff, enum1.getMaxPossibleValue());
	}

	@Test
	public void testMinMaxPossibleValuesNoSignednessSize2() {
		assertEquals(-0x8000, enum2.getMinPossibleValue());
		assertEquals(0xffff, enum2.getMaxPossibleValue());
	}

	@Test
	public void testMinMaxPossibleValuesNoSignednessSize4() {
		assertEquals(-0x80000000L, enum4.getMinPossibleValue());
		assertEquals(0xffffffffL, enum4.getMaxPossibleValue());
	}

	@Test
	public void testMinMaxPossibleValuesNoSignednessSize8() {
		assertEquals(Long.MIN_VALUE, enum8.getMinPossibleValue());
		assertEquals(Long.MAX_VALUE, enum8.getMaxPossibleValue());
	}

	public void testMinMaxPossibleValuesSignedSize1() {
		enum1.add("a", -1);	// this makes it an signed enum
		assertEquals(-0x80, enum1.getMinPossibleValue());
		assertEquals(0x7f, enum1.getMaxPossibleValue());
	}

	@Test
	public void testMinMaxPossibleValuesSignedSize2() {
		enum2.add("a", -1);	// this makes it an signed enum
		assertEquals(-0x8000, enum2.getMinPossibleValue());
		assertEquals(0x7fff, enum2.getMaxPossibleValue());
	}

	@Test
	public void testMinMaxPossibleValuesSignedSize4() {
		enum4.add("a", -1);	// this makes it an signed enum
		assertEquals(-0x80000000L, enum4.getMinPossibleValue());
		assertEquals(0x7fffffffL, enum4.getMaxPossibleValue());
	}

	@Test
	public void testMinMaxPossibleValuesSignedSize8() {
		enum8.add("a", -1);	// this makes it an signed enum
		assertEquals(Long.MIN_VALUE, enum8.getMinPossibleValue());
		assertEquals(Long.MAX_VALUE, enum8.getMaxPossibleValue());
	}

	public void testMinMaxPossibleValuesUnsignedSize1() {
		enum1.add("a", 0xff);	// this makes it an unsigned enum
		assertEquals(0, enum1.getMinPossibleValue());
		assertEquals(0xff, enum1.getMaxPossibleValue());
	}

	@Test
	public void testMinMaxPossibleValuesUnsignedSize2() {
		enum2.add("a", 0xffff);	// this makes it an signed enum
		assertEquals(0, enum2.getMinPossibleValue());
		assertEquals(0xffff, enum2.getMaxPossibleValue());
	}

	@Test
	public void testMinMaxPossibleValuesUnsignedSize4() {
		enum4.add("a", 0xffffffffL);	// this makes it an signed enum
		assertEquals(0, enum4.getMinPossibleValue());
		assertEquals(0xffffffffL, enum4.getMaxPossibleValue());
	}

	@Test
	public void testContainsName() {
		enum4.add("a", 0x1);
		enum4.add("b", -1);
		assertTrue(enum4.contains("a"));
		assertTrue(enum4.contains("b"));
		assertFalse(enum4.contains("c"));
	}

	@Test
	public void testContainsValue() {
		enum4.add("a", 0x1);
		enum4.add("b", -1);
		assertTrue(enum4.contains(-1));
		assertTrue(enum4.contains(1));
		assertFalse(enum4.contains(3));
	}

	@Test
	public void testGetMinPossibleLengthFor8ByteEnum() {
		enum8.add("a", -1);
		assertEquals(1, enum8.getMinimumPossibleLength());
	}

	@Test
	public void test8ByteEnumsAreSigned() {
		enum8.add("a", 0);
		assertEquals(Long.MIN_VALUE, enum8.getMinPossibleValue());
		assertEquals(Long.MAX_VALUE, enum8.getMaxPossibleValue());
		assertFalse(enum8.isSigned());
		enum8.add("b", -1);
		assertTrue(enum8.isSigned());
	}
}
