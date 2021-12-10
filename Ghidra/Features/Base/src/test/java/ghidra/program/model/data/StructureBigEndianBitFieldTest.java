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

import org.junit.Test;

public class StructureBigEndianBitFieldTest extends AbstractCompositeBitFieldTest {

	// NOTE: verified bitfields sample built with mips-elf-gcc (GCC) 4.9.2

	private static DataTypeManager dataMgr;

	@Override
	protected DataTypeManager getDataTypeManager() {
		synchronized (StructureBigEndianBitFieldTest.class) {
			if (dataMgr == null) {
				DataOrganizationImpl dataOrg = DataOrganizationImpl.getDefaultOrganization(null);
				DataOrganizationTestUtils.initDataOrganization32BitMips(dataOrg);
				dataMgr = createDataTypeManager("test", dataOrg);
			}
			return dataMgr;
		}
	}

	@Test
	public void testStructureBitFieldsA1() {
		Structure struct = getStructure("A1");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/A1\n" + 
			"pack()\n" + 
			"Structure A1 {\n" + 
			"   0   char[5]   5   a   \"\"\n" + 
			"   5   int:3(5)   1   b   \"\"\n" + 
			"   5   int:8(5)   2   c   \"\"\n" + 
			"   6   int:8(5)   2   d   \"\"\n" + 
			"   8   int:6(2)   1   e   \"\"\n" + 
			"}\n" + 
			"Size = 12   Actual Alignment = 4", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFieldsA2() {
		Structure struct = getStructure("A2");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/A2\n" + 
			"pack()\n" + 
			"Structure A2 {\n" + 
			"   0   oddStruct   5   a   \"\"\n" + 
			"   5   int:3(5)   1   b   \"\"\n" + 
			"   5   int:8(5)   2   c   \"\"\n" + 
			"   6   int:8(5)   2   d   \"\"\n" + 
			"   8   int:6(2)   1   e   \"\"\n" + 
			"}\n" + 
			"Size = 12   Actual Alignment = 4", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFieldsA3() {
		Structure struct = getStructure("A3");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/A3\n" + 
			"pack()\n" + 
			"Structure A3 {\n" + 
			"   0   char[5]   5   a   \"\"\n" + 
			"   5   int:3(5)   1   b   \"\"\n" + 
			"   5   int:8(5)   2   c   \"\"\n" + 
			"   8   int:85(0)   4   d   \"\"\n" + 
			"   12   int:6(2)   1   e   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 4\n", struct);
		//@formatter:on
		DataTypeComponent c = struct.getComponent(3);
		assertTrue(c.isBitFieldComponent());
		BitFieldDataType bfDt = (BitFieldDataType) c.getDataType();
		assertEquals(4, bfDt.getBaseTypeSize());
		assertEquals(32, bfDt.getBitSize());
		assertEquals(85, bfDt.getDeclaredBitSize());
	}

	@Test
	public void testStructureBitFieldsB1() {
		Structure struct = getStructure("B1");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/B1\n" + 
			"pack()\n" + 
			"Structure B1 {\n" + 
			"   0   char   1   a   \"\"\n" + 
			"   1   ushort:6(2)   1   b   \"\"\n" + 
			"   1   int:8(2)   2   c   \"\"\n" + 
			"   2   short:4(6)   2   d   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFieldsB1Flex() {
		Structure struct = getStructure("B1flex");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/B1flex\n" + 
			"pack()\n" + 
			"Structure B1flex {\n" + 
			"   0   char   1   a   \"\"\n" + 
			"   1   ushort:6(2)   1   b   \"\"\n" + 
			"   1   int:8(2)   2   c   \"\"\n" + 
			"   2   short:4(6)   2   d   \"\"\n" + 
			"   4   long[0]   0   flex   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFieldsB2() {
		Structure struct = getStructure("B2");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/B2\n" + 
			"pack()\n" + 
			"Structure B2 {\n" + 
			"   0   char   1   a   \"\"\n" + 
			"   1   ushort:6(2)   1   b   \"\"\n" + 
			"   1   int:8(2)   2   c   \"\"\n" + 
			"   2   int:4(6)   2   d   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFieldsB3() {
		Structure struct = getStructure("B3");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/B3\n" + 
			"pack()\n" + 
			"Structure B3 {\n" + 
			"   0   char   1   a   \"\"\n" + 
			"   1   ushort:6(2)   1   b   \"\"\n" + 
			"   1   int:8(2)   2   c   \"\"\n" + 
			"   3   char   1   d   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFieldsZ1() {
		Structure struct = getStructure("Z1");

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Z1\n" + 
			"pack()\n" + 
			"Structure Z1 {\n" + 
			"   0   char   1   a   \"\"\n" + 
			"   4   int:0(7)   0      \"\"\n" + 
			"   4   ushort:6(2)   1   b   \"\"\n" + 
			"   4   int:8(2)   2   c   \"\"\n" + 
			"   6   short:4(4)   1   d   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFieldsZ2() {
		Structure struct = getStructure("Z2");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Z2\n" + 
			"pack()\n" + 
			"Structure Z2 {\n" + 
			"   0   char   1   a   \"\"\n" + 
			"   1   ushort:6(2)   1   b   \"\"\n" + 
			"   1   int:8(2)   2   c   \"\"\n" + 
			"   4   int:0(7)   0      \"\"\n" + 
			"   4   short:4(4)   1   d   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFieldsZ3() {
		Structure struct = getStructure("Z3");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Z3\n" + 
			"pack()\n" + 
			"Structure Z3 {\n" + 
			"   0   char   1   a   \"\"\n" + 
			"   1   ushort:6(2)   1   b   \"\"\n" + 
			"   1   int:8(2)   2   c   \"\"\n" + 
			"   2   int:4(6)   2   d   \"\"\n" + 
			"   8   longlong:0(7)   0      \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 8", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFieldsZ4() {
		Structure struct = getStructure("Z4");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Z4\n" + 
			"pack()\n" + 
			"Structure Z4 {\n" + 
			"   0   char   1   a   \"\"\n" + 
			"   1   ushort:6(2)   1   b   \"\"\n" + 
			"   1   int:8(2)   2   c   \"\"\n" + 
			"   8   longlong:0(7)   0      \"\"\n" + 
			"   8   char   1   d   \"\"\n" + 
			"}\n" + 
			"Size = 12   Actual Alignment = 4", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFieldsZ5() {
		Structure struct = getStructure("Z5");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Z5\n" + 
			"pack()\n" + 
			"Structure Z5 {\n" + 
			"   0   char   1   a   \"\"\n" + 
			"   4   int:0(7)   0      \"\"\n" + 
			"   4   longlong:6(2)   1   b   \"\"\n" + 
			"   4   int:8(2)   2   c   \"\"\n" + 
			"   6   char   1   d   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 8", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFieldsZ6() {
		Structure struct = getStructure("Z6");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Z6\n" + 
			"pack()\n" + 
			"Structure Z6 {\n" + 
			"   0   char   1   a   \"\"\n" + 
			"   4   int:0(7)   0      \"\"\n" + 
			"   4   longlong:6(2)   1   b   \"\"\n" + 
			"   4   int:8(2)   2   c   \"\"\n" + 
			"   6   char   1   d   \"\"\n" + 
			"   7   longlong:6(2)   1   e   \"\"\n" + 
			"   8   int:8(0)   1   f   \"\"\n" + 
			"   9   char   1   g   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFieldsB1p1() {
		Structure struct = getStructure("B1p1");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/B1p1\n" + 
			"pack(1)\n" + 
			"Structure B1p1 {\n" + 
			"   0   char   1   a   \"\"\n" + 
			"   1   ushort:6(2)   1   b   \"\"\n" + 
			"   1   int:8(2)   2   c   \"\"\n" + 
			"   2   short:4(6)   2   d   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 1", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFieldsB2p1() {
		Structure struct = getStructure("B2p1");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/B2p1\n" + 
			"pack(1)\n" + 
			"Structure B2p1 {\n" + 
			"   0   char   1   a   \"\"\n" + 
			"   1   ushort:6(2)   1   b   \"\"\n" + 
			"   1   int:8(2)   2   c   \"\"\n" + 
			"   2   int:4(6)   2   d   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 1", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFieldsB3p1() {
		Structure struct = getStructure("B3p1");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/B3p1\n" + 
			"pack(1)\n" + 
			"Structure B3p1 {\n" + 
			"   0   char   1   a   \"\"\n" + 
			"   1   ushort:6(2)   1   b   \"\"\n" + 
			"   1   int:8(2)   2   c   \"\"\n" + 
			"   3   char   1   d   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 1", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFieldsZ1p1() {
		Structure struct = getStructure("Z1p1");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Z1p1\n" + 
			"pack(1)\n" + 
			"Structure Z1p1 {\n" + 
			"   0   char   1   a   \"\"\n" + 
			"   4   int:0(7)   0      \"\"\n" + 
			"   4   ushort:6(2)   1   b   \"\"\n" + 
			"   4   int:8(2)   2   c   \"\"\n" + 
			"   5   short:4(6)   2   d   \"\"\n" + 
			"}\n" + 
			"Size = 7   Actual Alignment = 1", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFieldsZ2p1() {
		Structure struct = getStructure("Z2p1");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Z2p1\n" + 
			"pack(1)\n" + 
			"Structure Z2p1 {\n" + 
			"   0   char   1   a   \"\"\n" + 
			"   1   ushort:6(2)   1   b   \"\"\n" + 
			"   1   int:8(2)   2   c   \"\"\n" + 
			"   4   int:0(7)   0      \"\"\n" + 
			"   4   short:4(4)   1   d   \"\"\n" + 
			"}\n" + 
			"Size = 5   Actual Alignment = 1", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFieldsZ3p1() {
		Structure struct = getStructure("Z3p1");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Z3p1\n" + 
			"pack(1)\n" + 
			"Structure Z3p1 {\n" + 
			"   0   char   1   a   \"\"\n" + 
			"   1   ushort:6(2)   1   b   \"\"\n" + 
			"   1   int:8(2)   2   c   \"\"\n" + 
			"   2   int:4(6)   2   d   \"\"\n" + 
			"   8   longlong:0(7)   0      \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 1", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFieldsZ3p1T() {
		Structure struct = getStructure("Z3p1T");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Z3p1T\n" + 
			"pack()\n" + 
			"Structure Z3p1T {\n" + 
			"   0   char   1   a   \"\"\n" + 
			"   1   Z3p1   8   z3p1   \"\"\n" + 
			"}\n" + 
			"Size = 9   Actual Alignment = 1", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFieldsZ4p1() {
		Structure struct = getStructure("Z4p1");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Z4p1\n" + 
			"pack(1)\n" + 
			"Structure Z4p1 {\n" + 
			"   0   char   1   a   \"\"\n" + 
			"   1   ushort:6(2)   1   b   \"\"\n" + 
			"   1   int:8(2)   2   c   \"\"\n" + 
			"   8   longlong:0(7)   0      \"\"\n" + 
			"   8   char   1   d   \"\"\n" + 
			"}\n" + 
			"Size = 9   Actual Alignment = 1", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFieldsB1p2() {
		Structure struct = getStructure("B1p2");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/B1p2\n" + 
			"pack(2)\n" + 
			"Structure B1p2 {\n" + 
			"   0   char   1   a   \"\"\n" + 
			"   1   ushort:6(2)   1   b   \"\"\n" + 
			"   1   int:8(2)   2   c   \"\"\n" + 
			"   2   short:4(6)   2   d   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 2", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFieldsB2p2() {
		Structure struct = getStructure("B2p2");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/B2p2\n" + 
			"pack(2)\n" + 
			"Structure B2p2 {\n" + 
			"   0   char   1   a   \"\"\n" + 
			"   1   ushort:6(2)   1   b   \"\"\n" + 
			"   1   int:8(2)   2   c   \"\"\n" + 
			"   2   int:4(6)   2   d   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 2", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFieldsB3p2() {
		Structure struct = getStructure("B3p2");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/B3p2\n" + 
			"pack(2)\n" + 
			"Structure B3p2 {\n" + 
			"   0   char   1   a   \"\"\n" + 
			"   1   ushort:6(2)   1   b   \"\"\n" + 
			"   1   int:8(2)   2   c   \"\"\n" + 
			"   3   char   1   d   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 2", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFieldsB4p2() {
		Structure struct = getStructure("B4p2");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/B4p2\n" + 
			"pack(2)\n" + 
			"Structure B4p2 {\n" + 
			"   0   char   1   a   \"\"\n" + 
			"   1   ushort:6(2)   1   b   \"\"\n" + 
			"   1   int:8(2)   2   c   \"\"\n" + 
			"   4   longlong   8   d   \"\"\n" + 
			"   12   int:4(4)   1   e   \"\"\n" + 
			"}\n" + 
			"Size = 14   Actual Alignment = 2", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFieldsZ1p2() {
		Structure struct = getStructure("Z1p2");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Z1p2\n" + 
			"pack(2)\n" + 
			"Structure Z1p2 {\n" + 
			"   0   char   1   a   \"\"\n" + 
			"   4   int:0(7)   0      \"\"\n" + 
			"   4   ushort:6(2)   1   b   \"\"\n" + 
			"   4   int:8(2)   2   c   \"\"\n" + 
			"   5   short:4(6)   2   d   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 2", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFieldsZ1p2x() {
		Structure struct = getStructure("Z1p2x");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Z1p2x\n" + 
			"pack(2)\n" + 
			"Structure Z1p2x {\n" + 
			"   0   char   1   a   \"\"\n" + 
			"   4   int:0(7)   0      \"\"\n" + 
			"   4   ushort:6(2)   1   b   \"\"\n" + 
			"   4   int:8(2)   2   c   \"\"\n" + 
			"   5   short:4(6)   2   d   \"\"\n" + 
			"   6   short:4(2)   1   d1   \"\"\n" + 
			"   6   short:4(6)   2   d2   \"\"\n" + 
			"   7   short:4(2)   1   d3   \"\"\n" + 
			"   7   short:4(6)   2   d4   \"\"\n" + 
			"   8   short:4(2)   1   d5   \"\"\n" + 
			"   8   short:4(6)   2   d6   \"\"\n" + 
			"   9   short:4(2)   1   d7   \"\"\n" + 
			"   10   short:0(7)   0      \"\"\n" + 
			"   10   ushort:6(2)   1   _b   \"\"\n" + 
			"   10   int:8(2)   2   _c   \"\"\n" + 
			"   11   short:4(6)   2   _d   \"\"\n" + 
			"   12   short:4(2)   1   _d1   \"\"\n" + 
			"   12   short:4(6)   2   _d2   \"\"\n" + 
			"   13   short:4(2)   1   _d3   \"\"\n" + 
			"   13   short:4(6)   2   _d4   \"\"\n" + 
			"   14   short:4(2)   1   _d5   \"\"\n" + 
			"   14   short:4(6)   2   _d6   \"\"\n" + 
			"   15   short:4(2)   1   _d7   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 2", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFieldsZ2p2() {
		Structure struct = getStructure("Z2p2");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Z2p2\n" + 
			"pack(2)\n" + 
			"Structure Z2p2 {\n" + 
			"   0   char   1   a   \"\"\n" + 
			"   1   ushort:6(2)   1   b   \"\"\n" + 
			"   1   int:8(2)   2   c   \"\"\n" + 
			"   4   int:0(7)   0      \"\"\n" + 
			"   4   short:4(4)   1   d   \"\"\n" + 
			"}\n" + 
			"Size = 6   Actual Alignment = 2", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFieldsZ3p2() {
		Structure struct = getStructure("Z3p2");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Z3p2\n" + 
			"pack(2)\n" + 
			"Structure Z3p2 {\n" + 
			"   0   char   1   a   \"\"\n" + 
			"   1   ushort:6(2)   1   b   \"\"\n" + 
			"   1   int:8(2)   2   c   \"\"\n" + 
			"   2   int:4(6)   2   d   \"\"\n" + 
			"   8   longlong:0(7)   0      \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 2", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFieldsZ4p2() {
		Structure struct = getStructure("Z4p2");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Z4p2\n" + 
			"pack(2)\n" + 
			"Structure Z4p2 {\n" + 
			"   0   char   1   a   \"\"\n" + 
			"   1   ushort:6(2)   1   b   \"\"\n" + 
			"   1   int:8(2)   2   c   \"\"\n" + 
			"   8   longlong:0(7)   0      \"\"\n" + 
			"   8   char   1   d   \"\"\n" + 
			"}\n" + 
			"Size = 10   Actual Alignment = 2", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFieldsZ5p2() {
		Structure struct = getStructure("Z5p2");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Z5p2\n" + 
			"pack(2)\n" + 
			"Structure Z5p2 {\n" + 
			"   0   char   1   a   \"\"\n" + 
			"   1   ushort:12(4)   2   b   \"\"\n" + 
			"   2   int:8(4)   2   c   \"\"\n" + 
			"   8   longlong:0(7)   0      \"\"\n" + 
			"   8   char   1   d   \"\"\n" + 
			"}\n" + 
			"Size = 10   Actual Alignment = 2", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFields_x1p2() {
		Structure struct = getStructure("x1p2");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/x1p2\n" + 
			"pack(2)\n" + 
			"Structure x1p2 {\n" + 
			"   0   char   1   a   \"\"\n" + 
			"}\n" + 
			"Size = 1   Actual Alignment = 1", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFields_x2p2() {
		Structure struct = getStructure("x2p2");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/x2p2\n" + 
			"pack(2)\n" + 
			"Structure x2p2 {\n" + 
			"   0   char   1   a   \"\"\n" + 
			"   1   int:27(5)   4   b   \"\"\n" + 
			"}\n" + 
			"Size = 6   Actual Alignment = 2", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFields_x3p2() {
		Structure struct = getStructure("x3p2");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/x3p2\n" + 
			"pack(2)\n" + 
			"Structure x3p2 {\n" + 
			"   0   char   1   a   \"\"\n" + 
			"   2   short:0(7)   0      \"\"\n" + 
			"   2   int:27(5)   4   b   \"\"\n" + 
			"}\n" + 
			"Size = 6   Actual Alignment = 2", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFields_x4p2() {
		Structure struct = getStructure("x4p2");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/x4p2\n" + 
			"pack(2)\n" + 
			"Structure x4p2 {\n" + 
			"   0   char   1   a   \"\"\n" + 
			"   1   int:27(5)   4   b   \"\"\n" + 
			"   8   longlong:0(7)   0      \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 2", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFieldsZ5p4() {
		Structure struct = getStructure("Z5p4");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Z5p4\n" + 
			"pack(4)\n" + 
			"Structure Z5p4 {\n" + 
			"   0   char   1   a   \"\"\n" + 
			"   1   ushort:12(4)   2   b   \"\"\n" + 
			"   2   int:8(4)   2   c   \"\"\n" + 
			"   8   longlong:0(7)   0      \"\"\n" + 
			"   8   char   1   d   \"\"\n" + 
			"}\n" + 
			"Size = 12   Actual Alignment = 4", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFields_x1p4() {
		Structure struct = getStructure("x1p4");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/x1p4\n" + 
			"pack(4)\n" + 
			"Structure x1p4 {\n" + 
			"   0   char   1   a   \"\"\n" + 
			"}\n" + 
			"Size = 1   Actual Alignment = 1", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFields_x2p4() {
		Structure struct = getStructure("x2p4");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/x2p4\n" + 
			"pack(4)\n" + 
			"Structure x2p4 {\n" + 
			"   0   char   1   a   \"\"\n" + 
			"   1   int:27(5)   4   b   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFields_x3p4() {
		Structure struct = getStructure("x3p4");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/x3p4\n" + 
			"pack(4)\n" + 
			"Structure x3p4 {\n" + 
			"   0   char   1   a   \"\"\n" + 
			"   2   short:0(7)   0      \"\"\n" + 
			"   2   int:27(5)   4   b   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFields_x4p4() {
		Structure struct = getStructure("x4p4");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/x4p4\n" + 
			"pack(4)\n" + 
			"Structure x4p4 {\n" + 
			"   0   char   1   a   \"\"\n" + 
			"   1   int:27(5)   4   b   \"\"\n" + 
			"   8   longlong:0(7)   0      \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFieldsT1() {
		Structure struct = getStructure("T1");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/T1\n" + 
			"pack()\n" + 
			"Structure T1 {\n" + 
			"   0   charTypedef   1   a   \"\"\n" + 
			"   1   myEnum:3(5)   1   b   \"\"\n" + 
			"   1   enumTypedef:3(2)   1   c   \"\"\n" + 
			"   2   charTypedef:7(1)   1   d   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFieldsT2() {
		Structure struct = getStructure("T2");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/T2\n" + 
			"pack()\n" + 
			"Structure T2 {\n" + 
			"   0   charTypedef   1   a   \"\"\n" + 
			"   1   intTypedef:17(7)   3   b   \"\"\n" + 
			"   3   enumTypedef:3(4)   1   c   \"\"\n" + 
			"   3   charTypedef:3(1)   1   d   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFieldsS1() {
		Structure struct = getStructure("S1");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/S1\n" + 
			"pack()\n" + 
			"Structure S1 {\n" + 
			"   0   B1   4   b1   \"\"\n" + 
			"   4   B2   4   b2   \"\"\n" + 
			"   8   Z1   8   z1   \"\"\n" + 
			"   16   Z2   8   z2   \"\"\n" + 
			"   24   Z3   8   z3   \"\"\n" + 
			"}\n" + 
			"Size = 32   Actual Alignment = 8", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFieldsS1p1() {
		Structure struct = getStructure("S1p1");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/S1p1\n" + 
			"pack(1)\n" + 
			"Structure S1p1 {\n" + 
			"   0   B1   4   b1   \"\"\n" + 
			"   4   B2   4   b2   \"\"\n" + 
			"   8   Z1   8   z1   \"\"\n" + 
			"   16   Z2   8   z2   \"\"\n" + 
			"   24   Z3   8   z3   \"\"\n" + 
			"}\n" + 
			"Size = 32   Actual Alignment = 1", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFieldsS2p1() {
		Structure struct = getStructure("S2p1");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/S2p1\n" + 
			"pack(1)\n" + 
			"Structure S2p1 {\n" + 
			"   0   B1p1   4   b1p1   \"\"\n" + 
			"   4   B2p1   4   b2p1   \"\"\n" + 
			"   8   Z1p1   7   z1p1   \"\"\n" + 
			"   15   Z2p1   5   z2p1   \"\"\n" + 
			"   20   Z3p1   8   z3p1   \"\"\n" + 
			"}\n" + 
			"Size = 28   Actual Alignment = 1", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFieldsS1p2() {
		Structure struct = getStructure("S1p2");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/S1p2\n" + 
			"pack(2)\n" + 
			"Structure S1p2 {\n" + 
			"   0   B1   4   b1   \"\"\n" + 
			"   4   B2   4   b2   \"\"\n" + 
			"   8   Z1   8   z1   \"\"\n" + 
			"   16   Z2   8   z2   \"\"\n" + 
			"   24   Z3   8   z3   \"\"\n" + 
			"}\n" + 
			"Size = 32   Actual Alignment = 2", struct);
		//@formatter:on
	}

	@Test
	public void testStructureBitFieldsS2p2() {
		Structure struct = getStructure("S2p2");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/S2p2\n" + 
			"pack(2)\n" + 
			"Structure S2p2 {\n" + 
			"   0   B1p2   4   b1p2   \"\"\n" + 
			"   4   B2p2   4   b2p2   \"\"\n" + 
			"   8   Z1p2   8   z1p2   \"\"\n" + 
			"   16   Z2p2   6   z2p2   \"\"\n" + 
			"   22   Z3p2   8   z3p2   \"\"\n" + 
			"}\n" + 
			"Size = 30   Actual Alignment = 2", struct);
		//@formatter:on
	}

}
