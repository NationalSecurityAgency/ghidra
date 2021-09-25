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

import org.junit.Test;

public class CompositeZeroArrayTest extends AbstractCompositeZeroArrayTest {

	// NOTE: In the absence of bit-fields these tests are not sensitive to endianess

	private static DataTypeManager dataMgr;

	@Override
	protected DataTypeManager getDataTypeManager() {
		synchronized (CompositeZeroArrayTest.class) {
			if (dataMgr == null) {
				DataOrganizationImpl dataOrg = DataOrganizationImpl.getDefaultOrganization(null);
				DataOrganizationTestUtils.initDataOrganization32BitMips(dataOrg);
				dataMgr = createDataTypeManager("test", dataOrg);
			}
			return dataMgr;
		}
	}

	@Test
	public void testStructureZeroArrayS1() {
		Structure struct = getStructure("zeroArrayStruct1");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/zeroArrayStruct1\n" + 
			"pack()\n" + 
			"Structure zeroArrayStruct1 {\n" + 
			"   0   int   4   a   \"\"\n" + 
			"   4   char[2]   2   a1   \"\"\n" + 
			"   6   char[0]   0   x   \"\"\n" + 
			"   8   int[0]   0   y   \"\"\n" + 
			"   8   int   4   b   \"\"\n" + 
			"}\n" + 
			"Size = 12   Actual Alignment = 4", struct);
		//@formatter:on
	}

	@Test
	public void testStructureZeroArrayS2() {
		Structure struct = getStructure("zeroArrayStruct2");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/zeroArrayStruct2\n" + 
			"pack()\n" + 
			"Structure zeroArrayStruct2 {\n" + 
			"   0   int   4   a   \"\"\n" + 
			"   4   char[2]   2   a1   \"\"\n" + 
			"   6   char[0]   0   x   \"\"\n" + 
			"   8   int[0]   0   y   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4", struct);
		//@formatter:on
	}

	@Test
	public void testStructureZeroArrayS3() {
		Structure struct = getStructure("zeroArrayStruct3");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/zeroArrayStruct3\n" + 
			"pack()\n" + 
			"Structure zeroArrayStruct3 {\n" + 
			"   0   int   4   a   \"\"\n" + 
			"   4   zeroArrayStruct2   8   s   \"\"\n" + 
			"}\n" + 
			"Size = 12   Actual Alignment = 4", struct);
		//@formatter:on
	}

	@Test
	public void testStructureZeroArrayU1() {
		Union union = getUnion("zeroArrayUnion1");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/zeroArrayUnion1\n" + 
			"pack()\n" + 
			"Union zeroArrayUnion1 {\n" + 
			"   0   int   4   a   \"\"\n" + 
			"   0   char[2]   2   a1   \"\"\n" + 
			"   0   char[0]   0   x   \"\"\n" + 
			"   0   int[0]   0   y   \"\"\n" + 
			"   0   int   4   b   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4", union);
		//@formatter:on
	}

	@Test
	public void testStructureZeroArrayU2() {
		Union union = getUnion("zeroArrayUnion2");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/zeroArrayUnion2\n" + 
			"pack()\n" + 
			"Union zeroArrayUnion2 {\n" + 
			"   0   int   4   a   \"\"\n" + 
			"   0   char[2]   2   a1   \"\"\n" + 
			"   0   char[0]   0   x   \"\"\n" + 
			"   0   int[0]   0   y   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4", union);
		//@formatter:on
	}

	@Test
	public void testStructureZeroArrayU3() {
		Union union = getUnion("zeroArrayUnion3");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/zeroArrayUnion3\n" + 
			"pack()\n" + 
			"Union zeroArrayUnion3 {\n" + 
			"   0   int   4   a   \"\"\n" + 
			"   0   zeroArrayStruct2   8   s   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4", union);
		//@formatter:on
	}
}
