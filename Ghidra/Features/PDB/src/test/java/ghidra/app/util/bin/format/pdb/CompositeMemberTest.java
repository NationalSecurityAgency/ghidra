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
package ghidra.app.util.bin.format.pdb;

import static org.junit.Assert.*;

import java.util.HashMap;
import java.util.List;
import java.util.function.Consumer;

import org.junit.*;

import ghidra.program.model.data.*;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import util.CollectionUtils;

public class CompositeMemberTest extends AbstractGhidraHeadlessIntegrationTest
		implements Consumer<String> {

	DataTypeManager dataMgr;
	PdbDataTypeParser dataTypeParser;

	@Before
	public void setUp() {
		// DataOrganization based on x86-64.cspec
		DataOrganizationImpl dataOrg = DataOrganizationImpl.getDefaultOrganization(null);
		dataOrg.setBigEndian(false);
		dataOrg.setAbsoluteMaxAlignment(0);
		dataOrg.setMachineAlignment(2);
		dataOrg.setDefaultPointerAlignment(8);
		dataOrg.setPointerSize(8);

		dataOrg.setSizeAlignment(8, 8);

		BitFieldPackingImpl bitFieldPacking = new BitFieldPackingImpl();
		bitFieldPacking.setUseMSConvention(true);
		dataOrg.setBitFieldPacking(bitFieldPacking);

		dataMgr = new TestDummyDataTypeManager() {
			HashMap<String, DataType> dataTypeMap = new HashMap<>();

			@Override
			public DataOrganization getDataOrganization() {
				return dataOrg;
			}

			@Override
			public DataType addDataType(DataType dataType, DataTypeConflictHandler handler) {
				// handler ignored - tests should not induce conflicts
				String pathname = dataType.getPathName();
				DataType myDt = dataTypeMap.get(pathname);
				if (myDt != null) {
					return myDt;
				}
				DataType dt = dataType.clone(this);
				dataTypeMap.put(pathname, dt);
				return dt;
			}

			@Override
			public DataType findDataType(String dataTypePath) {
				return dataTypeMap.get(dataTypePath);
			}

			@Override
			public DataType getDataType(CategoryPath path, String name) {
				return super.getDataType(new DataTypePath(path, name).getPath());
			}

			@Override
			public DataType getDataType(String dataTypePath) {
				return dataTypeMap.get(dataTypePath);
			}
		};

		dataTypeParser = new PdbDataTypeParser(dataMgr, null, null);
	}

	@After
	public void tearDown() {
		if (dataTypeParser != null && dataTypeParser.hasMissingBitOffsetError()) {
			fail("Test data specifies bitfield without bit-offset");
		}
	}

	@Override
	public void accept(String message) {
		Msg.info(this, message + " (Test: " + getName() + ")");
	}

	@Test
	public void testSimpleStructureWithBitFields() throws Exception {

		StructureDataType struct = new StructureDataType("struct", 0, dataMgr);

		//@formatter:off
		List<MyPdbMember> members =
			CollectionUtils.asList(new MyPdbMember("a", "uchar", 0),
				new MyPdbMember("b:0x4:0x0", "uchar", 1),
				new MyPdbMember("c:0x4:0x4", "uchar", 1),
				new MyPdbMember("d:0x4:0x0", "uchar", 2),
				new MyPdbMember("e:0x4:0x0", "uint", 4),
				new MyPdbMember("f", "ushort", 8));
		//@formatter:on

		assertTrue(DefaultCompositeMember.applyDataTypeMembers(struct, false, 12, members, this,
			TaskMonitor.DUMMY));

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this,
			"/struct\n" + 
			"pack()\n" + 
			"Structure struct {\n" + 
			"   0   uchar   1   a   \"\"\n" + 
			"   1   uchar:4(0)   1   b   \"\"\n" + 
			"   1   uchar:4(4)   1   c   \"\"\n" + 
			"   2   uchar:4(0)   1   d   \"\"\n" + 
			"   4   uint:4(0)   1   e   \"\"\n" + 
			"   8   ushort   2   f   \"\"\n" + 
			"}\n" + 
			"Size = 12   Actual Alignment = 4", struct);
		//@formatter:on
	}

	@Test
	public void testSimpleStructureWithFillerBitFields() throws Exception {

		StructureDataType struct = new StructureDataType("struct", 0, dataMgr);

		//@formatter:off
		List<MyPdbMember> members =
			CollectionUtils.asList(new MyPdbMember("a", "uchar", 0),
				new MyPdbMember("b:0x2:0x2", "uchar", 1),
				new MyPdbMember("c1:0x1:0x4", "uchar", 1),
				new MyPdbMember("c2:0x1:0x6", "uchar", 1),
				new MyPdbMember("d:0x7:0x0", "uchar", 2),
				new MyPdbMember("e:0x4:0x0", "uint", 4),
				new MyPdbMember("f", "ushort", 8));
		//@formatter:on

		assertTrue(DefaultCompositeMember.applyDataTypeMembers(struct, false, 12, members, this,
			TaskMonitor.DUMMY));

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this,
			"/struct\n" + 
			"pack()\n" + 
			"Structure struct {\n" + 
			"   0   uchar   1   a   \"\"\n" + 
			"   1   uchar:2(0)   1   padding   \"\"\n" + 
			"   1   uchar:2(2)   1   b   \"\"\n" + 
			"   1   uchar:1(4)   1   c1   \"\"\n" + 
			"   1   uchar:1(5)   1   padding   \"\"\n" + 
			"   1   uchar:1(6)   1   c2   \"\"\n" + 
			"   2   uchar:7(0)   1   d   \"\"\n" + 
			"   4   uint:4(0)   1   e   \"\"\n" + 
			"   8   ushort   2   f   \"\"\n" + 
			"}\n" + 
			"Size = 12   Actual Alignment = 4", struct, true);
		//@formatter:on
	}

	@Test
	public void testUnionedStructuresWithFillerBitFields() throws Exception {

		/*** Structure Source ***
		 
		 struct BitFieldUnionAlternatingPadded_s {
		   union {
		      struct {
		         char a0:1;
		         char :1;
		         char a2:1;
		         char :1;
		         char a4:1;
		         char :1;
		      };
		      struct {
		         char :1;
		         char a1:1;
		         char :1;
		         char a3:1;
		         char :1;
		         char a5:1;
		      };
		   };
		};
		 
		 */

		StructureDataType struct = new StructureDataType("struct", 0, dataMgr);

		//@formatter:off
		List<MyPdbMember> members =
			CollectionUtils.asList(
				new MyPdbMember("a0:0x1:0x0", "char", 0),
				new MyPdbMember("a2:0x1:0x2", "char", 0),
				new MyPdbMember("a4:0x1:0x4", "char", 0),
				new MyPdbMember("a1:0x1:0x1", "char", 0),
				new MyPdbMember("a3:0x1:0x3", "char", 0),
				new MyPdbMember("a5:0x1:0x5", "char", 0));
		//@formatter:on

		assertTrue(DefaultCompositeMember.applyDataTypeMembers(struct, false, 1, members, this,
			TaskMonitor.DUMMY));

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this,
			"/struct\n" + 
			"pack()\n" + 
			"Structure struct {\n" + 
			"   0   struct_u_0   1   null   \"\"\n" + 
			"}\n" + 
			"Size = 1   Actual Alignment = 1\n" + 
			"/struct/struct_u_0\n" + 
			"pack()\n" + 
			"Union struct_u_0 {\n" + 
			"   0   struct_u_0_s_0   1   _s_0   \"\"\n" + 
			"   0   struct_u_0_s_1   1   _s_1   \"\"\n" + 
			"}\n" + 
			"Size = 1   Actual Alignment = 1\n" + 
			"/struct/struct_u_0/struct_u_0_s_0\n" + 
			"pack()\n" + 
			"Structure struct_u_0_s_0 {\n" + 
			"   0   char:1(0)   1   a0   \"\"\n" + 
			"   0   char:1(1)   1   padding   \"\"\n" + 
			"   0   char:1(2)   1   a2   \"\"\n" + 
			"   0   char:1(3)   1   padding   \"\"\n" + 
			"   0   char:1(4)   1   a4   \"\"\n" + 
			"}\n" + 
			"Size = 1   Actual Alignment = 1\n" + 
			"/struct/struct_u_0/struct_u_0_s_1\n" + 
			"pack()\n" + 
			"Structure struct_u_0_s_1 {\n" + 
			"   0   char:1(0)   1   padding   \"\"\n" + 
			"   0   char:1(1)   1   a1   \"\"\n" + 
			"   0   char:1(2)   1   padding   \"\"\n" + 
			"   0   char:1(3)   1   a3   \"\"\n" + 
			"   0   char:1(4)   1   padding   \"\"\n" + 
			"   0   char:1(5)   1   a5   \"\"\n" + 
			"}\n" + 
			"Size = 1   Actual Alignment = 1", struct, true);
		//@formatter:on
	}

	@Test
	public void testSimpleUnion() throws Exception {

		UnionDataType union = new UnionDataType(CategoryPath.ROOT, "union", dataMgr);

		// NOTE: preference will be given to packing compatible bitfields at same byte
		// offset into structures (currently ambiguous data in PDB xml)

		//@formatter:off
		List<MyPdbMember> members =
			CollectionUtils.asList(new MyPdbMember("a", "uchar", 0),
				new MyPdbMember("b:0x4:0x0", "uchar", 0),
				new MyPdbMember("c:0x4:0x4", "uchar", 0),
				new MyPdbMember("d:0x4:0x0", "uchar", 0),
				new MyPdbMember("e:0x4:0x4", "uchar", 0), 
				new MyPdbMember("f", "ushort", 0));
		//@formatter:on

		assertTrue(DefaultCompositeMember.applyDataTypeMembers(union, false, 2, members, this,
			TaskMonitor.DUMMY));

		// NOTE: handling of bit-fields within union is rather ambiguous within
		// PDB data

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this,
			"/union\n" + 
			"pack()\n" + 
			"Union union {\n" + 
			"   0   uchar   1   a   \"\"\n" + 
			"   0   union_s_1   1   _s_1   \"\"\n" + 
			"   0   union_s_2   1   _s_2   \"\"\n" + 
			"   0   ushort   2   f   \"\"\n" + 
			"}\n" + 
			"Size = 2   Actual Alignment = 2\n" + 
			"/union/union_s_1\n" + 
			"pack()\n" + 
			"Structure union_s_1 {\n" + 
			"   0   uchar:4(0)   1   b   \"\"\n" + 
			"   0   uchar:4(4)   1   c   \"\"\n" + 
			"}\n" + 
			"Size = 1   Actual Alignment = 1\n" + 
			"/union/union_s_2\n" + 
			"pack()\n" + 
			"Structure union_s_2 {\n" + 
			"   0   uchar:4(0)   1   d   \"\"\n" + 
			"   0   uchar:4(4)   1   e   \"\"\n" + 
			"}\n" + 
			"Size = 1   Actual Alignment = 1", union, true);
			//@formatter:on
	}

	@Test
	public void testComplexStructureWithFlexArray() throws Exception {

		StructureDataType struct = new StructureDataType(CategoryPath.ROOT, "struct", 0, dataMgr);

		//@formatter:off
		List<MyPdbMember> members =
			CollectionUtils.asList(
				new MyPdbMember("a", "char", 0),
				new MyPdbMember("e", "char[0]", 1));
		//@formatter:on

		assertTrue(DefaultCompositeMember.applyDataTypeMembers(struct, false, 1, members, this,
			TaskMonitor.DUMMY));

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this,
			"/struct\n" + 
			"pack()\n" + 
			"Structure struct {\n" + 
			"   0   char   1   a   \"\"\n" + 
			"   1   char[0]   0   e   \"\"\n" + 
			"}\n" + 
			"Size = 1   Actual Alignment = 1", struct, true);
		//@formatter:on
	}

	@Test
	public void testComplexStructureWithFlexArray1() throws Exception {

		UnionDataType struct = new UnionDataType(CategoryPath.ROOT, "union", dataMgr);

		//@formatter:off
		List<MyPdbMember> members =
			CollectionUtils.asList(
				new MyPdbMember("a", "int", 0),
				new MyPdbMember("b", "int", 4),
				new MyPdbMember("c", "int", 8),
				new MyPdbMember("d", "char[0]", 12),
				new MyPdbMember("e", "longlong", 0),
				new MyPdbMember("f", "char[0]", 8));
		//@formatter:on

		assertTrue(DefaultCompositeMember.applyDataTypeMembers(struct, false, 16, members, this,
			TaskMonitor.DUMMY));

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this,
			"/union\n" + 
			"pack()\n" + 
			"Union union {\n" + 
			"   0   union_s_0   12   _s_0   \"\"\n" + 
			"   0   union_s_1   8   _s_1   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/union/union_s_0\n" + 
			"pack()\n" + 
			"Structure union_s_0 {\n" + 
			"   0   int   4   a   \"\"\n" + 
			"   4   int   4   b   \"\"\n" + 
			"   8   int   4   c   \"\"\n" + 
			"   12   char[0]   0   d   \"\"\n" + 
			"}\n" + 
			"Size = 12   Actual Alignment = 4\n" + 
			"/union/union_s_1\n" + 
			"pack()\n" + 
			"Structure union_s_1 {\n" + 
			"   0   longlong   8   e   \"\"\n" + 
			"   8   char[0]   0   f   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 8\n", struct, true);
		//@formatter:on
	}

	@Test
	public void testComplexStructureWithFlexArray2() throws Exception {

		UnionDataType struct = new UnionDataType(CategoryPath.ROOT, "union", dataMgr);

		//@formatter:off
		List<MyPdbMember> members =
			CollectionUtils.asList(
				new MyPdbMember("a", "int", 0),
				new MyPdbMember("b", "int", 4),
				new MyPdbMember("c", "int", 8),
				new MyPdbMember("d", "char[0]", 12),
				new MyPdbMember("f", "char[0]", 0));
		//@formatter:on

		assertTrue(DefaultCompositeMember.applyDataTypeMembers(struct, false, 12, members, this,
			TaskMonitor.DUMMY));

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this,
			"/union\n" + 
			"pack()\n" + 
			"Union union {\n" + 
			"   0   union_s_0   12   _s_0   \"\"\n" + 
			"   0   union_s_1   0   _s_1   \"\"\n" + 
			"}\n" + 
			"Size = 12   Actual Alignment = 4\n" + 
			"/union/union_s_0\n" + 
			"pack()\n" + 
			"Structure union_s_0 {\n" + 
			"   0   int   4   a   \"\"\n" + 
			"   4   int   4   b   \"\"\n" + 
			"   8   int   4   c   \"\"\n" + 
			"   12   char[0]   0   d   \"\"\n" + 
			"}\n" + 
			"Size = 12   Actual Alignment = 4\n" + 
			"/union/union_s_1\n" + 
			"pack()\n" + 
			"Structure union_s_1 {\n" + 
			"   0   char[0]   0   f   \"\"\n" + 
			"}\n" + 
			"Size = 1   Actual Alignment = 1\n", struct, true);
		//@formatter:on
	}

	@Test
	public void testComplexStructureWithFlexArray3() throws Exception {

		UnionDataType struct = new UnionDataType(CategoryPath.ROOT, "union", dataMgr);

		//@formatter:off
		List<MyPdbMember> members =
			CollectionUtils.asList(
				new MyPdbMember("a", "char", 0),
				new MyPdbMember("flex", "char[0]", 1),
				new MyPdbMember("b", "char", 0),
				new MyPdbMember("c", "char", 1));
		//@formatter:on

		assertTrue(DefaultCompositeMember.applyDataTypeMembers(struct, false, 1, members, this,
			TaskMonitor.DUMMY));

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this,
			"/union\n" + 
			"pack(disabled)\n" + 
			"Union union {\n" + 
			"   0   union_s_0   1   _s_0   \"\"\n" + 
			"   0   union_s_1   2   _s_1   \"\"\n" + 
			"}\n" + 
			"Size = 2   Actual Alignment = 1\n" + 
			"/union/union_s_0\n" + 
			"pack()\n" + 
			"Structure union_s_0 {\n" + 
			"   0   char   1   a   \"\"\n" + 
			"   1   char[0]   0   flex   \"\"\n" + 
			"}\n" + 
			"Size = 1   Actual Alignment = 1\n" + 
			"/union/union_s_1\n" + 
			"pack()\n" + 
			"Structure union_s_1 {\n" + 
			"   0   char   1   b   \"\"\n" + 
			"   1   char   1   c   \"\"\n" + 
			"}\n" + 
			"Size = 2   Actual Alignment = 1", struct, true);
		//@formatter:on
	}

	@Test
	public void testComplexStructureWithBitFields() throws Exception {

		StructureDataType struct = new StructureDataType("struct", 0, dataMgr);

		//@formatter:off
		List<MyPdbMember> members =
			CollectionUtils.asList(
				new MyPdbMember("s0:0x1:0x0", "char", 0),
				new MyPdbMember("s1:0x1:0x1", "char", 0),
				new MyPdbMember("s2:0x1:0x2", "char", 0),
				new MyPdbMember("s3:0x1:0x3", "char", 0),
				new MyPdbMember("s4:0x1:0x4", "char", 0),
				new MyPdbMember("s5:0x1:0x5", "char", 0),
				new MyPdbMember("s6:0x1:0x6", "char", 0),
				new MyPdbMember("s7:0x1:0x7", "char", 0),
				new MyPdbMember("u0:0x1:0x0", "uchar", 0),
				new MyPdbMember("u1:0x1:0x1", "uchar", 0),
				new MyPdbMember("u2:0x1:0x2", "uchar", 0),
				new MyPdbMember("u3:0x1:0x3", "uchar", 0),
				new MyPdbMember("u4:0x1:0x4", "uchar", 0),
				new MyPdbMember("u5:0x1:0x5", "uchar", 0),
				new MyPdbMember("u6:0x1:0x6", "uchar", 0),
				new MyPdbMember("u7:0x1:0x7", "uchar", 0),
				new MyPdbMember("a", "ulong", 8),
				new MyPdbMember("b", "longlong", 8));
		//@formatter:on

		assertTrue(DefaultCompositeMember.applyDataTypeMembers(struct, false, 16, members, this,
			TaskMonitor.DUMMY));

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this,
			"/struct\n" + 
			"pack()\n" + 
			"Structure struct {\n" + 
			"   0   struct_u_0   1   null   \"\"\n" + 
			"   8   struct_u_8   8   null   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/struct/struct_u_0\n" + 
			"pack()\n" + 
			"Union struct_u_0 {\n" + 
			"   0   struct_u_0_s_0   1   _s_0   \"\"\n" + 
			"   0   struct_u_0_s_1   1   _s_1   \"\"\n" + 
			"}\n" + 
			"Size = 1   Actual Alignment = 1\n" + 
			"/struct/struct_u_0/struct_u_0_s_0\n" + 
			"pack()\n" + 
			"Structure struct_u_0_s_0 {\n" + 
			"   0   char:1(0)   1   s0   \"\"\n" + 
			"   0   char:1(1)   1   s1   \"\"\n" + 
			"   0   char:1(2)   1   s2   \"\"\n" + 
			"   0   char:1(3)   1   s3   \"\"\n" + 
			"   0   char:1(4)   1   s4   \"\"\n" + 
			"   0   char:1(5)   1   s5   \"\"\n" + 
			"   0   char:1(6)   1   s6   \"\"\n" + 
			"   0   char:1(7)   1   s7   \"\"\n" + 
			"}\n" + 
			"Size = 1   Actual Alignment = 1\n" + 
			"/struct/struct_u_0/struct_u_0_s_1\n" + 
			"pack()\n" + 
			"Structure struct_u_0_s_1 {\n" + 
			"   0   uchar:1(0)   1   u0   \"\"\n" + 
			"   0   uchar:1(1)   1   u1   \"\"\n" + 
			"   0   uchar:1(2)   1   u2   \"\"\n" + 
			"   0   uchar:1(3)   1   u3   \"\"\n" + 
			"   0   uchar:1(4)   1   u4   \"\"\n" + 
			"   0   uchar:1(5)   1   u5   \"\"\n" + 
			"   0   uchar:1(6)   1   u6   \"\"\n" + 
			"   0   uchar:1(7)   1   u7   \"\"\n" + 
			"}\n" + 
			"Size = 1   Actual Alignment = 1\n" + 
			"/struct/struct_u_8\n" + 
			"pack()\n" + 
			"Union struct_u_8 {\n" + 
			"   0   ulong   4   a   \"\"\n" + 
			"   0   longlong   8   b   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 8\n", struct, true);
		//@formatter:on
	}

	@Test
	public void testComplexStructureWithBitFields2() throws Exception {

		UnionDataType struct = new UnionDataType(CategoryPath.ROOT, "union", dataMgr);

		//@formatter:off
		List<MyPdbMember> members =
			CollectionUtils.asList(
				new MyPdbMember("a", "ulong", 0),
				new MyPdbMember("b", "longlong", 0),
				new MyPdbMember("s0:0x1:0x0", "char", 0),
				new MyPdbMember("s1:0x1:0x1", "char", 0),
				new MyPdbMember("s2:0x1:0x2", "char", 0),
				new MyPdbMember("s3:0x1:0x3", "char", 0),
				new MyPdbMember("s4:0x1:0x4", "char", 0),
				new MyPdbMember("s5:0x1:0x5", "char", 0),
				new MyPdbMember("s6:0x1:0x6", "char", 0),
				new MyPdbMember("s7:0x1:0x7", "char", 0),
				new MyPdbMember("u0:0x1:0x0", "uchar", 1),
				new MyPdbMember("u1:0x1:0x1", "uchar", 1),
				new MyPdbMember("u2:0x1:0x2", "uchar", 1),
				new MyPdbMember("u3:0x1:0x3", "uchar", 1),
				new MyPdbMember("u4:0x1:0x4", "uchar", 1),
				new MyPdbMember("u5:0x1:0x5", "uchar", 1),
				new MyPdbMember("u6:0x1:0x6", "uchar", 1),
				new MyPdbMember("u7:0x1:0x7", "uchar", 1));
				
		//@formatter:on

		assertTrue(DefaultCompositeMember.applyDataTypeMembers(struct, false, 12, members, this,
			TaskMonitor.DUMMY));

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this,
			"/union\n" + 
			"pack(disabled)\n" + 
			"Union union {\n" + 
			"   0   ulong   4   a   \"\"\n" + 
			"   0   longlong   8   b   \"\"\n" + 
			"   0   union_s_2   2   _s_2   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 1\n" + 
			"/union/union_s_2\n" + 
			"pack()\n" + 
			"Structure union_s_2 {\n" + 
			"   0   char:1(0)   1   s0   \"\"\n" + 
			"   0   char:1(1)   1   s1   \"\"\n" + 
			"   0   char:1(2)   1   s2   \"\"\n" + 
			"   0   char:1(3)   1   s3   \"\"\n" + 
			"   0   char:1(4)   1   s4   \"\"\n" + 
			"   0   char:1(5)   1   s5   \"\"\n" + 
			"   0   char:1(6)   1   s6   \"\"\n" + 
			"   0   char:1(7)   1   s7   \"\"\n" + 
			"   1   uchar:1(0)   1   u0   \"\"\n" + 
			"   1   uchar:1(1)   1   u1   \"\"\n" + 
			"   1   uchar:1(2)   1   u2   \"\"\n" + 
			"   1   uchar:1(3)   1   u3   \"\"\n" + 
			"   1   uchar:1(4)   1   u4   \"\"\n" + 
			"   1   uchar:1(5)   1   u5   \"\"\n" + 
			"   1   uchar:1(6)   1   u6   \"\"\n" + 
			"   1   uchar:1(7)   1   u7   \"\"\n" + 
			"}\n" + 
			"Size = 2   Actual Alignment = 1", struct, true);
		//@formatter:on
	}

	// @Ignore defined structure is too ambiguous
	@Test
	public void testMoreComplicatedStructure() throws Exception {

		StructureDataType struct = new StructureDataType("MoreComplicated_s", 0, dataMgr);

		//@formatter:off
		List<MyPdbMember> members =
			CollectionUtils.asList(new MyPdbMember("s0:0x1:0x0", "char", 0x0),
				new MyPdbMember("s1:0x1:0x1", "char", 0x0),
					new MyPdbMember("s2:0x1:0x2", "char", 0x0),
					new MyPdbMember("s3:0x1:0x3", "char", 0x0),
					new MyPdbMember("s4:0x1:0x4", "char", 0x0),
					new MyPdbMember("s5:0x1:0x5", "char", 0x0),
					new MyPdbMember("s6:0x1:0x6", "char", 0x0),
					new MyPdbMember("s7:0x1:0x7", "char", 0x0),
					new MyPdbMember("u0:0x1:0x0", "uchar", 0x0),
					new MyPdbMember("u1:0x1:0x1", "uchar", 0x0),
					new MyPdbMember("u2:0x1:0x2", "uchar", 0x0),
					new MyPdbMember("u3:0x1:0x3", "uchar", 0x0),
					new MyPdbMember("u4:0x1:0x4", "uchar", 0x0),
					new MyPdbMember("u5:0x1:0x5", "uchar", 0x0),
					new MyPdbMember("u6:0x1:0x6", "uchar", 0x0),
					new MyPdbMember("u7:0x1:0x7", "uchar", 0x0),
					new MyPdbMember("val", "ulong", 0x8),
					new MyPdbMember("d", "double", 0x8),
					new MyPdbMember("n0:0x4:0x0", "ulong", 0x8),
					new MyPdbMember("n1:0x4:0x4", "ulong", 0x8),
					new MyPdbMember("n2:0x4:0x8", "ulong", 0x8),
					new MyPdbMember("n3:0x4:0xc", "ulong", 0x8),
					new MyPdbMember("n4:0x4:0x10", "ulong", 0x8),
					new MyPdbMember("n5:0x4:0x14", "ulong", 0x8),
					new MyPdbMember("n6:0x4:0x18", "ulong", 0x8),
					new MyPdbMember("n7:0x4:0x1c", "ulong", 0x8),
					new MyPdbMember("n8:0x4:0x0", "ulong", 0xc),
					new MyPdbMember("n9:0x4:0x4", "ulong", 0xc),
					new MyPdbMember("n10:0x4:0x8", "ulong", 0xc),
					new MyPdbMember("n11:0x4:0xc", "ulong", 0xc),
					new MyPdbMember("n12:0x4:0x10", "ulong", 0xc),
					new MyPdbMember("n13:0x4:0x14", "ulong", 0xc),
					new MyPdbMember("n14:0x4:0x18", "ulong", 0xc),
					new MyPdbMember("n15:0x4:0x1c", "ulong", 0xc),
					new MyPdbMember("x1:0x1:0x0", "ulong", 0x8),
					new MyPdbMember("x2:0x2:0x1", "ulong", 0x8),
					new MyPdbMember("x3:0x3:0x3", "ulong", 0x8),
					new MyPdbMember("x4:0x4:0x6", "ulong", 0x8),
					new MyPdbMember("x5:0x5:0xa", "ulong", 0x8),
					new MyPdbMember("x6:0x6:0xf", "ulong", 0x8),
					new MyPdbMember("x7:0x7:0x15", "ulong", 0x8),
					new MyPdbMember("x8:0x8:0x0", "ulong", 0xc),
					new MyPdbMember("x9:0x9:0x8", "ulong", 0xc),
					new MyPdbMember("x10:0xa:0x11", "ulong", 0xc),
					new MyPdbMember("y1:0x1:0x0", "uchar", 0x8),
					new MyPdbMember("y2:0x2:0x1", "uchar", 0x8),
					new MyPdbMember("y3:0x3:0x3", "uchar", 0x8),
					new MyPdbMember("y4:0x4:0x0", "uchar", 0x9),
					new MyPdbMember("y5:0x5:0x0", "uchar", 0xa),
					new MyPdbMember("y6:0x6:0x0", "uchar", 0xb),
					new MyPdbMember("y7:0x7:0x0", "uchar", 0xc),
					new MyPdbMember("y8:0x8:0x0", "uchar", 0xd),
					new MyPdbMember("y9:0x9:0x0", "ushort", 0xe),
					new MyPdbMember("da", "double", 0x10),
					new MyPdbMember("ca", "char[8]", 0x18),
					new MyPdbMember("cb", "char[8]", 0x10),
					new MyPdbMember("db", "double", 0x18),
					new MyPdbMember("beef", "char[10]", 0x20),
					new MyPdbMember("fromAddress", "int", 0x2c),
					new MyPdbMember("toAddress", "int", 0x30),
					new MyPdbMember("seqNum", "int", 0x34),
					new MyPdbMember("data", "char[0]", 0x38),
					new MyPdbMember("buf", "char[0]", 0x2c));
		//@formatter:on

		assertTrue(DefaultCompositeMember.applyDataTypeMembers(struct, false, 0x38, members, this,
			TaskMonitor.DUMMY));

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this,
			"/MoreComplicated_s\n" + 
			"pack()\n" + 
			"Structure MoreComplicated_s {\n" + 
			"   0   MoreComplicated_s_u_0   1   null   \"\"\n" + 
			"   8   MoreComplicated_s_u_8   8   null   \"\"\n" + 
			"   16   MoreComplicated_s_u_16   16   null   \"\"\n" + 
			"   32   char[10]   10   beef   \"\"\n" + 
			"   44   MoreComplicated_s_u_44   12   null   \"\"\n" + 
			"}\n" + 
			"Size = 56   Actual Alignment = 8\n" + 
			"/MoreComplicated_s/MoreComplicated_s_u_0\n" + 
			"pack()\n" + 
			"Union MoreComplicated_s_u_0 {\n" + 
			"   0   MoreComplicated_s_u_0_s_0   1   _s_0   \"\"\n" + 
			"   0   MoreComplicated_s_u_0_s_1   1   _s_1   \"\"\n" + 
			"}\n" + 
			"Size = 1   Actual Alignment = 1\n" + 
			"/MoreComplicated_s/MoreComplicated_s_u_0/MoreComplicated_s_u_0_s_0\n" + 
			"pack()\n" + 
			"Structure MoreComplicated_s_u_0_s_0 {\n" + 
			"   0   char:1(0)   1   s0   \"\"\n" + 
			"   0   char:1(1)   1   s1   \"\"\n" + 
			"   0   char:1(2)   1   s2   \"\"\n" + 
			"   0   char:1(3)   1   s3   \"\"\n" + 
			"   0   char:1(4)   1   s4   \"\"\n" + 
			"   0   char:1(5)   1   s5   \"\"\n" + 
			"   0   char:1(6)   1   s6   \"\"\n" + 
			"   0   char:1(7)   1   s7   \"\"\n" + 
			"}\n" + 
			"Size = 1   Actual Alignment = 1\n" + 
			"/MoreComplicated_s/MoreComplicated_s_u_0/MoreComplicated_s_u_0_s_1\n" + 
			"pack()\n" + 
			"Structure MoreComplicated_s_u_0_s_1 {\n" + 
			"   0   uchar:1(0)   1   u0   \"\"\n" + 
			"   0   uchar:1(1)   1   u1   \"\"\n" + 
			"   0   uchar:1(2)   1   u2   \"\"\n" + 
			"   0   uchar:1(3)   1   u3   \"\"\n" + 
			"   0   uchar:1(4)   1   u4   \"\"\n" + 
			"   0   uchar:1(5)   1   u5   \"\"\n" + 
			"   0   uchar:1(6)   1   u6   \"\"\n" + 
			"   0   uchar:1(7)   1   u7   \"\"\n" + 
			"}\n" + 
			"Size = 1   Actual Alignment = 1\n" + 
			"/MoreComplicated_s/MoreComplicated_s_u_16\n" + 
			"pack()\n" + 
			"Union MoreComplicated_s_u_16 {\n" + 
			"   0   MoreComplicated_s_u_16_s_0   16   _s_0   \"\"\n" + 
			"   0   MoreComplicated_s_u_16_s_1   16   _s_1   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/MoreComplicated_s/MoreComplicated_s_u_16/MoreComplicated_s_u_16_s_0\n" + 
			"pack()\n" + 
			"Structure MoreComplicated_s_u_16_s_0 {\n" + 
			"   0   double   8   da   \"\"\n" + 
			"   8   char[8]   8   ca   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/MoreComplicated_s/MoreComplicated_s_u_16/MoreComplicated_s_u_16_s_1\n" + 
			"pack()\n" + 
			"Structure MoreComplicated_s_u_16_s_1 {\n" + 
			"   0   char[8]   8   cb   \"\"\n" + 
			"   8   double   8   db   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/MoreComplicated_s/MoreComplicated_s_u_44\n" + 
			"pack()\n" + 
			"Union MoreComplicated_s_u_44 {\n" + 
			"   0   MoreComplicated_s_u_44_s_0   12   _s_0   \"\"\n" + 
			"   0   MoreComplicated_s_u_44_s_1   0   _s_1   \"\"\n" + 
			"}\n" + 
			"Size = 12   Actual Alignment = 4\n" + 
			"/MoreComplicated_s/MoreComplicated_s_u_44/MoreComplicated_s_u_44_s_0\n" + 
			"pack()\n" + 
			"Structure MoreComplicated_s_u_44_s_0 {\n" + 
			"   0   int   4   fromAddress   \"\"\n" + 
			"   4   int   4   toAddress   \"\"\n" + 
			"   8   int   4   seqNum   \"\"\n" + 
			"   12   char[0]   0   data   \"\"\n" + 
			"}\n" + 
			"Size = 12   Actual Alignment = 4\n" + 
			"/MoreComplicated_s/MoreComplicated_s_u_44/MoreComplicated_s_u_44_s_1\n" + 
			"pack()\n" + 
			"Structure MoreComplicated_s_u_44_s_1 {\n" + 
			"   0   char[0]   0   buf   \"\"\n" + 
			"}\n" + 
			"Size = 1   Actual Alignment = 1\n" + 
			"/MoreComplicated_s/MoreComplicated_s_u_8\n" + 
			"pack()\n" + 
			"Union MoreComplicated_s_u_8 {\n" + 
			"   0   ulong   4   val   \"\"\n" + 
			"   0   double   8   d   \"\"\n" + 
			"   0   MoreComplicated_s_u_8_s_2   8   _s_2   \"\"\n" + 
			"   0   MoreComplicated_s_u_8_s_3   8   _s_3   \"\"\n" + 
			"   0   MoreComplicated_s_u_8_s_4   8   _s_4   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 8\n" + 
			"/MoreComplicated_s/MoreComplicated_s_u_8/MoreComplicated_s_u_8_s_2\n" + 
			"pack()\n" + 
			"Structure MoreComplicated_s_u_8_s_2 {\n" + 
			"   0   ulong:4(0)   1   n0   \"\"\n" + 
			"   0   ulong:4(4)   1   n1   \"\"\n" + 
			"   1   ulong:4(0)   1   n2   \"\"\n" + 
			"   1   ulong:4(4)   1   n3   \"\"\n" + 
			"   2   ulong:4(0)   1   n4   \"\"\n" + 
			"   2   ulong:4(4)   1   n5   \"\"\n" + 
			"   3   ulong:4(0)   1   n6   \"\"\n" + 
			"   3   ulong:4(4)   1   n7   \"\"\n" + 
			"   4   ulong:4(0)   1   n8   \"\"\n" + 
			"   4   ulong:4(4)   1   n9   \"\"\n" + 
			"   5   ulong:4(0)   1   n10   \"\"\n" + 
			"   5   ulong:4(4)   1   n11   \"\"\n" + 
			"   6   ulong:4(0)   1   n12   \"\"\n" + 
			"   6   ulong:4(4)   1   n13   \"\"\n" + 
			"   7   ulong:4(0)   1   n14   \"\"\n" + 
			"   7   ulong:4(4)   1   n15   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/MoreComplicated_s/MoreComplicated_s_u_8/MoreComplicated_s_u_8_s_3\n" + 
			"pack()\n" + 
			"Structure MoreComplicated_s_u_8_s_3 {\n" + 
			"   0   ulong:1(0)   1   x1   \"\"\n" + 
			"   0   ulong:2(1)   1   x2   \"\"\n" + 
			"   0   ulong:3(3)   1   x3   \"\"\n" + 
			"   0   ulong:4(6)   2   x4   \"\"\n" + 
			"   1   ulong:5(2)   1   x5   \"\"\n" + 
			"   1   ulong:6(7)   2   x6   \"\"\n" + 
			"   2   ulong:7(5)   2   x7   \"\"\n" + 
			"   4   ulong:8(0)   1   x8   \"\"\n" + 
			"   5   ulong:9(0)   2   x9   \"\"\n" + 
			"   6   ulong:10(1)   2   x10   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/MoreComplicated_s/MoreComplicated_s_u_8/MoreComplicated_s_u_8_s_4\n" + 
			"pack()\n" + 
			"Structure MoreComplicated_s_u_8_s_4 {\n" + 
			"   0   uchar:1(0)   1   y1   \"\"\n" + 
			"   0   uchar:2(1)   1   y2   \"\"\n" + 
			"   0   uchar:3(3)   1   y3   \"\"\n" + 
			"   1   uchar:4(0)   1   y4   \"\"\n" + 
			"   2   uchar:5(0)   1   y5   \"\"\n" + 
			"   3   uchar:6(0)   1   y6   \"\"\n" + 
			"   4   uchar:7(0)   1   y7   \"\"\n" + 
			"   5   uchar:8(0)   1   y8   \"\"\n" + 
			"   6   ushort:9(0)   2   y9   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 2", struct, true);
		//@formatter:on
	}

	class MyPdbMember extends DefaultPdbMember {

		protected MyPdbMember(String memberName, String memberDataTypeName, int memberOffset) {
			super(memberName, memberDataTypeName, memberOffset, PdbKind.MEMBER, dataTypeParser);
		}

	}

}
