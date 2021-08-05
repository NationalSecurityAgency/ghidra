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
package ghidra.app.util.bin.format.dwarf4;

import static org.junit.Assert.*;

import java.io.IOException;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.app.util.bin.format.dwarf4.attribs.DWARFAttributeFactory;
import ghidra.app.util.bin.format.dwarf4.encoding.*;
import ghidra.app.util.bin.format.dwarf4.next.DWARFImportOptions;
import ghidra.app.util.bin.format.dwarf4.next.DWARFProgram;
import ghidra.app.util.bin.format.dwarf4.next.sectionprovider.NullSectionProvider;
import ghidra.program.model.listing.Program;
import ghidra.test.ToyProgramBuilder;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Testing the DIECreator, which is used in other tests.
 */
public class DIETest extends AbstractGenericTest {
	DWARFProgram prog;
	DWARFAttributeFactory attribFactory;
	MockDWARFCompilationUnit cu;

	@Before
	public void setUp() throws Exception {

		ToyProgramBuilder builder = new ToyProgramBuilder("Test", true);
		Program ghidraProgram = builder.getProgram();

		prog = new DWARFProgram(ghidraProgram, new DWARFImportOptions(), TaskMonitor.DUMMY,
			new NullSectionProvider());
		attribFactory = prog.getAttributeFactory();

		cu = new MockDWARFCompilationUnit(prog, 0x1000, 0x2000, 0, DWARFCompilationUnit.DWARF_32,
			(short) 4, 0, (byte) 8, 0, DWARFSourceLanguage.DW_LANG_C);
	}

	@Test
	public void testDIEAggregate()
			throws DWARFPreconditionException, CancelledException, DWARFException, IOException {
//		DebugInfoEntry baseType =
//			new DIECreator(DWARFTag.DW_TAG_base_type).addString(DWARFAttribute.DW_AT_name,
//				"base_type_name").addInt(DWARFAttribute.DW_AT_byte_size, 4).addInt(
//					DWARFAttribute.DW_AT_encoding, DWARFEncoding.DW_ATE_unsigned).create(cu);
//
//		DebugInfoEntry td =
//			new DIECreator(DWARFTag.DW_TAG_typedef).addString(DWARFAttribute.DW_AT_name,
//				"mytypedef").addRef(DWARFAttribute.DW_AT_type, baseType).create(cu);

		DebugInfoEntry declStruct =
			new DIECreator(DWARFTag.DW_TAG_structure_type).addString(DWARFAttribute.DW_AT_name,
				"mystruct").addBoolean(DWARFAttribute.DW_AT_declaration, true).addString(
					DWARFAttribute.DW_AT_const_value, "declConst").addString(
						DWARFAttribute.DW_AT_description, "declDesc").create(cu);

		DebugInfoEntry implStruct =
			new DIECreator(DWARFTag.DW_TAG_structure_type).addString(DWARFAttribute.DW_AT_name,
				"mystruct").addRef(DWARFAttribute.DW_AT_specification, declStruct).addString(
					DWARFAttribute.DW_AT_const_value, "specConst").addString(
						DWARFAttribute.DW_AT_description, "declDesc").create(cu);

		DebugInfoEntry aoStruct =
			new DIECreator(DWARFTag.DW_TAG_structure_type).addString(DWARFAttribute.DW_AT_name,
				"mystruct").addRef(DWARFAttribute.DW_AT_abstract_origin, implStruct).addString(
					DWARFAttribute.DW_AT_description, "aoDesc").create(cu);

		prog.checkPreconditions(TaskMonitor.DUMMY);
		prog.setCurrentCompilationUnit(cu, TaskMonitor.DUMMY);

		DIEAggregate struct_via_ao = prog.getAggregate(aoStruct);

		assertEquals("MyStruct aggregate should have 3 fragments", 3,
			struct_via_ao.getOffsets().length);
		assertEquals("Attr dw_at_const should be from spec", "specConst",
			struct_via_ao.getString(DWARFAttribute.DW_AT_const_value, null));
		assertEquals("Attr dw_at_description should be from ao", "aoDesc",
			struct_via_ao.getString(DWARFAttribute.DW_AT_description, null));
	}

	/**
	 * Tests the creation of DIEAggregates when there is a many-to-one layout of
	 * abstractorigin -> spec -> decl links.
	 * <p>
	 * <pre>
	 *                                                   mystruct ao1
	 *                                                 /
	 *   mystruct decl <------  mystruct spec  <------+
	 *                                                 \
	 *                                                   mystruct ao2
	 * </pre>
	 * @throws DWARFException
	 * @throws IOException
	 * @throws CancelledException
	 */
	@Test
	public void testDIEAggregateMulti() throws DWARFException, CancelledException, IOException {
//		DebugInfoEntry baseType =
//			new DIECreator(DWARFTag.DW_TAG_base_type).addString(DWARFAttribute.DW_AT_name,
//				"base_type_name").addInt(DWARFAttribute.DW_AT_byte_size, 4).addInt(
//					DWARFAttribute.DW_AT_encoding, DWARFEncoding.DW_ATE_unsigned).create(cu);
//
//		DebugInfoEntry td =
//			new DIECreator(DWARFTag.DW_TAG_typedef).addString(DWARFAttribute.DW_AT_name,
//				"mytypedef").addRef(DWARFAttribute.DW_AT_type, baseType).create(cu);

		DebugInfoEntry declStruct =
			new DIECreator(DWARFTag.DW_TAG_structure_type).addString(DWARFAttribute.DW_AT_name,
				"mystruct").addBoolean(DWARFAttribute.DW_AT_declaration, true).addString(
					DWARFAttribute.DW_AT_const_value, "declConst").addString(
						DWARFAttribute.DW_AT_description, "declDesc").create(cu);

		DebugInfoEntry implStruct =
			new DIECreator(DWARFTag.DW_TAG_structure_type).addString(DWARFAttribute.DW_AT_name,
				"mystruct").addRef(DWARFAttribute.DW_AT_specification, declStruct).addString(
					DWARFAttribute.DW_AT_const_value, "specConst").addString(
						DWARFAttribute.DW_AT_description, "declDesc").create(cu);

		DebugInfoEntry ao1Struct =
			new DIECreator(DWARFTag.DW_TAG_structure_type).addString(DWARFAttribute.DW_AT_name,
				"mystruct").addRef(DWARFAttribute.DW_AT_abstract_origin, implStruct).addString(
					DWARFAttribute.DW_AT_description, "ao1Desc").create(cu);

		DebugInfoEntry ao2Struct =
			new DIECreator(DWARFTag.DW_TAG_structure_type).addString(DWARFAttribute.DW_AT_name,
				"mystruct").addRef(DWARFAttribute.DW_AT_abstract_origin, implStruct).addString(
					DWARFAttribute.DW_AT_description, "ao2Desc").create(cu);

		prog.checkPreconditions(TaskMonitor.DUMMY);
		prog.setCurrentCompilationUnit(cu, TaskMonitor.DUMMY);

		DIEAggregate ao1 = prog.getAggregate(ao1Struct);
		DIEAggregate ao2 = prog.getAggregate(ao2Struct);

		assertEquals("Should have 3 fragments", 3, ao1.getOffsets().length);
		assertEquals("Should have 3 fragments", 3, ao2.getOffsets().length);
		assertEquals("Attr dw_at_const should be from spec", "specConst",
			ao1.getString(DWARFAttribute.DW_AT_const_value, null));
		assertEquals("Attr dw_at_const should be from spec", "specConst",
			ao2.getString(DWARFAttribute.DW_AT_const_value, null));
		assertEquals("Attr dw_at_description should be from ao1", "ao1Desc",
			ao1.getString(DWARFAttribute.DW_AT_description, null));
		assertEquals("Attr dw_at_description should be from ao2", "ao2Desc",
			ao2.getString(DWARFAttribute.DW_AT_description, null));
	}

	@Test
	public void testPagedEntryChecking() throws DWARFException, CancelledException, IOException {
		DebugInfoEntry die1 = new DIECreator(DWARFTag.DW_TAG_base_type).create(cu);

		prog.checkPreconditions(TaskMonitor.DUMMY);

		try {
			DIEAggregate diea1 = prog.getAggregate(die1);
			Assert.assertNotNull(diea1);
		}
		catch (RuntimeException rte) {
			// good, getAggregate() should fail if we haven't called setCurrentCompileUnit()
		}

		prog.setCurrentCompilationUnit(cu, TaskMonitor.DUMMY);
		DIEAggregate diea1 = prog.getAggregate(die1);
		Assert.assertNotNull(diea1);

	}

}
