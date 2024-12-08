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
package ghidra.app.util.bin.format.dwarf;

import static ghidra.app.util.bin.format.dwarf.DWARFTag.*;
import static ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute.*;
import static org.junit.Assert.*;

import java.io.IOException;

import org.junit.Test;

import ghidra.app.util.bin.format.dwarf.*;
import ghidra.util.exception.CancelledException;

/**
 * Testing the DIECreator, which is used in other tests.
 */
public class DIECreatorTest extends DWARFTestBase {

	@Test
	public void testDIEAggregate() throws CancelledException, DWARFException, IOException {
//		DebugInfoEntry baseType =
//			new DIECreator(DWARFTag.DW_TAG_base_type).addString(DWARFAttribute.DW_AT_name,
//				"base_type_name").addInt(DWARFAttribute.DW_AT_byte_size, 4).addInt(
//					DWARFAttribute.DW_AT_encoding, DWARFEncoding.DW_ATE_unsigned).create(cu);
//
//		DebugInfoEntry td =
//			new DIECreator(DWARFTag.DW_TAG_typedef).addString(DWARFAttribute.DW_AT_name,
//				"mytypedef").addRef(DWARFAttribute.DW_AT_type, baseType).create(cu);

		DebugInfoEntry declStruct =
			new DIECreator(dwarfProg, DW_TAG_structure_type).addString(DW_AT_name, "mystruct")
					.addBoolean(DW_AT_declaration, true)
					.addString(DW_AT_const_value, "declConst")
					.addString(DW_AT_description, "declDesc")
					.create();

		DebugInfoEntry implStruct =
			new DIECreator(dwarfProg, DW_TAG_structure_type).addString(DW_AT_name, "mystruct")
					.addRef(DW_AT_specification, declStruct)
					.addString(DW_AT_const_value, "specConst")
					.addString(DW_AT_description, "declDesc")
					.create();

		DebugInfoEntry aoStruct =
			new DIECreator(dwarfProg, DW_TAG_structure_type).addString(DW_AT_name, "mystruct")
					.addRef(DW_AT_abstract_origin, implStruct)
					.addString(DW_AT_description, "aoDesc")
					.create();

		buildMockDIEIndexes();

		DIEAggregate struct_via_ao = dwarfProg.getAggregate(aoStruct);

		assertEquals("MyStruct aggregate should have 3 fragments", 3,
			struct_via_ao.getOffsets().length);
		assertEquals("Attr dw_at_const should be from spec", "specConst",
			struct_via_ao.getString(DW_AT_const_value, null));
		assertEquals("Attr dw_at_description should be from ao", "aoDesc",
			struct_via_ao.getString(DW_AT_description, null));
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
			new DIECreator(dwarfProg, DW_TAG_structure_type).addString(DW_AT_name, "mystruct")
					.addBoolean(DW_AT_declaration, true)
					.addString(DW_AT_const_value, "declConst")
					.addString(DW_AT_description, "declDesc")
					.create();

		DebugInfoEntry implStruct =
			new DIECreator(dwarfProg, DW_TAG_structure_type).addString(DW_AT_name, "mystruct")
					.addRef(DW_AT_specification, declStruct)
					.addString(DW_AT_const_value, "specConst")
					.addString(DW_AT_description, "declDesc")
					.create();

		DebugInfoEntry ao1Struct =
			new DIECreator(dwarfProg, DW_TAG_structure_type).addString(DW_AT_name, "mystruct")
					.addRef(DW_AT_abstract_origin, implStruct)
					.addString(DW_AT_description, "ao1Desc")
					.create();

		DebugInfoEntry ao2Struct =
			new DIECreator(dwarfProg, DW_TAG_structure_type).addString(DW_AT_name, "mystruct")
					.addRef(DW_AT_abstract_origin, implStruct)
					.addString(DW_AT_description, "ao2Desc")
					.create();

		buildMockDIEIndexes();

		DIEAggregate ao1 = dwarfProg.getAggregate(ao1Struct);
		DIEAggregate ao2 = dwarfProg.getAggregate(ao2Struct);

		assertEquals("Should have 3 fragments", 3, ao1.getOffsets().length);
		assertEquals("Should have 3 fragments", 3, ao2.getOffsets().length);
		assertEquals("Attr dw_at_const should be from spec", "specConst",
			ao1.getString(DW_AT_const_value, null));
		assertEquals("Attr dw_at_const should be from spec", "specConst",
			ao2.getString(DW_AT_const_value, null));
		assertEquals("Attr dw_at_description should be from ao1", "ao1Desc",
			ao1.getString(DW_AT_description, null));
		assertEquals("Attr dw_at_description should be from ao2", "ao2Desc",
			ao2.getString(DW_AT_description, null));
	}

}
