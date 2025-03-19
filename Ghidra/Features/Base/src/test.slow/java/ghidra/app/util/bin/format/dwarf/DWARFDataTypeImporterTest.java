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

import static ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute.*;
import static org.junit.Assert.*;

import java.io.IOException;
import java.util.*;

import org.junit.Test;

import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.exception.CancelledException;

/**
 *
 * Tests for the {@link DWARFDataTypeImporter} using artificial DIE data.
 *
 *
 */
public class DWARFDataTypeImporterTest extends DWARFTestBase {

	/**
	 * Base type defs without a name should resolve directly to the Ghidra basetype instance.
	 *
	 * @throws CancelledException
	 * @throws IOException
	 * @throws DWARFException
	 */
	@Test
	public void testAnonBaseType() throws CancelledException, IOException, DWARFException {
		DebugInfoEntry baseDIE = addBaseType(null, 4, DWARFEncoding.DW_ATE_signed);

		importAllDataTypes();

		DataType baseTypeDT = dwarfDTM.getDataType(baseDIE.getOffset(), null);
		assertTrue(baseTypeDT instanceof AbstractIntegerDataType);
		assertTrue(((AbstractIntegerDataType) baseTypeDT).isSigned() == true);
	}

	@Test
	public void testAnonBaseTypeWithTypedef()
			throws CancelledException, IOException, DWARFException {
		DebugInfoEntry baseDIE = addBaseType(null, 4, DWARFEncoding.DW_ATE_signed);
		DebugInfoEntry typedefDIE = addTypedef("mytypedef", baseDIE);

		importAllDataTypes();

		DataType baseTypeDT = dwarfDTM.getDataType(baseDIE.getOffset(), null);
		DataType tdDT = dwarfDTM.getDataType(typedefDIE.getOffset(), null);

		assertEquals("mytypedef", baseTypeDT.getName());
		assertEquals("mytypedef", tdDT.getName());
	}

	/**
	 * Base type defs with a non-standard name should resolve to a typedef that points
	 * to the Ghidra basetype instance.
	 *
	 * @throws CancelledException
	 * @throws IOException
	 * @throws DWARFException
	 */
	@Test
	public void testNonStandardBaseTypeName()
			throws CancelledException, IOException, DWARFException {
		DebugInfoEntry baseDIE = addBaseType("blah", 4, DWARFEncoding.DW_ATE_signed);

		importAllDataTypes();

		TypeDef dt = (TypeDef) dwarfDTM.getDataType(baseDIE.getOffset(), null);

		DataType baseTypeDT = dt.getBaseDataType();
		assertTrue(baseTypeDT instanceof AbstractIntegerDataType);
		assertTrue(((AbstractIntegerDataType) baseTypeDT).isSigned() == true);
		assertTrue(baseTypeDT.hasLanguageDependantLength());
	}

	@Test
	public void testBaseTypeInt() throws CancelledException, IOException, DWARFException {
		addTypedef("mytypedef", addInt());

		importAllDataTypes();

		DataType tddt = dataMgr.getDataType(dwarfRootCP, "mytypedef");
		DataType baseTypeDT = ((TypeDef) tddt).getDataType();

		assertTrue(baseTypeDT.hasLanguageDependantLength());
		assertEquals(4, baseTypeDT.getLength());
		assertTrue(baseTypeDT instanceof AbstractIntegerDataType);
		assertTrue(((AbstractIntegerDataType) baseTypeDT).isSigned() == true);
	}

	@Test
	public void testBaseTypeUInt() throws CancelledException, IOException, DWARFException {

		addTypedef("mytypedef", addBaseType("unsigned int", 4, DWARFEncoding.DW_ATE_unsigned));

		importAllDataTypes();

		DataType tddt = dataMgr.getDataType(dwarfRootCP, "mytypedef");
		DataType baseTypeDT = ((TypeDef) tddt).getDataType();

		assertTrue(baseTypeDT.hasLanguageDependantLength());
		assertEquals(4, baseTypeDT.getLength());
		assertTrue(baseTypeDT instanceof AbstractIntegerDataType);
		assertTrue(((AbstractIntegerDataType) baseTypeDT).isSigned() == false);
	}

	@Test
	public void testBaseTypeExplictBitSize()
			throws CancelledException, IOException, DWARFException {
		// test when int data type name has a bitsize string (8|16|32|64,etc)

		addBaseType("uint32_t", 4, DWARFEncoding.DW_ATE_unsigned);
		addBaseType("blah32blah", 4, DWARFEncoding.DW_ATE_signed);

		importAllDataTypes();

		DataType tddt = dataMgr.getDataType(dwarfRootCP, "uint32_t");
		DataType baseTypeDT = ((TypeDef) tddt).getDataType();

		assertFalse(baseTypeDT.hasLanguageDependantLength());
		assertEquals(4, baseTypeDT.getLength());
		assertTrue(baseTypeDT instanceof AbstractIntegerDataType);
		assertTrue(((AbstractIntegerDataType) baseTypeDT).isSigned() == false);

		DataType blahDT = dataMgr.getDataType(dwarfRootCP, "blah32blah");
		assertFalse(blahDT.hasLanguageDependantLength());
		assertEquals(4, blahDT.getLength());
	}

	@Test
	public void testBaseTypeBadExplictBitSize()
			throws CancelledException, IOException, DWARFException {
		// test when int data type name has a bitsize string that doesn't make sense

		addBaseType("uint32_t", 2 /* not 4 */, DWARFEncoding.DW_ATE_unsigned);

		importAllDataTypes();

		DataType dt = dataMgr.getDataType(dwarfRootCP, "uint32_t");

		assertTrue(dt.hasLanguageDependantLength());
		assertEquals(2, dt.getLength());
	}

	@Test
	@SuppressWarnings("unused")
	public void testStructType() throws CancelledException, IOException, DWARFException {

		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry floatDIE = addFloat();

		DebugInfoEntry structDIE = newStruct("mystruct", 100).create();
		DebugInfoEntry structF1DIE = newMember(structDIE, "f1", intDIE, 0).create();
		DebugInfoEntry structF2DIE = newMember(structDIE, "f2", floatDIE, 10).create();

		importAllDataTypes();

		DataType structdt = dataMgr.getDataType(uncatCP, "mystruct");
	}

	@Test
	public void testStructDecl() throws CancelledException, IOException, DWARFException {

		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry floatDIE = addFloat();

		DebugInfoEntry declDIE = newDeclStruct("mystruct").create();
		DebugInfoEntry structDIE = newSpecStruct(declDIE, 100).create();
		newMember(structDIE, "f1", intDIE, 0).create();
		newMember(structDIE, "f2", floatDIE, 10).create();

		importAllDataTypes();

		DataType structdt = dataMgr.getDataType(uncatCP, "mystruct");
		assertEquals(100, structdt.getLength());
	}

	/**
	 * Test structure definition when a struct is fwd decl'd in one CU and fully
	 * defined in a second CU.
	 * 
	 * @throws CancelledException
	 * @throws IOException
	 * @throws DWARFException
	 */
	@Test
	public void testStructDanglingDecl() throws CancelledException, IOException, DWARFException {

		// CU1
		newDeclStruct("mystruct").create();
		
		addCompUnit();

		// CU2
		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry floatDIE = addFloat();

		DebugInfoEntry structDIE = newStruct("mystruct", 100).create();
		newMember(structDIE, "f1", intDIE, 0).create();
		newMember(structDIE, "f2", floatDIE, 10).create();

		importAllDataTypes();

		DataType structdt = dataMgr.getDataType(uncatCP, "mystruct");
		DataType structdt2 = dataMgr.getDataType(uncatCP, "mystruct.conflict");

		assertEquals(100, structdt.getLength());
		assertNull(structdt2);
	}

	/*
	 * This test is more about the StructureDB implementation updating ordinals of
	 * components correctly when an embedded datatype changes size.
	 * <p>
	 * The initial version of struct2.guardfield will have an ordinal of 15 to account for
	 * all the invisible undefines that are between the first field and the guardfield at offset
	 * 16.  When the data type for struct1 is overwritten with new information that
	 * changes it size, the undefines are no longer needed and the ordinal of guardfield should
	 * just be 1.
	 */
	@Test
	public void testStructDeclThenGrow() throws CancelledException, IOException, DWARFException {

		// CU1
		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry struct1Decl = newDeclStruct("struct1").create();
		DebugInfoEntry struct2 = newStruct("struct2", 20).create();
		newMember(struct2, "struct1field", struct1Decl, 0).create();
		newMember(struct2, "guardfield", intDIE, 16).create();

		addCompUnit();

		// CU2
		DebugInfoEntry int2DIE = addInt();

		DebugInfoEntry struct1Impl = newStruct("struct1", 16).create();
		newMember(struct1Impl, "f1", int2DIE, 0).create();
		newMember(struct1Impl, "f2", int2DIE, 4).create();
		newMember(struct1Impl, "f3", int2DIE, 8).create();
		newMember(struct1Impl, "f4", int2DIE, 12).create();

		importAllDataTypes();

		Structure struct2dt = (Structure)dataMgr.getDataType(uncatCP, "struct2");

		assertEquals(2, struct2dt.getNumComponents());
		assertEquals(2, struct2dt.getNumDefinedComponents());
	}

	@Test
	public void testStructDeclThatIsLaterDefined()
			throws CancelledException, IOException, DWARFException {

		// CU1
		// struct structA; // fwd decl
		// struct structB { structA struct1field; int guardfield; }
		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry structADecl = newDeclStruct("structA").create();
		DebugInfoEntry structB = newStruct("structB", 20).create();
		newMember(structB, "structAfield", structADecl, 0).create();
		newMember(structB, "guardfield", intDIE, 16).create();

		addCompUnit();

		// CU2
		// struct structB { structA struct1field; int guardfield; }
		// struct structA { int f1, f2, f3, f4; }
		// Redefine structB with the same info, but to a fully
		// specified structA instance instead of missing fwd decl.
		// The order of the DIE records is important.  The structure (structB) 
		// containing the problematic structA needs to be hit first so we can
		// test that cached types are handled correctly.
		DebugInfoEntry int2DIE = addInt();
		DebugInfoEntry structB_cu2 = newStruct("structB", 20).create();
		long structA_cu2_offset = dwarfProg.getRelativeDIEOffset(2);
		newMember(structB_cu2, "structAfield", structA_cu2_offset, 0).create();
		newMember(structB_cu2, "guardfield", int2DIE, 16).create();

		DebugInfoEntry structA_cu2 = newStruct("structA", 16).create();
		newMember(structA_cu2, "f1", int2DIE, 0).create();
		newMember(structA_cu2, "f2", int2DIE, 4).create();
		newMember(structA_cu2, "f3", int2DIE, 8).create();
		newMember(structA_cu2, "f4", int2DIE, 12).create();

		importAllDataTypes();

		Structure structAdt = (Structure) dataMgr.getDataType(uncatCP, "structA");
		Structure structBdt = (Structure) dataMgr.getDataType(uncatCP, "structB");
		assertEquals(2, structBdt.getNumComponents());
		assertEquals(4, structAdt.getNumComponents());
	}

	/*
	 * Test structure definition when the same structure is defined in two different CUs.
	 */
	@Test
	public void testStructDup() throws CancelledException, IOException, DWARFException {

		// CU1
		DebugInfoEntry intDIE1 = addInt();
		DebugInfoEntry floatDIE1 = addFloat();

		DebugInfoEntry structDIE1 = newStruct("mystruct", 100).create();
		newMember(structDIE1, "f1", intDIE1, 0).create();
		newMember(structDIE1, "f2", floatDIE1, 10).create();

		addCompUnit();

		// CU2
		DebugInfoEntry intDIE2 = addInt();
		DebugInfoEntry floatDIE2 = addFloat();

		DebugInfoEntry structDIE2 = newStruct("mystruct", 100).create();
		newMember(structDIE2, "f1", intDIE2, 0).create();
		newMember(structDIE2, "f2", floatDIE2, 10).create();

		importAllDataTypes();

		DataType structdt = dataMgr.getDataType(uncatCP, "mystruct");
		DataType structdt2 = dataMgr.getDataType(uncatCP, "mystruct.conflict");

		assertEquals(100, structdt.getLength());
		assertNull(structdt2);
	}

	/**
	 * Test structure definition when incompatible structure defs are present in two CUs.
	 * @throws CancelledException
	 * @throws IOException
	 * @throws DWARFException
	 */
	@Test
	public void testStructConflictDup() throws CancelledException, IOException, DWARFException {

		// CU1
		DebugInfoEntry intDIE1 = addInt();
		DebugInfoEntry floatDIE1 = addFloat();

		DebugInfoEntry structDIE1 = newStruct("mystruct", 100).create();
		newMember(structDIE1, "f1", intDIE1, 0).create();
		newMember(structDIE1, "f2", floatDIE1, 10).create();

		addCompUnit();

		// CU2
		DebugInfoEntry intDIE2 = addInt();
		DebugInfoEntry floatDIE2 = addFloat();

		// incompatible field datatypes when compared to previous def (int f1, float f2 vs float f1, int f2)
		DebugInfoEntry structDIE2 = newStruct("mystruct", 50).create();
		newMember(structDIE2, "f1", floatDIE2, 0).create();
		newMember(structDIE2, "f2", intDIE2, 10).create();

		importAllDataTypes();

		DataType structdt = dataMgr.getDataType(uncatCP, "mystruct");
		DataType structdt2 = dataMgr.getDataType(uncatCP, "mystruct.conflict");

		assertEquals(100, structdt.getLength());
		assertEquals(50, structdt2.getLength());
	}

	@Test
	public void testStructDupPartial() throws CancelledException, IOException, DWARFException {

		DebugInfoEntry floatDIE1 = addFloat();

		// this struct has only 1 field defined
		DebugInfoEntry structDIE1 = newStruct("mystruct", 100).create();
		// missing field def: newMember(structDIE1, "f1", intDIE1, 0).create();
		newMember(structDIE1, "f2", floatDIE1, 10).create();

		addCompUnit();

		DebugInfoEntry intDIE2 = addInt();
		DebugInfoEntry floatDIE2 = addFloat();

		// this struct has both fields defined
		DebugInfoEntry structDIE2 = newStruct("mystruct", 100).create();
		newMember(structDIE2, "f1", intDIE2, 0).create();
		newMember(structDIE2, "f2", floatDIE2, 10).create();

		importAllDataTypes();

		Structure structdt = (Structure) dataMgr.getDataType(uncatCP, "mystruct");
		DataType structdt2 = dataMgr.getDataType(uncatCP, "mystruct.conflict");

		assertEquals(100, structdt.getLength());
		assertEquals("f1", structdt.getComponentContaining(0).getFieldName());
		assertEquals("f2", structdt.getComponentContaining(10).getFieldName());
		assertNull(structdt2);
	}

	@Test
	public void testStructWithPtr() throws CancelledException, IOException, DWARFException {

		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry floatDIE = addFloat();

		DebugInfoEntry struct1DIE = newStruct("mystruct", 100).create();
		newMember(struct1DIE, "f1", intDIE, 0).create();
		newMember(struct1DIE, "f2", floatDIE, 10).create();

		DebugInfoEntry struct2DIE = newStruct("mystruct2", 10).create();
		newMember(struct2DIE, "ptr_to_struct1", addPtr(struct1DIE), 0).create();

		importAllDataTypes();

		DataType structdt = dataMgr.getDataType(uncatCP, "mystruct");
		Structure struct2dt = (Structure) dataMgr.getDataType(uncatCP, "mystruct2");

		assertEquals(100, structdt.getLength());
		assertEquals("ptr_to_struct1", struct2dt.getComponentContaining(0).getFieldName());
	}

	@Test
	@SuppressWarnings("unused")
	public void testStructWithLoop() throws CancelledException, IOException, DWARFException {

		// base types
		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry floatDIE = addFloat();
		//-----------------------
		// decl mystruct
		DebugInfoEntry struct1DeclDIE = newDeclStruct("mystruct").create();
		DebugInfoEntry struct1PtrDIE = addPtr(struct1DeclDIE);
		//-----------------------
		// mystruct2 { ptr_to_struct1 : struct1PtrDIE }
		DebugInfoEntry struct2DIE = newStruct("mystruct2", 10).create();
		DebugInfoEntry struct2F1DIE =
			newMember(struct2DIE, "ptr_to_struct1", struct1PtrDIE, 0).create();
		DebugInfoEntry struct2PtrDIE = addPtr(struct2DIE);
		//--------------------
		// spec mystruct { f1: intDIE; f2_ptr_to_struct2: struct2PtrDIE }
		DebugInfoEntry struct1DIE =
			newSpecStruct(struct1DeclDIE, 100).addString(DW_AT_name, "mystruct").create();
		DebugInfoEntry structF1DIE = newMember(struct1DIE, "f1", intDIE, 0).create();
		DebugInfoEntry structF2DIE =
			newMember(struct1DIE, "f2_ptr_to_struct2", struct2PtrDIE, 10).create();
		//----------------------

		importAllDataTypes();

		Structure structdt = (Structure) dataMgr.getDataType(uncatCP, "mystruct");
		Structure struct2dt = (Structure) dataMgr.getDataType(uncatCP, "mystruct2");

		assertEquals(100, structdt.getLength());
		assertEquals(10, struct2dt.getLength());

		assertEquals("f2_ptr_to_struct2", structdt.getDefinedComponents()[1].getFieldName());
		assertTrue(structdt.getDefinedComponents()[1].getDataType() instanceof Pointer);
	}

	@Test
	@SuppressWarnings("unused")
	public void testStructWithBadSelfLoop() throws CancelledException, IOException, DWARFException {

		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry floatDIE = addFloat();

		DebugInfoEntry struct1DeclDIE = newDeclStruct("mystruct").create();
		//-----------------------
		DebugInfoEntry struct1DIE =
			newSpecStruct(struct1DeclDIE, 100).addString(DW_AT_name, "mystruct").create();
		DebugInfoEntry structF1DIE = newMember(struct1DIE, "f1", intDIE, 0).create();
		DebugInfoEntry structF2DIE =
			newMember(struct1DIE, "f2_struct1", struct1DIE, 10).create();
		//----------------------

		importAllDataTypes();

		Structure structdt = (Structure) dataMgr.getDataType(uncatCP, "mystruct");
		assertEquals(100, structdt.getLength());
	}

	@Test
	@SuppressWarnings("unused")
	public void testStructConflictingMemberOffsets()
			throws CancelledException, IOException, DWARFException {
		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry floatDIE = addFloat();

		DebugInfoEntry declDIE = new DIECreator(dwarfProg, DWARFTag.DW_TAG_structure_type) //
				.addString(DW_AT_name, "mystruct")
				.addBoolean(DW_AT_declaration, true)
				.create();

		DebugInfoEntry structDIE = new DIECreator(dwarfProg, DWARFTag.DW_TAG_structure_type) //
				.addRef(DW_AT_specification, declDIE)
				.addInt(DW_AT_byte_size, 100)
				.create();

		DebugInfoEntry structF1DIE = new DIECreator(dwarfProg, DWARFTag.DW_TAG_member) //
				.addString(DW_AT_name, "f1")
				.addRef(DW_AT_type, intDIE)
				.addInt(DW_AT_data_member_location, 10)
				.setParent(structDIE)
				.create();

		DebugInfoEntry structF2DIE = new DIECreator(dwarfProg, DWARFTag.DW_TAG_member) //
				.addString(DW_AT_name, "f2")
				.addRef(DW_AT_type, floatDIE)
				.addInt(DW_AT_data_member_location, 10)
				.setParent(structDIE)
				.create();

		importAllDataTypes();

		Structure structdt = (Structure) dataMgr.getDataType(uncatCP, "mystruct");
		assertEquals(1, structdt.getDefinedComponents().length);
		assertEquals("f1", structdt.getDefinedComponents()[0].getFieldName());
	}

	@Test
	@SuppressWarnings("unused")
	public void testStructConflictingMemberNames()
			throws CancelledException, IOException, DWARFException {
		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry floatDIE = addFloat();

		DebugInfoEntry declDIE = new DIECreator(dwarfProg, DWARFTag.DW_TAG_structure_type) // 
				.addString(DW_AT_name, "mystruct")
				.addBoolean(DW_AT_declaration, true)
				.create();

		DebugInfoEntry structDIE = new DIECreator(dwarfProg, DWARFTag.DW_TAG_structure_type) //
				.addRef(DW_AT_specification, declDIE)
				.addInt(DW_AT_byte_size, 100)
				.create();

		DebugInfoEntry structF1DIE = new DIECreator(dwarfProg, DWARFTag.DW_TAG_member) //
				.addString(DW_AT_name, "f1")
				.addRef(DW_AT_type, intDIE)
				.addInt(DW_AT_data_member_location, 0)
				.setParent(structDIE)
				.create();

		DebugInfoEntry structF2DIE = new DIECreator(dwarfProg, DWARFTag.DW_TAG_member) //
				.addString(DW_AT_name, "f1")
				.addRef(DW_AT_type, floatDIE)
				.addInt(DW_AT_data_member_location, 10)
				.setParent(structDIE)
				.create();

		importAllDataTypes();

		Structure structdt = (Structure) dataMgr.getDataType(uncatCP, "mystruct");
		assertEquals(2, structdt.getDefinedComponents().length);
		assertEquals("f1", structdt.getDefinedComponents()[0].getFieldName());
		assertEquals("f1", structdt.getDefinedComponents()[1].getFieldName());
	}

	/**
	 * Tests when two structs in the same namespace have the same name and one includes the
	 * other.  (gcc linking options can cause types from different namespaces to be
	 * forced into the root namespace)
	 * <p>
	 * Currently this produces two structures one renamed with .conflict.
	 * <p>
	 * If this test starts failing it means this behavior in Ghidra's DTM has changed and
	 * the DWARF logic needs to be examined in light of those changes.
	 *
	 * @throws CancelledException
	 * @throws IOException
	 * @throws DWARFException
	 */
	@Test
	public void testStructMemberWithSameNameAsStruct()
			throws CancelledException, IOException, DWARFException {

		addInt();
		addFloat();

		DebugInfoEntry struct1aDIE = newStruct("mystruct", 1).create();
		DebugInfoEntry struct1bDIE = newStruct("mystruct", 4).create();
		newMember(struct1bDIE, "f1", struct1aDIE, 0).create();

		importAllDataTypes();

		DataType dt1a = dwarfDTM.getDataType(struct1aDIE.getOffset(), null);
		DataType dt1b = dwarfDTM.getDataType(struct1bDIE.getOffset(), null);

		assertEquals("mystruct", dt1a.getName());
		assertEquals("mystruct.conflict", dt1b.getName());
	}

	/**
	 * Tests when two structs have the same absolute type name and one includes the other,
	 * and they are the same size.
	 * <p>
	 * This (incorrectly) triggers an error checking case that prevents structs from
	 * including themselves as members.
	 *
	 * @throws CancelledException
	 * @throws IOException
	 * @throws DWARFException
	 */
	@Test
	@SuppressWarnings("unused")
	public void testStructMemberWithSameNameAsStruct2()
			throws CancelledException, IOException, DWARFException {

		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry floatDIE = addFloat();

		DebugInfoEntry struct1aDIE = newStruct("mystruct", 4).create();
		DebugInfoEntry struct1bDIE = newStruct("mystruct", 4).create();
		DebugInfoEntry struct1bF1DIE =
			newMember(struct1bDIE, "f1", struct1aDIE, 0).create();

		importAllDataTypes();

		Structure structdt = (Structure) dataMgr.getDataType(uncatCP, "mystruct");
		assertEquals(0, structdt.getNumDefinedComponents());
	}

	/**
	 * Test what happens when an impl struct contains a field who's db datatype has the same
	 * datatype name as the impl struct.  The embedded db struct needs to be empty and default
	 * sized (1 byte), and the outer impl struct needs to be bigger.
	 * <p>
	 * Currently the DTM resolve() will ignore the conflict handlers attempt to 
	 * replace since it will result in cyclic dependency issue.  It will instead
	 * rename the new structure as a conflict with its field refering to the original
	 * structure.
	 * <p>
	 * This situation happens in DWARF when there is a base class and a derived class
	 * that have the same name.  They are in different namespaces, but during compilation
	 * gcc was told to -feliminate-unused-debug-symbols which results in the DIE records
	 * for the structs being placed in the root namespace.
	 * <p>
	 * See GDTSD-351
	 */
	@Test
	public void testDTMIncorrectOverwrite() {

		DataType x = dataMgr.addDataType(new StructureDataType(uncatCP, "X", 1), null);
		StructureDataType x2 = new StructureDataType(uncatCP, "X", 4);
		x2.replaceAtOffset(0, x, 1, "f1", null);
		Structure x3 = (Structure) dataMgr.resolve(x2, DataTypeConflictHandler.REPLACE_HANDLER);
		assertEquals("X.conflict", x3.getName());
		DataTypeComponent dtc = x3.getComponent(0);
		DataType dtcDT = dtc.getDataType();
		assertEquals("f1", dtc.getFieldName());
		assertEquals("X", dtcDT.getName()); // undefined field is current behavior 
	}

	@Test
	public void testStructInherit() throws CancelledException, IOException, DWARFException {
		DebugInfoEntry intDIE = addInt();
		//-----------------------
		DebugInfoEntry baseDIE = newStruct("base", 10).create();
		newMember(baseDIE, "basef1", intDIE, 0).create();
		//--------------------
		DebugInfoEntry struct1DIE = newStruct("mystruct", 100).create();
		newInherit(struct1DIE, baseDIE, 0).create();
		newMember(struct1DIE, "f1", intDIE, 50).create();
		//--------------------

		importAllDataTypes();

		Structure structdt = (Structure) dataMgr.getDataType(uncatCP, "mystruct");
		DataTypeComponent dtc = structdt.getDefinedComponents()[0];
		DataType baseDT = dtc.getDataType();
		assertEquals("base", baseDT.getName());
		assertEquals("super_base", dtc.getFieldName());
	}

	@Test
	public void testEmbeddingStructWithPadding()
			throws CancelledException, IOException, DWARFException {
		// test when structs with trailing padding are embedded in an outer struct
		// and the outer struct has fields that are defined to be within the footprint
		// of the embedded struct's trailing padding.

		DebugInfoEntry intDIE = addInt();
		//-----------------------
		DebugInfoEntry baseDIE = newStruct("base", 20).create();
		newMember(baseDIE, "basef1", intDIE, 0).create();
		//--------------------
		DebugInfoEntry struct1DIE = newStruct("mystruct", 100).create();
		newInherit(struct1DIE, baseDIE, 0).create();
		newMember(struct1DIE, "f1", intDIE, 4).create();
		//--------------------

		importAllDataTypes();

		Structure structdt = (Structure) dataMgr.getDataType(uncatCP, "mystruct");
		DataTypeComponent dtc = structdt.getDefinedComponents()[0];
		DataType baseDT = dtc.getDataType();
		assertEquals("base", baseDT.getName());
		assertEquals("super_base", dtc.getFieldName());
		assertEquals(4, dtc.getLength());

		DataTypeComponent f1dtc = structdt.getDefinedComponents()[1];
		assertEquals("f1", f1dtc.getFieldName());
	}

	void dumpTypes() {
		List<DataType> dataTypes = new ArrayList<>();
		dataMgr.getAllDataTypes(dataTypes);

		for (DataType dt : dataTypes) {
			System.out.println("Data type: " + dt.getDataTypePath());
		}
	}

	@Test
	public void testStructNested() throws CancelledException, IOException, DWARFException {
		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry floatDIE = addFloat();

		//-----------------------
		DebugInfoEntry struct1DIE = newStruct("mystruct", 100).create();
		newMember(struct1DIE, "f1", intDIE, 0).create();
		newMember(struct1DIE, "f2", floatDIE, 10).create();
		//--------------------
		DebugInfoEntry struct2DIE =
			newStruct("mystruct2", 10).setParent(struct1DIE).create();
		newMember(struct2DIE, "blah1", intDIE, 0).create();
		//----------------------

		importAllDataTypes();

		Structure structdt = (Structure) dataMgr.getDataType(uncatCP, "mystruct");
		Structure struct2dt =
			(Structure) dataMgr.getDataType(new CategoryPath(uncatCP, "mystruct"), "mystruct2");

		assertNotNull(structdt);
		assertNotNull(struct2dt);
	}

	@Test
	public void testStructAnonNestedStructFurball()
			throws CancelledException, IOException, DWARFException {
		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry floatDIE = addFloat();

		//-----------------------
		DebugInfoEntry struct1DIE = newStruct("mystruct", 100).create();
		DebugInfoEntry anonStructDIE = newStruct(null, 10).setParent(struct1DIE).create();
		newMember(anonStructDIE, "blah1", intDIE, 0).create();
		newMember(struct1DIE, "f1", intDIE, 0).create();
		newMember(struct1DIE, "f2", floatDIE, 10).create();
		newMember(struct1DIE, "f3", anonStructDIE, 14).create();
		newMember(struct1DIE, "f4", anonStructDIE, 54).create();
		//----------------------

		importAllDataTypes();

		Structure structdt = (Structure) dataMgr.getDataType(uncatCP, "mystruct");
		DataTypeComponent dtc = structdt.getComponentContaining(14);
		DataType anonDT = dtc.getDataType();
		assertEquals("anon_struct_10_1_a7b17f80_for_f3_f4", anonDT.getName());
		assertEquals("/DWARF/_UNCATEGORIZED_/mystruct", anonDT.getCategoryPath().getPath());
	}

	@Test
	public void testStructAnonNaming()
			throws CancelledException, IOException, DWARFException {
		// tests that the dwarf context / location where an anon struct is defined
		// does not affect where the Ghidra data type is created (in the parent struct's
		// category path)
		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry floatDIE = addFloat();

		//-----------------------
		DebugInfoEntry anonStructDIE = newStruct(null, 10).create();
		newMember(anonStructDIE, "blah1", intDIE, 0).create();

		DebugInfoEntry struct1DIE = newStruct("mystruct", 100).create();
		newMember(struct1DIE, "f1", intDIE, 0).create();
		newMember(struct1DIE, "f2", floatDIE, 10).create();
		newMember(struct1DIE, "f3", anonStructDIE, 14).create();
		newMember(struct1DIE, "f4", anonStructDIE, 54).create();
		//----------------------

		importAllDataTypes();

		Structure structdt = (Structure) dataMgr.getDataType(uncatCP, "mystruct");
		DataTypeComponent dtc = structdt.getComponentContaining(14);
		DataType anonDT = dtc.getDataType();

		assertEquals("anon_struct_10_1_a7b17f80_for_f3_f4", anonDT.getName());
		assertEquals("/DWARF/_UNCATEGORIZED_/mystruct", anonDT.getCategoryPath().getPath());
	}

	@Test
	public void testTypedefToAnonStruct()
			throws CancelledException, IOException, DWARFException {
		// tests that an anon struct with a typedef to it gets the name of the typedef
		// and that the typedef itself isn't created

		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry anonStructDIE = newStruct(null, 10).create();
		newMember(anonStructDIE, "f1", intDIE, 0).create();
		newMember(anonStructDIE, "f2", intDIE, 0).create();
		addTypedef("mystruct", anonStructDIE);

		//----------------------

		importAllDataTypes();

		Structure mystruct = (Structure) dataMgr.getDataType(uncatCP, "mystruct");
		assertNotNull(mystruct);
		assertEquals(1, dataMgr.getDataTypes(uncatCP).length); // should not have an anon_struct_xyz either
	}

	@Test
	public void testStructFlexarray() throws CancelledException, IOException, DWARFException {

		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry arrayDIE = newArray(intDIE, false, -1);

		DebugInfoEntry structDIE = newStruct("mystruct", 100).create();
		newMember(structDIE, "f1", intDIE, 0).create();
		newMember(structDIE, "flexarray", arrayDIE, 100).create();

		importAllDataTypes();

		Structure structdt = (Structure) dataMgr.getDataType(uncatCP, "mystruct");
		DataTypeComponent component = structdt.getComponent(structdt.getNumComponents() - 1);
		assertNotNull(component);
		assertEquals(0, component.getLength());
		DataType dt = component.getDataType();
		assertTrue(dt instanceof Array);
		Array a = (Array) dt;
		assertEquals(0, a.getNumElements());
	}

	/*
	 * Test flex array where dims were specified with no value, relying on
	 * default.
	 */
	@Test
	public void testStructFlexarray_noValue()
			throws CancelledException, IOException, DWARFException {

		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry arrayDIE = newArray(intDIE, true, -1);

		DebugInfoEntry structDIE = newStruct("mystruct", 100).create();
		newMember(structDIE, "f1", intDIE, 0).create();
		newMember(structDIE, "flexarray", arrayDIE, 100).create();

		importAllDataTypes();

		Structure structdt = (Structure) dataMgr.getDataType(uncatCP, "mystruct");
		assertHasFlexArray(structdt);

	}

	/*
	 * Test flex array where dims were specified using a count=0 value instead of a
	 * upperbound=-1.
	 */
	@Test
	public void testStructFlexarray_0count()
			throws CancelledException, IOException, DWARFException {

		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry arrayDIE = newArrayUsingCount(intDIE, 0);

		DebugInfoEntry structDIE = newStruct("mystruct", 100).create();
		newMember(structDIE, "f1", intDIE, 0).create();
		newMember(structDIE, "flexarray", arrayDIE, 100).create();

		importAllDataTypes();

		Structure structdt = (Structure) dataMgr.getDataType(uncatCP, "mystruct");
		assertHasFlexArray(structdt);
	}

	@Test
	public void testStructInteriorFlexarray()
			throws CancelledException, IOException, DWARFException {

		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry arrayDIE = newArray(intDIE, false, -1);

		DebugInfoEntry structDIE = newStruct("mystruct", 100).create();
		newMember(structDIE, "f1", intDIE, 0).create();
		newMember(structDIE, "flexarray", arrayDIE, 100).create();

		importAllDataTypes();

		Structure structdt = (Structure) dataMgr.getDataType(uncatCP, "mystruct");

		List<DataTypeComponent> components = structdt.getComponentsContaining(100);
		assertEquals(1, components.size());
		DataTypeComponent component = components.get(0);
		assertEquals(0, component.getLength());
		DataType dt = component.getDataType();
		assertTrue(dt.isEquivalent(new ArrayDataType(IntegerDataType.dataType, 0, -1)));

		assertEquals(100, structdt.getLength());
	}

	@Test
	public void testStructZeroLenField()
			throws CancelledException, IOException, DWARFException {

		DebugInfoEntry intDIE = addInt();

		DebugInfoEntry emptyStructDIE = newStruct("emptystruct", 0).create();
		DebugInfoEntry structDIE = newStruct("mystruct", 10).create();
		newMember(structDIE, "f1", intDIE, 0).create();
		newMember(structDIE, "f2", emptyStructDIE, 4).create();

		importAllDataTypes();

		Structure structdt = (Structure) dataMgr.getDataType(uncatCP, "mystruct");

		assertEquals(2, structdt.getNumDefinedComponents());
		DataTypeComponent f1 = structdt.getDefinedComponents()[0];
		assertEquals(0, f1.getOffset());
		assertEquals(4, f1.getLength());
		DataTypeComponent f2 = structdt.getDefinedComponents()[1];
		assertEquals(4, f2.getOffset());
		assertTrue(f2.getDataType().isZeroLength());
		assertEquals(10, structdt.getLength());
	}

	@Test
	public void testStruct2ZeroLenField()
			throws CancelledException, IOException, DWARFException {

		DebugInfoEntry intDIE = addInt();

		DebugInfoEntry emptyStructDIE = newStruct("emptystruct", 0).create();
		DebugInfoEntry structDIE = newStruct("mystruct", 10).create();
		newMember(structDIE, "f1", intDIE, 0).create();
		newMember(structDIE, "f2", emptyStructDIE, 4).create();
		newMember(structDIE, "f3", emptyStructDIE, 4).create();
		newMember(structDIE, "f4", intDIE, 4).create();

		importAllDataTypes();

		Structure structdt = (Structure) dataMgr.getDataType(uncatCP, "mystruct");
		assertEquals(4, structdt.getNumDefinedComponents());
		DataTypeComponent f1 = structdt.getDefinedComponents()[0];
		assertEquals(0, f1.getOffset());
		assertEquals(4, f1.getLength());
		DataTypeComponent f2 = structdt.getDefinedComponents()[1];
		assertEquals(4, f2.getOffset());
		assertTrue(f2.getDataType().isZeroLength());
		DataTypeComponent f3 = structdt.getDefinedComponents()[2];
		assertEquals(4, f3.getOffset());
		assertTrue(f3.getDataType().isZeroLength());
		DataTypeComponent f4 = structdt.getDefinedComponents()[3];
		assertEquals(4, f4.getOffset());
		assertEquals(4, f4.getLength());

		assertEquals(10, structdt.getLength());
	}

	@Test
	public void testStructBitfields() throws CancelledException, IOException, DWARFException {

		DebugInfoEntry intDIE = addInt();

		DebugInfoEntry structDIE = newStruct("mystruct", 100).create();
		newMember(structDIE, "f1", intDIE, 0).create();
		newMember(structDIE, "bitfield1_3", intDIE, 4) //
			.addInt(DW_AT_bit_size, 3) //
			.addInt(DW_AT_bit_offset, 29) //
				.create();
		newMember(structDIE, "bitfield2_2", intDIE, 4) //
			.addInt(DW_AT_bit_size, 2) //
			.addInt(DW_AT_bit_offset, 27) //
				.create();
		newMember(structDIE, "bitfield3_9", intDIE, 4) //
			.addInt(DW_AT_bit_size, 9) //
			.addInt(DW_AT_bit_offset, 18) //
				.create();

		importAllDataTypes();

		Structure structdt = (Structure) dataMgr.getDataType(uncatCP, "mystruct");
		List<DataTypeComponent> bitfields = getBitFieldComponents(structdt);
		Set<Integer> expectedBitfieldSizes = new HashSet<>(Set.of(2, 3, 9));
		for (DataTypeComponent dtc : bitfields) {
			BitFieldDataType bfdt = (BitFieldDataType) dtc.getDataType();
			expectedBitfieldSizes.remove(bfdt.getBitSize());
		}
		assertTrue(expectedBitfieldSizes.size() == 0);
	}

	List<DataTypeComponent> getBitFieldComponents(Structure struct) {
		List<DataTypeComponent> results = new ArrayList<>();
		for (DataTypeComponent dtc : struct.getDefinedComponents()) {
			if (dtc.getDataType() instanceof BitFieldDataType) {
				results.add(dtc);
			}
		}
		return results;
	}

	@Test
	public void testStructNamespaceReservedChar_Colon()
			throws CancelledException, IOException, DWARFException {
		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry floatDIE = addFloat();

		//-----------------------
		DebugInfoEntry struct1DIE = newStruct("mystruct::with::colons", 100).create();
		DebugInfoEntry nestedStructDIE =
			newStruct("nested_struct", 10).setParent(struct1DIE).create();
		newMember(nestedStructDIE, "blah1", intDIE, 0).create();
		newMember(struct1DIE, "f1", intDIE, 0).create();
		newMember(struct1DIE, "f2", floatDIE, 10).create();
		newMember(struct1DIE, "f3", nestedStructDIE, 20).create();
		//----------------------

		importAllDataTypes();

		Structure structdt = (Structure) dataMgr.getDataType(uncatCP, "mystruct::with::colons");
		assertEquals(3, structdt.getNumDefinedComponents());
		Structure nestedStructDt = (Structure) structdt.getDefinedComponents()[2].getDataType();
		assertEquals("mystruct::with::colons", nestedStructDt.getCategoryPath().getName());
	}

	@Test
	public void testStructNamespaceReservedChar_FwdSlash()
			throws CancelledException, IOException, DWARFException {
		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry floatDIE = addFloat();

		//-----------------------
		DebugInfoEntry struct1DIE = newStruct("mystruct::operator/()", 100).create();
		DebugInfoEntry nestedStructDIE =
			newStruct("nested_struct", 10).setParent(struct1DIE).create();
		newMember(nestedStructDIE, "blah1", intDIE, 0).create();
		newMember(struct1DIE, "f1", intDIE, 0).create();
		newMember(struct1DIE, "f2", floatDIE, 10).create();
		newMember(struct1DIE, "f3", nestedStructDIE, 20).create();
		//----------------------

		importAllDataTypes();

		Structure structdt = (Structure) dataMgr.getDataType(uncatCP, "mystruct::operator/()");
		assertEquals(3, structdt.getNumDefinedComponents());
		Structure nestedStructDt = (Structure) structdt.getDefinedComponents()[2].getDataType();
		assertEquals("mystruct::operator/()", nestedStructDt.getCategoryPath().getName());
	}

	@Test
	public void testStructNamespaceReservedChar_Spaces()
			throws CancelledException, IOException, DWARFException {
		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry floatDIE = addFloat();

		//-----------------------
		DebugInfoEntry struct1DIE = newStruct("mystruct<int, float>", 100).create();
		newMember(struct1DIE, "f1", intDIE, 0).create();
		newMember(struct1DIE, "f2", floatDIE, 10).create();
		//----------------------

		importAllDataTypes();

		Structure structdt = (Structure) dataMgr.getDataType(uncatCP, "mystruct<int,_float>");
		assertEquals(2, structdt.getNumDefinedComponents());
	}
	//----------------------------------------------------------------------------------------------------

	@Test
	public void testUnion() throws CancelledException, IOException, DWARFException {

		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry doubleDIE = addDouble();

		DebugInfoEntry unionDeclDIE = new DIECreator(dwarfProg, DWARFTag.DW_TAG_union_type) //
				.addString(DW_AT_name, "myunion")
				.addBoolean(DW_AT_declaration, true)
				.create();

		//-----------------------

		int UNION_STATIC_SIZE = 10;
		DebugInfoEntry unionDIE = new DIECreator(dwarfProg, DWARFTag.DW_TAG_union_type) //
				.addRef(DW_AT_specification, unionDeclDIE)
				.addInt(DW_AT_byte_size, UNION_STATIC_SIZE)
				.create();

		newMember(unionDIE, "f1", intDIE, -1).create();
		newMember(unionDIE, "f2_self", unionDIE, -1).create();
		newMember(unionDIE, "f3", doubleDIE, -1).create();

		//----------------------

		importAllDataTypes();

		Union uniondt = (Union) dataMgr.getDataType(uncatCP, "myunion");

		assertEquals("f1", uniondt.getComponent(0).getFieldName());
		// "f2_self" field should not have been added as it was a recursive reference back to ourself
		assertEquals("f3", uniondt.getComponent(1).getFieldName());
		assertEquals(UNION_STATIC_SIZE, uniondt.getLength());
	}

	@Test
	public void testUnionFlexArray() throws CancelledException, IOException, DWARFException {
		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry arrayDIE = newArray(intDIE, false, -1);

		int UNION_STATIC_SIZE = 10;
		DebugInfoEntry unionDIE = new DIECreator(dwarfProg, DWARFTag.DW_TAG_union_type) //
				.addString(DW_AT_name, "myunion")
				.addInt(DW_AT_byte_size, UNION_STATIC_SIZE)
				.create();

		newMember(unionDIE, "f1", intDIE, -1).create();
		newMember(unionDIE, "flexarray", arrayDIE, -1).create();

		//----------------------

		importAllDataTypes();

		Union uniondt = (Union) dataMgr.getDataType(uncatCP, "myunion");

		assertEquals("f1", uniondt.getComponent(0).getFieldName());
		DataTypeComponent flexDTC = uniondt.getComponent(1);
		assertEquals("flexarray", flexDTC.getFieldName());
		assertTrue(flexDTC.getDataType() instanceof Array);
	}

	//----------------------------------------------------------------------------------------------
	/**
	 * Test skipping const, volatile data types.
	 * @throws CancelledException
	 * @throws IOException
	 * @throws DWARFException
	 */
	@Test
	public void testConstElide() throws CancelledException, IOException, DWARFException {
		DebugInfoEntry intDIE = addInt();

		DebugInfoEntry constDIE =
			new DIECreator(dwarfProg, DWARFTag.DW_TAG_const_type).addRef(DW_AT_type, intDIE)
					.create();

		DebugInfoEntry volatileDIE =
			new DIECreator(dwarfProg, DWARFTag.DW_TAG_volatile_type).addRef(DW_AT_type, intDIE)
					.create();

		DebugInfoEntry volatileconstDIE =
			new DIECreator(dwarfProg, DWARFTag.DW_TAG_volatile_type).addRef(DW_AT_type, constDIE)
					.create();

		DebugInfoEntry structDIE = new DIECreator(dwarfProg, DWARFTag.DW_TAG_structure_type) //
				.addString(DW_AT_name, "mystruct")
				.addInt(DW_AT_byte_size, 100)
				.create();

		newMember(structDIE, "f1", intDIE, 0).create();
		newMember(structDIE, "f2", constDIE, 10).create();
		newMember(structDIE, "f3", volatileDIE, 20).create();
		newMember(structDIE, "f4", volatileconstDIE, 40).create();

		importAllDataTypes();

		Structure structdt = (Structure) dataMgr.getDataType(uncatCP, "mystruct");
		DataTypeComponent f1dtc = structdt.getComponentContaining(0);
		DataTypeComponent f2dtc = structdt.getComponentContaining(10);
		DataTypeComponent f3dtc = structdt.getComponentContaining(20);
		DataTypeComponent f4dtc = structdt.getComponentContaining(40);

		assertEquals(f1dtc.getDataType(), f2dtc.getDataType());
		assertEquals(f1dtc.getDataType(), f3dtc.getDataType());
		assertEquals(f1dtc.getDataType(), f4dtc.getDataType());
	}

	// not implemented yet
	public void testNamespace() {

	}

	// not implemented yet
	public void testNamespaceAnonType() {
		// anon struct
	}

	/*
	 * Test array defintions that use upper_bound attribute
	 */
	@Test
	public void testArray() throws CancelledException, IOException, DWARFException {
		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry arrayDIE = newArray(intDIE, false, 10);

		importAllDataTypes();

		Array arr = (Array) dwarfDTM.getDataType(arrayDIE.getOffset(), null);
		assertNotNull(arr);
		assertEquals(11, arr.getNumElements());
	}

	/*
	 * Tests array definitions that use count attribute instead of upper_bounds
	 */
	@Test
	public void testArrayWithCountAttr() throws CancelledException, IOException, DWARFException {
		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry arrayDIE = newArrayUsingCount(intDIE, 10);

		importAllDataTypes();

		Array arr = (Array) dwarfDTM.getDataType(arrayDIE.getOffset(), null);
		assertNotNull(arr);
		assertEquals(10, arr.getNumElements());
	}
	
	@Test
	public void testArrayWithZeroLenDataType()
			throws CancelledException, IOException, DWARFException {
		// Tests that an array with non-zero elements, but with zero-len data type
		// becomes a zero-element array.  (yuck)
		DebugInfoEntry emptyStructDIE = newStruct("emptystruct", 0).create();
		DebugInfoEntry arrayDIE = newArrayUsingCount(emptyStructDIE, 10);

		importAllDataTypes();

		Structure emptyStruct = (Structure) dwarfDTM.getDataType(emptyStructDIE.getOffset(), null);
		Array arr = (Array) dwarfDTM.getDataType(arrayDIE.getOffset(), null);
		assertTrue(emptyStruct.isZeroLength());
		assertEquals(0, arr.getNumElements());
		assertTrue(arr.isZeroLength());
	}

	@Test
	public void testArrayWithZeroElements()
			throws CancelledException, IOException, DWARFException {
		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry arrayDIE = newArrayUsingCount(intDIE, 0);

		importAllDataTypes();

		Array arr = (Array) dwarfDTM.getDataType(arrayDIE.getOffset(), null);
		assertEquals(0, arr.getNumElements());
		assertTrue(arr.isZeroLength());
	}

	// not implemented yet
	public void testSubr() {
		// func ptrs
		// unamed, with typedefs pointing to
	}

	// not implemented yet
	public void testDeclParentVsHeadParent() {
		// test that type's name is derived from its decl die location
		// instead of its spec location.
	}

	// not implemented yet
	public void testMangledLinkageNames() {
		// test _Zblahblh
	}

	// not implemented yet
	public void testMangledLinkageInfoFromChildren() {
		// grub in children's info for their linkage and use it for us (their parent)
	}

	private static String longName(String prefix, String sufix, int len) {
		StringBuilder sb = new StringBuilder(prefix);
		for (int i = 0; i < len; i++) {
			sb.append((char) ('a' + (i % 26)));
		}
		sb.append(sufix);
		return sb.toString();
	}

	@Test
	public void testExtremeNames() throws CancelledException, DWARFException, IOException {

		int nameLenCutoff = SymbolUtilities.MAX_SYMBOL_NAME_LENGTH;

		String structLongName = longName("mystruct_", "", 1000);
		String templateLongName = longName("mystruct_", "", 1000);
		String substructLongName = longName("substruct_", "", 200);
		String exactName = longName("short", "", nameLenCutoff - "short".length());
		String exactTemplateName =
			longName("shorttemplate<", ">", nameLenCutoff - "shorttemplate<>".length());
		String exactTemplateName2 =
			longName("", "template<X>", nameLenCutoff - "template<X>".length() + 1);

		DebugInfoEntry structDIE = newStruct(structLongName, 0).create();
		DebugInfoEntry exactDIE = newStruct(exactName, 0).create();
		DebugInfoEntry exactTemplateDIE = newStruct(exactTemplateName, 0).create();
		DebugInfoEntry exactTemplateDIE2 = newStruct(exactTemplateName2, 0).create();
		DebugInfoEntry templateDIE = newStruct(templateLongName, 0).create();
		DebugInfoEntry struct3DIE =
			newStruct(substructLongName, 0).setParent(templateDIE).create();

		buildMockDIEIndexes();

		DWARFName sDNI = dwarfProg.getName(getAggregate(structDIE));
		DWARFName exactDNI = dwarfProg.getName(getAggregate(exactDIE));
		DWARFName exactTemplateDNI = dwarfProg.getName(getAggregate(exactTemplateDIE));
		DWARFName exactTemplateDNI2 = dwarfProg.getName(getAggregate(exactTemplateDIE2));
		DWARFName templateDNI = dwarfProg.getName(getAggregate(templateDIE));
		DWARFName s3DNI = dwarfProg.getName(getAggregate(struct3DIE));

		assertEquals(structLongName, sDNI.getOriginalName());

		assertEquals(exactName, exactDNI.getOriginalName());
		assertEquals(exactName, exactDNI.getName());

		assertEquals(exactTemplateName, exactTemplateDNI.getName());
		assertEquals(exactTemplateName, exactTemplateDNI.getOriginalName());

		assertTrue(exactTemplateDNI2.getName().length() < nameLenCutoff);

		assertEquals(templateLongName, templateDNI.getOriginalName());
		assertEquals(substructLongName, s3DNI.getOriginalName());

		assertTrue(sDNI.getName().length() < nameLenCutoff);
		assertTrue(templateDNI.getName().length() < nameLenCutoff);
		assertTrue(s3DNI.getName().length() < nameLenCutoff);
	}

	// not implemented yet
	public void testConflictingNamespace() {
		// test a conflict between namespace and class symbols and other symbols
		// when a DNI is trying to traverse to the final namespace
	}

	/**
	 * Tests that endless loops (impossible without manual editing or intentional creation of bad
	 * data) does not cause endless loop when processing.
	 *
	 * @throws CancelledException
	 * @throws IOException
	 * @throws DWARFException
	 */
	@Test
	public void testHostilePtrLoop() throws CancelledException, IOException, DWARFException {

		addCompUnit();

		// hack to make a forward reference to a DIE that hasn't been created yet.
		// This creates a hostile loop in the data type references.
		long fwdDIE = dwarfProg.getRelativeDIEOffset(1);
		DebugInfoEntry constDIE =
			new DIECreator(dwarfProg, DWARFTag.DW_TAG_const_type).addRef(DW_AT_type, fwdDIE)
					.create();
		DebugInfoEntry ptrDIE = addPtr(constDIE);

		importAllDataTypes();

		DataType constDT = dwarfDTM.getDataType(constDIE.getOffset(), null);
		DataType ptrDT = dwarfDTM.getDataType(ptrDIE.getOffset(), null);

		assertNotNull(constDT);
		assertEquals(dwarfDTM.getVoidType(), ((Pointer) ptrDT).getDataType());
	}

	/**
	 * Tests that struct definitions (ref'd via a pointer) overwrite a previous
	 * empty decl only DIE.
	 * <pre>
	 * CU1:
	 * 	ptr => struct1 { empty }
	 * CU2:
	 * 	ptr -> struct1 { field1 }
	 * </pre>
	 * This is necessary because DataType equiv checking doesn't traverse pointers and
	 * the resolve logic in the DataTypeManager was choosing the existing ptr data type
	 * instance which pointed to the empty struct instead of descending into what the pointer
	 * pointed to and comparing the contents of the struct to determine equiv.
	 * <p>
	 * The fix isn't to change the resolve logic or equiv logic, but to ensure that the
	 * direct struct datatype DIE is also submitted to the DTM to be resolved, instead of
	 * relying on the result that came out of the DTM when resolving the ptr DIE.
	 *
	 * @throws DWARFException
	 * @throws IOException
	 * @throws CancelledException
	 */
	@Test
	public void testStructDeclViaPtr() throws CancelledException, IOException, DWARFException {

		// CU1
		addFwdPtr(1); // points to the DIE created in the next line even though it doesn't exist yet
		newDeclStruct("mystruct").create();

		addCompUnit();

		// CU2
		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry floatDIE = addFloat();

		addFwdPtr(1); // fwd points to structDIE even though it doesn't exist yet
		DebugInfoEntry structDIE = newStruct("mystruct", 100).create();
		newMember(structDIE, "f1", intDIE, 0).create();
		newMember(structDIE, "f2", floatDIE, 10).create();

		importAllDataTypes();

		DataType structdt = dataMgr.getDataType(uncatCP, "mystruct");
		assertEquals(100, structdt.getLength());

	}

	/*
	 * These testAsymetricEquivTypedefedBaseTypes tests test when DWARF in 2 different
	 * CUs defines the same datatype in slightly different ways, where one CU uses a
	 * typedef to a basetype and the other CU just directly references the basetype.
	 * (ie. one CU was compiled with C rules/options, the other CU was compiled with C++ rules/options)
	 */
	@Test
	public void testAsymetricEquivTypedefedBaseTypes_fwd()
			throws CancelledException, IOException, DWARFException {
		// CU1
		// this struct has a field with a typedef to a basetype int
		DebugInfoEntry typedefDIE = addTypedef("intX_t", addInt());
		DebugInfoEntry structDIE = newStruct("mystruct", 10).create();
		newMember(structDIE, "f1", typedefDIE, 0).create();

		addCompUnit();

		// CU2
		// this struct has a field with a basetype int
		DebugInfoEntry cu2IntDIE = addInt();
		DebugInfoEntry structDIE_CU2 = newStruct("mystruct", 10).create();
		newMember(structDIE_CU2, "f1", cu2IntDIE, 0).create();

		importAllDataTypes();

		DataType dataType = dwarfDTM.getDataType(structDIE.getOffset(), null);
		DataType dataType2 = dwarfDTM.getDataType(structDIE_CU2.getOffset(), null);

		assertTrue(dataType == dataType2);
	}

	@Test
	public void testAsymetricEquivTypedefedBaseTypes_rev()
			throws CancelledException, IOException, DWARFException {

		// CU1
		DebugInfoEntry cu1IntDIE = addInt();

		// this struct has a field with a basetype int
		DebugInfoEntry structDIE = newStruct("mystruct", 10).create();
		newMember(structDIE, "f1", cu1IntDIE, 0).create();

		addCompUnit();

		// CU2
		DebugInfoEntry cu2IntDIE = addInt();
		DebugInfoEntry cu2TypedefDIE = addTypedef("intX_t", cu2IntDIE);

		// this struct has a field with a typedef of a basetype int
		DebugInfoEntry structDIE_CU2 = newStruct("mystruct", 10).create();
		newMember(structDIE_CU2, "f1", cu2TypedefDIE, 0).create();

		importAllDataTypes();

		DataType dataType = dwarfDTM.getDataType(structDIE.getOffset(), null);
		DataType dataType2 = dwarfDTM.getDataType(structDIE_CU2.getOffset(), null);

		assertTrue(dataType == dataType2);
	}

	@Test
	public void testAsymetricEquivTypedefedBaseTypes_not_false_positive()
			throws CancelledException, IOException, DWARFException {

		// CU1
		// this struct has a field with a typedef to a basetype int
		DebugInfoEntry cu2TypedefDIE = addTypedef("intX_t", addInt());
		DebugInfoEntry structDIE = newStruct("mystruct", 10).create();
		newMember(structDIE, "f1", cu2TypedefDIE, 0).create();

		// CU2
		DebugInfoEntry cu2FloatDIE = addFloat();
		// this struct has a field with a basetype float, which is incompatible with int
		DebugInfoEntry structDIE_CU2 = newStruct("mystruct", 10).create();
		newMember(structDIE_CU2, "f1", cu2FloatDIE, 0).create();

		importAllDataTypes();

		DataType dataType = dwarfDTM.getDataType(structDIE.getOffset(), null);
		DataType dataType2 = dwarfDTM.getDataType(structDIE_CU2.getOffset(), null);

		// should get 2 datatypes, one with a conflict name
		assertTrue(dataType != dataType2);
		assertTrue(dataType2.getName().endsWith(DataType.CONFLICT_SUFFIX));
	}

	//=================================================================================
	// Enum tests
	//=================================================================================
	@Test
	public void testEnum() throws CancelledException, IOException, DWARFException {
		DebugInfoEntry enumDIE = createEnum("enum1", 4);
		addEnumValue(enumDIE, "val1", 1);

		importAllDataTypes();

		Enum enumDT = (Enum) dwarfDTM.getDataType(enumDIE.getOffset(), null);
		assertEquals("enum1", enumDT.getName());
		assertEquals(1, enumDT.getValue("val1"));
		assertEquals(1, enumDT.getNames().length);
	}

	@Test
	public void testAnonEnum() throws CancelledException, IOException, DWARFException {
		DebugInfoEntry enumDIE = createEnum(null, 4);
		addEnumValue(enumDIE, "val1", 1);

		importAllDataTypes();

		Enum enumDT = (Enum) dwarfDTM.getDataType(enumDIE.getOffset(), null);
		assertEquals(1, enumDT.getValue("val1"));
		assertEquals(1, enumDT.getNames().length);
	}

	@Test
	public void testAnonEnumWithTypedef() throws CancelledException, IOException, DWARFException {
		DebugInfoEntry enumDIE = createEnum(null, 4);
		addEnumValue(enumDIE, "val1", 1);
		DebugInfoEntry typedefDIE = addTypedef("typedefed_enum", enumDIE);

		importAllDataTypes();

		Enum enumDT = (Enum) dwarfDTM.getDataType(enumDIE.getOffset(), null);
		Enum typedefDT = (Enum) dwarfDTM.getDataType(typedefDIE.getOffset(), null);

		assertTrue(enumDT == typedefDT);
		assertEquals(1, enumDT.getValue("val1"));
	}

	@Test
	public void testMultiAnonEnumWithTypedef()
			throws CancelledException, IOException, DWARFException {
		DebugInfoEntry enum1DIE = createEnum(null, 4);
		addEnumValue(enum1DIE, "val1", 1);
		DebugInfoEntry typedef1DIE = addTypedef("typedefed_enum1", enum1DIE);

		DebugInfoEntry enum2DIE = createEnum(null, 4);
		addEnumValue(enum2DIE, "abc1", 1);
		DebugInfoEntry typedef2DIE = addTypedef("typedefed_enum2", enum2DIE);

		importAllDataTypes();

		Enum enum1DT = (Enum) dwarfDTM.getDataType(enum1DIE.getOffset(), null);
		Enum enum2DT = (Enum) dwarfDTM.getDataType(enum2DIE.getOffset(), null);
		Enum typedef1DT = (Enum) dwarfDTM.getDataType(typedef1DIE.getOffset(), null);
		Enum typedef2DT = (Enum) dwarfDTM.getDataType(typedef2DIE.getOffset(), null);

		assertTrue(enum1DT == typedef1DT);
		assertTrue(enum2DT == typedef2DT);

		assertEquals(1, enum1DT.getNames().length);
		assertEquals(1, enum2DT.getNames().length);

		assertEquals("val1", enum1DT.getNames()[0]);
		assertEquals("abc1", enum2DT.getNames()[0]);
	}

	/**
	 * Test multiple anon enum with multiple typesdefs pointing to each anon enums.
	 * <p>
	 * Multiple inbound typedefs should disable the isCopyRenameAnonTypes feature for that
	 * enum.
	 *
	 * @throws CancelledException
	 * @throws IOException
	 * @throws DWARFException
	 */
	@Test
	public void testMultiAnonEnumWithTypedef2()
			throws CancelledException, IOException, DWARFException {
		DebugInfoEntry enum1DIE = createEnum(null, 4);
		addEnumValue(enum1DIE, "val1", 1);
		DebugInfoEntry typedef1aDIE = addTypedef("typedefed_enum1a", enum1DIE);

		DebugInfoEntry enum2DIE = createEnum(null, 4);
		addEnumValue(enum2DIE, "abc1", 1);
		DebugInfoEntry typedef2aDIE = addTypedef("typedefed_enum2a", enum2DIE);

		DebugInfoEntry enum3DIE = createEnum(null, 4);
		addEnumValue(enum3DIE, "three1", 1);
		DebugInfoEntry typedef3DIE = addTypedef("typedefed_enum3", enum3DIE);

		DebugInfoEntry enum4DIE = createEnum(null, 4);
		addEnumValue(enum4DIE, "four1", 1);

		DebugInfoEntry typedef1bDIE = addTypedef("typedefed_enum1b", enum1DIE);
		DebugInfoEntry typedef2bDIE = addTypedef("typedefed_enum2b", enum2DIE);

		importAllDataTypes();

		Enum enum1DT = (Enum) dwarfDTM.getDataType(enum1DIE.getOffset(), null);
		Enum enum2DT = (Enum) dwarfDTM.getDataType(enum2DIE.getOffset(), null);
		Enum enum3DT = (Enum) dwarfDTM.getDataType(enum3DIE.getOffset(), null);
		TypeDef typedef1aDT = (TypeDef) dwarfDTM.getDataType(typedef1aDIE.getOffset(), null);
		TypeDef typedef1bDT = (TypeDef) dwarfDTM.getDataType(typedef1bDIE.getOffset(), null);
		TypeDef typedef2aDT = (TypeDef) dwarfDTM.getDataType(typedef2aDIE.getOffset(), null);
		TypeDef typedef2bDT = (TypeDef) dwarfDTM.getDataType(typedef2bDIE.getOffset(), null);
		Enum typedef3DT = (Enum) dwarfDTM.getDataType(typedef3DIE.getOffset(), null);

		assertSame(enum1DT, enum2DT);
		assertNotSame(enum1DT, enum3DT);
		assertEquals("typedefed_enum1a", typedef1aDT.getName());
		assertEquals("typedefed_enum1b", typedef1bDT.getName());
		assertEquals("typedefed_enum2a", typedef2aDT.getName());
		assertEquals("typedefed_enum2b", typedef2bDT.getName());
		assertSame(enum3DT, typedef3DT);
		assertEquals(3, enum1DT.getNames().length);
		assertEquals(1, enum3DT.getNames().length);
	}
}
