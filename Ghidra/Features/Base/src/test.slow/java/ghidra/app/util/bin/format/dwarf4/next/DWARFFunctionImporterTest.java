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
package ghidra.app.util.bin.format.dwarf4.next;

import static org.junit.Assert.*;

import java.util.List;

import java.io.IOException;

import org.junit.Test;

import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.bin.format.dwarf4.*;
import ghidra.app.util.bin.format.dwarf4.encoding.DWARFAttribute;
import ghidra.app.util.bin.format.dwarf4.encoding.DWARFSourceLanguage;
import ghidra.app.util.bin.format.dwarf4.expression.DWARFExpressionOpCodes;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.*;

public class DWARFFunctionImporterTest extends DWARFTestBase {

	@Test
	public void testRustMethod_HasParamDefs()
			throws CancelledException, IOException, DWARFException {
		// test that Ghidra functions in a Rust compilation unit do have their info set
		// if they look like they have normal param info

		cu = new MockDWARFCompilationUnit(dwarfProg, 0x1000, 0x2000, 0,
			DWARFCompilationUnit.DWARF_32, (short) 4, 0, (byte) 8, 0,
			DWARFSourceLanguage.DW_LANG_Rust);
		cu2 = null;
		setMockCompilationUnits(cu);

		DebugInfoEntry intDIE = addInt(cu);
		DebugInfoEntry fooDIE = newSubprogram("foo", intDIE, 0x410, 10).create(cu);
		newFormalParam(fooDIE, "param1", intDIE, DWARFExpressionOpCodes.DW_OP_fbreg, 0x6c)
				.create(cu);

		importFunctions();

		Function fooFunc = program.getListing().getFunctionAt(addr(0x410));
		assertNotNull(fooFunc);

		assertEquals("foo", fooFunc.getName());
		DataType returnType = fooFunc.getReturnType();
		assertNotNull(returnType);
		assertEquals("int", returnType.getName());

		Parameter[] fooParams = fooFunc.getParameters();
		assertEquals(fooParams.length, 1);
		assertEquals("param1", fooParams[0].getName());
		assertEquals("int", fooParams[0].getDataType().getName());
	}

	@Test
	public void testRustMethod_NoParamDefs()
			throws CancelledException, IOException, DWARFException {
		// test that Ghidra functions in a Rust compilation unit don't have their info set
		// if they look like they are one of the stub DIE entries that Rust creates
		cu = new MockDWARFCompilationUnit(dwarfProg, 0x1000, 0x2000, 0,
			DWARFCompilationUnit.DWARF_32, (short) 4, 0, (byte) 8, 0,
			DWARFSourceLanguage.DW_LANG_Rust);
		cu2 = null;
		setMockCompilationUnits(cu);

		DebugInfoEntry intDIE = addInt(cu);
		newSubprogram("foo", intDIE, 0x410, 10).create(cu);

		importFunctions();

		Function fooFunc = program.getListing().getFunctionAt(addr(0x410));
		assertNotNull(fooFunc);

		assertEquals("foo", fooFunc.getName());
		DataType returnType = fooFunc.getReturnType();
		assertNotNull(returnType);
		assertEquals("undefined", returnType.getName());
	}

	@Test
	public void testNotRustMethod_NoParamDefs()
			throws CancelledException, IOException, DWARFException {
		// test that Ghidra functions in a non-Rust compilation unit do have their info set
		// even if their param info is empty.
		cu = new MockDWARFCompilationUnit(dwarfProg, 0x1000, 0x2000, 0,
			DWARFCompilationUnit.DWARF_32, (short) 4, 0, (byte) 8, 0,
			DWARFSourceLanguage.DW_LANG_C);
		cu2 = null;
		setMockCompilationUnits(cu);

		DebugInfoEntry intDIE = addInt(cu);
		newSubprogram("foo", intDIE, 0x410, 10).create(cu);

		importFunctions();

		Function fooFunc = program.getListing().getFunctionAt(addr(0x410));
		assertNotNull(fooFunc);

		assertEquals("foo", fooFunc.getName());
		DataType returnType = fooFunc.getReturnType();
		assertNotNull(returnType);
		assertEquals("int", returnType.getName());
	}

	@Test
	public void testNamespace_with_reserved_chars()
			throws CancelledException, IOException, DWARFException {
		// simulate what happens when a C++ operator/ or a templated classname
		// that contains a namespace template argument (templateclass<ns1::ns2::argclass>)
		// is encountered and a Ghidra namespace is created

		DebugInfoEntry intDIE = addInt(cu);
		DebugInfoEntry floatDIE = addFloat(cu);
		DebugInfoEntry struct1DIE = newStruct("mystruct::operator/()", 100).create(cu);
		DebugInfoEntry nestedStructPtrDIE = addFwdPtr(cu, 1);
		DebugInfoEntry nestedStructDIE =
			newStruct("nested_struct", 10).setParent(struct1DIE).create(cu);
		newMember(nestedStructDIE, "blah1", intDIE, 0).create(cu);
		DebugInfoEntry fooDIE =
			newSubprogram("foo", intDIE, 0x410, 10).setParent(nestedStructDIE).create(cu);
		newFormalParam(fooDIE, "this", nestedStructPtrDIE, DWARFExpressionOpCodes.DW_OP_fbreg, 0x6c)
				.create(cu);

		newMember(struct1DIE, "f1", intDIE, 0).create(cu);
		newMember(struct1DIE, "f2", floatDIE, 10).create(cu);
		newMember(struct1DIE, "f3", nestedStructDIE, 20).create(cu);

		importFunctions();

		Function fooFunc = program.getListing().getFunctionAt(addr(0x410));
		List<Namespace> nsParts = NamespaceUtils.getNamespaceParts(fooFunc.getParentNamespace());

		assertEquals("foo", fooFunc.getName());
		assertEquals("nested_struct",
			((Pointer) fooFunc.getParameter(0).getDataType()).getDataType().getName());
		assertEquals("__thiscall", fooFunc.getCallingConventionName());
		assertEquals("nested_struct", nsParts.get(nsParts.size() - 1).getName());
		assertEquals("mystruct::operator/()", nsParts.get(nsParts.size() - 2).getName());

		// Test that VariableUtilities can find the structure for the this* pointer
		Structure nestedStructDT1 = (Structure) dataMgr
				.getDataType(new CategoryPath(uncatCP, "mystruct::operator/()"), "nested_struct");
		Structure nestedStructDT2 = VariableUtilities.findExistingClassStruct(fooFunc);
		assertTrue(nestedStructDT1 == nestedStructDT2);
	}

	@Test
	public void testNoReturnFlag_True() throws CancelledException, IOException, DWARFException {
		DebugInfoEntry intDIE = addInt(cu);
		DIECreator func = newSubprogram("foo", intDIE, 0x410, 10);
		func.addBoolean(DWARFAttribute.DW_AT_noreturn, true);
		func.create(cu);

		importFunctions();

		Function fooFunc = program.getListing().getFunctionAt(addr(0x410));
		assertNotNull(fooFunc);
		assertTrue(fooFunc.hasNoReturn());
	}

	@Test
	public void testNoReturnFlag_False() throws CancelledException, IOException, DWARFException {
		DebugInfoEntry intDIE = addInt(cu);
		DIECreator func = newSubprogram("foo", intDIE, 0x410, 10);
		func.create(cu);

		importFunctions();

		Function fooFunc = program.getListing().getFunctionAt(addr(0x410));
		assertNotNull(fooFunc);
		assertFalse(fooFunc.hasNoReturn());
	}

	@Test
	public void testDetailParamLocation_Converted_to_spill()
			throws CancelledException, IOException, DWARFException {
		// Test that a parameter's storage info is ignored if it looks invalid.
		// In this case, it refers to a location in the function's local variable area, so
		// it should have been converted to a spill local variable.

		DebugInfoEntry intDIE = addInt(cu);
		DebugInfoEntry fooDIE = newSubprogram("foo", intDIE, 0x410, 10).create(cu);
		newFormalParam(fooDIE, "param1", intDIE, DWARFExpressionOpCodes.DW_OP_fbreg, 0x6c) // fbreg -14, func local variable area
				.create(cu);

		importFunctions();

		Function fooFunc = program.getListing().getFunctionAt(addr(0x410));
		assertNotNull(fooFunc);

		assertEquals("foo", fooFunc.getName());
		DataType returnType = fooFunc.getReturnType();
		assertNotNull(returnType);
		assertEquals("int", returnType.getName());

		Parameter[] fooParams = fooFunc.getParameters();
		assertEquals(fooParams.length, 1);
		assertEquals("param1", fooParams[0].getName());
		assertEquals("int", fooParams[0].getDataType().getName());

		assertFalse(fooParams[0].isStackVariable());  // was converted to register storage via default calling convention
	}

	@Test
	public void testDetailParamLocation_Used()
			throws CancelledException, IOException, DWARFException {
		// Test that a parameter's storage info is used if it looks valid and is present at
		// the start of the function.

		// TODO: need to also test location info from a debug_loc sequence that specifies a lexical offset

		DebugInfoEntry intDIE = addInt(cu);
		DebugInfoEntry fooDIE = newSubprogram("foo", intDIE, 0x410, 10).create(cu);
		newFormalParam(fooDIE, "param1", intDIE, DWARFExpressionOpCodes.DW_OP_fbreg, 0x8) // fbreg +8, caller stack area
				.create(cu);

		importFunctions();

		Function fooFunc = program.getListing().getFunctionAt(addr(0x410));
		assertNotNull(fooFunc);

		assertEquals("foo", fooFunc.getName());
		DataType returnType = fooFunc.getReturnType();
		assertNotNull(returnType);
		assertEquals("int", returnType.getName());

		Parameter[] fooParams = fooFunc.getParameters();
		assertEquals(fooParams.length, 1);
		assertEquals("param1", fooParams[0].getName());
		assertEquals("int", fooParams[0].getDataType().getName());

		assertTrue(fooParams[0].isStackVariable());
		assertEquals(8, fooParams[0].getStackOffset());
	}

	@Test
	public void testThisParamDetect_NamedThis()
			throws CancelledException, IOException, DWARFException {
		DebugInfoEntry intDIE = addInt(cu);
		DebugInfoEntry floatDIE = addFloat(cu);
		DebugInfoEntry struct1PtrDIE = addFwdPtr(cu, 1);
		DebugInfoEntry struct1DIE = newStruct("mystruct", 100).create(cu);
		DebugInfoEntry fooDIE =
			newSubprogram("foo", intDIE, 0x410, 10).setParent(struct1DIE).create(cu);
		newFormalParam(fooDIE, "this", struct1PtrDIE, DWARFExpressionOpCodes.DW_OP_fbreg, 0x6c)
				.create(cu);

		newMember(struct1DIE, "f1", intDIE, 0).create(cu);
		newMember(struct1DIE, "f2", floatDIE, 10).create(cu);

		importFunctions();

		Function fooFunc = program.getListing().getFunctionAt(addr(0x410));

		assertEquals("foo", fooFunc.getName());
		assertEquals("__thiscall", fooFunc.getCallingConventionName());
	}

	@Test
	public void testThisParamDetect_ArtificalUnNamed()
			throws CancelledException, IOException, DWARFException {
		DebugInfoEntry intDIE = addInt(cu);
		DebugInfoEntry floatDIE = addFloat(cu);
		DebugInfoEntry struct1PtrDIE = addFwdPtr(cu, 1);
		DebugInfoEntry struct1DIE = newStruct("mystruct", 100).create(cu);
		DebugInfoEntry fooDIE =
			newSubprogram("foo", intDIE, 0x410, 10).setParent(struct1DIE).create(cu);
		newFormalParam(fooDIE, null, struct1PtrDIE, DWARFExpressionOpCodes.DW_OP_fbreg, 0x6c)
				.addBoolean(DWARFAttribute.DW_AT_artificial, true)
				.create(cu);

		newMember(struct1DIE, "f1", intDIE, 0).create(cu);
		newMember(struct1DIE, "f2", floatDIE, 10).create(cu);

		importFunctions();

		Function fooFunc = program.getListing().getFunctionAt(addr(0x410));

		assertEquals("foo", fooFunc.getName());
		assertEquals("__thiscall", fooFunc.getCallingConventionName());
	}

	@Test
	public void testThisParamDetect_ObjectPointer()
			throws CancelledException, IOException, DWARFException {
		DebugInfoEntry intDIE = addInt(cu);
		DebugInfoEntry floatDIE = addFloat(cu);
		DebugInfoEntry struct1PtrDIE = addFwdPtr(cu, 1);
		DebugInfoEntry struct1DIE = newStruct("mystruct", 100).create(cu);
		DebugInfoEntry fooDIE =
			newSubprogram("foo", intDIE, 0x410, 10)
					.addRef(DWARFAttribute.DW_AT_object_pointer, getForwardOffset(cu, 1))
					.setParent(struct1DIE)
					.create(cu);
		newFormalParam(fooDIE, null, struct1PtrDIE, DWARFExpressionOpCodes.DW_OP_fbreg, 0x6c)
				.create(cu);

		newMember(struct1DIE, "f1", intDIE, 0).create(cu);
		newMember(struct1DIE, "f2", floatDIE, 10).create(cu);

		importFunctions();

		Function fooFunc = program.getListing().getFunctionAt(addr(0x410));

		assertEquals("foo", fooFunc.getName());
		assertEquals("__thiscall", fooFunc.getCallingConventionName());
	}

	@Test
	public void testThisParamDetect_Unnamed()
			throws CancelledException, IOException, DWARFException {
		DebugInfoEntry intDIE = addInt(cu);
		DebugInfoEntry floatDIE = addFloat(cu);
		DebugInfoEntry struct1PtrDIE = addFwdPtr(cu, 1);
		DebugInfoEntry struct1DIE = newStruct("mystruct", 100).create(cu);
		DebugInfoEntry fooDIE =
			newSubprogram("foo", intDIE, 0x410, 10)
					.setParent(struct1DIE)
					.create(cu);
		newFormalParam(fooDIE, null, struct1PtrDIE, DWARFExpressionOpCodes.DW_OP_fbreg, 0x6c)
				.create(cu);

		newMember(struct1DIE, "f1", intDIE, 0).create(cu);
		newMember(struct1DIE, "f2", floatDIE, 10).create(cu);

		importFunctions();

		Function fooFunc = program.getListing().getFunctionAt(addr(0x410));

		assertEquals("foo", fooFunc.getName());
		assertEquals("__thiscall", fooFunc.getCallingConventionName());
	}

	@Test
	public void testParamNameConflictsWithLocalVar()
			throws CancelledException, IOException, DWARFException,
			InvalidInputException, OverlappingFunctionException, DuplicateNameException {
		Function initialFoo = program.getListing()
				.createFunction("foo", addr(0x410), new AddressSet(addr(0x410), addr(0x411)),
					SourceType.DEFAULT);

		DataType intDT = IntegerDataType.getSignedDataType(4, program.getDataTypeManager());
		initialFoo.addLocalVariable(new LocalVariableImpl("testxyz", intDT, -16, program),
			SourceType.USER_DEFINED);
		
		DebugInfoEntry intDIE = addInt(cu);
		DebugInfoEntry fooDIE = newSubprogram("foo", intDIE, 0x410, 10).create(cu);
		newFormalParam(fooDIE, "param1", intDIE).create(cu);
		newFormalParam(fooDIE, "param2", intDIE).create(cu);
		newFormalParam(fooDIE, "testxyz" /* should collide with local var */, intDIE).create(cu);

		importFunctions();

		Function fooFunc = program.getListing().getFunctionAt(addr(0x410));
		assertNotNull(fooFunc);
		Parameter[] parameters = fooFunc.getParameters();
		assertEquals("param1", parameters[0].getName());
		assertEquals("param2", parameters[1].getName());
		assertEquals("testxyz_1", parameters[2].getName());
	}

	@Test
	public void testParamNameBadChars()
			throws CancelledException, IOException, DWARFException, InvalidInputException,
			OverlappingFunctionException, DuplicateNameException {

		DebugInfoEntry intDIE = addInt(cu);
		DebugInfoEntry fooDIE = newSubprogram("foo", intDIE, 0x410, 10).create(cu);
		newFormalParam(fooDIE, "param 1", intDIE).create(cu);
		newFormalParam(fooDIE, "param\t2", intDIE).create(cu);

		importFunctions();

		Function fooFunc = program.getListing().getFunctionAt(addr(0x410));

		assertNotNull(fooFunc);
		Parameter[] parameters = fooFunc.getParameters();
		assertEquals("param_1", parameters[0].getName());
		assertEquals("param_2", parameters[1].getName());
	}
}
