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

import java.io.IOException;
import java.util.List;

import org.junit.Test;

import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.bin.format.dwarf4.*;
import ghidra.app.util.bin.format.dwarf4.encoding.DWARFAttribute;
import ghidra.app.util.bin.format.dwarf4.encoding.DWARFSourceLanguage;
import ghidra.app.util.bin.format.dwarf4.expression.DWARFExpressionOpCodes;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.CompilerSpec;
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

		addCompUnit(DWARFSourceLanguage.DW_LANG_Rust);

		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry fooDIE = newSubprogram("foo", intDIE, 0x410, 10).create();
		newFormalParam(fooDIE, "param1", intDIE, DWARFExpressionOpCodes.DW_OP_fbreg, 0x6c)
				.create();

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
	public void testRustMethod_SetsRustCC()
			throws CancelledException, IOException, DWARFException {
		addCompUnit(DWARFSourceLanguage.DW_LANG_Rust);

		DebugInfoEntry intDIE = addInt();
		newSubprogram("foo", intDIE, 0x410, 10).create();

		importFunctions();

		Function fooFunc = program.getListing().getFunctionAt(addr(0x410));
		assertNotNull(fooFunc);

		assertEquals("foo", fooFunc.getName());
		assertEquals(CompilerSpec.CALLING_CONVENTION_rustcall, fooFunc.getCallingConventionName());
	}

	@Test
	public void testNamespace_with_reserved_chars()
			throws CancelledException, IOException, DWARFException {
		// simulate what happens when a C++ operator/ or a templated classname
		// that contains a namespace template argument (templateclass<ns1::ns2::argclass>)
		// is encountered and a Ghidra namespace is created

		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry floatDIE = addFloat();
		DebugInfoEntry struct1DIE = newStruct("mystruct::operator/()", 100).create();
		DebugInfoEntry nestedStructPtrDIE = addFwdPtr(1);
		DebugInfoEntry nestedStructDIE =
			newStruct("nested_struct", 10).setParent(struct1DIE).create();
		newMember(nestedStructDIE, "blah1", intDIE, 0).create();
		DebugInfoEntry fooDIE =
			newSubprogram("foo", intDIE, 0x410, 10).setParent(nestedStructDIE).create();
		newFormalParam(fooDIE, "this", nestedStructPtrDIE, DWARFExpressionOpCodes.DW_OP_fbreg, 0x6c)
				.create();

		newMember(struct1DIE, "f1", intDIE, 0).create();
		newMember(struct1DIE, "f2", floatDIE, 10).create();
		newMember(struct1DIE, "f3", nestedStructDIE, 20).create();

		importFunctions();

		Function fooFunc = program.getListing().getFunctionAt(addr(0x410));
		List<Namespace> nsParts = NamespaceUtils.getNamespaceParts(fooFunc.getParentNamespace());

		assertEquals("foo", fooFunc.getName());
		assertEquals("nested_struct",
			((Pointer) fooFunc.getParameter(0).getDataType()).getDataType().getName());
		assertEquals(CompilerSpec.CALLING_CONVENTION_thiscall, fooFunc.getCallingConventionName());
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
		DebugInfoEntry intDIE = addInt();
		DIECreator func = newSubprogram("foo", intDIE, 0x410, 10);
		func.addBoolean(DWARFAttribute.DW_AT_noreturn, true);
		func.create();

		importFunctions();

		Function fooFunc = program.getListing().getFunctionAt(addr(0x410));
		assertNotNull(fooFunc);
		assertTrue(fooFunc.hasNoReturn());
	}

	@Test
	public void testNoReturnFlag_False() throws CancelledException, IOException, DWARFException {
		DebugInfoEntry intDIE = addInt();
		DIECreator func = newSubprogram("foo", intDIE, 0x410, 10);
		func.create();

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

		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry fooDIE = newSubprogram("foo", intDIE, 0x410, 10).create();
		newFormalParam(fooDIE, "param1", intDIE, DWARFExpressionOpCodes.DW_OP_fbreg, 0x6c) // fbreg -14, func local variable area
				.create();

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

		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry fooDIE = newSubprogram("foo", intDIE, 0x410, 10).create();
		newFormalParam(fooDIE, "param1", intDIE, DWARFExpressionOpCodes.DW_OP_fbreg, 0x8) // fbreg +8, caller stack area
				.create();

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
		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry floatDIE = addFloat();
		DebugInfoEntry struct1PtrDIE = addFwdPtr(1);
		DebugInfoEntry struct1DIE = newStruct("mystruct", 100).create();
		DebugInfoEntry fooDIE =
			newSubprogram("foo", intDIE, 0x410, 10).setParent(struct1DIE).create();
		newFormalParam(fooDIE, "this", struct1PtrDIE, DWARFExpressionOpCodes.DW_OP_fbreg, 0x6c)
				.create();

		newMember(struct1DIE, "f1", intDIE, 0).create();
		newMember(struct1DIE, "f2", floatDIE, 10).create();

		importFunctions();

		Function fooFunc = program.getListing().getFunctionAt(addr(0x410));

		assertEquals("foo", fooFunc.getName());
		assertEquals(CompilerSpec.CALLING_CONVENTION_thiscall, fooFunc.getCallingConventionName());
	}

	@Test
	public void testThisParamDetect_ArtificalUnNamed()
			throws CancelledException, IOException, DWARFException {
		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry floatDIE = addFloat();
		DebugInfoEntry struct1PtrDIE = addFwdPtr(1);
		DebugInfoEntry struct1DIE = newStruct("mystruct", 100).create();
		DebugInfoEntry fooDIE =
			newSubprogram("foo", intDIE, 0x410, 10).setParent(struct1DIE).create();
		newFormalParam(fooDIE, null, struct1PtrDIE, DWARFExpressionOpCodes.DW_OP_fbreg, 0x6c)
				.addBoolean(DWARFAttribute.DW_AT_artificial, true)
				.create();

		newMember(struct1DIE, "f1", intDIE, 0).create();
		newMember(struct1DIE, "f2", floatDIE, 10).create();

		importFunctions();

		Function fooFunc = program.getListing().getFunctionAt(addr(0x410));

		assertEquals("foo", fooFunc.getName());
		assertEquals(CompilerSpec.CALLING_CONVENTION_thiscall, fooFunc.getCallingConventionName());
	}

	@Test
	public void testThisParamDetect_ObjectPointer()
			throws CancelledException, IOException, DWARFException {
		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry floatDIE = addFloat();
		DebugInfoEntry struct1PtrDIE = addFwdPtr(1);
		DebugInfoEntry struct1DIE = newStruct("mystruct", 100).create();
		long formalParamDIEOffset = dwarfProg.getRelativeDIEOffset(2);
		DebugInfoEntry fooDIE =
			newSubprogram("foo", intDIE, 0x410, 10)
					.addRef(DWARFAttribute.DW_AT_object_pointer, formalParamDIEOffset)
					.setParent(struct1DIE)
					.create();

		// give the param a non-this name to defeat the logic in DWARFUtil.isThisParam()
		newFormalParam(fooDIE, "not_the_normal_this_name", struct1PtrDIE,
			DWARFExpressionOpCodes.DW_OP_fbreg, 0x6c).create();

		newMember(struct1DIE, "f1", intDIE, 0).create();
		newMember(struct1DIE, "f2", floatDIE, 10).create();

		importFunctions();

		Function fooFunc = program.getListing().getFunctionAt(addr(0x410));

		assertEquals("foo", fooFunc.getName());
		assertEquals(CompilerSpec.CALLING_CONVENTION_thiscall, fooFunc.getCallingConventionName());
	}

	@Test
	public void testThisParamDetect_ObjectPointer_inverse()
			throws CancelledException, IOException, DWARFException {
		// Test that Ghidra doesn't mark foo()'s param as 'this' when we don't have a DW_AT_obj_ptr
		// This is to ensure that testThisParamDetect_ObjectPointer() is a strong test
		// The data in this test needs to mirror the data in testThisParamDetect_ObjectPointer(),
		// minus the DW_AT_object_pointer attribute.
		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry floatDIE = addFloat();
		DebugInfoEntry struct1PtrDIE = addFwdPtr(1);
		DebugInfoEntry struct1DIE = newStruct("mystruct", 100).create();
		DebugInfoEntry fooDIE = newSubprogram("foo", intDIE, 0x410, 10)
				//.addRef(DWARFAttribute.DW_AT_object_pointer, ??) don't add this attribute
				.setParent(struct1DIE)
				.create();

		// give the param a non-this name to defeat the logic in DWARFUtil.isThisParam()
		newFormalParam(fooDIE, "not_the_normal_this_name", struct1PtrDIE,
			DWARFExpressionOpCodes.DW_OP_fbreg, 0x6c).create();

		newMember(struct1DIE, "f1", intDIE, 0).create();
		newMember(struct1DIE, "f2", floatDIE, 10).create();

		importFunctions();

		Function fooFunc = program.getListing().getFunctionAt(addr(0x410));

		assertEquals("foo", fooFunc.getName());
		assertNotEquals(CompilerSpec.CALLING_CONVENTION_thiscall,
			fooFunc.getCallingConventionName());
	}

	@Test
	public void testThisParamDetect_Unnamed()
			throws CancelledException, IOException, DWARFException {
		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry floatDIE = addFloat();
		DebugInfoEntry struct1PtrDIE = addFwdPtr(1);
		DebugInfoEntry struct1DIE = newStruct("mystruct", 100).create();

		DebugInfoEntry fooDIE =
			newSubprogram("foo", intDIE, 0x410, 10).setParent(struct1DIE).create();
		newFormalParam(fooDIE, null, struct1PtrDIE, DWARFExpressionOpCodes.DW_OP_fbreg, 0x6c)
				.create();

		newMember(struct1DIE, "f1", intDIE, 0).create();
		newMember(struct1DIE, "f2", floatDIE, 10).create();

		importFunctions();

		Function fooFunc = program.getListing().getFunctionAt(addr(0x410));

		assertEquals("foo", fooFunc.getName());
		assertEquals(CompilerSpec.CALLING_CONVENTION_thiscall, fooFunc.getCallingConventionName());
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
		
		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry fooDIE = newSubprogram("foo", intDIE, 0x410, 10).create();
		newFormalParam(fooDIE, "param1", intDIE).create();
		newFormalParam(fooDIE, "param2", intDIE).create();
		newFormalParam(fooDIE, "testxyz" /* should collide with local var */, intDIE).create();

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
			throws CancelledException, IOException, DWARFException {

		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry fooDIE = newSubprogram("foo", intDIE, 0x410, 10).create();
		newFormalParam(fooDIE, "param 1", intDIE).create();
		newFormalParam(fooDIE, "param\t2", intDIE).create();

		importFunctions();

		Function fooFunc = program.getListing().getFunctionAt(addr(0x410));

		assertNotNull(fooFunc);
		Parameter[] parameters = fooFunc.getParameters();
		assertEquals("param_1", parameters[0].getName());
		assertEquals("param_2", parameters[1].getName());
	}
}
