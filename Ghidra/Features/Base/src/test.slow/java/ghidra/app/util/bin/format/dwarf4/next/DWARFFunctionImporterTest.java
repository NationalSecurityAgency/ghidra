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
import ghidra.app.util.bin.format.dwarf4.encoding.DWARFSourceLanguage;
import ghidra.app.util.bin.format.dwarf4.expression.DWARFExpressionOpCodes;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.exception.CancelledException;

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
				.getDataType(new CategoryPath(rootCP, "mystruct::operator/()"), "nested_struct");
		Structure nestedStructDT2 = VariableUtilities.findExistingClassStruct(fooFunc);
		assertTrue(nestedStructDT1 == nestedStructDT2);
	}
}
