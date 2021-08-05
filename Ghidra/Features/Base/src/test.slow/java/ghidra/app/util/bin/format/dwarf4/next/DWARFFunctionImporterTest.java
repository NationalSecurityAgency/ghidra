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

import org.junit.Test;

import ghidra.app.util.bin.format.dwarf4.*;
import ghidra.app.util.bin.format.dwarf4.encoding.DWARFSourceLanguage;
import ghidra.app.util.bin.format.dwarf4.expression.DWARFExpressionOpCodes;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
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
}
