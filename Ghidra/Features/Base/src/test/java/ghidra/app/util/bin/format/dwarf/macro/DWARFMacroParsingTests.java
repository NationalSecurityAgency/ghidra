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
package ghidra.app.util.bin.format.dwarf.macro;

import static org.junit.Assert.*;

import java.io.IOException;

import org.apache.commons.lang3.StringUtils;
import org.junit.Before;
import org.junit.Test;

import ghidra.app.util.bin.format.dwarf.DWARFTestBase;
import ghidra.app.util.bin.format.dwarf.line.DWARFLine;
import ghidra.app.util.bin.format.dwarf.macro.entry.DWARFMacroDefine;
import ghidra.app.util.bin.format.dwarf.macro.entry.DWARFMacroDefine.MacroInfo;

public class DWARFMacroParsingTests extends DWARFTestBase {
	DWARFMacroHeader header;

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		ensureCompUnit();
		header = new DWARFMacroHeader(0, 5, 0, 0, 4, 0, cu, DWARFLine.empty(),
			DWARFMacroOpcode.defaultOpcodeOperandMap);
	}

	@Test
	public void testDefinedOnly() throws IOException {
		DWARFMacroDefine entry = new DWARFMacroDefine(1, "TEST", header);
		MacroInfo macroInfo = entry.getMacroInfo();
		assertEquals(1, entry.getLineNumber());
		assertFalse(macroInfo.isFunctionLike());
		assertEquals("TEST", macroInfo.symbolName());
		assertTrue(macroInfo.parameters().isEmpty());
		assertEquals(StringUtils.EMPTY, macroInfo.definition());
	}

	@Test
	public void testObjectLikeMacro() throws IOException {
		DWARFMacroDefine entry = new DWARFMacroDefine(2, "TEST 0x4", header);
		MacroInfo macroInfo = entry.getMacroInfo();
		assertEquals(2, entry.getLineNumber());
		assertFalse(macroInfo.isFunctionLike());
		assertEquals("TEST", macroInfo.symbolName());
		assertTrue(macroInfo.parameters().isEmpty());
		assertEquals("0x4", macroInfo.definition());
	}

	@Test
	public void testObjectListMacroExpression() throws IOException {
		DWARFMacroDefine entry = new DWARFMacroDefine(2, "ONE_PLUS_TWO 1 + 2", header);
		MacroInfo macroInfo = entry.getMacroInfo();
		assertEquals(2, entry.getLineNumber());
		assertFalse(macroInfo.isFunctionLike());
		assertEquals("ONE_PLUS_TWO", macroInfo.symbolName());
		assertTrue(macroInfo.parameters().isEmpty());
		assertEquals("1 + 2", macroInfo.definition());
	}

	@Test
	public void testObjectListMacroExpressionParens1() throws IOException {
		DWARFMacroDefine entry = new DWARFMacroDefine(2, "ONE_PLUS_TWO (1) + (2)", header);
		MacroInfo macroInfo = entry.getMacroInfo();
		assertEquals(2, entry.getLineNumber());
		assertFalse(macroInfo.isFunctionLike());
		assertEquals("ONE_PLUS_TWO", macroInfo.symbolName());
		assertTrue(macroInfo.parameters().isEmpty());
		assertEquals("(1) + (2)", macroInfo.definition());
	}

	@Test
	public void testObjectListMacroExpressionParens2() throws IOException {
		DWARFMacroDefine entry = new DWARFMacroDefine(2, "ONE_PLUS_TWO ((1) + (2))", header);
		MacroInfo macroInfo = entry.getMacroInfo();
		assertEquals(2, entry.getLineNumber());
		assertFalse(macroInfo.isFunctionLike());
		assertEquals("ONE_PLUS_TWO", macroInfo.symbolName());
		assertTrue(macroInfo.parameters().isEmpty());
		assertEquals("((1) + (2))", macroInfo.definition());
	}

	@Test
	public void testFunctionLikeMacro() throws IOException {
		DWARFMacroDefine entry = new DWARFMacroDefine(3, "SUM(A,B) A + B", header);
		MacroInfo macroInfo = entry.getMacroInfo();
		assertEquals(3, entry.getLineNumber());
		assertTrue(macroInfo.isFunctionLike());
		assertEquals("SUM", macroInfo.symbolName());
		assertEquals(2, macroInfo.parameters().size());
		assertEquals("A", macroInfo.parameters().get(0));
		assertEquals("B", macroInfo.parameters().get(1));
		assertEquals("A + B", macroInfo.definition());
	}

	@Test
	public void testFunctionLikeMacroParens1() throws IOException {
		DWARFMacroDefine entry = new DWARFMacroDefine(3, "SUM(A,B) (A) + (B)", header);
		MacroInfo macroInfo = entry.getMacroInfo();
		assertEquals(3, entry.getLineNumber());
		assertTrue(macroInfo.isFunctionLike());
		assertEquals("SUM", macroInfo.symbolName());
		assertEquals(2, macroInfo.parameters().size());
		assertEquals("A", macroInfo.parameters().get(0));
		assertEquals("B", macroInfo.parameters().get(1));
		assertEquals("(A) + (B)", macroInfo.definition());
	}

	@Test
	public void testFunctionLikeMacroParens2() throws IOException {
		DWARFMacroDefine entry = new DWARFMacroDefine(3, "SUM(A,B) ((A) + (B))", header);
		MacroInfo macroInfo = entry.getMacroInfo();
		assertEquals(3, entry.getLineNumber());
		assertTrue(macroInfo.isFunctionLike());
		assertEquals("SUM", macroInfo.symbolName());
		assertEquals(2, macroInfo.parameters().size());
		assertEquals("A", macroInfo.parameters().get(0));
		assertEquals("B", macroInfo.parameters().get(1));
		assertEquals("((A) + (B))", macroInfo.definition());
	}

}
