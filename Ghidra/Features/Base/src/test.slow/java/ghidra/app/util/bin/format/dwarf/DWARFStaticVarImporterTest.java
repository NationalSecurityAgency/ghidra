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
import static ghidra.app.util.bin.format.dwarf.expression.DWARFExpressionOpCode.*;
import static org.junit.Assert.*;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import org.junit.Test;

import ghidra.program.model.data.*;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;

public class DWARFStaticVarImporterTest extends DWARFTestBase {

	@Test
	public void testIntStaticVar() throws CancelledException, IOException, DWARFException {
		DebugInfoEntry intDIE = addInt();
		new DIECreator(dwarfProg, DW_TAG_variable).addString(DW_AT_name, "static_var1")
				.addRef(DW_AT_type, intDIE)
				.addBlockBytes(DW_AT_location, instr(DW_OP_addr, 0x10, 0x4, 0, 0, 0, 0, 0, 0))
				.create();

		importFunctions();

		CodeUnit codeunit = program.getListing().getCodeUnitAt(addr(0x410));
		assertNotNull(codeunit);
		assertEquals("static_var1", codeunit.getLabel());
		assertEquals(4, codeunit.getLength());
		assertTrue(((Data) codeunit).getDataType() instanceof IntegerDataType);
	}

	@Test
	public void testZeroLenGlobalVar() throws CancelledException, IOException, DWARFException {
		DebugInfoEntry emptyStructDIE = newStruct("emptystruct", 0).create();
		new DIECreator(dwarfProg, DW_TAG_variable).addString(DW_AT_name, "static_var1")
				.addRef(DW_AT_type, emptyStructDIE)
				.addBlockBytes(DW_AT_location, instr(DW_OP_addr, 0x10, 0x4, 0, 0, 0, 0, 0, 0))
				.create();

		importFunctions();

		CodeUnit codeunit = program.getListing().getCodeUnitAt(addr(0x410));
		assertNotNull(codeunit);
		assertEquals("static_var1", codeunit.getLabel());
		assertEquals(1, codeunit.getLength());
		DataType dataType = ((Data) codeunit).getDataType();
		assertTrue(dataType instanceof Undefined || dataType instanceof DefaultDataType);
	}

	@Test
	public void test2ZeroLenGlobalVar() throws CancelledException, IOException, DWARFException {
		DebugInfoEntry emptyStructDIE = newStruct("emptystruct", 0).create();
		new DIECreator(dwarfProg, DW_TAG_variable).addString(DW_AT_name, "static_var1")
				.addRef(DW_AT_type, emptyStructDIE)
				.addBlockBytes(DW_AT_location, instr(DW_OP_addr, 0x10, 0x4, 0, 0, 0, 0, 0, 0))
				.create();
		new DIECreator(dwarfProg, DW_TAG_variable).addString(DW_AT_name, "static_var2")
				.addRef(DW_AT_type, emptyStructDIE)
				.addBlockBytes(DW_AT_location, instr(DW_OP_addr, 0x10, 0x4, 0, 0, 0, 0, 0, 0))
				.create();

		importFunctions();

		Set<String> labelNames = getLabelNames(program.getSymbolTable().getSymbols(addr(0x410)));
		assertTrue(labelNames.contains("static_var1"));
		assertTrue(labelNames.contains("static_var2"));
	}

	@Test
	public void testZeroLenGlobalVarOnTopOfNormalVar()
			throws CancelledException, IOException, DWARFException {
		DebugInfoEntry emptyStructDIE = newStruct("emptystruct", 0).create();
		DebugInfoEntry intDIE = addInt();
		new DIECreator(dwarfProg, DW_TAG_variable).addString(DW_AT_name, "static_var1")
				.addRef(DW_AT_type, intDIE)
				.addBlockBytes(DW_AT_location, instr(DW_OP_addr, 0x10, 0x4, 0, 0, 0, 0, 0, 0))
				.create();
		new DIECreator(dwarfProg, DW_TAG_variable).addString(DW_AT_name, "static_var2")
				.addRef(DW_AT_type, emptyStructDIE)
				.addBlockBytes(DW_AT_location, instr(DW_OP_addr, 0x10, 0x4, 0, 0, 0, 0, 0, 0))
				.create();

		importFunctions();

		Set<String> labelNames = getLabelNames(program.getSymbolTable().getSymbols(addr(0x410)));
		assertTrue(labelNames.contains("static_var1"));
		assertTrue(labelNames.contains("static_var2"));

		CodeUnit codeunit = program.getListing().getCodeUnitAt(addr(0x410));
		assertNotNull(codeunit);
		assertEquals("static_var1", codeunit.getLabel());
		assertEquals(4, codeunit.getLength());
		assertTrue(((Data) codeunit).getDataType() instanceof IntegerDataType);
	}

	private Set<String> getLabelNames(Symbol[] symbols) {
		Set<String> result = new HashSet<>();
		for (Symbol symbol : symbols) {
			if (symbol.getSymbolType() == SymbolType.LABEL) {
				result.add(symbol.getName());
			}
		}
		return result;
	}
}
