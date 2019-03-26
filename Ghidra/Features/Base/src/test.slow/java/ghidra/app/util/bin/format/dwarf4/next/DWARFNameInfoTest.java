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

import static org.junit.Assert.assertEquals;

import java.io.IOException;

import org.junit.Assert;
import org.junit.Test;

import ghidra.app.util.bin.format.dwarf4.*;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;

public class DWARFNameInfoTest extends DWARFTestBase {

	private DWARFNameInfo root =
		DWARFNameInfo.createRoot(new CategoryPath(CategoryPath.ROOT, "TEST_DNI"));

	@Test
	public void testSimple() {
		DWARFNameInfo dni = root.createChild("simplename", "simplename", SymbolType.CLASS);
		Assert.assertEquals(new CategoryPath("/TEST_DNI/simplename"), dni.asCategoryPath());
		Assert.assertEquals(
			NamespacePath.create(NamespacePath.ROOT, "simplename", SymbolType.CLASS),
			dni.getNamespacePath());
	}

	@Test
	public void testSlash() {
		DWARFNameInfo dni = root.createChild("blah/", "blah/", SymbolType.CLASS);
		Assert.assertEquals(new CategoryPath("/TEST_DNI/blah-fwdslash-"), dni.asCategoryPath());
		Assert.assertEquals(
			NamespacePath.create(NamespacePath.ROOT, "blah-fwdslash-", SymbolType.CLASS),
			dni.getNamespacePath());
	}

	@Test
	public void testNestedStructNames() throws CancelledException, IOException, DWARFException {
		DebugInfoEntry structDIE = newStruct("struct", 100).create(cu);
		DebugInfoEntry substructDIE = newStruct("substruct", 200).setParent(structDIE).create(cu);

		importAllDataTypes();

		DataType structDT = dwarfDTM.getDataType(structDIE.getOffset(), null);
		DataType substructDT = dwarfDTM.getDataType(substructDIE.getOffset(), null);

		Assert.assertEquals(rootCP.getPath() + "/struct", structDT.getPathName());
		Assert.assertEquals(rootCP.getPath() + "/struct/substruct", substructDT.getPathName());
	}

	@Test
	public void testNestedAnonStructNames_NotUsedInParent()
			throws CancelledException, IOException, DWARFException {
		DebugInfoEntry structDIE = newStruct("struct", 100).create(cu);
		DebugInfoEntry substructDIE = newStruct(null, 200).setParent(structDIE).create(cu);

		importAllDataTypes();

		DataType structDT = dwarfDTM.getDataType(structDIE.getOffset(), null);
		DataType substructDT = dwarfDTM.getDataType(substructDIE.getOffset(), null);

		Assert.assertEquals(rootCP.getPath() + "/struct", structDT.getPathName());
		Assert.assertEquals(rootCP.getPath() + "/struct/anon_struct_0", substructDT.getPathName());
	}

	@Test
	public void testNestedAnonStructNames_UsedInParent_Once()
			throws CancelledException, IOException, DWARFException {
		DebugInfoEntry structDIE = newStruct("struct", 100).create(cu);
		DebugInfoEntry substructDIE = newStruct(null, 10).setParent(structDIE).create(cu);
		newMember(structDIE, "f1", substructDIE, 0).create(cu);

		importAllDataTypes();

		DataType structDT = dwarfDTM.getDataType(structDIE.getOffset(), null);
		DataType substructDT = dwarfDTM.getDataType(substructDIE.getOffset(), null);

		Assert.assertEquals(rootCP.getPath() + "/struct", structDT.getPathName());
		Assert.assertEquals(rootCP.getPath() + "/struct/anon_struct_for_f1",
			substructDT.getPathName());
	}

	@Test
	public void testNestedAnonStructNames_UsedInParent_Multi()
			throws CancelledException, IOException, DWARFException {
		DebugInfoEntry structDIE = newStruct("struct", 100).create(cu);
		DebugInfoEntry substructDIE = newStruct(null, 10).setParent(structDIE).create(cu);
		newMember(structDIE, "f1", substructDIE, 0).create(cu);
		newMember(structDIE, "f2", substructDIE, 20).create(cu);

		importAllDataTypes();

		DataType structDT = dwarfDTM.getDataType(structDIE.getOffset(), null);
		DataType substructDT = dwarfDTM.getDataType(substructDIE.getOffset(), null);

		Assert.assertEquals(rootCP.getPath() + "/struct", structDT.getPathName());
		Assert.assertEquals(rootCP.getPath() + "/struct/anon_struct_for_f1_f2",
			substructDT.getPathName());
	}

	@Test
	public void testNonNestedAnonStructNames_UsedInParent_Once()
			throws CancelledException, IOException, DWARFException {
		DebugInfoEntry anonstructDIE = newStruct(null, 10).create(cu);
		DebugInfoEntry structDIE = newStruct("struct", 100).create(cu);
		newMember(structDIE, "f1", anonstructDIE, 0).create(cu);
		newMember(structDIE, "f2", anonstructDIE, 20).create(cu);

		importAllDataTypes();

		Structure structDT = (Structure) dwarfDTM.getDataType(structDIE.getOffset(), null);
		DataTypeComponent f1 = structDT.getComponentAt(0);
		DataTypeComponent f2 = structDT.getComponentAt(20);
		System.out.println(f1.getDataType());
		System.out.println(f2.getDataType());

		Assert.assertEquals(rootCP.getPath() + "/struct", structDT.getPathName());
	}

	@Test
	public void testNonNestedStructNames() throws CancelledException, IOException, DWARFException {
		DebugInfoEntry struct4FieldDIE = newStruct("struct_10", 10).create(cu);
		DebugInfoEntry structDIE = newStruct("struct", 100).create(cu);
		newMember(structDIE, "f1", struct4FieldDIE, 0).create(cu);
		newMember(structDIE, "f2", struct4FieldDIE, 20).create(cu);

		importAllDataTypes();

		Structure structDT = (Structure) dwarfDTM.getDataType(structDIE.getOffset(), null);
		DataTypeComponent f1 = structDT.getComponentAt(0);
		DataTypeComponent f2 = structDT.getComponentAt(20);
		System.out.println(f1.getDataType());
		System.out.println(f2.getDataType());

		Assert.assertEquals(rootCP.getPath() + "/struct", structDT.getPathName());
	}

	@Test
	public void testFuncDef() throws CancelledException, IOException, DWARFException {
		DebugInfoEntry intDIE = addInt(cu);
		DebugInfoEntry funcDIE = addSubroutineType("operator <", intDIE, cu);

		importAllDataTypes();

		DataType dt = dwarfDTM.getDataType(funcDIE.getOffset(), null);

		assertEquals("operator<", dt.getName());
	}

	@Test
	public void testAnonFuncDef() throws CancelledException, IOException, DWARFException {
		DebugInfoEntry intDIE = addInt(cu);
		DebugInfoEntry funcDIE = addSubroutineType(null, intDIE, cu);
		DebugInfoEntry func2DIE = addSubroutineType(null, null, cu);

		importAllDataTypes();

		DataType dt = dwarfDTM.getDataType(funcDIE.getOffset(), null);
		DataType dt2 = dwarfDTM.getDataType(func2DIE.getOffset(), null);

		assertEquals("anon_subr_int", dt.getName());
		assertEquals("anon_subr_void", dt2.getName());
	}
}
