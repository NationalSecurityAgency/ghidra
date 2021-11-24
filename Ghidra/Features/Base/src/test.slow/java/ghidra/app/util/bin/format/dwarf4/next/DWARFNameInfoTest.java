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
import ghidra.program.model.data.*;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;

public class DWARFNameInfoTest extends DWARFTestBase {

	private DWARFNameInfo root =
		DWARFNameInfo.createRoot(new CategoryPath(CategoryPath.ROOT, "TEST_DNI"));

	@Test
	public void testSimple() {
		DWARFNameInfo dni = root.createChild("simplename", "simplename", SymbolType.CLASS);
		assertEquals(new CategoryPath("/TEST_DNI/simplename"), dni.asCategoryPath());
		assertEquals(
			NamespacePath.create(NamespacePath.ROOT, "simplename", SymbolType.CLASS),
			dni.getNamespacePath());
	}

	@Test
	public void testSlash() {
		DWARFNameInfo dni = root.createChild("blah/", "blah/", SymbolType.CLASS);
		assertEquals(new CategoryPath(CategoryPath.ROOT, "TEST_DNI", "blah/"),
			dni.asCategoryPath());

		Namespace testNamespace = dni.asNamespace(program);
		assertEquals("blah/", testNamespace.getName(true));
		assertEquals(
			NamespacePath.create(NamespacePath.ROOT, "blah/", SymbolType.CLASS),
			dni.getNamespacePath());
	}

	@Test
	public void testColon() {
		DWARFNameInfo dni = root.createChild("blah::blah", "blah::blah", SymbolType.CLASS);
		DWARFNameInfo dni2 = dni.createChild("sub::sub", "sub::sub", SymbolType.CLASS);
		assertEquals(new CategoryPath("/TEST_DNI/blah::blah/sub::sub"),
			dni2.asCategoryPath());

		Namespace testNamespace = dni2.asNamespace(program);
		assertEquals("sub::sub", testNamespace.getName());
		assertEquals("blah::blah", testNamespace.getParentNamespace().getName());
		assertTrue(testNamespace instanceof GhidraClass);
		assertTrue(testNamespace.getParentNamespace() instanceof GhidraClass);
	}

	@Test
	public void testNamespaceTypes() {
		DWARFNameInfo dni_ns1 = root.createChild("ns1", "ns1", SymbolType.NAMESPACE);
		DWARFNameInfo dni_ns1class1 = dni_ns1.createChild("class1", "class1", SymbolType.CLASS);
		assertEquals(new CategoryPath("/TEST_DNI/ns1/class1"), dni_ns1class1.asCategoryPath());

		Namespace class1_ns = dni_ns1class1.asNamespace(program);
		assertEquals("ns1::class1", class1_ns.getName(true));
		assertTrue(class1_ns instanceof GhidraClass);
		assertFalse(class1_ns.getParentNamespace() instanceof GhidraClass);
	}

	@Test
	public void testNamespaceConvertToClass() {
		// tests that a plain namespace can be 'upgraded' to a class namespace
		DWARFNameInfo dni_ns1 = root.createChild("ns1", "ns1", SymbolType.NAMESPACE);

		Namespace ns1 = dni_ns1.asNamespace(program);
		assertFalse(ns1 instanceof GhidraClass);

		DWARFNameInfo dni_ns1a = root.createChild("ns1", "ns1", SymbolType.CLASS);
		Namespace ns1a = dni_ns1a.asNamespace(program);
		assertTrue(ns1a instanceof GhidraClass);
	}

	@Test
	public void testClassConvertToNamespace() {
		// tests that a class namespace isn't 'downgraded' to a plain namespace
		DWARFNameInfo dni_class1 = root.createChild("class1", "class1", SymbolType.CLASS);

		Namespace class1 = dni_class1.asNamespace(program);
		assertTrue(class1 instanceof GhidraClass);

		DWARFNameInfo dni_class1a = root.createChild("class1", "class1", SymbolType.NAMESPACE);
		Namespace class1a = dni_class1a.asNamespace(program);
		// symbol should NOT have been converted to a plain namespace.
		assertTrue(class1a instanceof GhidraClass);
	}

	@Test
	public void testNestedStructNames() throws CancelledException, IOException, DWARFException {
		DebugInfoEntry structDIE = newStruct("struct", 100).create(cu);
		DebugInfoEntry substructDIE = newStruct("substruct", 200).setParent(structDIE).create(cu);

		importAllDataTypes();

		DataType structDT = dwarfDTM.getDataType(structDIE.getOffset(), null);
		DataType substructDT = dwarfDTM.getDataType(substructDIE.getOffset(), null);

		assertEquals(rootCP.getPath() + "/struct", structDT.getPathName());
		assertEquals(rootCP.getPath() + "/struct/substruct", substructDT.getPathName());
	}

	@Test
	public void testNestedAnonStructNames_NotUsedInParent()
			throws CancelledException, IOException, DWARFException {
		DebugInfoEntry structDIE = newStruct("struct", 100).create(cu);
		DebugInfoEntry substructDIE = newStruct(null, 200).setParent(structDIE).create(cu);

		importAllDataTypes();

		DataType structDT = dwarfDTM.getDataType(structDIE.getOffset(), null);
		DataType substructDT = dwarfDTM.getDataType(substructDIE.getOffset(), null);

		assertEquals(rootCP.getPath() + "/struct", structDT.getPathName());
		assertEquals(rootCP.getPath() + "/struct/anon_struct_0", substructDT.getPathName());
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

		assertEquals(rootCP.getPath() + "/struct", structDT.getPathName());
		assertEquals(rootCP.getPath() + "/struct/anon_struct_for_f1",
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

		assertEquals(rootCP.getPath() + "/struct", structDT.getPathName());
		assertEquals(rootCP.getPath() + "/struct/anon_struct_for_f1_f2",
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

		assertEquals(rootCP.getPath() + "/struct", structDT.getPathName());
	}

	@Test
	public void testNonNestedStructNames() throws CancelledException, IOException, DWARFException {
		DebugInfoEntry struct4FieldDIE = newStruct("struct_10", 10).create(cu);
		DebugInfoEntry structDIE = newStruct("struct", 100).create(cu);
		newMember(structDIE, "f1", struct4FieldDIE, 0).create(cu);
		newMember(structDIE, "f2", struct4FieldDIE, 20).create(cu);

		importAllDataTypes();

		Structure structDT = (Structure) dwarfDTM.getDataType(structDIE.getOffset(), null);

		assertEquals(rootCP.getPath() + "/struct", structDT.getPathName());
	}

	@Test
	public void testFuncDef() throws CancelledException, IOException, DWARFException {
		DebugInfoEntry intDIE = addInt(cu);
		DebugInfoEntry funcDIE = addSubroutineType("operator <", intDIE, cu);

		importAllDataTypes();

		DataType dt = dwarfDTM.getDataType(funcDIE.getOffset(), null);

		// note: for now we are adding an underscore to the name; we hope to fix this in the future
		assertEquals("operator_<", dt.getName());
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
