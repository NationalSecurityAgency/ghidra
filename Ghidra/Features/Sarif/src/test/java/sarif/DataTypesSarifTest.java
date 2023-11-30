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
package sarif;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.util.ProgramDiff;

public class DataTypesSarifTest extends AbstractSarifTest {

	public DataTypesSarifTest() {
		super();
	}

	@Test
	public void testCreateCategoryHierarchy() throws Exception {
		ProgramBasedDataTypeManager dataMgr = program.getDataTypeManager();
		String fullName = "/cat1/cat2/cat3/cat4/cat5";
		CategoryPath cp = new CategoryPath(fullName);
		dataMgr.createCategory(cp);
		assertTrue(dataMgr.containsCategory(cp));

		dataMgr.createCategory(cp);
		assertTrue(dataMgr.containsCategory(cp));

		dataMgr.createCategory(cp);
		assertTrue(dataMgr.containsCategory(cp));

		cp = new CategoryPath("/A/B/C/D/E/F/G/H");
		dataMgr.createCategory(cp);
		assertTrue(dataMgr.containsCategory(cp));
		
		ProgramDiff programDiff = readWriteCompare();
		
		AddressSetView differences = programDiff.getDifferences(monitor);
		assert(differences.isEmpty());
	}

	@Test
	public void testCreateArray() throws Exception {
		ProgramBasedDataTypeManager dataMgr = program.getDataTypeManager();
		ArrayDataType adt = new ArrayDataType(new ByteDataType(), 3, 1);
		Array array = (Array) dataMgr.addDataType(adt, null);
		assertNotNull(array);

		ProgramDiff programDiff = readWriteCompare();
		
		AddressSetView differences = programDiff.getDifferences(monitor);
		assert(differences.isEmpty());
	}

	@Test
	public void testCreateTypedef() throws Exception {
		ProgramBasedDataTypeManager dataMgr = program.getDataTypeManager();
		ArrayDataType adt = new ArrayDataType(new ByteDataType(), 3, 1);
		Array array = (Array) dataMgr.addDataType(adt, null);
		TypedefDataType tdt = new TypedefDataType("ArrayTypedef", array);
		TypeDef td = (TypeDef) dataMgr.addDataType(tdt, null);
		assertNotNull(td);

		ProgramDiff programDiff = readWriteCompare();
		
		AddressSetView differences = programDiff.getDifferences(monitor);
		assert(differences.isEmpty());
	}

	@Test
	public void testCreatePointer() throws Exception {
		ProgramBasedDataTypeManager dataMgr = program.getDataTypeManager();
		ArrayDataType adt = new ArrayDataType(new ByteDataType(), 5, 1);
		Array array = (Array) dataMgr.addDataType(adt, null);
		TypedefDataType tdt = new TypedefDataType("ArrayTypedef", array);
		TypeDef td = (TypeDef) dataMgr.addDataType(tdt, null);
		PointerDataType pdt = new Pointer32DataType(td);
		Pointer ptr = (Pointer) dataMgr.addDataType(pdt, null);
		assertNotNull(ptr);

		ProgramDiff programDiff = readWriteCompare();
		
		AddressSetView differences = programDiff.getDifferences(monitor);
		assert(differences.isEmpty());
	}

	@Test
	public void testCreatePointers() throws Exception {
		ProgramBasedDataTypeManager dataMgr = program.getDataTypeManager();
		Array array = new ArrayDataType(new ByteDataType(), 5, 1);
		TypeDef td = new TypedefDataType("ByteTypedef", array);
		Pointer p = new Pointer32DataType(td);
		Pointer p2 = new Pointer32DataType(p);

		Pointer ptr = (Pointer) dataMgr.resolve(p2, null);
		assertNotNull(ptr);
		assertEquals("ByteTypedef * *", ptr.getMnemonic(null));

		p = new Pointer32DataType(null);
		ptr = (Pointer) dataMgr.resolve(p, null);
		assertNotNull(ptr);
		
		ProgramDiff programDiff = readWriteCompare();
		
		AddressSetView differences = programDiff.getDifferences(monitor);
		assert(differences.isEmpty());
	}

	@Test
	public void testCreateStructure() throws Exception {
		ProgramBasedDataTypeManager dataMgr = program.getDataTypeManager();
		StructureDataType sdt = new StructureDataType("test", 0);
		Structure struct = (Structure) dataMgr.addDataType(sdt, null);
		assertNotNull(struct);

		ProgramDiff programDiff = readWriteCompare();
		
		AddressSetView differences = programDiff.getDifferences(monitor);
		assert(differences.isEmpty());
	}

	@Test
	public void testCreateUnion() throws Exception {
		ProgramBasedDataTypeManager dataMgr = program.getDataTypeManager();
		UnionDataType udt = new UnionDataType("test");
		Union union = (Union) dataMgr.addDataType(udt, null);
		assertNotNull(union);

		ProgramDiff programDiff = readWriteCompare();
		
		AddressSetView differences = programDiff.getDifferences(monitor);
		assert(differences.isEmpty());
	}

	@Test
	public void testCreateFunctionDef() throws Exception {
		ProgramBasedDataTypeManager dataMgr = program.getDataTypeManager();
		FunctionDefinitionDataType fdt =
			new FunctionDefinitionDataType(new FunctionDefinitionDataType("test"));
		FunctionDefinition funcDef = (FunctionDefinition) dataMgr.addDataType(fdt, null);
		assertNotNull(funcDef);

		ProgramDiff programDiff = readWriteCompare();
		
		AddressSetView differences = programDiff.getDifferences(monitor);
		assert(differences.isEmpty());
	}

}
