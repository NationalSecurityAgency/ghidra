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

import static org.junit.Assert.*;

import org.junit.Test;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.*;
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
		assert (differences.isEmpty());
	}

	@Test
	public void testCreateArray() throws Exception {
		ProgramBasedDataTypeManager dataMgr = program.getDataTypeManager();
		ArrayDataType adt = new ArrayDataType(new ByteDataType(), 3, 1);
		Array array = (Array) dataMgr.addDataType(adt, null);
		assertNotNull(array);

		ProgramDiff programDiff = readWriteCompare();

		AddressSetView differences = programDiff.getDifferences(monitor);
		assert (differences.isEmpty());
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
		assert (differences.isEmpty());
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
		assert (differences.isEmpty());
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
		assert (differences.isEmpty());
	}

	@Test
	public void testCreateStructure() throws Exception {
		ProgramBasedDataTypeManager dataMgr = program.getDataTypeManager();
		Structure sdt = createComplexStructureDataType(dataMgr);
		Structure struct = (Structure) dataMgr.addDataType(sdt, null);
		assertNotNull(struct);

		ProgramDiff programDiff = readWriteCompare();

		AddressSetView differences = programDiff.getDifferences(monitor);
		assert (differences.isEmpty());
	}

	@Test
	public void testCreateUnion() throws Exception {
		ProgramBasedDataTypeManager dataMgr = program.getDataTypeManager();
		UnionDataType udt = new UnionDataType("test");
		Union union = (Union) dataMgr.addDataType(udt, null);
		assertNotNull(union);

		ProgramDiff programDiff = readWriteCompare();

		AddressSetView differences = programDiff.getDifferences(monitor);
		assert (differences.isEmpty());
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
		assert (differences.isEmpty());
	}

	static Structure createComplexStructureDataType(DataTypeManager dtm) throws Exception {

		/**
		 * /structA
		 * aligned(8) pack(disabled)
		 * Structure structA {
		 *    0   char   1   a0   ""
		 *    4   int   4   a1   ""
		 *    16   int[4]   16   a3   ""
		 *    32   char[0]   0   az   ""
		 *    40   short   2   a4   ""
		 *    48   int[0]   0   aflex   ""
		 * }
		 * Length: 48 Alignment: 8
		 */
		Structure structA = new StructureDataType("structA", 0);
		structA.insertAtOffset(0, CharDataType.dataType, -1, "a0", null);
		structA.insertAtOffset(4, IntegerDataType.dataType, -1, "a1", null);
		structA.insertAtOffset(0x10, new ArrayDataType(CharDataType.dataType, 0, -1), -1, "az",
			null);
		structA.insertAtOffset(0x10, new ArrayDataType(IntegerDataType.dataType, 4, -1), -1, "a3",
			null);
		structA.insertAtOffset(0x28, ShortDataType.dataType, -1, "a4", null);
		structA.insertAtOffset(0x30, new ArrayDataType(IntegerDataType.dataType, 0, -1), -1,
			"aflex", null);
		structA.setExplicitMinimumAlignment(8);

		/**
		 * /structB
		 * pack()
		 * Structure structB {
		 *    0   short   2   b0   ""
		 *    2   byte[0]   0   bfs   ""
		 *    2   int:4(0)   1   bf1   ""
		 *    2   int:6(4)   2   bf2   ""
		 *    3   int:2(2)   1   bf3   ""
		 *    8   structA   48   b1   ""
		 * }
		 * Length: 56 Alignment: 8
		 */
		Structure structB = new StructureDataType("structB", 0);
		structB.setPackingEnabled(true);
		structB.add(ShortDataType.dataType, "b0", null);
		structB.add(new ArrayDataType(ByteDataType.dataType, 0, -1), "bfs", null);
		structB.addBitField(IntegerDataType.dataType, 4, "bf1", null);
		structB.addBitField(IntegerDataType.dataType, 6, "bf2", null);
		structB.addBitField(IntegerDataType.dataType, 2, "bf3", null);
		structB.add(structA, "b1", null);

		/**
		 * /structC
		 * pack()
		 * Structure structC {
		 *    0   char   1   c0   ""
		 *    8   structB   56   c1   ""
		 * }
		 * Length: 64 Alignment: 8
		 */
		Structure structC = new StructureDataType("structC", 0);
		structC.setPackingEnabled(true);
		structC.add(CharDataType.dataType, "c0", null);
		structC.add(structB, "c1", null);

		return structC;
	}

}
