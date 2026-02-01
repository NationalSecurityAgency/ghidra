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
package ghidra.program.util;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;

public class DataTypeCleanerTest extends AbstractGenericTest {

	private Program program;

	private Structure structA;
	private Structure structB;
	private Structure structC;

	@Before
	public void setUp() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("Test", ProgramBuilder._TOY);
		program = builder.getProgram();

		program.startTransaction("TEST");

		/**
		 * /structA
		 * pack(disabled)
		 * Structure structA {
		 *    0   int   4   a0   ""
		 *    4   char[0]   0   az   ""
		 *    5   byte   1   a1   ""
		 *    6   char[0]   0   aflex   ""
		 * }
		 * Size = 6   Actual Alignment = 1
		 */
		structA = new StructureDataType("structA", 0);
		structA.add(IntegerDataType.dataType, "a0", null);
		structA.add(new ArrayDataType(CharDataType.dataType, 0, -1), "az", null);
		structA.add(DataType.DEFAULT);
		structA.add(ByteDataType.dataType, "a1", null);
		structA.add(new ArrayDataType(IntegerDataType.dataType, 0, -1), "aflex", null);

		/**
		 * /structB
		 * pack()
		 * Structure structB {
		 *    0   short   2   b0   ""
		 *    4   int:0(0)   0      ""
		 *    4   byte[0]   0   bfs   ""
		 *    4   int:4(0)   1   bf1   ""
		 *    4   int:6(4)   2   bf2   ""
		 *    5   int:2(2)   1   bf3   ""
		 *    6   structA   6   b1   ""
		 * }
		 * Size = 12   Actual Alignment = 4
		 */
		structB = new StructureDataType("structB", 0);
		structB.setPackingEnabled(true);
		structB.add(ShortDataType.dataType, "b0", null);
		structB.addBitField(IntegerDataType.dataType, 0, null, null); // force integer alignment
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
		 *    4   structB   12   c1   ""
		 * }
		 * Size = 16   Actual Alignment = 4
		 */
		structC = new StructureDataType("structC", 0);
		structC.setDescription("My structC");
		structC.setPackingEnabled(true);
		structC.add(CharDataType.dataType, "c0", null);
		structC.add(structB, "c1", null);

	}

	@Test
	public void testClean() {

		DataTypeManager dtm = program.getDataTypeManager();
		DataOrganization dataOrganization = dtm.getDataOrganization();

		try (DataTypeCleaner dtCleaner = new DataTypeCleaner(program.getDataTypeManager(), false)) {

			Structure cleanC = (Structure) dtCleaner.clean(structC);
			assertEquals(structC.getCategoryPath(), cleanC.getCategoryPath());
			assertEquals(structC.getName(), cleanC.getName());
			assertEquals(structC.getDescription(), cleanC.getDescription());
			assertTrue(cleanC.isNotYetDefined());

			Pointer ptr = new PointerDataType(structB);
			Pointer cleanPtr = (Pointer) dtCleaner.clean(ptr);
			assertEquals(dataOrganization.getPointerSize(), cleanPtr.getLength());
			DataType dt = cleanPtr.getDataType();
			assertTrue(dt instanceof Structure);
			assertEquals(structB.getCategoryPath(), dt.getCategoryPath());
			assertEquals(structB.getName(), dt.getName());

		}
	}

	@Test
	public void testCleanWithExisting1() {

		DataTypeManager dtm = program.getDataTypeManager();
		DataOrganization dataOrganization = dtm.getDataOrganization();

		dtm.resolve(structC, null);

		try (DataTypeCleaner dtCleaner = new DataTypeCleaner(program.getDataTypeManager(), false)) {

			Structure cleanC = (Structure) dtCleaner.clean(structC);
			assertEquals(structC.getCategoryPath(), cleanC.getCategoryPath());
			assertEquals(structC.getName(), cleanC.getName());
			assertEquals(structC.getDescription(), cleanC.getDescription());
			assertTrue(cleanC.isNotYetDefined());

			Pointer ptr = new PointerDataType(structC);
			Pointer cleanPtr = (Pointer) dtCleaner.clean(ptr);
			assertEquals(dataOrganization.getPointerSize(), cleanPtr.getLength());
			DataType dt = cleanPtr.getDataType();
			assertTrue(dt instanceof Structure);
			assertEquals(structC.getCategoryPath(), dt.getCategoryPath());
			assertEquals(structC.getName(), dt.getName());

		}
	}

	@Test
	public void testCleanWithExisting2() {

		DataTypeManager dtm = program.getDataTypeManager();
		DataOrganization dataOrganization = dtm.getDataOrganization();

		DataType resolvedDt = dtm.resolve(structC, null);

		try (DataTypeCleaner dtCleaner = new DataTypeCleaner(program.getDataTypeManager(), true)) {

			Structure cleanC = (Structure) dtCleaner.clean(structC);
			assertEquals(structC.getCategoryPath(), cleanC.getCategoryPath());
			assertEquals(structC.getName(), cleanC.getName());
			assertEquals(structC.getDescription(), cleanC.getDescription());
			assertFalse(cleanC.isNotYetDefined());
			assertTrue(resolvedDt.isEquivalent(cleanC));

			Pointer ptr = new PointerDataType(structC);
			Pointer cleanPtr = (Pointer) dtCleaner.clean(ptr);
			assertEquals(dataOrganization.getPointerSize(), cleanPtr.getLength());
			DataType dt = cleanPtr.getDataType();
			assertTrue(dt instanceof Structure);
			assertEquals(structC.getCategoryPath(), dt.getCategoryPath());
			assertEquals(structC.getName(), dt.getName());
			assertFalse(dt.isNotYetDefined());
			assertTrue(resolvedDt.isEquivalent(dt));

		}
	}

	@Test
	public void testCleanWithExisting3() {

		DataTypeManager dtm = program.getDataTypeManager();
		DataOrganization dataOrganization = dtm.getDataOrganization();

		dtm.resolve(structA, null);

		try (DataTypeCleaner dtCleaner = new DataTypeCleaner(program.getDataTypeManager(), true)) {

			FunctionDefinition funcDef =
				new FunctionDefinitionDataType(new CategoryPath("/Foo"), "Bar");
			Pointer ptr1 = new PointerDataType(structA);
			Pointer ptr2 = new PointerDataType(structC);
			funcDef.setArguments(
				new ParameterDefinition[] { new ParameterDefinitionImpl("P1", ptr1, null) });
			funcDef.setReturnType(ptr2);

			FunctionDefinition cleanFuncDef = (FunctionDefinition) dtCleaner.clean(funcDef);
			Pointer cleanPtr1 = (Pointer) cleanFuncDef.getArguments()[0].getDataType();
			assertTrue(ptr1.isEquivalent(cleanPtr1));
			assertEquals(dataOrganization.getPointerSize(), cleanPtr1.getLength());
			Pointer cleanPtr2 = (Pointer) cleanFuncDef.getReturnType();
			assertFalse(ptr2.isEquivalent(cleanPtr2));
			assertEquals(dataOrganization.getPointerSize(), cleanPtr2.getLength());
			DataType dt = cleanPtr2.getDataType();
			assertTrue(dt instanceof Structure);
			assertEquals(structC.getCategoryPath(), dt.getCategoryPath());
			assertEquals(structC.getName(), dt.getName());
			assertTrue(dt.isNotYetDefined());

		}
	}

}
