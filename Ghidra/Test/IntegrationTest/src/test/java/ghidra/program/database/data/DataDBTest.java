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
package ghidra.program.database.data;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;

public class DataDBTest extends AbstractGenericTest {

	private Program program;
	private Listing listing;

	@Before
	public void setUp() throws Exception {
		program = buildProgram();
		listing = program.getListing();
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
		Structure structA = new StructureDataType("structA", 0);
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
		Structure structB = new StructureDataType("structB", 0);
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
		Structure structC = new StructureDataType("structC", 0);
		structC.setPackingEnabled(true);
		structC.add(CharDataType.dataType, "c0", null);
		structC.add(structB, "c1", null);

		ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
		structC = (Structure) dtm.resolve(structC, null);

		listing.createData(addr(0x1100), structC);

	}

	private Address addr(long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	private Program buildProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("Test", ProgramBuilder._TOY);
		builder.createMemory("test1", "0x1000", 0x200);
		return builder.getProgram();
	}

	@Test
	public void testGetComponentFromPath() throws Exception {
		
		Data d = listing.getDataAt(addr(0x1100));
		Data c = d.getComponent(new int[] { 1 });
		assertNotNull(c);
		assertEquals("c1", c.getComponentPathName());

		c = d.getComponent(new int[] { 1, 6 });
		assertNotNull(c);
		assertEquals("c1.b1", c.getComponentPathName());

		c = d.getComponent(new int[] { 1, 6, 3 });
		assertNotNull(c);
		assertEquals("c1.b1.a1", c.getComponentPathName());

		c = d.getComponent(new int[] { 1, 6, 4 }); // may not be visible in listing display
		assertNotNull(c);
		assertEquals("c1.b1.aflex", c.getComponentPathName());

	}

	@Test
	public void testGetComponentContainingAt() throws Exception {
		
		Data d = listing.getDataAt(addr(0x1100));
		Data c = d.getComponentContaining(4);
		assertNotNull(c);
		assertEquals("c1", c.getComponentPathName());

		Data c2 = c.getComponentContaining(4); // zero-length component is ignored
		assertNotNull(c2);
		assertEquals("c1.bf1", c2.getComponentPathName());

		Data c3 = c.getComponentContaining(5);
		assertNotNull(c3);
		assertEquals("c1.bf2", c3.getComponentPathName());

	}

	@Test
	public void testGetComponentsContaining() throws Exception {

		Data d = listing.getDataAt(addr(0x1100));
		Data c = d.getComponent(new int[] { 1 });
		assertNotNull(c);
		assertEquals("c1", c.getComponentPathName());

		List<Data> dataComponents = c.getComponentsContaining(4);
		assertEquals("[int:0 , db[0] , int:4 0h, int:6 0h]", dataComponents.toString());

		c = d.getComponent(new int[] { 1, 6 });
		assertNotNull(c);
		assertEquals("c1.b1", c.getComponentPathName());

		dataComponents = c.getComponentsContaining(4);
		assertEquals("[char[0] , ?? 00h]", dataComponents.toString());

		dataComponents = c.getComponentsContaining(5);
		assertEquals("[db 0h]", dataComponents.toString());

		// last structA.aflex component is beyond data bounds
		dataComponents = c.getComponentsContaining(6);
		assertNull(dataComponents);
	}

}
