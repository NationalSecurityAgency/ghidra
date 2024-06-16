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

import org.junit.Test;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.util.ProgramDiff;

public class DefinedDataSarifTest extends AbstractSarifTest {

	public DefinedDataSarifTest() {
		super();
	}

	@Test
	public void testDefinedData() throws Exception {
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
		 *    2   byte[0]   0   bfs   ""
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

		program.getListing().createData(addr(0x100), structC);

		ProgramDiff programDiff = readWriteCompare();
		
		AddressSetView differences = programDiff.getDifferences(monitor);
		assert(differences.isEmpty());
	}

}
