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
package ghidra.program.model.data;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.util.Collection;

import org.junit.Test;

import generic.test.AbstractGTest;
import ghidra.program.database.data.DataTypeUtilities;

public class DataTypeUtilitiesTest extends AbstractGTest {

	@Test
	public void testGetContainedDataTypes() {
		DataType byteDt = new ByteDataType();
		DataType wordDt = new WordDataType();
		Structure simpleStruct = new StructureDataType("simpleStruct", 2);
		simpleStruct.add(wordDt);
		simpleStruct.add(byteDt);

		Structure notAsSimpleStruct = new StructureDataType("notAsSimpleStruct", 2);
		notAsSimpleStruct.add(simpleStruct);
		notAsSimpleStruct.add(byteDt);

		Structure selfRefStruct = new StructureDataType("selfRefStruct", 2);
		selfRefStruct.add(byteDt);
		selfRefStruct.add(new Pointer32DataType(selfRefStruct));

		TypeDef typedef = new TypedefDataType("simpleTypedef", simpleStruct);

		Structure complexStruct = new StructureDataType("complexStruct", 2);
		complexStruct.add(new Pointer32DataType(typedef));
		complexStruct.add(notAsSimpleStruct);
		complexStruct.add(selfRefStruct);

		TypeDef rootDt = new TypedefDataType("root", complexStruct);

		Collection<DataType> dts = DataTypeUtilities.getContainedDataTypes(rootDt);
		assertEquals(11, dts.size());
	}

	@Test
	public void testGetCPrimitiveType() {
		assertEquals(IntegerDataType.dataType, getType("signed int"));
		assertEquals(IntegerDataType.dataType, getType(" signed     int   "));
		assertEquals(IntegerDataType.dataType, getType("SIGNED int"));
		assertEquals(UnsignedLongLongDataType.dataType, getType("unsigned long long int"));
		assertNull(getType("foo bar"));
	}

	private DataType getType(String typeName) {
		return DataTypeUtilities.getCPrimitiveDataType(typeName);
	}

}
