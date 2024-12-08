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

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.program.model.data.*;

public class TypedefDBTest extends AbstractGenericTest {

	private final String NAME = "Test";
	
	private DataTypeManagerDB dataMgr;
	private int txId;

	@Before
	public void setUp() throws Exception {
		dataMgr = new StandAloneDataTypeManager("dummyDTM");
		txId = dataMgr.startTransaction("Test");
	}
	
	@After
	public void tearDown() {
		if (txId > 0) {
			dataMgr.endTransaction(txId, true);
			dataMgr.close();
		}
	}
	
	@Test
	public void testDuplicateNameResolve() throws Exception {
		
		Structure struct = new StructureDataType(NAME, 0);
		struct.add(new ByteDataType(), "field1", "Comment1");
		struct.add(new WordDataType(), null, "Comment2");
		struct.add(new DWordDataType(), "field3", null);
		struct.add(new ByteDataType(), "field4", "Comment4");
		
		Pointer structPtr = new PointerDataType(struct);
		
		TypeDef typeDef = new TypedefDataType(NAME, structPtr);
		
		TypeDef td = (TypeDef) dataMgr.resolve(typeDef, null);
		assertNotNull(td);
		assertEquals(NAME + ".conflict", td.getName());
		
		assertTrue(td.isEquivalent(typeDef));
		
		assertEquals("typedef Test.conflict Test *", td.toString());
		
	}

}
