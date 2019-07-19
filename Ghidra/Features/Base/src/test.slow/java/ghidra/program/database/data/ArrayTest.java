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

import ghidra.docking.settings.SettingsDefinition;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.task.TaskMonitorAdapter;

import org.junit.*;

/**
 *
 * To change the template for this generated type comment go to
 * Window>Preferences>Java>Code Generation>Code and Comments
 * 
 * 
 * 
 */
public class ArrayTest extends AbstractGhidraHeadedIntegrationTest {
	private ProgramDB program;
	private DataTypeManagerDB dataMgr;
	private int transactionID;
	private Structure struct;
	private Listing listing;
	private AddressSpace space;

	public ArrayTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		program = createDefaultProgram(testName.getMethodName(), ProgramBuilder._TOY, this);
		dataMgr = program.getDataTypeManager();
		listing = program.getListing();
		space = program.getAddressFactory().getDefaultAddressSpace();
		transactionID = program.startTransaction("Test");
		addBlock();

		struct = new StructureDataType("test", 0);
		struct.add(new ByteDataType(), "field0", "Comment1");
		struct.add(new WordDataType(), null, "Comment2");
		struct.add(new DWordDataType(), "field3", null);
		struct.add(new ByteDataType(), "field4", "Comment4");
		struct = (Structure) dataMgr.resolve(struct, null);

		Structure s = new StructureDataType("inner", 0);
		s.add(new ByteDataType(), null, null);
		s.add(new WordDataType(), "word field", null);
		s = (Structure) dataMgr.resolve(s, null);

		struct.insert(1, s);

	}

	@After
	public void tearDown() throws Exception {
		program.endTransaction(transactionID, true);
		program.release(this);
	}

	@Test
	public void testCreateArray() throws Exception {

		Array array =
			(Array) dataMgr.resolve(new ArrayDataType(struct, 5, struct.getLength()), null);
		assertEquals(5, array.getNumElements());
		int structLen = struct.getLength();
		assertEquals(5 * structLen, array.getLength());
	}

	@Test
	public void testApplyArray() throws Exception {
		Array array =
			(Array) dataMgr.resolve(new ArrayDataType(struct, 5, struct.getLength()), null);

		listing.createData(addr(0x100), array, 0);

		Data data = listing.getDataAt(addr(0x100));
		assertNotNull(data);
		assertTrue(data.getDataType() instanceof Array);
		assertEquals(addr(0x100 + array.getLength() - 1), data.getMaxAddress());
	}

	@Test
	public void testDeleteArray() throws Exception {
		Array array =
			(Array) dataMgr.resolve(new ArrayDataType(struct, 5, struct.getLength()), null);
		DataType dt = array.getDataType();
		String name = dt.getName();
		listing.createData(addr(0x100), array, 0);

		listing.getDataAt(addr(0x100));
		CategoryPath path = dt.getCategoryPath();
		assertNotNull(path);
		dt.getDataTypeManager().remove(dt, TaskMonitorAdapter.DUMMY_MONITOR);

		assertTrue(array.isDeleted());
		assertNull(dt.getDataTypeManager().getDataType(path, name));
	}

	@Test
	public void testArrayDataSettings() throws Exception {
		ArrayDataType dataType = new ArrayDataType(new ByteDataType(), 10, 1);
		assertEquals(5, dataType.getSettingsDefinitions().length);

		Array array = (Array) dataMgr.resolve(dataType, null);
		assertEquals(5, array.getSettingsDefinitions().length);

		listing.createData(addr(0x100), array, 0);
		Data data = listing.getDataAt(addr(0x100));
		assertEquals(5, data.getDataType().getSettingsDefinitions().length);

		assertArrayEquals(new ByteDataType().getSettingsDefinitions(),
			data.getDataType().getSettingsDefinitions());

	}

	@Test
	public void testArrayDataSettingsInAStructure() throws Exception {
		ArrayDataType arrayDataType = new ArrayDataType(new ByteDataType(), 10, 1);
		StructureDataType structDataType = new StructureDataType("TestStruct", 0);
		structDataType.add(new FloatDataType());
		structDataType.add(arrayDataType);

		Structure structDB = (Structure) dataMgr.resolve(structDataType, null);
		DataTypeComponent component = structDB.getComponent(1);
		DataType dataType = component.getDataType();
		assertEquals(5, dataType.getSettingsDefinitions().length);

		listing.createData(addr(0x100), structDB, 0);
		Data data = listing.getDataAt(addr(0x100));
		Data subData = data.getComponent(1);
		SettingsDefinition[] settingsDefinitions = subData.getDataType().getSettingsDefinitions();

		assertArrayEquals(new ByteDataType().getSettingsDefinitions(), settingsDefinitions);

	}

	@Test
	public void testSettingArrayElementAffectsAllElements() throws Exception {
		ArrayDataType dataType = new ArrayDataType(new ByteDataType(), 10, 1);
		listing.createData(addr(0x100), dataType, 0);
		Data data = listing.getDataAt(addr(0x100));

		assertEquals(10, data.getNumComponents());

		for (int i = 0; i < 10; i++) {
			Data comp = data.getComponent(i);
			assertEquals(null, comp.getLong("MySetting"));
		}

		Data component4 = data.getComponent(4);
		component4.setLong("MySetting", 10L);

		for (int i = 0; i < 10; i++) {
			Data comp = data.getComponent(i);
			assertEquals((Long) 10L, comp.getLong("MySetting"));
		}

	}

	@Test
	public void testSettingArrayElementInStructAffectsAllElements() throws Exception {
		ArrayDataType arrayDataType = new ArrayDataType(new ByteDataType(), 10, 1);
		StructureDataType structDataType = new StructureDataType("TestStruct", 0);
		structDataType.add(new FloatDataType());
		structDataType.add(arrayDataType);

		Structure structDB = (Structure) dataMgr.resolve(structDataType, null);

		listing.createData(addr(0x100), structDB, 0);
		Data parentData = listing.getDataAt(addr(0x100));
		Data subData = parentData.getComponent(1);

		for (int i = 0; i < 10; i++) {
			Data comp = subData.getComponent(i);
			assertEquals(null, comp.getLong("MySetting"));
		}

		Data component4 = subData.getComponent(4);
		component4.setLong("MySetting", 10L);

		for (int i = 0; i < 10; i++) {
			Data comp = subData.getComponent(i);
			assertEquals((Long) 10L, comp.getLong("MySetting"));
		}

	}

	private void addBlock() throws Exception {
		Memory mem = program.getMemory();
		mem.createInitializedBlock("test", addr(0), 0x1000L, (byte) 0,
			TaskMonitorAdapter.DUMMY_MONITOR, false);
	}

	private Address addr(int offset) {
		return space.getAddress(offset);
	}

}
