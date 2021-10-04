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

import java.awt.Color;

import org.junit.*;

import ghidra.docking.settings.*;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 *
 * Test setting default and instance settings on Data.
 *  
 * 
 */
public class SettingsTest extends AbstractGhidraHeadedIntegrationTest {
	private ProgramDB program;
	private ProgramBasedDataTypeManager dataMgr;
	private Listing listing;
	private AddressSpace space;
	private int transactionID;

	// NOTE: Datatypes must be resolved before settings may be changed
	// with the exception of TypeDefDataType which does permit
	// TypeDefSettingsDefinition settings defined by the base-datatype.

	public SettingsTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		program = createDefaultProgram(testName.getMethodName(), ProgramBuilder._TOY, this);
		space = program.getAddressFactory().getDefaultAddressSpace();
		dataMgr = program.getDataTypeManager();
		listing = program.getListing();
		transactionID = program.startTransaction("Test");
		addBlock();
	}

	@After
	public void tearDown() throws Exception {
		if (program.getCurrentTransaction() != null) {
			program.endTransaction(transactionID, true);
		}
		program.release(this);
	}

	@Test
	public void testSetDefaultSettings() throws Exception {

		DataType dt = ByteDataType.dataType;

		Settings defaultSettings = dt.getDefaultSettings();
		defaultSettings.setString("color", "red");
		defaultSettings.setLong("someLongValue", 10);

		assertNull(defaultSettings.getString("color"));
		assertNull(defaultSettings.getLong("someLongValue"));

		// May modify byte default settings after resolve
		dt = dataMgr.resolve(dt, null);

		defaultSettings = dt.getDefaultSettings();
		defaultSettings.setString("color", "red");
		defaultSettings.setLong("someLongValue", 10);

		assertEquals("red", defaultSettings.getString("color"));
		Long lv = defaultSettings.getLong("someLongValue");
		assertNotNull(lv);
		assertEquals(10, lv.longValue());

		defaultSettings.setValue("long", 10L);
		Object obj = defaultSettings.getValue("long");
		assertNotNull(obj);
		assertEquals(10, ((Long) obj).longValue());
	}

	@Test
	public void testSetTypedefDefaultSettings() throws Exception {

		TypeDef typeDef = new TypedefDataType(CategoryPath.ROOT, "ByteTypedef",
			new ByteDataType(dataMgr), dataMgr);

		assertEquals(0, ByteDataType.dataType.getTypeDefSettingsDefinitions().length);

		Settings defaultSettings = typeDef.getDefaultSettings();
		defaultSettings.setString("color", "red");
		defaultSettings.setLong("someLongValue", 10);

		assertNull(defaultSettings.getString("color"));
		assertNull(defaultSettings.getLong("someLongValue"));

		// May modify arbitrary typedef default settings after resolve
		typeDef = (TypeDef) dataMgr.resolve(typeDef, null);

		defaultSettings = typeDef.getDefaultSettings();
		defaultSettings.setString("color", "red");
		defaultSettings.setLong("someLongValue", 10);

		assertEquals("red", defaultSettings.getString("color"));
		Long lv = defaultSettings.getLong("someLongValue");
		assertNotNull(lv);
		assertEquals(10, lv.longValue());

		defaultSettings.setValue("long", 10L);
		Object obj = defaultSettings.getValue("long");
		assertNotNull(obj);
		assertEquals(10, ((Long) obj).longValue());

		try {
			defaultSettings.setValue("color", Color.RED);
			Assert.fail("Should not be able to set arbitrary objects");
		}
		catch (IllegalArgumentException e) {
			// expected
		}
	}

	@Test
	public void testIsEmpty() throws Exception {

		DataType dt = dataMgr.resolve(ByteDataType.dataType, null);
		Settings defaultSettings = dt.getDefaultSettings();
		defaultSettings.setString("color", "red");
		defaultSettings.setLong("someLongValue", 10);

		assertTrue(!defaultSettings.isEmpty());

		defaultSettings.clearAllSettings();
		assertTrue(defaultSettings.isEmpty());
	}

	@Test
	public void testGetNames() throws Exception {

		DataType dt = dataMgr.resolve(ByteDataType.dataType, null);
		Settings defaultSettings = dt.getDefaultSettings();
		defaultSettings.setString("color", "red");
		defaultSettings.setLong("someLongValue", 10);
		defaultSettings.setString("endian", "big Endian");

		String[] names = defaultSettings.getNames();
		assertEquals(3, names.length);
	}

	@Test
	public void testClearSetting() throws Exception {

		DataType dt = dataMgr.resolve(ByteDataType.dataType, null);
		Settings defaultSettings = dt.getDefaultSettings();
		defaultSettings.setString("color", "red");
		defaultSettings.setLong("someLongValue", 10);

		defaultSettings.clearSetting("color");
		assertNull(defaultSettings.getString("color"));
	}

	@Test
	public void testInstanceSettings() throws Exception {

		listing.createData(addr(10), new ByteDataType(), 1);
		Data data = listing.getDataAt(addr(10));
		ByteDataType dt = (ByteDataType) data.getDataType();
		Settings defaultSettings = dt.getDefaultSettings();
		defaultSettings.setLong("format", FormatSettingsDefinition.CHAR);
		defaultSettings.setLong("signed", 0);
		defaultSettings.setLong("padded", 1);

		SettingsDefinition[] defs = dt.getSettingsDefinitions();
		for (int i = 0; i < defs.length; i++) {

			if (defs[i] instanceof EnumSettingsDefinition) {
				EnumSettingsDefinition enumDef = (EnumSettingsDefinition) defs[i];
				int value = enumDef.getChoice(data);
				enumDef.setChoice(data, value);
				if (i == 0) {
					assertEquals(FormatSettingsDefinition.CHAR, data.getLong("format").longValue());
				}
				else if (i == 1) {
					assertEquals(0, data.getLong("signed").longValue());
				}
				else if (i == 2) {
					assertEquals(1, data.getLong("padded").longValue());
				}

			}
		}
	}

	@Test
	public void testGetInstanceNames() throws Exception {
		listing.createData(addr(10), new ByteDataType(), 1);
		Data data = listing.getDataAt(addr(10));
		data.setString("color", "red");
		data.setLong("someLongValue", 10);
		data.setString("endian", "big Endian");

		String[] names = data.getNames();
		assertEquals(3, names.length);
	}

	@Test
	public void testClearInstanceSettings() throws Exception {
		listing.createData(addr(10), new ByteDataType(), 1);
		Data data = listing.getDataAt(addr(10));

		data.setString("color", "red");
		data.setLong("someLongValue", 10);

		data.clearSetting("color");
		assertNull(data.getString("color"));
	}

	@Test
	public void testClearAllInstanceSettings() throws Exception {
		listing.createData(addr(10), new ByteDataType(), 1);
		Data data = listing.getDataAt(addr(10));

		data.setString("color", "red");
		data.setLong("someLongValue", 10);
		data.setString("endian", "big Endian");

		data.clearAllSettings();
		assertNull(data.getString("color"));
		assertNull(data.getLong("someLongValue"));
		assertNull(data.getString("endian"));
	}

	@Test
	public void testIsEmptyInstanceSettings() throws Exception {
		listing.createData(addr(10), new ByteDataType(), 1);
		Data data = listing.getDataAt(addr(10));

		data.setString("color", "red");
		data.setLong("someLongValue", 10);
		data.setString("endian", "big Endian");

		assertTrue(!data.isEmpty());
		data.clearAllSettings();

		assertTrue(data.isEmpty());
	}

	@Test
	public void testMoveSettings() throws Exception {

		for (int i = 0; i < 10; i++) {
			Address a = addr(i);
			dataMgr.setStringSettingsValue(a, "color", "red" + i);
			dataMgr.setLongSettingsValue(a, "someLongValue", i);
		}
		dataMgr.moveAddressRange(addr(0), addr(20), 10, TaskMonitor.DUMMY);
		int j = 0;
		for (int i = 20; i < 30; i++, j++) {
			Address a = addr(i);

			String s = dataMgr.getStringSettingsValue(a, "color");
			assertEquals("red" + j, s);

			Long lvalue = dataMgr.getLongSettingsValue(a, "someLongValue");
			assertEquals(j, lvalue.longValue());
		}
	}

	@Test
	public void testMoveSettings2() {

		for (int i = 0; i < 10; i++) {
			Address a = addr(i);
			dataMgr.setStringSettingsValue(a, "color", "red" + i);
			dataMgr.setLongSettingsValue(a, "someLongValue", i);
		}
		try {
			dataMgr.moveAddressRange(addr(0), addr(5), 10, TaskMonitor.DUMMY);
		}
		catch (CancelledException e) {
			Assert.fail("Unexpected cancelled exception");
		}

		int j = 0;
		for (int i = 5; i < 15; i++, j++) {
			Address a = addr(i);

			String s = dataMgr.getStringSettingsValue(a, "color");
			assertEquals("red" + j, s);

			Long lvalue = dataMgr.getLongSettingsValue(a, "someLongValue");
			assertEquals(j, lvalue.longValue());
		}
	}

	@Test
	public void testMoveSettings3() {

		int j = 20;
		for (int i = 20; i < 30; i++, j++) {
			Address a = addr(i);
			dataMgr.setStringSettingsValue(a, "color", "red" + i);
			dataMgr.setLongSettingsValue(a, "someLongValue", i);
		}
		j = 20;
		try {
			dataMgr.moveAddressRange(addr(20), addr(5), 10, TaskMonitor.DUMMY);
		}
		catch (CancelledException e) {
			Assert.fail("Unexpected cancelled exception");
		}
		for (int i = 5; i < 15; i++, j++) {
			Address a = addr(i);

			String s = dataMgr.getStringSettingsValue(a, "color");
			assertEquals("red" + j, s);

			Long lvalue = dataMgr.getLongSettingsValue(a, "someLongValue");
			assertEquals(j, lvalue.longValue());
		}

	}

	@Test
	public void testDefaultSettingsOnCharArray() throws Exception {
		DataType charDT = dataMgr.resolve(new CharDataType(), null);
		SettingsDefinition[] settingsDefinitions = charDT.getSettingsDefinitions();

		assertTrue("Expect multiple settings on char type", settingsDefinitions.length > 2); // make sure we get more than two settings

		Array array = new ArrayDataType(charDT, 5, -1);
		assertArrayEquals(settingsDefinitions, array.getSettingsDefinitions());

		array = (Array) dataMgr.resolve(array, null);
		assertArrayEquals(settingsDefinitions, array.getSettingsDefinitions());

		Settings defaultSettings = array.getDefaultSettings();

		assertEquals(FormatSettingsDefinition.CHAR,
			FormatSettingsDefinition.DEF_CHAR.getChoice(defaultSettings));

		assertEquals(MutabilitySettingsDefinition.NORMAL,
			MutabilitySettingsDefinition.DEF.getChoice(defaultSettings));

		assertEquals(String.class, array.getValueClass(defaultSettings));

		FormatSettingsDefinition.DEF_CHAR.setChoice(defaultSettings, FormatSettingsDefinition.HEX);

		assertEquals(Array.class, array.getValueClass(defaultSettings));
	}

	@Test
	public void testDefaultSettingsOnTypedef() throws Exception {
		DataType byteDT = dataMgr.resolve(new ByteDataType(), null);
		SettingsDefinition[] settingsDefinitions = byteDT.getSettingsDefinitions();
		Settings settings = byteDT.getDefaultSettings();
		settings.setLong("format", FormatSettingsDefinition.OCTAL);
		settings.setString("color", "red");

		TypedefDataType tdt = new TypedefDataType("ByteTypedef", byteDT);
		TypeDef td = (TypeDef) dataMgr.addDataType(tdt, null);

		SettingsDefinition[] sdefs = td.getSettingsDefinitions();
		assertTrue(sdefs.length >= settingsDefinitions.length);  // TypeDef may add some of its own

		Settings defSettings = td.getDefaultSettings();
		defSettings.setLong("someLongValue", 10);

		assertEquals((long) FormatSettingsDefinition.OCTAL, defSettings.getValue("format")); // inherits from byteDt
		assertEquals("red", defSettings.getValue("color")); // inherits from byteDt
		assertEquals(10L, defSettings.getValue("someLongValue"));
	}

	@Test
	public void testDefaultSettingsOnTypedef2() throws Exception {
		DataType byteDT = dataMgr.resolve(new ByteDataType(), null);
		Settings settings = byteDT.getDefaultSettings();

		TypedefDataType tdt = new TypedefDataType("ByteTypedef", byteDT);
		TypeDef td = (TypeDef) dataMgr.addDataType(tdt, null);
		Settings defSettings = td.getDefaultSettings();
		defSettings.setLong("format", FormatSettingsDefinition.OCTAL);
		assertEquals((long) FormatSettingsDefinition.OCTAL, defSettings.getValue("format"));

		// change the default settings for Byte data type; should not 
		// affect the typedef default settings

		settings.setLong("format", FormatSettingsDefinition.BINARY);

		defSettings = td.getDefaultSettings();
		assertEquals((long) FormatSettingsDefinition.OCTAL, defSettings.getValue("format"));
	}

	@Test
	public void testDefaultSettingsOnTypedefUndoRedo() throws Exception {
		DataType byteDT = dataMgr.resolve(new ByteDataType(), null);
		Settings settings = byteDT.getDefaultSettings();
		settings.setLong("format", FormatSettingsDefinition.OCTAL);
		endTransaction();

		startTransaction();
		TypedefDataType tdt = new TypedefDataType("ByteTypedef", byteDT);
		TypeDef td = (TypeDef) dataMgr.addDataType(tdt, null);
		Settings defSettings = td.getDefaultSettings();
		assertEquals((long) FormatSettingsDefinition.OCTAL, defSettings.getValue("format")); // inherits from byteDt
		endTransaction();

		startTransaction();
		defSettings.setLong("format", FormatSettingsDefinition.BINARY);
		assertEquals((long) FormatSettingsDefinition.BINARY, defSettings.getValue("format"));
		endTransaction();

		undo(program);
		defSettings = td.getDefaultSettings();
		assertEquals((long) FormatSettingsDefinition.OCTAL, defSettings.getValue("format")); // inherits from byteDt

		redo(program);
		defSettings = td.getDefaultSettings();
		assertEquals((long) FormatSettingsDefinition.BINARY, defSettings.getValue("format"));
	}

	@Test
	public void testDefaultSettingsOnDeletedTypdef() throws Exception {
		DataType byteDT = dataMgr.resolve(new ByteDataType(), null);
		Settings settings = byteDT.getDefaultSettings();
		settings.setLong("format", FormatSettingsDefinition.OCTAL);

		TypedefDataType tdt = new TypedefDataType("ByteTypedef", byteDT);
		TypeDef td = (TypeDef) dataMgr.addDataType(tdt, null);
		long dtID = dataMgr.getID(td);
		endTransaction();

		startTransaction();
		// apply typedef
		program.getListing().createData(addr(50), td);
		endTransaction();

		startTransaction();
		dataMgr.remove(td, TaskMonitor.DUMMY);
		endTransaction();
		// make sure accessing the settings does not blow up
		assertTrue(td.isDeleted());
		assertNotNull(td.getDefaultSettings());

		undo(program);
		td = (TypeDef) dataMgr.getDataType(dtID);
		assertTrue(!td.isDeleted());

		Settings s = td.getDefaultSettings();
		assertEquals((long) FormatSettingsDefinition.OCTAL, s.getValue("format"));

		redo(program);
		assertTrue(td.isDeleted());
		s = td.getDefaultSettings();
		assertNull(s.getValue("format"));
	}

	private void startTransaction() {
		transactionID = program.startTransaction("Test");
	}

	private void endTransaction() {
		program.endTransaction(transactionID, true);
	}

	private Address addr(long l) {
		return space.getAddress(l);
	}

	private void addBlock() throws Exception {

		Memory memory = program.getMemory();
		memory.createInitializedBlock("test", addr(0), 100, (byte) 0,
			TaskMonitor.DUMMY, false);
	}
}
