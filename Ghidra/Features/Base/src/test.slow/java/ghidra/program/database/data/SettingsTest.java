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

import generic.theme.GThemeDefaults.Colors.Palette;
import ghidra.docking.settings.*;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
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
	private Listing listing;
	private ProgramBasedDataTypeManager dataMgr;
	private AddressSpace space;
	private int transactionID;

	// Suitable settings allowed for StringDataType data
	private static String LONG_SETTING_NAME = "mutability";
	private static String STRING_SETTING_NAME = "charset";

	// NOTE: Datatypes must be resolved before settings may be changed
	// with the exception of TypeDefDataType which does permit
	// TypeDefSettingsDefinition settings defined by the base-datatype.

	public SettingsTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		program = createDefaultProgram(testName.getMethodName(), ProgramBuilder._TOY, this);
		listing = program.getListing();
		space = program.getAddressFactory().getDefaultAddressSpace();
		dataMgr = program.getDataTypeManager();
		transactionID = program.startTransaction("Test");
		addBlock();

		// pointer-typedef has the largest 
//		System.out.println("Defined string settings:");
//		for (SettingsDefinition def : StringDataType.dataType.getSettingsDefinitions()) {
//			System.out.println(def.getStorageKey());
//		}

		for (int i = 0; i < 40; i++) {
			DataUtilities.createData(program, addr(i), StringDataType.dataType, 1,
				ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
		}
	}

	@After
	public void tearDown() throws Exception {
		if (program.getCurrentTransactionInfo() != null) {
			program.endTransaction(transactionID, true);
		}
		program.release(this);
	}

	@Test
	public void testSetDefaultSettings() throws Exception {

		DataType dt = StringDataType.dataType;

		Settings defaultSettings = dt.getDefaultSettings();

		// immutable warnings expected
		defaultSettings.setString(STRING_SETTING_NAME, "red");
		defaultSettings.setLong(LONG_SETTING_NAME, 10);

		assertNull(defaultSettings.getString(STRING_SETTING_NAME));
		assertNull(defaultSettings.getLong(LONG_SETTING_NAME));

		// May modify byte default settings after resolve
		dt = dataMgr.resolve(dt, null);

		defaultSettings = dt.getDefaultSettings();
		defaultSettings.setString(STRING_SETTING_NAME, "red");
		defaultSettings.setLong(LONG_SETTING_NAME, 10);

		assertEquals("red", defaultSettings.getString(STRING_SETTING_NAME));
		Long lv = defaultSettings.getLong(LONG_SETTING_NAME);
		assertNotNull(lv);
		assertEquals(10, lv.longValue());

		defaultSettings.setValue(LONG_SETTING_NAME, 20L);
		Object obj = defaultSettings.getValue(LONG_SETTING_NAME);
		assertTrue(obj instanceof Long);
		assertEquals(20, ((Long) obj).longValue());
	}

	@Test
	public void testSetTypedefDefaultSettings() throws Exception {

		TypeDef typeDef = new TypedefDataType(CategoryPath.ROOT, "ByteTypedef",
			new ByteDataType(dataMgr), dataMgr);

		assertEquals(0, ByteDataType.dataType.getTypeDefSettingsDefinitions().length);

		Settings defaultSettings = typeDef.getDefaultSettings();

		// immutable warnings expected
		FormatSettingsDefinition.DEF.setChoice(defaultSettings, FormatSettingsDefinition.CHAR);
		EndianSettingsDefinition.DEF.setBigEndian(defaultSettings, false);
		PaddingSettingsDefinition.DEF.setPadded(defaultSettings, true);

		assertNull(defaultSettings.getLong("format"));
		assertNull(defaultSettings.getLong("endian"));
		assertNull(defaultSettings.getLong("padding"));

		// May modify arbitrary typedef default settings after resolve
		typeDef = (TypeDef) dataMgr.resolve(typeDef, null);

		defaultSettings = typeDef.getDefaultSettings();
		FormatSettingsDefinition.DEF.setChoice(defaultSettings, FormatSettingsDefinition.CHAR);
		EndianSettingsDefinition.DEF.setBigEndian(defaultSettings, false);
		PaddingSettingsDefinition.DEF.setPadded(defaultSettings, true);

		assertEquals(FormatSettingsDefinition.CHAR, defaultSettings.getLong("format").longValue());
		assertEquals(EndianSettingsDefinition.LITTLE,
			defaultSettings.getLong("endian").longValue());
		assertEquals(PaddingSettingsDefinition.PADDED_VALUE,
			defaultSettings.getLong("padded").longValue());

		try {
			defaultSettings.setValue("format", Palette.RED);
			Assert.fail("Should not be able to set arbitrary objects");
		}
		catch (IllegalArgumentException e) {
			// expected
		}
	}

	@Test
	public void testIsEmpty() throws Exception {

		DataType dt = dataMgr.resolve(StringDataType.dataType, null);
		Settings defaultSettings = dt.getDefaultSettings();
		defaultSettings.setString(STRING_SETTING_NAME, "red");
		defaultSettings.setLong(LONG_SETTING_NAME, 10);

		assertTrue(!defaultSettings.isEmpty());

		defaultSettings.clearAllSettings();
		assertTrue(defaultSettings.isEmpty());
	}

	@Test
	public void testGetNames() throws Exception {

		DataType dt = dataMgr.resolve(StringDataType.dataType, null);
		Settings defaultSettings = dt.getDefaultSettings();
		defaultSettings.setString(STRING_SETTING_NAME, "red");
		defaultSettings.setLong(LONG_SETTING_NAME, 10);

		String[] names = defaultSettings.getNames();
		assertEquals(2, names.length);
	}

	@Test
	public void testClearSetting() throws Exception {

		DataType dt = dataMgr.resolve(StringDataType.dataType, null);
		Settings defaultSettings = dt.getDefaultSettings();
		defaultSettings.setString(STRING_SETTING_NAME, "red");
		defaultSettings.setLong(LONG_SETTING_NAME, 10);

		defaultSettings.clearSetting(STRING_SETTING_NAME);
		assertNull(defaultSettings.getString(STRING_SETTING_NAME));
	}

	@Test
	public void testInstanceSettings() throws Exception {

		Data data = DataUtilities.createData(program, addr(10), ByteDataType.dataType, 1,
			ClearDataMode.CLEAR_ALL_CONFLICT_DATA);

		DataType dt = data.getDataType();
		Settings defaultSettings = dt.getDefaultSettings();
		FormatSettingsDefinition.DEF.setChoice(defaultSettings, FormatSettingsDefinition.CHAR);
		EndianSettingsDefinition.DEF.setBigEndian(defaultSettings, false);
		PaddingSettingsDefinition.DEF.setPadded(defaultSettings, true);

		assertEquals(FormatSettingsDefinition.CHAR, data.getLong("format").longValue());
		FormatSettingsDefinition.DEF.setChoice(data, FormatSettingsDefinition.DECIMAL);
		assertEquals(FormatSettingsDefinition.DECIMAL, data.getLong("format").longValue());

		assertEquals(EndianSettingsDefinition.LITTLE, data.getLong("endian").longValue());
		EndianSettingsDefinition.DEF.setChoice(data, EndianSettingsDefinition.BIG);
		assertEquals(EndianSettingsDefinition.BIG, data.getLong("endian").longValue());

		assertEquals(PaddingSettingsDefinition.PADDED_VALUE, data.getLong("padded").longValue());
		PaddingSettingsDefinition.DEF.setChoice(data, PaddingSettingsDefinition.UNPADDED_VALUE);
		assertEquals(PaddingSettingsDefinition.UNPADDED_VALUE, data.getLong("padded").longValue());

		FormatSettingsDefinition.DEF.setChoice(defaultSettings, FormatSettingsDefinition.HEX);
		EndianSettingsDefinition.DEF.clear(defaultSettings);
		PaddingSettingsDefinition.DEF.clear(defaultSettings);

		assertEquals(FormatSettingsDefinition.DECIMAL, data.getLong("format").longValue());
		assertEquals(EndianSettingsDefinition.BIG, data.getLong("endian").longValue());
		assertEquals(PaddingSettingsDefinition.UNPADDED_VALUE, data.getLong("padded").longValue());
	}

	@Test
	public void testGetInstanceNames() throws Exception {
		Data data = listing.getDataAt(addr(10));
		data.setString(STRING_SETTING_NAME, "red");
		data.setLong(LONG_SETTING_NAME, 10);

		String[] names = data.getNames();
		assertEquals(2, names.length);
	}

	@Test
	public void testClearInstanceSettings() throws Exception {
		Data data = listing.getDataAt(addr(10));

		data.setString(STRING_SETTING_NAME, "red");
		data.setLong(LONG_SETTING_NAME, 10);

		data.clearSetting(STRING_SETTING_NAME);
		assertNull(data.getString(STRING_SETTING_NAME));
	}

	@Test
	public void testClearAllInstanceSettings() throws Exception {
		Data data = listing.getDataAt(addr(10));

		data.setString(STRING_SETTING_NAME, "red");
		data.setLong(LONG_SETTING_NAME, 10);

		data.clearAllSettings();
		assertNull(data.getString(STRING_SETTING_NAME));
		assertNull(data.getLong(LONG_SETTING_NAME));
	}

	@Test
	public void testIsEmptyInstanceSettings() throws Exception {
		Data data = listing.getDataAt(addr(10));

		data.setString(STRING_SETTING_NAME, "red");
		data.setLong(LONG_SETTING_NAME, 10);

		assertTrue(!data.isEmpty());
		data.clearAllSettings();

		assertTrue(data.isEmpty());
	}

	private Data getDataAt(long offset) {
		Data data = listing.getDataAt(addr(offset));
		assertNotNull("expected data at address 0x" + Long.toHexString(offset));
		return data;
	}

	@Test
	public void testMoveSettings() throws Exception {

		for (int i = 0; i < 10; i++) {
			Data d = getDataAt(i);
			dataMgr.setStringSettingsValue(d, STRING_SETTING_NAME, "red" + i);
			dataMgr.setLongSettingsValue(d, LONG_SETTING_NAME, i);
		}
		dataMgr.moveAddressRange(addr(0), addr(20), 10, TaskMonitor.DUMMY);
		int j = 0;
		for (int i = 20; i < 30; i++, j++) {
			Data d = getDataAt(i);

			String s = dataMgr.getStringSettingsValue(d, STRING_SETTING_NAME);
			assertEquals("red" + j, s);

			Long lvalue = dataMgr.getLongSettingsValue(d, LONG_SETTING_NAME);
			assertEquals(j, lvalue.longValue());
		}
	}

	@Test
	public void testMoveSettings2() {

		for (int i = 0; i < 10; i++) {
			Data d = getDataAt(i);
			dataMgr.setStringSettingsValue(d, STRING_SETTING_NAME, "red" + i);
			dataMgr.setLongSettingsValue(d, LONG_SETTING_NAME, i);
		}
		try {
			dataMgr.moveAddressRange(addr(0), addr(5), 10, TaskMonitor.DUMMY);
		}
		catch (CancelledException e) {
			Assert.fail("Unexpected cancelled exception");
		}

		int j = 0;
		for (int i = 5; i < 15; i++, j++) {
			Data d = getDataAt(i);

			String s = dataMgr.getStringSettingsValue(d, STRING_SETTING_NAME);
			assertEquals("red" + j, s);

			Long lvalue = dataMgr.getLongSettingsValue(d, LONG_SETTING_NAME);
			assertEquals(j, lvalue.longValue());
		}
	}

	@Test
	public void testMoveSettings3() {

		int j = 20;
		for (int i = 20; i < 30; i++, j++) {
			Data d = getDataAt(i);
			dataMgr.setStringSettingsValue(d, STRING_SETTING_NAME, "red" + i);
			dataMgr.setLongSettingsValue(d, LONG_SETTING_NAME, i);
		}
		j = 20;
		try {
			dataMgr.moveAddressRange(addr(20), addr(5), 10, TaskMonitor.DUMMY);
		}
		catch (CancelledException e) {
			Assert.fail("Unexpected cancelled exception");
		}
		for (int i = 5; i < 15; i++, j++) {
			Data d = getDataAt(i);

			String s = dataMgr.getStringSettingsValue(d, STRING_SETTING_NAME);
			assertEquals("red" + j, s);

			Long lvalue = dataMgr.getLongSettingsValue(d, LONG_SETTING_NAME);
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
		DataType byteDT = dataMgr.resolve(ByteDataType.dataType, null);
		SettingsDefinition[] settingsDefinitions = byteDT.getSettingsDefinitions();
		Settings settings = byteDT.getDefaultSettings();
		FormatSettingsDefinition.DEF.setChoice(settings, FormatSettingsDefinition.OCTAL);

		TypedefDataType tdt = new TypedefDataType("ByteTypedef", byteDT);
		TypeDef td = (TypeDef) dataMgr.addDataType(tdt, null);

		SettingsDefinition[] sdefs = td.getSettingsDefinitions();
		assertTrue(sdefs.length >= settingsDefinitions.length);  // TypeDef may add some of its own

		Settings defSettings = td.getDefaultSettings();
		assertEquals(FormatSettingsDefinition.OCTAL,
			FormatSettingsDefinition.DEF.getChoice(defSettings));

		FormatSettingsDefinition.DEF.setChoice(defSettings, FormatSettingsDefinition.DECIMAL);
		assertEquals(FormatSettingsDefinition.DECIMAL,
			FormatSettingsDefinition.DEF.getChoice(defSettings));

		FormatSettingsDefinition.DEF.setChoice(settings, FormatSettingsDefinition.HEX);

		assertEquals(FormatSettingsDefinition.DECIMAL,
			FormatSettingsDefinition.DEF.getChoice(defSettings)); // unchanged

	}

	@Test
	public void testDefaultSettingsOnTypedef2() throws Exception {
		DataType byteDT = dataMgr.resolve(ByteDataType.dataType, null);
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
		DataType byteDT = dataMgr.resolve(ByteDataType.dataType, null);
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
		DataType byteDT = dataMgr.resolve(ByteDataType.dataType, null);
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
