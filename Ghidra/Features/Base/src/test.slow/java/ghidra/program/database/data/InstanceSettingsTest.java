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

import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.docking.settings.Settings;
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
public class InstanceSettingsTest extends AbstractGhidraHeadedIntegrationTest {

	// Suitable settings allowed for StringDataType data
	private static String LONG_SETTING_NAME = "mutability";
	private static String STRING_SETTING_NAME = "charset";

	private ProgramDB program;
	private ProgramDataTypeManager dataMgr;
	private Listing listing;
	private AddressSpace space;
	private int transactionID;

	public InstanceSettingsTest() {
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

		for (int i = 0; i < 40; i++) {
			DataUtilities.createData(program, addr(i), StringDataType.dataType, 1, false,
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
	public void testInstanceSettings() throws Exception {

		Data data = DataUtilities.createData(program, addr(10), ByteDataType.dataType, 1, false,
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

	@Test
	public void testGetNames() throws Exception {

		Data data = listing.getDataAt(addr(10));

		data.setString(STRING_SETTING_NAME, "red");
		data.setLong(LONG_SETTING_NAME, 10);

		String[] names = data.getNames();
		assertEquals(2, names.length);
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

	private Address addr(long l) {
		return space.getAddress(l);
	}

	private void addBlock() throws Exception {

		Memory memory = program.getMemory();
		memory.createInitializedBlock("test", addr(0), 100, (byte) 0,
			TaskMonitor.DUMMY, false);
	}
}
