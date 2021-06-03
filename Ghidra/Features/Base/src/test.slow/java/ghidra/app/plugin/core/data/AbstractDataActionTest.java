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
package ghidra.app.plugin.core.data;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.util.*;

import javax.swing.event.ChangeEvent;
import javax.swing.table.TableCellEditor;

import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.action.MenuData;
import docking.widgets.combobox.GComboBox;
import docking.widgets.dialogs.StringChoices;
import docking.widgets.table.AbstractSortedTableModel;
import docking.widgets.table.GTable;
import ghidra.app.LocationCallback;
import ghidra.app.context.ListingActionContext;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.clear.ClearCmd;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.data.DataSettingsDialog.SettingsEditor;
import ghidra.app.plugin.core.data.DataSettingsDialog.SettingsRowObject;
import ghidra.app.plugin.core.navigation.NextPrevAddressPlugin;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;
import ghidra.test.*;
import ghidra.util.*;

public abstract class AbstractDataActionTest extends AbstractGhidraHeadedIntegrationTest
		implements LocationCallback {

	// Add data types whose format settings are not supported by this test
	protected static final Set<String> FORMAT_TEST_SKIP_LIST = createFormatTestSkipList();

	protected static Set<String> createFormatTestSkipList() {
		Set<String> set = new HashSet<>();
		set.add("GUID");
		set.add("unicode");
//		set.add("TerminatedCString");
//		set.add("TerminatedUnicode");
		return set;
	}

	protected Program program;
	protected TestEnv env;
	protected PluginTool tool;
	protected DataPlugin plugin;
	protected CodeBrowserPlugin cb;

	protected String error;

	// DataPlugin action's
	protected static final String CREATE_STRUCTURE = "Create Structure";
	protected static final String EDIT_DATA_TYPE = "Edit Data Type";
	protected static final String CREATE_ARRAY = "Define Array";
	protected static final String DEFAULT_DATA_SETTINGS = "Default Data Settings";
	protected static final String DATA_SETTINGS = "Data Settings";
	protected static final String CHOOSE_DATA_TYPE = "Choose Data Type";

	// CycleGroupAction's
	protected static final String CYCLE_FLOAT_DOUBLE = "Cycle: float,double";
	protected static final String CYCLE_BYTE_WORD_DWORD_QWORD = "Cycle: byte,word,dword,qword";
	protected static final String CYCLE_CHAR_STRING_UNICODE = "Cycle: char,string,unicode";

	// DataAction's
	protected static final String DEFINE_BYTE = "Define byte";
	protected static final String DEFINE_WORD = "Define word";
	protected static final String DEFINE_DWORD = "Define dword";
	protected static final String DEFINE_QWORD = "Define qword";
	protected static final String DEFINE_FLOAT = "Define float";
	protected static final String DEFINE_DOUBLE = "Define double";
	protected static final String DEFINE_CHAR = "Define char";
	protected static final String DEFINE_STRING = "Define string";
	protected static final String DEFINE_TERM_CSTRING = "Define TerminatedCString";
	protected static final String DEFINE_TERM_UNICODE = "Define TerminatedUnicode";
	protected static final String DEFINE_POINTER = "Define pointer";

	protected static final int ACTION_COUNT = 23;

	protected static final String RECENTLY_USED = "Recently Used";

	@Before
	public void setUp() throws Exception {

		env = new TestEnv();
		tool = env.showTool();
		tool.addPlugin(DataPlugin.class.getName());
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(NextPrevAddressPlugin.class.getName());
		cb = getPlugin(tool, CodeBrowserPlugin.class);
		plugin = env.getPlugin(DataPlugin.class);

		ClassicSampleX86ProgramBuilder builder = new ClassicSampleX86ProgramBuilder();
		try {
			program = builder.getProgram();

			initializeFavorites();

			openProgram();
		}
		finally {
			builder.dispose();
		}
	}

	protected void closeProgram() {
		env.close(program);
		waitForBusyTool(tool);
	}

	protected void openProgram() {
		env.open(program);
		waitForBusyTool(tool);
	}

	@After
	public void tearDown() {
		closeAllWindows();
		env.dispose();
	}

	protected void clearFavorites() {
		BuiltInDataTypeManager builtInDataTypesManager =
			BuiltInDataTypeManager.getDataTypeManager();
		for (DataType dt : builtInDataTypesManager.getFavorites()) {
			builtInDataTypesManager.setFavorite(dt, false);
		}
	}

	protected void initializeFavorites() {
		clearFavorites();
		BuiltInDataTypeManager builtInDataTypesManager =
			BuiltInDataTypeManager.getDataTypeManager();
		Category root = builtInDataTypesManager.getRootCategory();

		builtInDataTypesManager.setFavorite(root.getDataType("byte"), true);
		builtInDataTypesManager.setFavorite(root.getDataType("char"), true);
		builtInDataTypesManager.setFavorite(root.getDataType("float"), true);
		builtInDataTypesManager.setFavorite(root.getDataType("pointer"), true);
		builtInDataTypesManager.setFavorite(root.getDataType("string"), true);
		builtInDataTypesManager.setFavorite(root.getDataType("dword"), true);
		builtInDataTypesManager.setFavorite(root.getDataType("double"), true);
		builtInDataTypesManager.setFavorite(root.getDataType("qword"), true);
		builtInDataTypesManager.setFavorite(root.getDataType("TerminatedCString"), true);
		builtInDataTypesManager.setFavorite(root.getDataType("TerminatedUnicode"), true);
		builtInDataTypesManager.setFavorite(root.getDataType("unicode"), true);
		builtInDataTypesManager.setFavorite(root.getDataType("word"), true);
	}

	protected void checkActions(Set<DockingActionIf> actions, boolean enabled, String caseStr) {
		checkAction(actions, CREATE_STRUCTURE, enabled, caseStr);
		checkAction(actions, EDIT_DATA_TYPE, enabled, caseStr);
		checkAction(actions, CREATE_ARRAY, enabled, caseStr);
		checkAction(actions, CHOOSE_DATA_TYPE, enabled, caseStr);
		checkAction(actions, DEFAULT_DATA_SETTINGS, enabled, caseStr);
		checkAction(actions, DATA_SETTINGS, enabled, caseStr);
		checkAction(actions, CYCLE_FLOAT_DOUBLE, enabled, caseStr);
		checkAction(actions, CYCLE_BYTE_WORD_DWORD_QWORD, enabled, caseStr);
		checkAction(actions, CYCLE_CHAR_STRING_UNICODE, enabled, caseStr);
		checkAction(actions, DEFINE_BYTE, enabled, caseStr);
		checkAction(actions, DEFINE_WORD, enabled, caseStr);
		checkAction(actions, DEFINE_DWORD, enabled, caseStr);
		checkAction(actions, DEFINE_QWORD, enabled, caseStr);
		checkAction(actions, DEFINE_FLOAT, enabled, caseStr);
		checkAction(actions, DEFINE_DOUBLE, enabled, caseStr);
		checkAction(actions, DEFINE_CHAR, enabled, caseStr);
		checkAction(actions, DEFINE_STRING, enabled, caseStr);
		checkAction(actions, DEFINE_TERM_CSTRING, enabled, caseStr);
		checkAction(actions, DEFINE_TERM_UNICODE, enabled, caseStr);
		checkAction(actions, DEFINE_POINTER, enabled, caseStr);
	}

	/**
	 * Asserts that the next value returned from the iterator matches the specified properties.
	 *
	 * @param dit data iterator
	 * @param dtClass data type class to expect
	 * @param offset address offset to expect
	 * @param length data instance length to expect
	 * @return Data instance that iterator's .next() returned.
	 */
	protected Data checkNextData(DataIterator dit, Class<?> dtClass, long offset, int length) {
		Data d = dit.next();
		assertNotNull(d);
		assertTrue(dtClass.isInstance(d.getDataType()));
		assertEquals(addr(offset), d.getMinAddress());
		assertEquals(length, d.getLength());
		return d;
	}

	protected void useDefaultSettings() throws Exception {

		doAction(DATA_SETTINGS, false);

		waitForSwing();

		final DataSettingsDialog dlg = waitForDialogComponent(DataSettingsDialog.class);
		assertNotNull("Expected data settings dialog", dlg);

		waitForSwing();

		Runnable r = () -> {
			AbstractSortedTableModel<SettingsRowObject> model = dlg.getSettingsTableModel();
			int useDefaultCol = model.findColumn("Use Default");
			int rowCnt = model.getRowCount();

			for (int i = 0; i < rowCnt; i++) {
				model.setValueAt(Boolean.TRUE, i, useDefaultCol);
			}
		};
		runSwing(r);

		pressButtonByText(dlg, "OK");

		waitForSwing();
	}

	protected void changeSettings(final boolean defaultSetting, final String[] settingNames,
			final String[] newValues) throws Exception {

		doAction(defaultSetting ? DEFAULT_DATA_SETTINGS : DATA_SETTINGS, false);

		waitForSwing();

		final DataSettingsDialog dlg = waitForDialogComponent(DataSettingsDialog.class);
		assertNotNull("Expected data settings dialog", dlg);

		waitForSwing();

		AbstractSortedTableModel<SettingsRowObject> model = dlg.getSettingsTableModel();

		error = null;

		Runnable r = () -> {

			int nameCol = model.findColumn("Name");
			int settingsCol = model.findColumn("Settings");
			int rowCnt = model.getRowCount();

			for (int row = 0; row < rowCnt; row++) {
				String name = (String) model.getValueAt(row, nameCol);
				int index = findSettingIndex(settingNames, name);
				if (index != -1) {
					Object v = model.getValueAt(row, settingsCol);
					if (v instanceof StringChoices) {
						StringChoices choices = (StringChoices) v;

						triggerEdit(dlg, row, settingsCol);
						setComboValue(dlg, newValues[index]);
						endEdit(dlg);

						choices.setSelectedValue(newValues[index]);
						model.setValueAt(choices, row, settingsCol);
					}
					else {
						error = "Unsupported test setting: " + v.getClass();
						return;
					}
				}
			}
		};
		runSwing(r);

		if (error != null) {
			Assert.fail(error);
		}

		pressButtonByText(dlg, "OK");

		waitForSwing();
	}

	private void endEdit(DataSettingsDialog d) {
		GTable table = d.getSettingsTable();
		runSwing(() -> table.editingStopped(new ChangeEvent(table)));
	}

	private void setComboValue(DataSettingsDialog d, String string) {
		GTable table = d.getSettingsTable();
		TableCellEditor activeEditor = runSwing(() -> table.getCellEditor());
		assertNotNull("Table should be editing, but is not", activeEditor);
		assertTrue("Editor type is not correct", activeEditor instanceof SettingsEditor);

		SettingsEditor settingsEditor = (SettingsEditor) activeEditor;
		GComboBox<String> combo = settingsEditor.getComboBox();

		int index = runSwing(() -> {
			int n = combo.getItemCount();
			for (int i = 0; i < n; i++) {
				String item = combo.getItemAt(i);
				if (item.equals(string)) {
					return i;
				}
			}
			return -1;
		});

		assertNotEquals("Combo does not contain item '" + string + "'", -1, index);

		runSwing(() -> {
			combo.setSelectedIndex(index);
		});
	}

	private void triggerEdit(DataSettingsDialog d, int row, int col) {
		GTable table = d.getSettingsTable();
		boolean editStarted = runSwing(() -> table.editCellAt(row, col));
		assertTrue("Unable to edit dialog table cell at " + row + ", " + col, editStarted);
	}

	protected int findSettingIndex(String[] settingNames, String name) {
		for (int i = 0; i < settingNames.length; i++) {
			if (settingNames[i].equals(name)) {
				return i;
			}
		}
		return -1;
	}

	protected void clearRange(long start, long end) {
		AddressSet set = new AddressSet(addr(start), addr(end));
		ClearCmd cmd = new ClearCmd(set);
		tool.execute(cmd, program);
	}

	protected void clearLocation(long offset) {
		Address addr = addr(offset);
		AddressSet set = new AddressSet(addr, addr);
		ClearCmd cmd = new ClearCmd(set);
		tool.execute(cmd, program);
	}

	protected boolean firstIteration = true;

	protected void manipulateAllSettings(boolean testDefaultSetting, boolean insideStruct,
			boolean commonStruct, String defineAction) throws Exception {

		long loc1 = 0x1006a02;
		long loc2 = 0x100abeb;

		DockingActionIf dockingAction = getAction(defineAction);
		assertNotNull(dockingAction);

		DataType dt;
		boolean useSelection = true;

		if (dockingAction instanceof DataAction) {
			DataAction action = (DataAction) getAction(defineAction);
			dt = action.getDataType();
			useSelection = (dt instanceof StringDataType);
		}
		else if (dockingAction instanceof CreateArrayAction) {
			// array case based upon existing data at location
			gotoLocation(loc1);
			Data data1 = getContextData();
			dt = data1.getDataType();
		}
		else {
			fail("Unsupported data action for test: " + dockingAction.getClass().getName());
			return;
		}

		if (FORMAT_TEST_SKIP_LIST.contains(dt.getName())) {
			System.out.println("Settings not tested for data type: " + dt.getName());
			return;
		}

		final SettingsDefinition[] sdefs = dt.getSettingsDefinitions();
		if (sdefs.length == 0) {
			System.out.println("Data type does not have settings: " + dt.getName());
			return;
		}

		boolean commonDataType =
			!(dt instanceof StringDataType) && (!insideStruct || (insideStruct && commonStruct));

		gotoLocation(loc1);
		if (useSelection) {
			makeSelection(loc1, loc1 + 0x10);
		}
		doAction(defineAction, true);
		Data data1 = getContextData();

		if (insideStruct) {

			int len = data1.getLength();
			if (len < 1) {
				len = 1;
			}
			makeSelection(loc1, loc1 + len - 1);
			doCreateStructureAction();
			clearSelection();
			if (firstIteration) {
				cb.toggleOpen(getContextData());
			}
			gotoLocation(loc1, new int[] { 0 });
			data1 = getContextData();

		}

		clearSelection();

		Data data2 = null;
		gotoLocation(loc2);
		if (insideStruct && commonStruct) {
			doAction(RECENTLY_USED, true);
		}
		else {
			if (useSelection) {
				makeSelection(loc2, loc2 + 0x10);
			}
			doAction(defineAction, true);
			data2 = getContextData();

			if (insideStruct) {
				int len = data2.getLength();
				if (len < 1) {
					len = 1;
				}
				makeSelection(loc2, loc2 + len - 1);
				doCreateStructureAction();
				clearSelection();
			}
		}
		if (insideStruct) {
			if (firstIteration) {
				cb.toggleOpen(getContextData());
			}
			gotoLocation(loc2, new int[] { 0 });
			data2 = getContextData();
		}
		clearSelection();

		try {
			dt = data1.getBaseDataType();
			assertTrue("Default data type unexpected", !DefaultDataType.class.isInstance(dt));
			assertNotNull(data2);

			DataType dt2 = data2.getBaseDataType();

			if (commonDataType) {
				assertTrue("Data type instances differ: " + dt.getClass().getName() + " / " +
					dt2.getClass().getName(), dt == dt2);
			}

			for (SettingsDefinition sdef : sdefs) {

				if (sdef instanceof FormatSettingsDefinition) {
					manipulateFormatSettings(testDefaultSetting, insideStruct, commonStruct, data1,
						data2);
				}
				else if (sdef instanceof EndianSettingsDefinition) {
					// tested by manipulateFormatSettings
				}
				else if (sdef instanceof PaddingSettingsDefinition) {
					// tested by manipulateFormatSettings
				}
				else if (sdef instanceof TerminatedSettingsDefinition) {
					manipulateTerminatedSettings(testDefaultSetting, insideStruct, commonStruct,
						data1, data2);
				}

				else if (sdef instanceof DataTypeMnemonicSettingsDefinition) {
					// TODO: ???
				}
				else if (sdef instanceof MutabilitySettingsDefinition) {
					manipulateMutabilitySettings(testDefaultSetting, insideStruct, commonStruct,
						data1, data2);
					if (data1.isArray() && data2.isArray()) {
						manipulateMutabilitySettings(testDefaultSetting, insideStruct, commonStruct,
							data1.getComponent(1), data2.getComponent(1));
					}
				}
				else if (sdef == null) {
					System.out.println("DataActionTest: null SettingsDefinition");
				}

			}
		}
		finally {
			if (useSelection) {
				clearRange(loc1, loc1 + 0x10);
				clearRange(loc2, loc2 + 0x10);
			}
			else {
				clearLocation(loc1);
				clearLocation(loc2);
			}
			firstIteration = false;
		}
	}

	/**
	 * Test TERMINATED data setting
	 * @param testDefaultSetting if true test default setting, else test instance setting for data2
	 * @param insideStruct data are inside two structure instances
	 * @param commonStruct data structures are the same type
	 * @param data1 data at some location with same type as data2
	 * @param data2 data at current location
	 * @throws Exception
	 */
	protected void manipulateTerminatedSettings(boolean testDefaultSetting, boolean insideStruct,
			boolean commonStruct, Data data1, Data data2) throws Exception {

		boolean settingsAreShared =
			testDefaultSetting && (!insideStruct || (insideStruct && commonStruct));

		byte[] bytes1 = data1.getBytes();
		byte[] bytes2 = data2.getBytes();
		DataType dt = data1.getDataType();

		if (FORMAT_TEST_SKIP_LIST.contains(dt.getName())) {
			System.out.println("Settings not tested for data type: " + dt.getName());
			return;
		}
		// none of the following code is ever executed with the current FORMAT_TEST_SKIP_LIST

		String[] settingNames = new String[] { "Termination" };
		String[] terminated = new String[] { "terminated" };
		String[] unterminated = new String[] { "unterminated" };

		if (insideStruct && !commonStruct) {

			gotoLocation(data1.getMinAddress().getOffset(), new int[] { 0 });
			useDefaultSettings();
			changeSettings(true, settingNames, terminated);

			gotoLocation(data2.getMinAddress().getOffset(), new int[] { 0 });
		}

		useDefaultSettings();
		changeSettings(true, settingNames, terminated);

		String caseStr = (testDefaultSetting ? "Default " : "") + "Settings on " +
			(insideStruct ? (commonStruct ? "Common " : "") + "Structure " : "") + dt.getName() +
			": terminated";
//System.out.println(caseStr);

		changeSettings(testDefaultSetting, settingNames, terminated);
		assertEquals(caseStr, getString(bytes1, true), data1.getDefaultValueRepresentation());
		assertEquals(caseStr, getString(bytes2, true), data2.getDefaultValueRepresentation());

		caseStr = (testDefaultSetting ? "Default " : "") + "Settings on " +
			(insideStruct ? (commonStruct ? "Common " : "") + "Structure " : "") + dt.getName() +
			": unterminated";
//System.out.println(caseStr);

		changeSettings(testDefaultSetting, settingNames, unterminated);

		if (settingsAreShared) {
			assertEquals(caseStr, getString(bytes1, false), data1.getDefaultValueRepresentation());
		}
		else {
			assertEquals(caseStr, getString(bytes1, true), data1.getDefaultValueRepresentation());
		}

		assertEquals(caseStr, getString(bytes2, false), data2.getDefaultValueRepresentation());

	}

	protected static final String[] FORMAT_CHOICES =
		{ "hex", "decimal", "binary", "octal", "char" };
	protected static final String[] PADDING_CHOICES = { "unpadded", "padded" };
	protected static final String[] ENDIAN_CHOICES = { "default", "little", "big" };

	/**
	 * Test FORMAT data setting (includes testing of SIGN, ENDIAN and PADDING setting)
	 * @param testDefaultSetting if true test default setting, else test instance setting for data2
	 * @param insideStruct data are inside two structure instances
	 * @param commonStruct data structures are the same type
	 * @param data1 data at some location with same type as data2
	 * @param data2 data at current location
	 * @throws Exception
	 */
	protected void manipulateFormatSettings(boolean testDefaultSetting, boolean insideStruct,
			boolean commonStruct, Data data1, Data data2) throws Exception {

		assertTrue(data1.getDataType() == data2.getDataType());

		boolean settingsAreShared =
			testDefaultSetting && (!insideStruct || (insideStruct && commonStruct));

		if (data1.isArray()) {
			data1 = data1.getComponent(0);
		}
		if (data2.isArray()) {
			data2 = data2.getComponent(0);
		}

		byte[] bytes1 = data1.getBytes();
		byte[] bytes2 = data2.getBytes();
		int byteCnt = bytes1.length;
		DataType dt = data1.getDataType();

		boolean testEndianSetting = (bytes1.length > 1);
		String[] settingNames = testEndianSetting ? new String[] { "Format", "Padding", "Endian" }
				: new String[] { "Format", "Padding" };

		ArrayList<String[]> cases = new ArrayList<>();
		String[] settings = new String[testEndianSetting ? 3 : 2];
		for (String element : FORMAT_CHOICES) {
			if ("decimal".equals(element)) {
				continue;// Defer testing of Decimal format with SIGN setting
			}
			settings[0] = element;
			for (String element2 : PADDING_CHOICES) {
				settings[1] = element2;
				if (testEndianSetting) {
					for (String element3 : ENDIAN_CHOICES) {
						settings[2] = element3;
						cases.add(settings.clone());
					}
				}
				else {
					cases.add(settings.clone());
				}
			}
		}

		useDefaultSettings();
		changeSettings(true, settingNames, cases.get(0));

		// NOTE: default settings for the same datatype within different composites
		// is based upon the parent composite and not the stand-alone type.

		long val1 = getValue(bytes1, true);
		if (insideStruct && !commonStruct && dt instanceof CharDataType) {
			// Inside Struct: Component type format default Hex differs from the original default of Char
			assertEquals("Default setting", getCharString(val1, byteCnt),
				data1.getDefaultValueRepresentation());
		}
		else {
			assertEquals("Default setting", getHexString(val1, byteCnt, false),
				data1.getDefaultValueRepresentation());
		}

		long val2 = getValue(bytes2, true);
		assertEquals("Default setting", getHexString(val2, byteCnt, false),
			data2.getDefaultValueRepresentation());

		Iterator<String[]> iter = cases.iterator();
		while (iter.hasNext()) {
			settings = iter.next();

			boolean littleEndian = !(testEndianSetting && "big".equals(settings[2]));
			boolean pad = "padded".equals(settings[1]);

			String caseStr = (testDefaultSetting ? "Default " : "") + "Settings on " +
				(insideStruct ? (commonStruct ? "Common " : "") + "Structure " : "") +
				dt.getName() + ": " + settings[0] + "/" + settings[1];
			if (testEndianSetting) {
				caseStr += "/" + settings[2];
			}
//System.out.println(caseStr);

			changeSettings(testDefaultSetting, settingNames, settings);

			if (settingsAreShared) {
				val1 = getValue(bytes1, littleEndian);
			}
			else if (insideStruct && dt instanceof CharDataType) {
				assertEquals("Default setting applies", getCharString(val1, byteCnt),
					data1.getDefaultValueRepresentation());
			}
			else {
				assertEquals("Default setting applies", getHexString(val1, byteCnt, false),
					data1.getDefaultValueRepresentation());
			}

			val2 = getValue(bytes2, littleEndian);

			if ("char".equals(settings[0])) {
				// skip testing char format settings as those are tested in CharDataTypeRenderTest
			}
			else if ("binary".equals(settings[0])) {
				if (settingsAreShared) {
					assertEquals(caseStr, getBinaryString(val1, byteCnt, pad),
						data1.getDefaultValueRepresentation());
				}
				assertEquals(caseStr, getBinaryString(val2, byteCnt, pad),
					data2.getDefaultValueRepresentation());
			}
			else if ("octal".equals(settings[0])) {
				if (settingsAreShared) {
					assertEquals(caseStr, getOctalString(val1, byteCnt, pad),
						data1.getDefaultValueRepresentation());
				}
				assertEquals(caseStr, getOctalString(val2, byteCnt, pad),
					data2.getDefaultValueRepresentation());
			}
			else {// hex
				if (settingsAreShared) {
					assertEquals(caseStr, getHexString(val1, byteCnt, pad),
						data1.getDefaultValueRepresentation());
				}
				assertEquals(caseStr, getHexString(val2, byteCnt, pad),
					data2.getDefaultValueRepresentation());
			}

		}

		useDefaultSettings();
		changeSettings(true, settingNames, cases.get(0));

		val1 = getValue(bytes1, true);
		if (insideStruct && !commonStruct && dt instanceof CharDataType) {
			// Inside Struct: Component type format default Hex differs from the original default of Char
			assertEquals("Default setting", getCharString(val1, byteCnt),
				data1.getDefaultValueRepresentation());
		}
		else {
			assertEquals("Default setting", getHexString(val1, byteCnt, false),
				data1.getDefaultValueRepresentation());
		}

		val2 = getValue(bytes2, true);
		assertEquals("Default setting", getHexString(val2, byteCnt, false),
			data2.getDefaultValueRepresentation());

		settingNames =
			testEndianSetting ? new String[] { "Format", "Endian" } : new String[] { "Format" };

		cases.clear();

		settings = new String[testEndianSetting ? 2 : 1];
		settings[0] = "decimal";
		if (testEndianSetting) {
			for (String element2 : ENDIAN_CHOICES) {
				settings[1] = element2;
				cases.add(settings.clone());
			}
		}
		else {
			cases.add(settings.clone());
		}

		iter = cases.iterator();
		while (iter.hasNext()) {
			settings = iter.next();

			boolean littleEndian = !(testEndianSetting && "big".equals(settings[1]));
//			boolean unsigned = "unsigned".equals(settings[1]);

			String caseStr = (testDefaultSetting ? "Default " : "") + "Settings on " +
				(insideStruct ? (commonStruct ? "Common " : "") + "Structure " : "") +
				dt.getName() + ": " + settings[0];
			if (testEndianSetting) {
				caseStr += "/" + settings[1];
			}
//System.out.println(caseStr);

			changeSettings(testDefaultSetting, settingNames, settings);

			if (settingsAreShared) {
				val1 = getValue(bytes1, littleEndian);
			}
			else if (insideStruct && dt instanceof CharDataType) {
				assertEquals(caseStr + ", Default setting applies", getCharString(val1, byteCnt),
					data1.getDefaultValueRepresentation());
			}
			else {
				assertEquals(caseStr + ", Default setting applies",
					getHexString(val1, byteCnt, false), data1.getDefaultValueRepresentation());
			}

			val2 = getValue(bytes2, littleEndian);

			if (settingsAreShared) {
				assertEquals(caseStr, getDecimalString(val1, byteCnt, isUnsignedData(data1)),
					data1.getDefaultValueRepresentation());
			}

			assertEquals(caseStr, getDecimalString(val2, byteCnt, isUnsignedData(data2)),
				data2.getDefaultValueRepresentation());
		}

	}

	protected boolean isUnsignedData(Data data) {
		DataType dt = data.getDataType();
		if (dt instanceof AbstractIntegerDataType) {
			return !((AbstractIntegerDataType) dt).isSigned();
		}
		return true;
	}

	/**
	 * Test MUTABILITY data setting
	 * @param testDefaultSetting if true test default setting, else test instance setting for data2
	 * @param insideStruct data are inside two structure instances
	 * @param commonStruct data structures are the same type
	 * @param data1 data at some location with same type as data2
	 * @param data2 data at current location
	 * @throws Exception
	 */
	protected void manipulateMutabilitySettings(boolean testDefaultSetting, boolean insideStruct,
			boolean commonStruct, Data data1, Data data2) throws Exception {

		assertSame(data1.getDataType(), data2.getDataType());

		boolean settingsAreShared =
			testDefaultSetting && (!insideStruct || (insideStruct && commonStruct));

		String[] settingNames = new String[] { "Mutability" };

		useDefaultSettings();

		assertTrue(!data1.isVolatile());
		assertTrue(!data1.isConstant());
		assertTrue(!data2.isVolatile());
		assertTrue(!data2.isConstant());

		changeSettings(testDefaultSetting, settingNames, new String[] { "constant" });
		if (settingsAreShared) {
			assertTrue(!data1.isVolatile());
			assertTrue(data1.isConstant());
		}
		assertTrue(!data2.isVolatile());
		assertTrue(data2.isConstant());

		changeSettings(testDefaultSetting, settingNames, new String[] { "volatile" });

		if (settingsAreShared) {
			assertTrue(data1.isVolatile());
			assertTrue(!data1.isConstant());
		}
		assertTrue(data2.isVolatile());
		assertTrue(!data2.isConstant());

		changeSettings(testDefaultSetting, settingNames, new String[] { "normal" });

		if (settingsAreShared) {
			assertTrue(!data1.isVolatile());
			assertTrue(!data1.isConstant());
		}
		assertTrue(!data2.isVolatile());
		assertTrue(!data2.isConstant());

	}

	protected String getDataTypeAction(String dtName) {
		String actionName = "Define " + dtName;
		if (getAction(actionName) == null) {
			// Force data-type as a favorite to create action
			BuiltInDataTypeManager builtInDtm = BuiltInDataTypeManager.getDataTypeManager();
			DataType dt = builtInDtm.getDataType(CategoryPath.ROOT, dtName);
			assertNotNull("Built-in data-type not found: " + dtName, dt);
			builtInDtm.setFavorite(dt, true);
		}
		return actionName;
	}

	protected List<DataType> getBuiltInDataTypesAsFavorites() {
		return BuiltInDataTypeManager.getDataTypeManager().getFavorites();
	}

	protected long getValue(byte[] bytes, boolean littleEndian) {
		long val = 0;
		if (littleEndian) {
			for (int i = bytes.length - 1; i >= 0; --i) {
				val <<= 8;
				val |= (0x00ff & bytes[i]);
			}
		}
		else {
			for (byte element : bytes) {
				val <<= 8;
				val |= (0x00ff & element);
			}
		}
		return val;
	}

	protected String getString(byte[] bytes, boolean terminated) {
		StringBuffer strBuf = new StringBuffer(bytes.length + 2);
		boolean bytemode = true;
		for (int index = 0; index < bytes.length; index++) {
			char c = (char) (bytes[index]);
			c &= 0xff;
			if (c > 31 && c < 128) {
				if (bytemode) {
					if (index != 0) {
						strBuf.append(',');
					}
					strBuf.append('\"');
				}
				strBuf.append(c);
				bytemode = false;
			}
			else {
				if (!bytemode) {
					strBuf.append('\"');
				}
				if (index != 0) {
					strBuf.append(',');
				}
				strBuf.append(StringFormat.hexByteString((byte) c));
				bytemode = true;
			}
			if (terminated && c == 0) {
				break;
			}
		}
		if (!bytemode) {
			strBuf.append('\"');
		}
		String str = strBuf.toString();
		if ("00".equals(str)) {
			str = "\"\",00";
		}
		return str;
	}

	protected String getUnicodeString(byte[] bytes) {
		StringBuffer strBuf = new StringBuffer(bytes.length + 2);
		boolean bytemode = true;
		for (int index = 0; index < bytes.length; index += 2) {
			char c = 0;
			if (program.getLanguage().isBigEndian()) {
				c = (char) ((bytes[index + 1] & 0xff) | ((bytes[index] << 8) & 0xff00));
			}
			else {
				c = (char) ((bytes[index] & 0xff) | ((bytes[index + 1] << 8) & 0xff00));
			}
			if (Character.isDefined(c) && c > 31) {
				if (bytemode) {
					if (index != 0) {
						strBuf.append(',');
					}
					strBuf.append('\"');
				}
				strBuf.append(c);
				bytemode = false;
			}
			else {
				if (!bytemode) {
					strBuf.append('\"');
				}
				if (index != 0) {
					strBuf.append(',');
				}
//                strBuf.append("\\u");
				strBuf.append(StringFormat.hexWordString((short) c));
				bytemode = true;
			}
		}
		if (!bytemode) {
			strBuf.append('\"');
		}
		return strBuf.toString();
	}

	protected String getHexString(long val, int byteCnt, boolean padded) {
		byte[] bytes = new byte[byteCnt + 1];
		for (int i = byteCnt; i > 0; i--) {
			bytes[i] = (byte) val;
			val = val >> 8;
		}
		String str = (new BigInteger(bytes)).toString(16).toUpperCase();
		if (padded) {
			int digits = 2 * byteCnt;
			for (int i = str.length(); i < digits; i++) {
				str = "0" + str;
			}
		}
		return str + "h";
	}

	protected String getOctalString(long val, int byteCnt, boolean padded) {
		byte[] bytes = new byte[byteCnt + 1];
		for (int i = byteCnt; i > 0; i--) {
			bytes[i] = (byte) val;
			val = val >> 8;
		}
		String str = (new BigInteger(bytes)).toString(8).toUpperCase();
		if (padded) {
			int digits = ((8 * byteCnt) + 2) / 3;
			for (int i = str.length(); i < digits; i++) {
				str = "0" + str;
			}
		}
		return str + "o";
	}

	protected String getBinaryString(long val, int byteCnt, boolean padded) {
		String str = Long.toBinaryString(val);
		if (padded) {
			int digits = 8 * byteCnt;
			for (int i = str.length(); i < digits; i++) {
				str = "0" + str;
			}
		}
		return str + "b";
	}

	protected String getCharString(long val, int byteCnt) {
		BigInteger v = BigInteger.valueOf(val);
		byte[] bytes = v.toByteArray();
		if (bytes.length != byteCnt) {
			byte[] newBytes = new byte[byteCnt];
			System.arraycopy(bytes, 0, newBytes, 0, Math.min(byteCnt, bytes.length));
			bytes = newBytes;
		}
		return StringUtilities.toQuotedString(bytes);
	}

	protected String getDecimalString(long val, int byteCnt, boolean unsigned) {
		if (unsigned) {
			byte[] bytes = new byte[byteCnt + 1];
			for (int i = byteCnt; i > 0; i--) {
				bytes[i] = (byte) val;
				val = val >> 8;
			}
			return (new BigInteger(bytes)).toString(10);
		}
		// signed
		byte[] bytes = new byte[byteCnt];
		for (int i = byteCnt - 1; i >= 0; i--) {
			bytes[i] = (byte) val;
			val = val >> 8;
		}
		return (new BigInteger(bytes)).toString(10);
	}

	protected Address addr(long offset) {
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		return space.getAddress(offset);
	}

	protected void gotoLocation(long offset, int[] componentPath) {
		Address addr = addr(offset);
		ProgramLocation loc =
			new AddressFieldLocation(program, addr, componentPath, addr.toString(), 0);
		locationGenerated(loc);
	}

	protected void gotoLocation(long offset) {
		gotoLocation(offset, null);
	}

	protected void clearSelection() {
		ProgramSelection sel = new ProgramSelection();
		tool.firePluginEvent(new ProgramSelectionPluginEvent("test", sel, program));
	}

	protected void makeSelection(long from, long to) {

		ProgramSelection sel = new ProgramSelection(addr(from), addr(to));

		tool.firePluginEvent(new ProgramSelectionPluginEvent("test", sel, program));

		locationGenerated(new AddressFieldLocation(program, sel.getMinAddress()));
	}

	protected void checkDataType(long from, long to, Class<?> dtClass, int definedCount,
			int undefinedCount) {

		Address fromAddr = addr(from);
		Address toAddr = addr(to);

		DataIterator iter = program.getListing().getData(fromAddr, true);
		int dcnt = 0;
		int ucnt = 0;
		while (iter.hasNext()) {
			Data d = iter.next();
			if (d.getMinAddress().compareTo(toAddr) > 0) {
				break;
			}
			if (dtClass != null && dtClass.isInstance(d.getBaseDataType())) {
				++dcnt;
			}
			else if (!d.isDefined()) {
				++ucnt;
			}
		}

		if (dtClass != null) {
			assertEquals("Instances of " + dtClass.getName(), definedCount, dcnt);
		}
		assertEquals("Undefined data", undefinedCount, ucnt);
	}

	@Override
	public void locationGenerated(ProgramLocation loc) {

		tool.firePluginEvent(new ProgramLocationPluginEvent("test", loc, program));

		ProgramSelection sel = getCurrentSelection();
		boolean useSelection = (sel != null && !sel.isEmpty());

		Set<DockingActionIf> actions = getActionsByOwner(tool, plugin.getName());

		for (DockingActionIf element : actions) {
			MenuData menuBarData = element.getMenuBarData();
			String[] menuPath = menuBarData == null ? null : menuBarData.getMenuPath();
			if (menuPath == null) {
				// TODO: ???
			}
			else if (menuPath.length == 3) {
				assertEquals("Data", menuPath[0]);
				assertEquals("Cycle", menuPath[1]);
				assertTrue(menuPath[2] != null && menuPath[2].startsWith("Cycle:"));
			}
			else {
				assertEquals(2, menuPath.length);
				assertEquals("Data", menuPath[0]);
				assertNotNull(menuPath[1]);
			}
		}

		Address addr = loc.getAddress();
		String caseName = "At " + addr;
		if (!loc.equals(getCurrentLocation())) {
			return;
		}
		Data data = getContextData();

		boolean hasSettings = false;
		boolean editStructOK = false;

		if (useSelection) {
			// Data actions not available if selection contains instructions
			if (program.getListing().getInstructions(sel, true).hasNext()) {
				data = null;
				useSelection = false;
			}
		}
		else if (data != null) {

			DataType dt = data.getBaseDataType();
			hasSettings = (dt.getSettingsDefinitions().length != 0);
			editStructOK = (dt instanceof Structure);

			// Array elements may not be manipulated
			Data pdata = data.getParent();
			if (pdata != null && pdata.isArray()) {
				data = null;
			}
		}

		if (data != null) {

			DataType dt = data.getDataType();
			if (dt instanceof DefaultDataType) {
				checkOnUndefined(actions);
				return;
			}
			else if (dt instanceof Composite) {
				checkOnStructure(actions, -1);
				return;
			}
			else if (dt instanceof Array) {
				checkOnArray(actions, ((Array) dt).getDataType(), -1);
				return;
			}
			else {
				checkOnDefined(actions, dt.getClass());
				return;
			}
		}

		// All actions should be disabled for non-data locations
		checkAction(actions, CREATE_STRUCTURE, false, caseName);
		checkAction(actions, EDIT_DATA_TYPE, editStructOK, caseName);
		checkAction(actions, CREATE_ARRAY, false, caseName);
		checkAction(actions, DEFAULT_DATA_SETTINGS, hasSettings, caseName);
		checkAction(actions, DATA_SETTINGS, hasSettings, caseName);
		checkAction(actions, CYCLE_FLOAT_DOUBLE, false, caseName);
		checkAction(actions, CYCLE_BYTE_WORD_DWORD_QWORD, false, caseName);
		checkAction(actions, CYCLE_CHAR_STRING_UNICODE, false, caseName);
		checkAction(actions, DEFINE_BYTE, false, caseName);
		checkAction(actions, DEFINE_WORD, false, caseName);
		checkAction(actions, DEFINE_DWORD, false, caseName);
		checkAction(actions, DEFINE_QWORD, false, caseName);
		checkAction(actions, DEFINE_FLOAT, false, caseName);
		checkAction(actions, DEFINE_DOUBLE, false, caseName);
		checkAction(actions, DEFINE_TERM_CSTRING, false, caseName);
		checkAction(actions, DEFINE_POINTER, false, caseName);

		DockingActionIf recentlyUsedAction = getAction(RECENTLY_USED);
		if (recentlyUsedAction != null) {
			checkAction(recentlyUsedAction, false, caseName);
		}

	}

	protected void checkOnUndefined(Set<DockingActionIf> actions) {

		if (actions == null) {
			actions = getActionsByOwner(tool, plugin.getName());
		}

		Data data = getContextData();
		assertNotNull("Undefined data expected", data);
		assertTrue("Undefined data expected", !data.isDefined());

		String caseName = "On Undefined at: " + getCurrentLocation();
		ProgramSelection sel = getCurrentSelection();

		boolean hasSelection = sel != null && !sel.isEmpty();
		boolean hasInteriorSelection = hasSelection && sel.getInteriorSelection() != null;
		boolean hasNormalUnitSelection = hasSelection && !hasInteriorSelection;

		Data pdata = data.getParent();

		checkAction(actions, CREATE_STRUCTURE, sel != null && !sel.isEmpty(), caseName);
		checkAction(actions, EDIT_DATA_TYPE,
			pdata != null && (pdata.isStructure() || pdata.isUnion()), caseName);
		checkAction(actions, CREATE_ARRAY, true, caseName);
		checkAction(actions, DEFAULT_DATA_SETTINGS, false, caseName);
		checkAction(actions, DATA_SETTINGS, hasNormalUnitSelection, caseName);
		checkAction(actions, CYCLE_FLOAT_DOUBLE, true, caseName);
		checkAction(actions, CYCLE_BYTE_WORD_DWORD_QWORD, true, caseName);
		checkAction(actions, CYCLE_CHAR_STRING_UNICODE, true, caseName);
		checkAction(actions, DEFINE_BYTE, true, caseName);
		checkAction(actions, DEFINE_WORD, true, caseName);
		checkAction(actions, DEFINE_DWORD, true, caseName);
		checkAction(actions, DEFINE_QWORD, true, caseName);
		checkAction(actions, DEFINE_FLOAT, true, caseName);
		checkAction(actions, DEFINE_DOUBLE, true, caseName);
		checkAction(actions, DEFINE_TERM_CSTRING, true, caseName);
		checkAction(actions, DEFINE_POINTER, true, caseName);

	}

	protected void checkOnDefined(Set<DockingActionIf> actions, Class<?> expectedDataType) {

		if (actions == null) {
			actions = getActionsByOwner(tool, plugin.getName());
		}

		String dtName = expectedDataType.getName();
		int ix = dtName.lastIndexOf('.');
		if (ix >= 0) {
			dtName = dtName.substring(ix + 1);
		}

		Data d = getContextData();
		assertNotNull("Expected data type: " + dtName, d);
		assertTrue("Expected data type: " + dtName, expectedDataType.isInstance(d.getDataType()));

		DataType dt = d.getDataType();

		boolean onByteWordData = true;
		boolean onFloatDoubleData = true;
		boolean onCharData = true;

//		boolean onByteWordData = (expectedDataType.equals(ByteDataType.class)
//			|| expectedDataType.equals(WordDataType.class)
//			|| expectedDataType.equals(DWordDataType.class)
//			|| expectedDataType.equals(QWordDataType.class));
//
//		boolean onFloatDoubleData = (expectedDataType.equals(FloatDataType.class)
//			|| expectedDataType.equals(DoubleDataType.class));
//
//		boolean onCharData = (expectedDataType.equals(AsciiDataType.class)
//			|| expectedDataType.equals(StringDataType.class)
//			|| expectedDataType.equals(UnicodeDataType.class));

		boolean hasSettings = dt.getSettingsDefinitions().length != 0;

		String caseName = "On " + dtName + " at: " + getCurrentLocation();

		ProgramSelection sel = getCurrentSelection();

		boolean hasSelection = sel != null && !sel.isEmpty();
		boolean hasInteriorSelection = hasSelection && sel.getInteriorSelection() != null;
		boolean hasNormalUnitSelection = hasSelection && !hasInteriorSelection;

		Data pdata = d.getParent();

		checkAction(actions, CREATE_STRUCTURE, hasSelection, caseName);
		checkAction(actions, EDIT_DATA_TYPE,
			(pdata != null && (pdata.isStructure() || pdata.isUnion())) || (dt instanceof Enum),
			caseName);
		checkAction(actions, CREATE_ARRAY, true, caseName);
		checkAction(actions, DEFAULT_DATA_SETTINGS,
			(!hasSelection || isSelectionJustSingleDataInstance(sel, d)) && hasSettings, caseName);
		checkAction(actions, DATA_SETTINGS, hasNormalUnitSelection || hasSettings, caseName);
		checkAction(actions, CYCLE_FLOAT_DOUBLE, onFloatDoubleData, caseName);
		checkAction(actions, CYCLE_BYTE_WORD_DWORD_QWORD, onByteWordData, caseName);
		checkAction(actions, CYCLE_CHAR_STRING_UNICODE, onCharData, caseName);
		checkAction(actions, DEFINE_BYTE, true, caseName);
		checkAction(actions, DEFINE_WORD, true, caseName);
		checkAction(actions, DEFINE_DWORD, true, caseName);
		checkAction(actions, DEFINE_QWORD, true, caseName);
		checkAction(actions, DEFINE_FLOAT, true, caseName);
		checkAction(actions, DEFINE_DOUBLE, true, caseName);
		checkAction(actions, DEFINE_TERM_CSTRING, true, caseName);
		checkAction(actions, DEFINE_POINTER, true, caseName);
	}

	protected void checkOnArray(Set<DockingActionIf> actions, DataType interiorDt, int arraySize) {

		if (actions == null) {
			actions = getActionsByOwner(tool, plugin.getName());
		}

		Data d = getContextData();
		assertNotNull("Expected Array", d);
		assertTrue("Expected Array", d.isArray());
		DataType dt = d.getDataType();
		assertTrue("Expected Array", Array.class.isInstance(dt));

		String caseName = "On Array at: " + getCurrentLocation();

		if (arraySize >= 0) {
			String dtName = "undefined";
			int interiorDtLen = 1;
			if (interiorDt != null && !(interiorDt instanceof DefaultDataType)) {
				dtName = interiorDt.getName();
				interiorDtLen = interiorDt.getLength();
			}
			dtName += "[" + arraySize + "]";
			assertEquals(dtName, dt.getName());
			assertEquals(caseName, arraySize * interiorDtLen, dt.getLength());

			Data d0 = d.getComponent(0);
			if (interiorDt == null) {
				assertTrue("Undefined data expected inside array", !d0.isDefined());
			}
			else {
				assertTrue("Array contains incorrect data type elements",
					interiorDt.getClass().equals(d0.getDataType().getClass()));
			}
		}

		ProgramSelection sel = getCurrentSelection();

		boolean hasSelection = sel != null && !sel.isEmpty();

		boolean hasSettings = (d.getBaseDataType().getSettingsDefinitions().length != 0);

		Data pdata = d.getParent();

		checkAction(actions, CREATE_STRUCTURE, hasSelection, caseName);
		checkAction(actions, EDIT_DATA_TYPE,
			pdata != null && (pdata.isStructure() || pdata.isUnion()), caseName);
		checkAction(actions, CREATE_ARRAY, true, caseName);
		checkAction(actions, DEFAULT_DATA_SETTINGS,
			hasSettings && (!hasSelection || isSelectionJustSingleDataInstance(sel, d)), caseName);
		checkAction(actions, DATA_SETTINGS, hasSettings, caseName);
		checkAction(actions, CYCLE_FLOAT_DOUBLE, true, caseName);
		checkAction(actions, CYCLE_BYTE_WORD_DWORD_QWORD, true, caseName);
		checkAction(actions, CYCLE_CHAR_STRING_UNICODE, true, caseName);
		checkAction(actions, DEFINE_BYTE, true, caseName);
		checkAction(actions, DEFINE_WORD, true, caseName);
		checkAction(actions, DEFINE_DWORD, true, caseName);
		checkAction(actions, DEFINE_QWORD, true, caseName);
		checkAction(actions, DEFINE_FLOAT, true, caseName);
		checkAction(actions, DEFINE_DOUBLE, true, caseName);
		checkAction(actions, DEFINE_TERM_CSTRING, true, caseName);
		checkAction(actions, DEFINE_POINTER, true, caseName);

	}

	/**
	 * Check actions on structure
	 * @param actions
	 * @param structSize structure size or -1 to disable size check
	 */
	protected void checkOnStructure(Set<DockingActionIf> actions, int structSize) {

		if (actions == null) {
			actions = getActionsByOwner(tool, plugin.getName());
		}

		Data d = getContextData();
		assertNotNull("Expected Structure", d);
		assertTrue("Expected Structure", d.isStructure());
		DataType dt = d.getDataType();
		assertTrue("Expected Structure", Structure.class.isInstance(dt));

		String caseName = "On Structure at: " + getCurrentLocation();

		if (structSize >= 0) {
			assertEquals(structSize, dt.getLength());
		}

		ProgramSelection sel = getCurrentSelection();

		boolean hasSelection = sel != null && !sel.isEmpty();
		boolean hasInteriorSelection = hasSelection && sel.getInteriorSelection() != null;
		boolean hasNormalUnitSelection = hasSelection && !hasInteriorSelection;

		checkAction(actions, CREATE_STRUCTURE, sel != null && !sel.isEmpty(), caseName);
		checkAction(actions, EDIT_DATA_TYPE, true, caseName);
		checkAction(actions, CREATE_ARRAY, true, caseName);
		checkAction(actions, DEFAULT_DATA_SETTINGS, false, caseName);
		checkAction(actions, DATA_SETTINGS, hasNormalUnitSelection, caseName);
		checkAction(actions, CYCLE_FLOAT_DOUBLE, true, caseName);
		checkAction(actions, CYCLE_BYTE_WORD_DWORD_QWORD, true, caseName);
		checkAction(actions, CYCLE_CHAR_STRING_UNICODE, true, caseName);
		checkAction(actions, DEFINE_BYTE, true, caseName);
		checkAction(actions, DEFINE_WORD, true, caseName);
		checkAction(actions, DEFINE_DWORD, true, caseName);
		checkAction(actions, DEFINE_QWORD, true, caseName);
		checkAction(actions, DEFINE_FLOAT, true, caseName);
		checkAction(actions, DEFINE_DOUBLE, true, caseName);
		checkAction(actions, DEFINE_TERM_CSTRING, true, caseName);
		checkAction(actions, DEFINE_POINTER, true, caseName);

	}

	protected DockingActionIf getAction(String name) {
		Set<DockingActionIf> actions = getActionsByOwner(tool, plugin.getName());
		for (DockingActionIf element : actions) {
			String actionName = element.getName();
			int pos = actionName.indexOf(" (");
			if (pos > 0) {
				actionName = actionName.substring(0, pos);
			}
			if (actionName.equals(name)) {
				return element;
			}
		}
		return null;
	}

	protected void doAction(String name, boolean waitForCompletion) {
		DockingActionIf action = getAction(name);
		assertNotNull("Action was not found: " + name, action);
		if (!action.isEnabledForContext(getProgramContext())) {
			Assert.fail("Action is not valid: " + name);
		}

		try {
			performAction(action, cb.getProvider(), waitForCompletion);
		}
		catch (Throwable t) {
			t.printStackTrace();
			Assert.fail("Action '" + name + "' failed: " + t.toString());
		}

	}

	protected void doCreateStructureAction() throws Exception {
		doAction(CREATE_STRUCTURE, false);
		CreateStructureDialog d = waitForDialogComponent(CreateStructureDialog.class);
		assertNotNull(d);
		pressButtonByText(d, "OK");

	}

	protected void checkAction(Set<DockingActionIf> actions, String name, boolean isEnabled,
			String caseName) {
		for (DockingActionIf element : actions) {
			String actionName = element.getName();
			int pos = actionName.indexOf(" (");
			if (pos > 0) {
				actionName = actionName.substring(0, pos);
			}
			if (actionName.equals(name)) {
				checkAction(element, isEnabled, caseName);
				return;
			}
		}
		Assert.fail("Action " + name + " not found");
	}

	protected void checkAction(DockingActionIf action, boolean isValidContext, String caseName) {

		ActionContext programContext = getProgramContext();
		String addrStr = "<none>";
		if (programContext instanceof ListingActionContext) {
			Address addr = ((ListingActionContext) programContext).getLocation().getAddress();
			if (addr != null) {
				addrStr = addr.toString();
			}
		}

		boolean enabledForContext = action.isEnabledForContext(programContext);
		if (isValidContext != enabledForContext) {
			Msg.debug(this, "checkAction(): ");
		}
		assertEquals(
			"Context is not in correct valid state. Context: actionName = " + action.getName() +
				", address=" + addrStr + " [case: " + caseName + "]",
			isValidContext, enabledForContext);
		return;
	}

	private boolean isSelectionJustSingleDataInstance(ProgramSelection selection, Data data) {
		if (selection != null && data != null) {
			AddressSet dataAS = new AddressSet(data.getAddress(), data.getMaxAddress());
			return dataAS.hasSameAddresses(selection);
		}
		return false;
	}

	protected ActionContext getProgramContext() {
		cb.updateNow();
		ActionContext context = cb.getProvider().getActionContext(null);
		if (context == null) {
			context = new ActionContext();
		}
		return context;
	}

	protected ProgramLocation getCurrentLocation() {
		cb.updateNow();
		ListingActionContext context =
			(ListingActionContext) cb.getProvider().getActionContext(null);
		return context.getLocation();
	}

	protected ProgramSelection getCurrentSelection() {
		cb.updateNow();
		ListingActionContext context =
			(ListingActionContext) cb.getProvider().getActionContext(null);
		return context.getSelection();
	}

	protected Data getContextData() {
		cb.updateNow();
		ListingActionContext context =
			(ListingActionContext) cb.getProvider().getActionContext(null);
		return plugin.getDataUnit(context);
	}
}
