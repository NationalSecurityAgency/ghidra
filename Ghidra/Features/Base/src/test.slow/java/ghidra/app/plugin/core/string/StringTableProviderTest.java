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
package ghidra.app.plugin.core.string;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;
import java.util.List;

import javax.swing.*;

import org.junit.*;

import docking.AbstractErrDialog;
import docking.action.*;
import docking.widgets.OptionDialog;
import docking.widgets.textfield.IntegerTextField;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.progmgr.ProgramManagerPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.util.string.FoundString;
import ghidra.program.util.string.FoundString.DefinedState;
import ghidra.test.*;
import ghidra.util.table.GhidraTable;

public class StringTableProviderTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private ProgramDB program;
	private AddressSpace space;
	private StringTableModel model;
	private GhidraTable table;
	private StringTableProvider provider;
	private StringTablePlugin plugin;
	private DockingActionIf searchAction;

	@SuppressWarnings("unchecked")
	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		setUpCodeBrowserTool(tool);
		openProgram();
		env.showTool();

		plugin = env.getPlugin(StringTablePlugin.class);
		searchAction = getAction(plugin, "Search for Strings");

		SearchStringDialog stringSearchDialog = getStringSearchDialog();
		pressButtonByText(stringSearchDialog.getComponent(), "Search");

		provider =
			((List<StringTableProvider>) getInstanceField("transientProviders", plugin)).get(0);
		model = (StringTableModel) getInstanceField("stringModel", provider);
		table = (GhidraTable) getInstanceField("table", provider);
		waitForTableModel(model);
	}

	private SearchStringDialog getStringSearchDialog() throws Exception {

		CodeBrowserPlugin cb = env.getPlugin(CodeBrowserPlugin.class);
		CodeViewerProvider cbProvider = cb.getProvider();
		runSwingLater(
			() -> searchAction.actionPerformed(cbProvider.getActionContext(null)));
		waitForSwing();
		return getDialogComponent(SearchStringDialog.class);
	}

	@Test
	public void testMakeStringButtonAndActionsEnablementState() {
		JButton makeStringsButton = (JButton) getInstanceField("makeStringButton", provider);
		JButton makeCharArrayButton = (JButton) getInstanceField("makeCharArrayButton", provider);
		DockingAction makeStringAction =
			(DockingAction) getInstanceField("makeStringAction", provider);
		DockingAction makeCharArrayAction =
			(DockingAction) getInstanceField("makeCharArrayAction", provider);

		// first no selection, should be disabled
		assertEquals(0, table.getSelectedRowCount());
		assertFalse(makeStringsButton.isEnabled());
		assertFalse(makeCharArrayButton.isEnabled());
		assertFalse(makeStringAction.isEnabledForContext(null));
		assertFalse(makeCharArrayAction.isEnabledForContext(null));

		// select a conflicting string, should be disabled
		selectRows(addr(0x300));
		assertFalse(makeStringsButton.isEnabled());
		assertFalse(makeCharArrayButton.isEnabled());
		assertFalse(makeStringAction.isEnabledForContext(null));
		assertFalse(makeCharArrayAction.isEnabledForContext(null));

		// select a non-defined string, should be enabled
		selectRows(addr(0x100));
		assertTrue(makeStringsButton.isEnabled());
		assertTrue(makeCharArrayButton.isEnabled());
		assertTrue(makeStringAction.isEnabledForContext(null));
		assertTrue(makeCharArrayAction.isEnabledForContext(null));

		// select a defined String, should be disabled
		selectRows(addr(0x200));
		assertFalse(makeStringsButton.isEnabled());
		assertFalse(makeCharArrayButton.isEnabled());
		assertFalse(makeStringAction.isEnabledForContext(null));
		assertFalse(makeCharArrayAction.isEnabledForContext(null));

		// select both defined and undefined, should be enabled
		selectRows(addr(0x100), addr(0x200));
		assertTrue(makeStringsButton.isEnabled());
		assertTrue(makeCharArrayButton.isEnabled());
		assertTrue(makeStringAction.isEnabledForContext(null));
		assertTrue(makeCharArrayAction.isEnabledForContext(null));

		// clear selection, should be disabled
		table.clearSelection();
		assertFalse(makeStringsButton.isEnabled());
		assertFalse(makeCharArrayButton.isEnabled());
		assertFalse(makeStringAction.isEnabledForContext(null));
		assertFalse(makeCharArrayAction.isEnabledForContext(null));
	}

	@Test
	public void testShowDefinedStateToggles() throws Exception {

		assertDefinedAndUndefinedStringsAreOnByDefault();

		int definedCount = countStrings(DefinedState.DEFINED);
		int undefinedCount = countStrings(DefinedState.NOT_DEFINED);
		int partiallyDefinedCount = countStrings(DefinedState.PARTIALLY_DEFINED);
		int conflictingCount = countStrings(DefinedState.CONFLICTS);

		boolean defined = true;
		boolean undefined = false;
		boolean partial = false;
		boolean conflicting = false;
		toggleDefinedStateButtons(defined, undefined, partial, conflicting);
		assertEquals(definedCount, table.getRowCount());

		defined = false;
		undefined = true;
		partial = false;
		conflicting = false;
		toggleDefinedStateButtons(defined, undefined, partial, conflicting);
		assertEquals(undefinedCount, table.getRowCount());

		defined = false;
		undefined = false;
		partial = true;
		conflicting = false;
		toggleDefinedStateButtons(defined, undefined, partial, conflicting);
		assertEquals(partiallyDefinedCount, table.getRowCount());

		defined = false;
		undefined = false;
		partial = false;
		conflicting = true;
		toggleDefinedStateButtons(defined, undefined, partial, conflicting);
		assertEquals(conflictingCount, table.getRowCount());

	}

	@Test
	public void testOffsetAndPreview() {
		JTextField previewTextField = (JTextField) getInstanceField("preview", provider);

		// no selection, preview is blank
		assertEquals("", previewTextField.getText());

		// select single undefined string, preview should show string ("localtime" is at 0x1006afc)
		selectRows(addr(0x100));
		assertEquals("\"abcdefgh\"", previewTextField.getText());

		// change offset to 1, preview should show string at offset 1
		setOffsetFieldValue(1);
		assertEquals("\"bcdefgh\"", previewTextField.getText());

		// change offset to 8, preview should show string at offset 8
		setOffsetFieldValue(8);
		assertEquals("\"\"", previewTextField.getText());

		// change offset to 9, preview should be empty
		setOffsetFieldValue(9);
		assertEquals("", previewTextField.getText());
	}

	@Test
	public void testMakeString() {

		DockingAction makeStringAction =
			(DockingAction) getInstanceField("makeStringAction", provider);

		Address address = addr(0x100);

		Data data = program.getListing().getDataAt(address);
		assertEquals(DefaultDataType.class, data.getDataType().getClass());

		selectRows(address);		// string abcdefg is here
		performAction(makeStringAction, true);

		data = program.getListing().getDataAt(address);

		assertEquals(StringDataType.class, data.getDataType().getClass());
		assertEquals("abcdefgh", data.getValue());

	}

	@Test
	public void testMakeStringWithLabel() {
		JCheckBox autoLabelCheckbox = (JCheckBox) getInstanceField("autoLabelCheckbox", provider);
		setCheckbox(autoLabelCheckbox, true);

		DockingAction makeStringAction =
			(DockingAction) getInstanceField("makeStringAction", provider);

		Address address = addr(0x100);

		Data data = program.getListing().getDataAt(address);
		assertEquals(DefaultDataType.class, data.getDataType().getClass());
		assertNull(program.getSymbolTable().getPrimarySymbol(address));

		selectRows(address);		// string localtime is here
		performAction(makeStringAction, true);

		data = program.getListing().getDataAt(address);

		assertEquals(StringDataType.class, data.getDataType().getClass());
		assertEquals("abcdefgh", data.getValue());
		assertEquals("s_abcdefgh", program.getSymbolTable().getPrimarySymbol(address).getName());
	}

	@Test
	public void testMakeStringAtOffset() {

		DockingAction makeStringAction =
			(DockingAction) getInstanceField("makeStringAction", provider);

		Address address = addr(0x100);

		Data data = program.getListing().getDataAt(address);
		assertEquals(DefaultDataType.class, data.getDataType().getClass());

		selectRows(address);		// string abcdefg is here
		int offset = 2;
		setOffsetFieldValue(offset);

		performAction(makeStringAction, true);

		data = program.getListing().getDataAt(address.add(offset));

		assertEquals(StringDataType.class, data.getDataType().getClass());
		assertEquals("cdefgh", data.getValue());
	}

	@Test
	public void testMakeStringAtOffsetThatIsTooBig() {

		DockingAction makeStringAction =
			(DockingAction) getInstanceField("makeStringAction", provider);

		Address address = addr(0x100);

		Data data = program.getListing().getDataAt(address);
		assertEquals(DefaultDataType.class, data.getDataType().getClass());

		selectRows(address);		// string abcdefg is here
		int offset = 50;
		setOffsetFieldValue(offset);

		setErrorsExpected(true);
		performAction(makeStringAction, true);
		setErrorsExpected(false);

		data = program.getListing().getDataAt(address.add(offset));
		AbstractErrDialog dialog = waitForErrorDialog();
		String title = dialog.getTitle();
		assertThat(title, containsString("Failed"));
		close(dialog);

		Assert.assertNotEquals(StringDataType.class, data.getDataType().getClass());
	}

	@Test
	public void testMakeStringThatBumpsIntoDefinedTruncateNotAllowed() throws Exception {
		JCheckBox truncationCheckbox =
			(JCheckBox) getInstanceField("allowTruncationCheckbox", provider);
		assertFalse(truncationCheckbox.isSelected());

		DockingAction makeStringAction =
			(DockingAction) getInstanceField("makeStringAction", provider);

		Address address = addr(0x100);
		createDataAt(address.add(4));

		Data data = program.getListing().getDataAt(address);
		assertEquals(DefaultDataType.class, data.getDataType().getClass());

		selectRows(address);		// string abcefg is here

		performAction(makeStringAction, false);
		waitForSwing();

		OptionDialog dialogProvider = getDialogComponent(OptionDialog.class);
		assertNotNull(dialogProvider);
		pressButtonByText(dialogProvider.getComponent(), "OK");

		data = program.getListing().getDataAt(address);

		assertEquals(DefaultDataType.class, data.getDataType().getClass());
	}

	@Test
	public void testMakeStringThatBumpsIntoDefinedTruncateAllowed() throws Exception {
		JCheckBox truncationCheckbox =
			(JCheckBox) getInstanceField("allowTruncationCheckbox", provider);
		setCheckbox(truncationCheckbox, true);

		DockingAction makeStringAction =
			(DockingAction) getInstanceField("makeStringAction", provider);

		Address address = addr(0x100);
		createDataAt(address.add(4));

		Data data = program.getListing().getDataAt(address);
		assertEquals(DefaultDataType.class, data.getDataType().getClass());

		selectRows(address);		// string abcdefgh is here

		performAction(makeStringAction, true);

		data = program.getListing().getDataAt(address);

		assertEquals(StringDataType.class, data.getDataType().getClass());
		assertEquals("abcd", data.getValue());
	}

	@Test
	public void testMakeStringThatAddsAlignmentFiller() throws Exception {
		JCheckBox addAlignmentBytesCheckbox =
			(JCheckBox) getInstanceField("addAlignmentBytesCheckbox", provider);
		setCheckbox(addAlignmentBytesCheckbox, true);

		StringTableOptions options = (StringTableOptions) getInstanceField("options", provider);
		options.setAlignment(2);

		DockingAction makeStringAction =
			(DockingAction) getInstanceField("makeStringAction", provider);

		Address address = addr(0x100); 	// abcdefg

		Data data = program.getListing().getDataAt(address);
		assertEquals(DefaultDataType.class, data.getDataType().getClass());

		selectRows(address);		// string abcdefg is here

		performAction(makeStringAction, true);

		data = program.getListing().getDataAt(address);

		assertEquals(StringDataType.class, data.getDataType().getClass());
		assertEquals("abcdefgh", data.getValue());
		assertEquals("abcdefgh".length() + 2, data.getLength());
	}

	@Test
	public void testMakeStringThatAddsAlignmentFillerButFillerBumpsIntoDefined() throws Exception {
		JCheckBox addAlignmentBytesCheckbox =
			(JCheckBox) getInstanceField("addAlignmentBytesCheckbox", provider);
		setCheckbox(addAlignmentBytesCheckbox, true);

		StringTableOptions options = (StringTableOptions) getInstanceField("options", provider);
		options.setAlignment(2);

		DockingAction makeStringAction =
			(DockingAction) getInstanceField("makeStringAction", provider);

		Address address = addr(0x100); 	// abcdefgh

		Data data = program.getListing().getDataAt(address);
		assertEquals(DefaultDataType.class, data.getDataType().getClass());
		createDataAt(addr(0x109));

		selectRows(address);		// string localtime is here

		performAction(makeStringAction, true);

		data = program.getListing().getDataAt(address);

		assertEquals(StringDataType.class, data.getDataType().getClass());
		assertEquals("abcdefgh", data.getValue());
		assertEquals("abcdefgh".length() + 1, data.getLength());
	}

	@Test
	public void testMakePascalString() {
		StringTableOptions options = (StringTableOptions) getInstanceField("options", provider);
		options.setRequirePascal(true);
		model.reload();
		waitForTableModel(model);

		DockingAction makeStringAction =
			(DockingAction) getInstanceField("makeStringAction", provider);

		Address address = addr(0x400);

		Data data = program.getListing().getDataAt(address);
		assertEquals(DefaultDataType.class, data.getDataType().getClass());

		selectRows(address);		// string localtime is here
		performAction(makeStringAction, true);

		data = program.getListing().getDataAt(address);

		assertEquals(PascalUnicodeDataType.class, data.getDataType().getClass());
		assertEquals("abcdef", data.getValue());
	}

	private void createDataAt(Address addr) throws Exception {
		tx(program, () -> {
			program.getListing().createData(addr, new ByteDataType());
		});
	}

	private void setCheckbox(final JCheckBox checkbox, final boolean selected) {
		runSwing(() -> checkbox.setSelected(selected));
	}

	private void setOffsetFieldValue(final int offset) {
		runSwing(() -> {
			IntegerTextField offsetField =
				(IntegerTextField) getInstanceField("offsetField", provider);
			offsetField.setValue(offset);
		});
		waitForSwing();
	}

	private void openProgram() throws Exception {
		ToyProgramBuilder builder = new ToyProgramBuilder("TestGhidraSearches", false);
		builder.createMemory("test", "0x0", 1000);

		// create bytes for string at 100
		builder.setBytes("0x100", "61, 62, 63, 64, 65, 66, 67, 68");

		// create defined string at 200
		builder.createEncodedString("200", "abcdefghij", StandardCharsets.US_ASCII, true);

		// create conflict at 300
		builder.setBytes("0x300", "61, 62, 63, 64, 65, 66, 67");
		builder.applyDataType("0x300", new PointerDataType());
		builder.applyDataType("0x304", new PointerDataType());

		// create a pascal unicode
		builder.setBytes("0x400", "06 00, 61, 00, 62, 00, 63, 00, 64, 00, 65, 00, 66, 00");
		program = builder.getProgram();
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());
		space = program.getAddressFactory().getDefaultAddressSpace();
	}

	private void setUpCodeBrowserTool(PluginTool tool) throws Exception {
		tool.addPlugin(ProgramManagerPlugin.class.getName());
		tool.addPlugin(StringTablePlugin.class.getName());
		tool.addPlugin(CodeBrowserPlugin.class.getName());
	}

	private void selectRows(Address... addrs) {
		table.clearSelection();
		for (Address address : addrs) {
			int row = findRow(address);
			table.addRowSelectionInterval(row, row);
		}

	}

	private int findRow(Address address) {
		int n = model.getRowCount();
		for (int i = 0; i < n; i++) {
			FoundString string = model.getRowObject(i);
			if (string.getAddress().equals(address)) {
				return i;
			}
		}
		return -1;
	}

	@After
	public void tearDown() {
		env.closeTool(tool);
		env.dispose();
	}

	private Address addr(long offset) {
		return space.getAddress(offset);
	}

	private void assertDefinedAndUndefinedStringsAreOnByDefault() {
		ToggleDockingAction showUndefinedAction =
			(ToggleDockingAction) getInstanceField("showUndefinedAction", provider);
		ToggleDockingAction showDefinedAction =
			(ToggleDockingAction) getInstanceField("showDefinedAction", provider);

		assertTrue(showDefinedAction.isSelected());
		assertTrue(showUndefinedAction.isSelected());

	}

	private void toggleDefinedStateButtons(final boolean defined, final boolean undefined,
			final boolean partial, final boolean conflicting) {
		runSwing(() -> {
			ToggleDockingAction showUndefinedAction =
				(ToggleDockingAction) getInstanceField("showUndefinedAction", provider);
			ToggleDockingAction showDefinedAction =
				(ToggleDockingAction) getInstanceField("showDefinedAction", provider);
			ToggleDockingAction showPartialAction =
				(ToggleDockingAction) getInstanceField("showPartialDefinedAction", provider);
			ToggleDockingAction showConflictingAction =
				(ToggleDockingAction) getInstanceField("showConflictsAction", provider);

			setActionState(showUndefinedAction, undefined);
			setActionState(showDefinedAction, defined);
			setActionState(showPartialAction, partial);
			setActionState(showConflictingAction, conflicting);
		});
		waitForTableModel(model);
	}

	private void setActionState(ToggleDockingAction action, boolean state) {
		action.setSelected(state);
		action.actionPerformed(null);
	}

	private int countStrings(DefinedState state) {
		int count = 0;
		List<FoundString> strings = model.getModelData();
		for (FoundString foundString : strings) {
			if (foundString.getDefinedState() == state) {
				count++;
			}
		}
		return count;
	}

}
