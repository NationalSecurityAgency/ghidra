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
package ghidra.app.plugin.core.strings;

import static org.junit.Assert.*;

import java.lang.Character.UnicodeScript;
import java.nio.charset.StandardCharsets;

import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.data.AbstractStringDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.test.AbstractProgramBasedTest;
import ghidra.test.ToyProgramBuilder;
import ghidra.util.Swing;

public class EncodedStringsDialogTest extends AbstractProgramBasedTest {
	private MemoryBlock ram;
	private DockingActionIf encodedStringsAction;
	private EncodedStringsDialog dialog;
	private EncodedStringsTableModel tableModel;
	private EncodedStringsPlugin plugin;


	@Before
	public void setUp() throws Exception {
		initialize();
		ram = program.getMemory().getBlock("RAM");
		plugin = env.addPlugin(EncodedStringsPlugin.class);
		encodedStringsAction = plugin.getSearchForEncodedStringsAction();
	}

	@Override
	protected ProgramDB getProgram() throws Exception {
		ToyProgramBuilder builder = new ToyProgramBuilder("String Examples", false);
		builder.createMemory("RAM", "0x0", 0x500);

		builder.createString("0x100", "Hello World!\n", StandardCharsets.US_ASCII, true, null);
		builder.createString("0x10e", "Next string", StandardCharsets.US_ASCII, true, null);

		builder.createString("0x150", bytes(0, 1, 2, 3, 4, 0x80, 0x81, 0x82, 0x83),
			StandardCharsets.US_ASCII, null);

		builder.createString("0x200", "\u6211\u96bb\u6c23\u588a\u8239\u88dd\u6eff\u6652\u9c54",
			StandardCharsets.UTF_16, true, null);

		builder.createString("0x250", "Exception %s\n\tline: %d\n", StandardCharsets.US_ASCII, true,
			null);

		builder.createString("0x330", "A: \u6211\u96bb\u6c23\u588a\u8239\u88dd\u6eff\u6652\u9c54",
			StandardCharsets.UTF_8, true, null);

		builder.createString("0x450",
			"Roses are \u001b[0;31mred\u001b[0m, violets are \u001b[0;34mblue. Hope you enjoy terminal hue",
			StandardCharsets.US_ASCII, true, null);

		return builder.getProgram();
	}

	private ActionContext getCBAC() {
		return runSwing(() -> {
			return codeBrowser.getProvider().getActionContext(null);
		});
	}

	@Override
	@After
	public void tearDown() throws Exception {
		closeDialog();
		env.dispose();
	}

	private void closeDialog() {
		if (dialog != null) {
			close(dialog);
			dialog = null;
			tableModel = null;
		}
	}

	private void showDialog(AddressRange range) {
		closeDialog();
		makeSelection(tool, program, range.getMinAddress(), range.getMaxAddress());
		performAction(encodedStringsAction, getCBAC(), false);
		dialog = waitForDialogComponent(EncodedStringsDialog.class);
		tableModel = dialog.getStringModel();
		waitForTableModel(tableModel);
	}

	@Test
	public void testDefaultUSASCII() {
		showDialog(ram.getAddressRange());
		assertEquals(3, tableModel.getRowCount());
	}

	@Test
	public void testSingleString() {
		showDialog(new AddressRangeImpl(addr(0x100), addr(0x100)));
		assertEquals(1, tableModel.getRowCount());
		EncodedStringsRow row0 = tableModel.getRowObject(0);
		assertEquals("Hello World!\n", row0.stringInfo().stringValue());
	}

	@Test
	public void testUTF8() {
		showDialog(ram.getAddressRange());
		Swing.runNow(() -> {
			dialog.setSelectedCharset("UTF-8");
		});
		waitForTableModel(tableModel);
		assertEquals(4, tableModel.getRowCount());
	}

	@Test
	public void testUTF8_Nonstdctrlchars() {
		showDialog(ram.getAddressRange());
		Swing.runNow(() -> {
			dialog.setShowAdvancedOptions(true);
			dialog.setExcludeNonStdCtrlChars(false);
			dialog.setSelectedCharset("UTF-8");
		});
		waitForTableModel(tableModel);
		assertEquals(5, tableModel.getRowCount());
	}

	@Test
	public void testUTF8_HanScript() {
		showDialog(ram.getAddressRange());
		Swing.runNow(() -> {
			dialog.setShowAdvancedOptions(true);
			dialog.setRequireValidStringOption(false);
			dialog.setSelectedCharset("UTF-8");
		});
		waitForTableModel(tableModel);
		assertEquals(4, tableModel.getRowCount());
		Swing.runNow(() -> {
			dialog.setShowScriptOptions(true);
			dialog.setShowAdvancedOptions(true);
			dialog.setRequireValidStringOption(false);
			dialog.setAllowAnyScriptOption(false);
			dialog.setAllowLatinScriptOption(true);
			dialog.setAllowCommonScriptOption(true);
			dialog.setRequiredScript(UnicodeScript.HAN);
		});
		waitForTableModel(tableModel);
		assertEquals(1, tableModel.getRowCount());
	}

	@Test
	public void testCreateString() {
		Data data = program.getListing().getDataAt(addr(0x100));
		assertFalse(data.isDefined());

		showDialog(ram.getAddressRange());
		assertEquals(3, tableModel.getRowCount());

		Swing.runNow(() -> dialog.getCreateButton().doClick());

		waitForSwing();

		data = program.getListing().getDataAt(addr(0x100));
		assertNotNull(data);
		assertTrue(data.getDataType() instanceof AbstractStringDataType);
	}

}
