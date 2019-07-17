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
package ghidra.app.plugin.core.searchmem;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.awt.Container;
import java.awt.Window;

import javax.swing.JComboBox;
import javax.swing.JTextField;

import org.junit.*;

import docking.action.DockingActionIf;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.marker.MarkerManagerPlugin;
import ghidra.app.plugin.core.programtree.ProgramTreePlugin;
import ghidra.app.plugin.core.searchmem.mask.MnemonicSearchPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

public class MnemonicSearchPluginTest extends AbstractGhidraHeadedIntegrationTest {
	private TestEnv env;
	private PluginTool tool;
	private ProgramDB program;
	private MnemonicSearchPlugin plugin;
	private DockingActionIf searchMnemonicOperandsNoConstAction;
	private DockingActionIf searchMnemonicNoOperandsNoConstAction;
	private DockingActionIf searchMnemonicOperandsConstAction;
	private CodeBrowserPlugin cb;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		tool.addPlugin(ProgramTreePlugin.class.getName());
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(MarkerManagerPlugin.class.getName());
		tool.addPlugin(MemSearchPlugin.class.getName());
		tool.addPlugin(MnemonicSearchPlugin.class.getName());
		plugin = env.getPlugin(MnemonicSearchPlugin.class);
		cb = env.getPlugin(CodeBrowserPlugin.class);
		program = (ProgramDB) buildProgram();

		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());

		searchMnemonicOperandsNoConstAction =
			getAction(plugin, "Include Operands (except constants)");
		searchMnemonicNoOperandsNoConstAction = getAction(plugin, "Exclude Operands");
		searchMnemonicOperandsConstAction = getAction(plugin, "Include Operands");

		env.showTool();
	}

	private Program buildProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("TestX86", ProgramBuilder._X86);
		builder.createMemory(".text", Long.toHexString(0x1001000), 0x6600);

		//create and disassemble some code
		builder.setBytes("0x01004062", "55 8b ec 81 ec 04 01 00 00");
		builder.disassemble("0x01004062", 9, true);

		return builder.getProgram();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testSearchMnemonicOperandsNoConst() {
		ProgramSelection sel = new ProgramSelection(addr(0x01004062), addr(0x0100406a));
		tool.firePluginEvent(new ProgramSelectionPluginEvent("Test", sel, program));

		performAction(searchMnemonicOperandsNoConstAction, cb.getProvider(), true);

		MemSearchDialog dialog =
			waitForDialogComponent(tool.getToolFrame(), MemSearchDialog.class, 2000);
		assertNotNull(dialog);
		Container component = dialog.getComponent();

		@SuppressWarnings("unchecked")
		JComboBox<String> comboBox = findComponent(component, JComboBox.class);
		JTextField valueField = (JTextField) comboBox.getEditor().getEditorComponent();

		assertEquals(
			"01010101 10001011 11101100 10000001 11101100 ........ ........ ........ ........ ",
			valueField.getText());

	}

	@Test
	public void testSearchMnemonicNoOperandsNoConst() {
		ProgramSelection sel = new ProgramSelection(addr(0x01004062), addr(0x0100406a));
		tool.firePluginEvent(new ProgramSelectionPluginEvent("Test", sel, program));

		performAction(searchMnemonicNoOperandsNoConstAction, cb.getProvider(), true);

		MemSearchDialog dialog =
			waitForDialogComponent(tool.getToolFrame(), MemSearchDialog.class, 2000);
		assertNotNull(dialog);
		Container component = dialog.getComponent();

		@SuppressWarnings("unchecked")
		JComboBox<String> comboBox = findComponent(component, JComboBox.class);
		JTextField valueField = (JTextField) comboBox.getEditor().getEditorComponent();

		assertEquals(
			"01010... 10001011 11...... 10000001 11101... ........ ........ ........ ........ ",
			valueField.getText());

	}

	@Test
	public void testSearchMnemonicOperandsConst() {
		ProgramSelection sel = new ProgramSelection(addr(0x01004062), addr(0x0100406a));
		tool.firePluginEvent(new ProgramSelectionPluginEvent("Test", sel, program));

		performAction(searchMnemonicOperandsConstAction, cb.getProvider(), true);

		MemSearchDialog dialog =
			waitForDialogComponent(tool.getToolFrame(), MemSearchDialog.class, 2000);
		assertNotNull(dialog);
		Container component = dialog.getComponent();

		@SuppressWarnings("unchecked")
		JComboBox<String> comboBox = findComponent(component, JComboBox.class);
		JTextField valueField = (JTextField) comboBox.getEditor().getEditorComponent();

		assertEquals(
			"01010101 10001011 11101100 10000001 11101100 00000100 00000001 00000000 00000000 ",
			valueField.getText());
	}

	/**
	 * Tests that when multiple regions are selected, the user is notified via
	 * pop-up that this is not acceptable.
	 * 
	 */
	@Test
	public void testMultipleSelection() {

		// First set up two selection ranges.
		AddressRange range1 = new AddressRangeImpl(addr(0x01004062), addr(0x01004064));
		AddressRange range2 = new AddressRangeImpl(addr(0x0100406c), addr(0x0100406e));
		AddressSet addrSet = new AddressSet();
		addrSet.add(range1);
		addrSet.add(range2);

		// Create an event that we can fire to all subscribers, and send it.
		makeSelection(tool, program, addrSet);

		// Now invoke the menu option we want to test.
		performAction(searchMnemonicOperandsConstAction, cb.getProvider(), false);

		// Here's the main assert: If the code recognizes that we have multiple selection, the 
		// MemSearchDialog will NOT be displayed (an error message pops up instead).  So verify that
		// the dialog is null and we're ok.
		Window errorDialog = waitForWindow("Mnemonic Search Error", 2000);
		assertNotNull(errorDialog);
		errorDialog.setVisible(false);
	}

	private Address addr(int offset) {
		return program.getMinAddress().getNewAddress(offset);
	}

}
