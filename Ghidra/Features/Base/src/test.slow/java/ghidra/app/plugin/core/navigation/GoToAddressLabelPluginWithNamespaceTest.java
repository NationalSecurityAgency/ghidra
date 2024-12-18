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
package ghidra.app.plugin.core.navigation;

import static org.junit.Assert.*;

import javax.swing.JCheckBox;

import org.junit.*;

import generic.test.TestUtils;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.progmgr.MultiTabPlugin;
import ghidra.app.plugin.core.progmgr.ProgramManagerPlugin;
import ghidra.app.plugin.core.table.TableComponentProvider;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.navigation.GoToAddressLabelDialog;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Program;
import ghidra.test.*;
import ghidra.util.Swing;
import ghidra.util.table.GhidraProgramTableModel;

public class GoToAddressLabelPluginWithNamespaceTest extends AbstractGhidraHeadedIntegrationTest {
	private TestEnv env;
	private PluginTool tool;
	private AddressFactory addrFactory;
	private Program program;
	private GoToAddressLabelPlugin plugin;
	private GoToAddressLabelDialog dialog;
	private CodeBrowserPlugin cbPlugin;
	private CodeViewerProvider provider;
	private GhidraProgramTableModel<?> model;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		tool.addPlugin(GoToAddressLabelPlugin.class.getName());
		tool.addPlugin(ProgramManagerPlugin.class.getName());
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(MultiTabPlugin.class.getName());

		plugin = env.getPlugin(GoToAddressLabelPlugin.class);
		cbPlugin = env.getPlugin(CodeBrowserPlugin.class);
		provider = cbPlugin.getProvider();
		showTool(tool);
		buildProgram();
		final ProgramManager pm = tool.getService(ProgramManager.class);
		runSwing(() -> pm.openProgram(program.getDomainFile()));

		dialog = plugin.getDialog();
		setCaseSensitive(true);
		showDialog();
	}

	@After
	public void tearDown() {
		closeAllWindows();
		env.dispose();
	}

	@Test
	public void testExactSearch() throws Exception {
		setText("billy");
		performOkCallback();
		assertEquals(addr("00001000"), cbPlugin.getCurrentAddress());

		model = waitForModel();
		assertEquals(4, model.getRowCount());

		assertRow(0, "00001000", "billy");
		assertRow(1, "00001001", "billy");
		assertRow(2, "00001002", "billy");
		assertRow(3, "00001003", "billy");
	}

	@Test
	public void testWildInSymbolName() throws Exception {
		setText("*ll*");
		performOkCallback();

		model = waitForModel();
		assertEquals(8, model.getRowCount());

		assertRow(0, "00001000", "billy");
		assertRow(1, "00001001", "billy");
		assertRow(2, "00001002", "billy");
		assertRow(3, "00001003", "billy");
		assertRow(4, "00001004", "sally");
		assertRow(5, "00001005", "sally");
		assertRow(6, "00001006", "sally");
		assertRow(7, "00001007", "sally");
	}

	@Test
	public void testWildWithSpecifiedNamespace() throws Exception {
		setText("parent::*");
		performOkCallback();
		assertEquals(addr("00001000"), cbPlugin.getCurrentAddress());

		model = waitForModel();
		assertEquals(6, model.getRowCount());

		assertRow(0, "00001001", "billy");
		assertRow(1, "00001002", "billy");
		assertRow(2, "00001003", "billy");
		assertRow(3, "00001005", "sally");
		assertRow(4, "00001006", "sally");
		assertRow(5, "00001007", "sally");
	}

	@Test
	public void testWildSymbolNameForSpecificParent() throws Exception {
		setText("parent2::*");
		performOkCallback();

		model = waitForModel();
		assertEquals(3, model.getRowCount());

		assertRow(0, "00001009", "bob");
		assertRow(1, "0000100a", "bob");
		assertRow(2, "0000100b", "bob");
	}

	@Test
	public void testWildSymbolNameAndWildParentInSpecifiedUpperNamesapce() throws Exception {
		setText("middle::*::*");
		performOkCallback();

		model = waitForModel();
		assertEquals(6, model.getRowCount());

		assertRow(0, "00001002", "billy");
		assertRow(1, "00001003", "billy");
		assertRow(2, "00001006", "sally");
		assertRow(3, "00001007", "sally");
		assertRow(4, "0000100a", "bob");
		assertRow(5, "0000100b", "bob");
	}

	@Test
	public void testAbsoluteNamespacePathWithWilds() throws Exception {
		setText("::middle::*::*");
		performOkCallback();

		model = waitForModel();
		assertEquals(3, model.getRowCount());

		assertRow(0, "00001002", "billy");
		assertRow(1, "00001006", "sally");
		assertRow(2, "0000100a", "bob");
	}

	@Test
	public void testNoMatches() throws Exception {
		setText("xyz");
		performOkCallback();
		waitForTasks();
		assertTrue(dialog.isVisible());
	}

//==================================================================================================
// Private Methods
//==================================================================================================
	private void assertRow(int row, String address, String name) {
		assertEquals(address, model.getValueAt(row, 0).toString());
		assertEquals(name, model.getValueAt(row, 1));
	}

	private void buildProgram() throws Exception {
		ToyProgramBuilder builder = new ToyProgramBuilder("Test", false);

		builder.createMemory("Block1", "0x1000", 1000);

		builder.createLabel("0x1000", "billy");
		builder.createLabel("0x1001", "billy", "parent");
		builder.createLabel("0x1002", "billy", "middle::parent");
		builder.createLabel("0x1003", "billy", "top::middle::parent");
		builder.createLabel("0x1004", "sally");
		builder.createLabel("0x1005", "sally", "parent");
		builder.createLabel("0x1006", "sally", "middle::parent");
		builder.createLabel("0x1007", "sally", "top::middle::parent");
		builder.createLabel("0x1008", "bob");
		builder.createLabel("0x1009", "bob", "parent2");
		builder.createLabel("0x100a", "bob", "middle::parent2");
		builder.createLabel("0x100b", "bob", "top::middle::parent2");
		program = builder.getProgram();
		addrFactory = program.getAddressFactory();
	}

	private GhidraProgramTableModel<?> waitForModel() throws Exception {
		TableComponentProvider<?> tableProvider =
			waitForComponentProvider(TableComponentProvider.class);
		GhidraProgramTableModel<?> tableModel = tableProvider.getModel();
		waitForTableModel(tableModel);
		return tableModel;
	}

	private void setCaseSensitive(final boolean selected) {
		final JCheckBox checkBox =
			(JCheckBox) TestUtils.getInstanceField("caseSensitiveBox", dialog);
		runSwing(() -> checkBox.setSelected(selected));
	}

	private Address addr(String address) {
		return addrFactory.getAddress(address);
	}

	private void showDialog() {
		Swing.runLater(() -> dialog.show(provider, cbPlugin.getCurrentAddress(), tool));
		waitForSwing();
	}

	private void setText(final String text) throws Exception {
		runSwing(() -> dialog.setText(text));
	}

	private void performOkCallback() throws Exception {
		runSwing(() -> dialog.okCallback());
	}

}
