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
package ghidra.app.plugin.core.label;

import static org.junit.Assert.*;

import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;

import org.junit.*;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.navigation.GoToAddressLabelPlugin;
import ghidra.app.util.AddEditDialog;
import ghidra.app.util.NamespaceChooserDialog;
import ghidra.app.util.viewer.field.MnemonicFieldFactory;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.test.*;

public class AddEditDialogWithNamespaceChooserTest extends AbstractGhidraHeadedIntegrationTest {
	private TestEnv env;
	private Program program;
	private AddEditDialog dialog;
	private PluginTool tool;
	private LabelMgrPlugin plugin;
	private JComboBox<?> namespacesComboBox;
	private Symbol symbol1;
	private Symbol symbol2;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();

		ClassicSampleX86ProgramBuilder builder = new ClassicSampleX86ProgramBuilder();
		builder.createNamespace("Foo");
		builder.createNamespace("Bar");
		program = builder.getProgram();

		tool = env.showTool(program);
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(LabelMgrPlugin.class.getName());
		tool.addPlugin(GoToAddressLabelPlugin.class.getName());

		plugin = getPlugin(tool, LabelMgrPlugin.class);

		symbol1 = builder.createLabel("0x10065a6", "symbol1");
		symbol2 = builder.createLabel("0x10065a9", "symbol2");
		createEntryFunction();
		builder.dispose();

		dialog = getAddEditDialog();

		namespacesComboBox = dialog.getNamespaceComboBox();

	}

	private AddEditDialog getAddEditDialog() {
		return runSwing(() -> plugin.getAddEditDialog());
	}

	@After
	public void tearDown() throws Exception {
		close(dialog);
		env.dispose();
	}

	@Test
	public void testUsingNamespaceChooser() throws Exception {

		editLabel(symbol1);
		assertNamespaces("Global", "entry");
		assertSelected("Global");
		chooseNamespaceFromChooser("Foo");
		assertSelected("Foo");
		pressOk();

		editLabel(symbol2);
		assertNamespaces("Global", "entry", "Foo");
		assertSelected("Global");
		chooseNamespaceFromChooser("Bar");
		assertSelected("Bar");
		pressOk();

		editLabel(symbol1);
		assertNamespaces("Global", "Foo", "entry", "Bar");
		assertSelected("Foo");
		pressOk();
	}

	private void assertSelected(String name) {
		assertEquals(name, getSelectedNamespace().getName());
	}

	private void assertNamespaces(String... names) {
		List<Namespace> comboNamespaces = getComboNamespaces();
		assertEquals(names.length, comboNamespaces.size());
		for (int i = 0; i < names.length; i++) {
			assertEquals(names[i], comboNamespaces.get(i).getName());
		}
	}

	private void chooseNamespaceFromChooser(String text) {
		AbstractButton button = findButtonByName(dialog.getComponent(), "BrowseButton");
		pressButton(button, false);
		NamespaceChooserDialog nd = waitForDialogComponent(NamespaceChooserDialog.class);
		JTextField field = findComponent(nd.getComponent(), JTextField.class);
		typeText(field, text, true);
		enter(field);
		pressButtonByText(nd.getComponent(), "OK");
	}

	protected void enter(JTextField field) {
		triggerActionKey(field, 0, KeyEvent.VK_ENTER);
		waitForSwing();
	}

	protected void typeText(JTextField textField, String text, boolean expectWindow) {
		waitForSwing();
		triggerText(textField, text);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void pressOk() {
		pressButtonByText(dialog, "OK");
	}

	private Namespace getSelectedNamespace() {
		return runSwing(() -> {
			Object selectedItem = namespacesComboBox.getSelectedItem();
			return ((AddEditDialog.NamespaceWrapper) selectedItem).getNamespace();
		});
	}

	private List<Namespace> getComboNamespaces() {
		return runSwing(() -> {
			List<Namespace> namespaces = new ArrayList<>();
			int count = namespacesComboBox.getItemCount();
			for (int i = 0; i < count; i++) {
				Object itemAt = namespacesComboBox.getItemAt(i);
				namespaces.add(((AddEditDialog.NamespaceWrapper) itemAt).getNamespace());
			}
			return namespaces;
		});
	}

	private void editLabel(final Symbol symbol) {
		// this makes debugging easier
		CodeBrowserPlugin cb = getPlugin(tool, CodeBrowserPlugin.class);
		cb.goToField(symbol.getAddress(), MnemonicFieldFactory.FIELD_NAME, 0, 0);

		runSwing(() -> dialog.editLabel(symbol, program), false);
		waitForSwing();
	}

	private void createEntryFunction() throws Exception {
		Symbol s = getUniqueSymbol(program, "entry", null);
		Function f = program.getListing().getFunctionAt(s.getAddress());
		if (f == null) {
			Address addr = s.getAddress();
			AddressSet body = new AddressSet(addr, addr.getNewAddress(0x010065cc));
			body.addRange(addr.getNewAddress(0x10065a4), addr.getNewAddress(0x010065cc));
			CreateFunctionCmd cmd =
				new CreateFunctionCmd(null, addr, body, SourceType.USER_DEFINED);
			assertTrue(tool.execute(cmd, program));
		}
	}
}
