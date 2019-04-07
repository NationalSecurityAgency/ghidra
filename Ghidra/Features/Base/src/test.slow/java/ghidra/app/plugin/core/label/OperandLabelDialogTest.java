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

import static org.junit.Assert.assertEquals;

import org.junit.*;

import docking.ActionContext;
import docking.widgets.combobox.GhidraComboBox;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.OperandFieldLocation;
import ghidra.test.*;

public class OperandLabelDialogTest extends AbstractGhidraHeadedIntegrationTest {
	private TestEnv env;
	private PluginTool tool;
	private LabelMgrPlugin plugin;
	private CodeBrowserPlugin cb;
	private Program program;
	private OperandLabelDialog dialog;
	private GhidraComboBox<?> combo;
	private SetOperandLabelAction setLabelAction;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();

		ClassicSampleX86ProgramBuilder builder = new ClassicSampleX86ProgramBuilder();
		program = builder.getProgram();
		tool = env.launchDefaultTool(program);
		plugin = getPlugin(tool, LabelMgrPlugin.class);
		cb = getPlugin(tool, CodeBrowserPlugin.class);

		dialog = runSwing(() -> plugin.getOperandLabelDialog());

		combo = (GhidraComboBox<?>) findComponentByName(dialog, "MYCHOICE");

		setLabelAction = (SetOperandLabelAction) getAction(plugin, "Set Operand Label");
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	private Address addr(long addr) {
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		return space.getAddress(addr);
	}

	@Test
	public void testSet() throws Exception {
		OperandFieldLocation loc =
			new OperandFieldLocation(program, addr(0x100644f), null, addr(0x1001160), null, 0, 0);
		tool.firePluginEvent(
			new ProgramLocationPluginEvent(testName.getMethodName(), loc, program));
		waitForSwing();

		ActionContext context = runSwing(() -> cb.getProvider().getActionContext(null));
		performAction(setLabelAction, context, false);
		waitForSwing();

		runSwing(() -> combo.setSelectedItem("bob"));

		pressButtonByText(dialog, "OK");
		waitForSwing();

		Symbol[] symbols = program.getSymbolTable().getSymbols(addr(0x1001160));
		assertEquals(2, symbols.length);

		cb.updateNow();
		assertEquals("dword ptr [bob]", cb.getCurrentFieldText());

		performAction(setLabelAction, context, false);
		waitForSwing();

		runSwing(() -> combo.setSelectedItem("b"));
		pressButtonByText(dialog, "OK");

		program.flushEvents();

		waitForSwing();

		symbols = program.getSymbolTable().getSymbols(addr(0x1001160));
		assertEquals(3, symbols.length);

		cb.updateNow();
		assertEquals("dword ptr [b]", cb.getCurrentFieldText());
	}

}
