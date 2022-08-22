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
package ghidra.app.plugin.core.select;

import static org.junit.Assert.*;

import org.junit.*;

import docking.action.ToggleDockingAction;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.codebrowser.CodeBrowserSelectionPlugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.test.*;

public class MarkAndSelectActionTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private Program program;
	private PluginTool tool;
	private CodeBrowserPlugin cb;
	private ToyProgramBuilder builder;
	private ToggleDockingAction markAndSelectAction;

	public MarkAndSelectActionTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		builder = new ToyProgramBuilder("program", false);
		program = buildProgram();
		tool = env.launchDefaultTool(program);
		cb = env.getPlugin(CodeBrowserPlugin.class);
		CodeBrowserSelectionPlugin selectPlugin = env.getPlugin(CodeBrowserSelectionPlugin.class);
		markAndSelectAction = (ToggleDockingAction) getAction(selectPlugin, "Mark and Select");
	}

	private Program buildProgram() throws Exception {
		builder.createMemory(".text", "0x1001000", 1000);
		return builder.getProgram();
	}

	@After
	public void tearDown() throws Exception {
		builder.dispose();
		env.dispose();
	}

	@Test
	public void testMarkAndSelectAction() {
		assertNoSelection();
		assertMarkAndSelectActionArmed(false);

		goTo("0x1001010");
		invokeMarkAndSelectAction();
		assertNoSelection();
		assertMarkAndSelectActionArmed(true);

		goTo("0x1001020");
		invokeMarkAndSelectAction();
		assertSelection("0x1001010", "0x1001020");
		assertMarkAndSelectActionArmed(false);
	}

	@Test
	public void testMarkAndSelectReplacesCurrentSelection() {
		createSelection("0x1001000", "0x1001002");
		assertSelection("0x1001000", "0x1001002");
		assertMarkAndSelectActionArmed(false);

		goTo("0x1001010");
		invokeMarkAndSelectAction();

		goTo("0x1001020");
		invokeMarkAndSelectAction();
		assertSelection("0x1001010", "0x1001020");
	}

	private void createSelection(String string, String string2) {
		Address from = addr(string);
		Address to = addr(string2);
		runSwing(() -> cb.getProvider().setSelection(new ProgramSelection(from, to)));
	}

	private void assertMarkAndSelectActionArmed(boolean armed) {
		assertEquals(armed, runSwing(() -> markAndSelectAction.isSelected()));
	}

	private void assertSelection(String startAddr, String endAddr) {
		ProgramSelection selection = cb.getCurrentSelection();
		Address start = addr(startAddr);
		Address end = addr(endAddr);
		assertEquals(new ProgramSelection(start, end), selection);
	}

	private void invokeMarkAndSelectAction() {
		performAction(markAndSelectAction, cb.getProvider().getActionContext(null), true);
	}

	private void goTo(String addrString) {
		cb.goToField(addr(addrString), "Address", 0, 0);
	}

	private void assertNoSelection() {
		ProgramSelection currentSelection = cb.getCurrentSelection();
		assertTrue(currentSelection.isEmpty());
	}

	private Address addr(String addrString) {
		return program.getAddressFactory().getAddress(addrString);
	}
}
