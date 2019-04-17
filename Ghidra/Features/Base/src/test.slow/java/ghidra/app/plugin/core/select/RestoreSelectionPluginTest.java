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

import docking.action.DockingActionIf;
import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.support.FieldLocation;
import docking.widgets.fieldpanel.support.FieldSelection;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.test.*;

public class RestoreSelectionPluginTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private Program primaryProgram;
	private DockingActionIf restoreSelectionAction;
	private PluginTool tool;
	private CodeBrowserPlugin cb;

	public RestoreSelectionPluginTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();

		primaryProgram = buildProgram1();
		tool = env.launchDefaultTool(primaryProgram);

		// make sure the plugin is in the tool (it will be in the default eventually)
		tool.addPlugin(RestoreSelectionPlugin.class.getName());

		cb = env.getPlugin(CodeBrowserPlugin.class);

		RestoreSelectionPlugin p1 = getPlugin(tool, RestoreSelectionPlugin.class);
		restoreSelectionAction = getAction(p1, "Restore Selection");
	}

	private Program buildProgram1() throws Exception {
		ToyProgramBuilder builder = new ToyProgramBuilder("program1", false);
		builder.createMemory(".text", "0x1001000", 1000);
		return builder.getProgram();
	}

	private Program buildProgram2() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("program2", ProgramBuilder._X86_16_REAL_MODE);
		builder.createMemory("Seg_0", "1000:0000", 0x32c0);
		builder.createMemory("Seg_1", "132c:0000", 0x9be);
		return builder.getProgram();
	}

	@After
	public void tearDown() throws Exception {
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.closeAllPrograms(true);
		env.dispose();
	}

	@Test
	public void testRestoreSelectionWithMultiplePrograms() throws Exception {
		// make sure the action is disabled when there is no prior selection
		assertTrue(!restoreSelectionAction.isEnabled());

		// make a selection and make sure the action is enabled 
		selectInPrimary(primaryProgram);
		assertTrue(!restoreSelectionAction.isEnabled());

		selectAgainInPrimary(primaryProgram);
		assertTrue(restoreSelectionAction.isEnabled());

		// multiple programs
		Program secondaryProgram = buildProgram2();
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(secondaryProgram.getDomainFile());

		// make sure the selection is disabled when this program is active
		pm.setCurrentProgram(secondaryProgram);
		assertTrue(!restoreSelectionAction.isEnabled());

		// change back to the primary program and make sure the action is enabled
		pm.setCurrentProgram(primaryProgram);
		assertTrue(restoreSelectionAction.isEnabled());

		// change back to the secondary program and make sure the action is still disabled
		pm.setCurrentProgram(secondaryProgram);
		assertTrue(!restoreSelectionAction.isEnabled());

		// make a selection in the secondary program and make sure the action is enabled
		ProgramSelection secondarySelection = selectInSecondary(secondaryProgram);
		assertTrue(!restoreSelectionAction.isEnabled());

		selectAgainInSecondary(secondaryProgram);
		assertTrue(restoreSelectionAction.isEnabled());

		// execute the action in the secondary *with* a selection already in place
		performAction(restoreSelectionAction, true);
		ProgramSelection newSelection = cb.getCurrentSelection();
		assertEquals(secondarySelection, newSelection);

		// switch back to the primary and make sure the action is still enabled
		pm.setCurrentProgram(primaryProgram);
		assertTrue(restoreSelectionAction.isEnabled());

		// close the secondary and make sure the action is still enabled
		pm.closeProgram(secondaryProgram, true);
	}

	@Test
	public void testBasicRestore() {
		// make sure the action is disabled when there is no prior selection
		assertTrue(!restoreSelectionAction.isEnabled());

		// make a selection and make sure the action is enabled 
		ProgramSelection previousSelection = selectInPrimary(primaryProgram);
		assertTrue(!restoreSelectionAction.isEnabled());

		selectAgainInPrimary(primaryProgram);
		assertTrue(restoreSelectionAction.isEnabled());

		performAction(restoreSelectionAction, true);
		ProgramSelection newSelection = cb.getCurrentSelection();
		assertEquals(previousSelection, newSelection);
	}

	@Test
	public void testRestoreWithClear() {
		// make sure the action is disabled when there is no prior selection
		assertTrue(!restoreSelectionAction.isEnabled());

		// make a selection and make sure the action is enabled 
		selectInPrimary(primaryProgram);
		assertTrue(!restoreSelectionAction.isEnabled());

		ProgramSelection secondarySelection = selectAgainInPrimary(primaryProgram);
		assertTrue(restoreSelectionAction.isEnabled());

		clearSelection(primaryProgram);

		performAction(restoreSelectionAction, true);
		ProgramSelection newSelection = cb.getCurrentSelection();
		assertEquals(secondarySelection, newSelection);
	}

	@Test
	public void testRestoreWithSingleSelectionAndClear() {
		// make sure the action is disabled when there is no prior selection
		assertTrue(!restoreSelectionAction.isEnabled());

		ProgramSelection previousSelection = selectInPrimary(primaryProgram);
		assertTrue(!restoreSelectionAction.isEnabled());

		clearSelection(primaryProgram);

		performAction(restoreSelectionAction, true);
		ProgramSelection newSelection = cb.getCurrentSelection();
		assertEquals(previousSelection, newSelection);
	}

	private ProgramSelection selectAgainInPrimary(Program program) {
		AddressFactory addressFactory = program.getAddressFactory();
		return selectRange(addressFactory.getAddress("1001024"),
			addressFactory.getAddress("1001028"));
	}

	private ProgramSelection selectInPrimary(Program program) {
		AddressFactory addressFactory = program.getAddressFactory();
		return selectRange(addressFactory.getAddress("1001010"),
			addressFactory.getAddress("1001020"));
	}

	private ProgramSelection selectAgainInSecondary(Program program) {
		AddressFactory addressFactory = program.getAddressFactory();
		return selectRange(addressFactory.getAddress("1000:0b2b"),
			addressFactory.getAddress("1000:0b2d"));
	}

	private ProgramSelection selectInSecondary(Program program) {
		AddressFactory addressFactory = program.getAddressFactory();
		return selectRange(addressFactory.getAddress("1000:0b12"),
			addressFactory.getAddress("1000:0b21"));
	}

	private ProgramSelection selectRange(Address start, Address end) {
		FieldPanel fp = cb.getFieldPanel();
		cb.goToField(start, "Address", 0, 0);
		FieldLocation p1 = fp.getCursorLocation();
		cb.goToField(end, "Address", 0, 0);
		FieldLocation p2 = fp.getCursorLocation();
		FieldSelection sel = new FieldSelection();
		sel.addRange(p1, p2);
		setSelection(fp, sel);

		ProgramSelection currentSelection = cb.getCurrentSelection();
		assertNotNull(currentSelection);
		return currentSelection;
	}

	private void setSelection(FieldPanel fp, FieldSelection sel) {
		fp.setSelection(sel);
		Class<?>[] argClasses = new Class<?>[] { EventTrigger.class };
		Object[] args = new Object[] { EventTrigger.GUI_ACTION };

		runSwing(() -> {
			invokeInstanceMethod("notifySelectionChanged", fp, argClasses, args);
		});
	}

	private void clearSelection(final Program program) {
		runSwing(() -> tool.firePluginEvent(
			new ProgramSelectionPluginEvent("Foo", new ProgramSelection(), program)));

		ProgramSelection currentSelection = cb.getCurrentSelection();
		assertTrue((currentSelection == null || currentSelection.isEmpty()));
	}
}
