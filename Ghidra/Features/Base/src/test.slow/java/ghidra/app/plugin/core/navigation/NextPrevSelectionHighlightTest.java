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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.support.FieldLocation;
import docking.widgets.fieldpanel.support.FieldSelection;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.highlight.SetHighlightPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Program;
import ghidra.test.*;

public class NextPrevSelectionHighlightTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private AddressFactory addrFactory;
	private Program program;
	private CodeBrowserPlugin cb;
	private DockingActionIf nextSelection;
	private DockingActionIf prevSelection;
	private DockingActionIf nextHighlight;
	private DockingActionIf prevHighlight;
	private DockingActionIf createHighlight;

	private Address addr(String address) {
		return addrFactory.getAddress(address);
	}

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		setupTool(tool);

		cb = env.getPlugin(CodeBrowserPlugin.class);
	}

	private void setupTool(PluginTool tool) throws Exception {
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(NextPrevAddressPlugin.class.getName());
		tool.addPlugin(NextPrevSelectedRangePlugin.class.getName());
		tool.addPlugin(NextPrevHighlightRangePlugin.class.getName());
		tool.addPlugin(SetHighlightPlugin.class.getName());

		NextPrevSelectedRangePlugin p1 = getPlugin(tool, NextPrevSelectedRangePlugin.class);
		NextPrevHighlightRangePlugin p2 = getPlugin(tool, NextPrevHighlightRangePlugin.class);
		nextSelection = getAction(p1, "Next Selected Range");
		prevSelection = getAction(p1, "Previous Selected Range");
		nextHighlight = getAction(p2, "Next Highlighted Range");
		prevHighlight = getAction(p2, "Previous Highlighted Range");

		SetHighlightPlugin hp = getPlugin(tool, SetHighlightPlugin.class);
		createHighlight = getAction(hp, "Set Highlight From Selection");
	}

	private void closeProgram() {
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.closeProgram(program, true);
	}

	@After
	public void tearDown() {
		env.dispose();
	}

	private void loadProgram(String programName) throws Exception {
		ClassicSampleX86ProgramBuilder builder = new ClassicSampleX86ProgramBuilder();
		builder.setName(programName);
		program = builder.getProgram();

		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());
		builder.dispose();
		addrFactory = program.getAddressFactory();
	}

	private void setSelection(FieldPanel fp, FieldSelection sel) {
		fp.setSelection(sel);
		Class<?>[] argClasses = new Class<?>[] { EventTrigger.class };
		Object[] args = new Object[] { EventTrigger.GUI_ACTION };
		invokeInstanceMethod("notifySelectionChanged", fp, argClasses, args);
	}

	@Test
	public void testSelectionEnablement() throws Exception {

		env.showTool();
		assertTrue(!nextSelection.isEnabledForContext(getActionContext()));
		assertTrue(!prevSelection.isEnabledForContext(getActionContext()));
		loadProgram("notepad");
		assertTrue(!nextSelection.isEnabledForContext(getActionContext()));
		assertTrue(!prevSelection.isEnabledForContext(getActionContext()));
		FieldSelection sel = new FieldSelection();

		FieldPanel fp = cb.getFieldPanel();
		cb.goToField(addr("0x1003698"), "Bytes", 0, 4);
		FieldLocation p1 = fp.getCursorLocation();
		cb.goToField(addr("0x10036a2"), "Address", 0, 1);
		FieldLocation p2 = fp.getCursorLocation();
		sel.addRange(p1, p2);
		setSelection(fp, sel);

		assertTrue(!nextSelection.isEnabledForContext(getActionContext()));
		assertTrue(prevSelection.isEnabledForContext(getActionContext()));

		cb.goToField(addr("0x1001000"), "Address", 0, 0);
		assertTrue(nextSelection.isEnabledForContext(getActionContext()));
		assertTrue(!prevSelection.isEnabledForContext(getActionContext()));

		cb.goToField(addr("0x1003698"), "Address", 0, 0);
		assertTrue(!nextSelection.isEnabledForContext(getActionContext()));
		assertTrue(!prevSelection.isEnabledForContext(getActionContext()));

		cb.goToField(addr("0x10036d3"), "Bytes", 0, 4);
		p1 = fp.getCursorLocation();
		cb.goToField(addr("0x10036de"), "Address", 0, 0);
		p2 = fp.getCursorLocation();
		sel.addRange(p1, p2);
		setSelection(fp, sel);

		cb.goToField(addr("0x10036c0"), "Address", 0, 0);
		assertTrue(nextSelection.isEnabledForContext(getActionContext()));
		assertTrue(prevSelection.isEnabledForContext(getActionContext()));

		cb.goToField(addr("1003699"), "Address", 0, 0);
		assertTrue(nextSelection.isEnabledForContext(getActionContext()));
		assertTrue(prevSelection.isEnabledForContext(getActionContext()));

		cb.goToField(addr("10036d7"), "Address", 0, 0);
		assertTrue(!nextSelection.isEnabledForContext(getActionContext()));
		assertTrue(prevSelection.isEnabledForContext(getActionContext()));

		closeProgram();
		assertTrue(!nextSelection.isEnabledForContext(getActionContext()));
		assertTrue(!prevSelection.isEnabledForContext(getActionContext()));

	}

	@Test
	public void testNextPrevSelectionAction() throws Exception {
		env.showTool();
		loadProgram("notepad");
		FieldSelection sel = new FieldSelection();

		FieldPanel fp = cb.getFieldPanel();
		cb.goToField(addr("0x1003698"), "Bytes", 0, 4);
		FieldLocation p1 = fp.getCursorLocation();
		cb.goToField(addr("0x10036a2"), "Address", 0, 0);
		FieldLocation p2 = fp.getCursorLocation();
		sel.addRange(p1, p2);

		cb.goToField(addr("0x10036d3"), "Bytes", 0, 4);
		p1 = fp.getCursorLocation();
		cb.goToField(addr("0x10036de"), "Address", 0, 0);
		p2 = fp.getCursorLocation();
		sel.addRange(p1, p2);
		setSelection(fp, sel);

		cb.goToField(addr("0x1001000"), "Address", 0, 0);
		performAction(nextSelection, cb.getProvider(), true);
		assertEquals(addr("0x1003698"), cb.getCurrentAddress());
		performAction(nextSelection, cb.getProvider(), true);
		assertEquals(addr("0x10036d3"), cb.getCurrentAddress());
		assertTrue(!nextSelection.isEnabledForContext(getActionContext()));

		performAction(prevSelection, cb.getProvider(), true);
		assertEquals(addr("0x1003698"), cb.getCurrentAddress());
		assertTrue(!prevSelection.isEnabledForContext(getActionContext()));

		cb.goToField(addr("0x1004000"), "Address", 0, 0);
		assertTrue(prevSelection.isEnabledForContext(getActionContext()));
		performAction(prevSelection, cb.getProvider(), true);
		assertEquals(addr("0x10036d3"), cb.getCurrentAddress());

	}

	@Test
	public void testHighlightEnablement() throws Exception {

		env.showTool();
		assertTrue(!nextHighlight.isEnabledForContext(getActionContext()));
		assertTrue(!prevHighlight.isEnabledForContext(getActionContext()));
		loadProgram("notepad");
		assertTrue(!nextHighlight.isEnabledForContext(getActionContext()));
		assertTrue(!prevHighlight.isEnabledForContext(getActionContext()));

		FieldSelection sel = new FieldSelection();
		FieldPanel fp = cb.getFieldPanel();
		cb.goToField(addr("0x1003698"), "Bytes", 0, 4);
		FieldLocation p1 = fp.getCursorLocation();
		cb.goToField(addr("0x10036a2"), "Address", 0, 0);
		FieldLocation p2 = fp.getCursorLocation();
		sel.addRange(p1, p2);
		setSelection(fp, sel);

		performAction(createHighlight, cb.getProvider(), true);
		cb.goToField(addr("0x1001000"), "Address", 0, 0);
		setSelection(fp, new FieldSelection());

		assertTrue(nextHighlight.isEnabledForContext(getActionContext()));
		assertTrue(!prevHighlight.isEnabledForContext(getActionContext()));

		cb.goToField(addr("0x1003698"), "Address", 0, 0);
		assertTrue(!nextHighlight.isEnabledForContext(getActionContext()));
		assertTrue(!prevHighlight.isEnabledForContext(getActionContext()));

		sel.clear();
		cb.goToField(addr("0x1003698"), "Bytes", 0, 4);
		p1 = fp.getCursorLocation();
		cb.goToField(addr("0x10036a2"), "Address", 0, 0);
		p2 = fp.getCursorLocation();
		sel.addRange(p1, p2);

		cb.goToField(addr("0x10036d3"), "Bytes", 0, 4);
		p1 = fp.getCursorLocation();
		cb.goToField(addr("0x10036de"), "Address", 0, 0);
		p2 = fp.getCursorLocation();
		sel.addRange(p1, p2);
		setSelection(fp, sel);

		performAction(createHighlight, cb.getProvider(), true);
		cb.goToField(addr("0x1001000"), "Address", 0, 0);
		setSelection(fp, new FieldSelection());

		cb.goToField(addr("0x10036c0"), "Address", 0, 0);
		assertTrue(nextHighlight.isEnabledForContext(getActionContext()));
		assertTrue(prevHighlight.isEnabledForContext(getActionContext()));

		cb.goToField(addr("1003699"), "Address", 0, 0);
		assertTrue(nextHighlight.isEnabledForContext(getActionContext()));
		assertTrue(prevHighlight.isEnabledForContext(getActionContext()));

		cb.goToField(addr("10036d7"), "Address", 0, 0);
		assertTrue(!nextHighlight.isEnabledForContext(getActionContext()));
		assertTrue(prevHighlight.isEnabledForContext(getActionContext()));

		closeProgram();
		assertTrue(!nextHighlight.isEnabledForContext(getActionContext()));
		assertTrue(!prevHighlight.isEnabledForContext(getActionContext()));

	}

	@Test
	public void testNextPrevHighlightAction() throws Exception {
		env.showTool();
		loadProgram("notepad");

		FieldSelection sel = new FieldSelection();
		FieldPanel fp = cb.getFieldPanel();

		cb.goToField(addr("0x1003698"), "Bytes", 0, 4);
		FieldLocation p1 = fp.getCursorLocation();
		cb.goToField(addr("0x10036a2"), "Address", 0, 1);
		FieldLocation p2 = fp.getCursorLocation();
		sel.addRange(p1, p2);

		cb.goToField(addr("0x10036d3"), "Bytes", 0, 4);
		p1 = fp.getCursorLocation();
		cb.goToField(addr("0x10036de"), "Address", 0, 1);
		p2 = fp.getCursorLocation();
		sel.addRange(p1, p2);
		setSelection(fp, sel);

		performAction(createHighlight, cb.getProvider(), true);
		cb.goToField(addr("0x1001000"), "Address", 0, 0);

		setSelection(fp, new FieldSelection());

		cb.goToField(addr("0x1001000"), "Address", 0, 0);
		performAction(nextHighlight, cb.getProvider(), true);
		assertEquals(addr("0x1003698"), cb.getCurrentAddress());
		performAction(nextHighlight, cb.getProvider(), true);
		assertEquals(addr("0x10036d3"), cb.getCurrentAddress());
		assertTrue(!nextHighlight.isEnabledForContext(getActionContext()));

		performAction(prevHighlight, cb.getProvider(), true);
		assertEquals(addr("0x1003698"), cb.getCurrentAddress());
		assertTrue(!prevHighlight.isEnabledForContext(getActionContext()));

		cb.goToField(addr("0x1004000"), "Address", 0, 0);
		assertTrue(prevHighlight.isEnabledForContext(getActionContext()));
		performAction(prevHighlight, cb.getProvider(), true);
		assertEquals(addr("0x10036d3"), cb.getCurrentAddress());

	}

	ActionContext getActionContext() {
		ActionContext context = cb.getProvider().getActionContext(null);
		if (context == null) {
			context = new ActionContext();
		}
		return context;

	}
}
