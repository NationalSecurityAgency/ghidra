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
package ghidra.app.plugin.core.highlight;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.widgets.fieldpanel.support.FieldSelection;
import ghidra.app.events.ProgramHighlightPluginEvent;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.test.*;

public class SetHighlightPluginTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private Program program;
	private PluginTool tool;
	private SetHighlightPlugin plugin;
	private CodeBrowserPlugin cb;

	public SetHighlightPluginTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();

		ToyProgramBuilder builder = new ToyProgramBuilder("notepad", true);
		builder.createMemory("test", "0x01001000", 0x1000);
		program = builder.getProgram();

		tool = env.showTool(program);
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(SetHighlightPlugin.class.getName());

		plugin = getPlugin(tool, SetHighlightPlugin.class);
		cb = getPlugin(tool, CodeBrowserPlugin.class);
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	private Address addr(long addr) {
		return program.getAddressFactory().getAddress(Long.toHexString(addr));
	}

	@Test
	public void testEnablement() {
		DockingActionIf setHighlightAction =
			getAction(plugin, "Set Highlight From Selection");
		DockingActionIf clearHighlightAction = getAction(plugin, "Remove Highlight");
		DockingActionIf addSelectionAction = getAction(plugin, "Add Selection To Highlight");
		DockingActionIf subtractSelectionAction =
			getAction(plugin, "Subtract Selection From Highlight");
		DockingActionIf setSelectionAction =
			getAction(plugin, "Set Selection From Highlight");

		// No selection or highlight
		assertEquals(new ProgramSelection(), cb.getCurrentSelection());
		assertEquals(new ProgramSelection(), getHighlight());
		ActionContext context = cb.getProvider().getActionContext(null);
		assertEquals(false, setHighlightAction.isEnabledForContext(context));
		assertEquals(false, clearHighlightAction.isEnabledForContext(context));
		assertEquals(false, addSelectionAction.isEnabledForContext(context));
		assertEquals(false, subtractSelectionAction.isEnabledForContext(context));
		assertEquals(false, setSelectionAction.isEnabledForContext(context));

		AddressSet selectionSet = new AddressSet(addr(0x01001234), addr(0x01001277));
		tool.firePluginEvent(
			new ProgramSelectionPluginEvent("test", new ProgramSelection(selectionSet), program));
		waitForPostedSwingRunnables();
		context = cb.getProvider().getActionContext(null);

		// Selection Only
		assertEquals(new ProgramSelection(selectionSet), cb.getCurrentSelection());
		assertEquals(new ProgramSelection(), getHighlight());
		assertEquals(true, setHighlightAction.isEnabledForContext(context));
		assertEquals(false, clearHighlightAction.isEnabledForContext(context));
		assertEquals(false, addSelectionAction.isEnabledForContext(context));
		assertEquals(false, subtractSelectionAction.isEnabledForContext(context));
		assertEquals(false, setSelectionAction.isEnabledForContext(context));

		AddressSet highlightSet = new AddressSet(addr(0x01001270), addr(0x01001297));
		tool.firePluginEvent(
			new ProgramHighlightPluginEvent("test", new ProgramSelection(highlightSet), program));
		waitForPostedSwingRunnables();
		context = cb.getProvider().getActionContext(null);

		// Selection & Highlight
		assertEquals(new ProgramSelection(selectionSet), cb.getCurrentSelection());
		assertEquals(new ProgramSelection(highlightSet), getHighlight());
		assertEquals(true, setHighlightAction.isEnabledForContext(context));
		assertEquals(true, clearHighlightAction.isEnabledForContext(context));
		assertEquals(true, addSelectionAction.isEnabledForContext(context));
		assertEquals(true, subtractSelectionAction.isEnabledForContext(context));
		assertEquals(true, setSelectionAction.isEnabledForContext(context));

		selectionSet = new AddressSet();
		tool.firePluginEvent(
			new ProgramSelectionPluginEvent("test", new ProgramSelection(selectionSet), program));
		waitForPostedSwingRunnables();
		context = cb.getProvider().getActionContext(null);

		// Highlight Only
		assertEquals(new ProgramSelection(), cb.getCurrentSelection());
		assertEquals(new ProgramSelection(highlightSet), getHighlight());
		assertEquals(false, setHighlightAction.isEnabledForContext(context));
		assertEquals(true, clearHighlightAction.isEnabledForContext(context));
		assertEquals(false, addSelectionAction.isEnabledForContext(context));
		assertEquals(false, subtractSelectionAction.isEnabledForContext(context));
		assertEquals(true, setSelectionAction.isEnabledForContext(context));

	}

	@Test
	public void testSetHighlight() {
		DockingActionIf setHighlightAction =
			getAction(plugin, "Set Highlight From Selection");
		assertNotNull(setHighlightAction);

		AddressSet selectionSet = new AddressSet(addr(0x01001234), addr(0x01001277));
		tool.firePluginEvent(
			new ProgramSelectionPluginEvent("test", new ProgramSelection(selectionSet), program));
		waitForPostedSwingRunnables();

		assertEquals(new ProgramSelection(selectionSet), cb.getCurrentSelection());
		assertEquals(new ProgramSelection(), getHighlight());

		performAction(setHighlightAction, cb.getProvider(), true);

		assertEquals(new ProgramSelection(selectionSet), cb.getCurrentSelection());
		assertEquals(new ProgramSelection(selectionSet), getHighlight());
	}

	@Test
	public void testClearHighlight() {
		DockingActionIf clearHighlightAction = getAction(plugin, "Remove Highlight");
		assertNotNull(clearHighlightAction);

		AddressSet highlightSet = new AddressSet(addr(0x01001270), addr(0x01001297));
		tool.firePluginEvent(
			new ProgramHighlightPluginEvent("test", new ProgramSelection(highlightSet), program));
		waitForPostedSwingRunnables();

		assertEquals(new ProgramSelection(), cb.getCurrentSelection());
		assertEquals(new ProgramSelection(highlightSet), getHighlight());

		performAction(clearHighlightAction, cb.getProvider(), true);

		assertEquals(new ProgramSelection(), cb.getCurrentSelection());
		assertEquals(new ProgramSelection(), getHighlight());
	}

	@Test
	public void testAddSelectionToHighlight() {
		DockingActionIf addSelectionAction = getAction(plugin, "Add Selection To Highlight");
		assertNotNull(addSelectionAction);

		AddressSet selectionSet = new AddressSet(addr(0x01001234), addr(0x01001277));
		tool.firePluginEvent(
			new ProgramSelectionPluginEvent("test", new ProgramSelection(selectionSet), program));
		waitForPostedSwingRunnables();

		AddressSet highlightSet = new AddressSet(addr(0x01001270), addr(0x01001297));
		tool.firePluginEvent(
			new ProgramHighlightPluginEvent("test", new ProgramSelection(highlightSet), program));
		waitForPostedSwingRunnables();

		assertEquals(new ProgramSelection(selectionSet), cb.getCurrentSelection());
		assertEquals(new ProgramSelection(highlightSet), getHighlight());

		performAction(addSelectionAction, cb.getProvider(), true);

		AddressSet resultHighlightSet = new AddressSet(addr(0x01001234), addr(0x01001297));

		assertEquals(new ProgramSelection(selectionSet), cb.getCurrentSelection());
		assertEquals(new ProgramSelection(resultHighlightSet), getHighlight());
	}

	@Test
	public void testSubtractSelectionFromHighlight() {
		DockingActionIf subtractSelectionAction =
			getAction(plugin, "Subtract Selection From Highlight");
		assertNotNull(subtractSelectionAction);

		AddressSet selectionSet = new AddressSet(addr(0x01001234), addr(0x01001277));
		tool.firePluginEvent(
			new ProgramSelectionPluginEvent("test", new ProgramSelection(selectionSet), program));
		waitForPostedSwingRunnables();

		AddressSet highlightSet = new AddressSet(addr(0x01001270), addr(0x01001297));
		tool.firePluginEvent(
			new ProgramHighlightPluginEvent("test", new ProgramSelection(highlightSet), program));
		waitForPostedSwingRunnables();

		assertEquals(new ProgramSelection(selectionSet), cb.getCurrentSelection());
		assertEquals(new ProgramSelection(highlightSet), getHighlight());

		performAction(subtractSelectionAction, cb.getProvider(), true);

		AddressSet resultHighlightSet = new AddressSet(addr(0x01001278), addr(0x01001297));

		assertEquals(new ProgramSelection(selectionSet), cb.getCurrentSelection());
		assertEquals(new ProgramSelection(resultHighlightSet), getHighlight());
	}

	@Test
	public void testSetSelection() {
		DockingActionIf setSelectionAction =
			getAction(plugin, "Set Selection From Highlight");
		assertNotNull(setSelectionAction);

		AddressSet highlightSet = new AddressSet(addr(0x01001270), addr(0x01001297));
		tool.firePluginEvent(
			new ProgramHighlightPluginEvent("test", new ProgramSelection(highlightSet), program));
		waitForPostedSwingRunnables();

		assertEquals(new ProgramSelection(), cb.getCurrentSelection());
		assertEquals(new ProgramSelection(highlightSet), getHighlight());

		performAction(setSelectionAction, cb.getProvider(), true);

		assertEquals(new ProgramSelection(highlightSet), cb.getCurrentSelection());
		assertEquals(new ProgramSelection(highlightSet), getHighlight());
	}

	private ProgramSelection getHighlight() {
		ListingPanel listingPanel = cb.getListingPanel();
		FieldSelection fieldHighlight = listingPanel.getFieldPanel().getHighlight();
		AddressSet highlightSet = listingPanel.getAddressIndexMap().getAddressSet(fieldHighlight);
		return new ProgramSelection(highlightSet);
	}
}
