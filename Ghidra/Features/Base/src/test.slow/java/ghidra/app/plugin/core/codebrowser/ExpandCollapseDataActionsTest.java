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
package ghidra.app.plugin.core.codebrowser;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.viewer.listingpanel.ListingModel;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.test.*;

public class ExpandCollapseDataActionsTest extends AbstractGhidraHeadedIntegrationTest {
	private Program program;
	private AddressFactory addrFactory;
	private TestEnv env;
	private PluginTool tool;
	private CodeViewerProvider provider;
	private ListingModel listingModel;
	private DockingActionIf toggleExpand;
	private DockingActionIf expandAll;
	private DockingActionIf collapseAll;

	private static String STRUCT_1 = "0x10";
	private static String STRUCT_2 = "0x110";
	private static String STRUCT_3 = "0x210";
	private static String STRUCT_1_SUB_11 = "0x2e"; // this is the address of a sub structure in Struct_1

	// Component Paths for various structures.
	private static int[] STRUCT_1_SUB_11_PATH = new int[] { 11 };
	private static int[] STRUCT_1_PATH = new int[] {};
	private static int[] STRUCT_1_SUB_0_PATH = new int[] { 0 };
	private static int[] STRUCT_1_SUB_0_SUB_0_PATH = new int[] { 0, 0 };

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		tool.addPlugin(CodeBrowserPlugin.class.getName());

		program = buildProgram();
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());
		addrFactory = program.getAddressFactory();
		env.showTool();
		provider = (CodeViewerProvider) tool.getComponentProvider("Listing");
		listingModel = provider.getListingPanel().getListingModel();
		CodeBrowserPlugin plugin = getPlugin(tool, CodeBrowserPlugin.class);
		toggleExpand = getAction(plugin, "Toggle Expand/Collapse Data");
		expandAll = getAction(plugin, "Expand All Data");
		collapseAll = getAction(plugin, "Collapse All Data");
	}

	@After
	public void tearDown() {
		if (program != null) {
			program.release(this);
		}
		env.dispose();
	}

	private Program buildProgram() throws Exception {
		ToyProgramBuilder builder = new ToyProgramBuilder("Test", true, this);
		builder.createMemory("Data", "0", 10000, "Test");
		Structure struct = createStructure();
		builder.applyDataType(STRUCT_1, struct);
		builder.applyDataType(STRUCT_2, struct);
		builder.applyDataType(STRUCT_3, struct);
		return builder.getProgram();
	}

	private Structure createStructure() {
		StructureDataType struct2 = new StructureDataType("inner2", 0);

		ByteDataType b = new ByteDataType();
		for (int i = 0; i < 10; i++) {
			struct2.add(b);
		}

		StructureDataType struct1 = new StructureDataType("inner1", 0);

		for (int i = 0; i < 10; i++) {
			struct1.add(b);
		}
		struct1.add(struct2);

		StructureDataType struct = new StructureDataType("Struct", 0);
		struct.add(struct1);
		for (int i = 0; i < 10; i++) {
			struct.add(b);
		}
		struct.add(struct1);
		return struct;
	}

	@Test
	public void testToggleTopLevel() {
		Address addr = addr(STRUCT_1);
		assertDataClosed(addr);
		performAction(toggleExpand, getContext(addr, null), true);
		assertDataOpen(addr);
		performAction(toggleExpand, getContext(addr, null), true);
		assertDataClosed(addr);
	}

	@Test
	public void testToggleSubLevel() {
		Address topAddr = addr(STRUCT_1);
		performAction(toggleExpand, getContext(topAddr, null), true);

		Address subAddr = addr(STRUCT_1_SUB_11);
		assertDataClosed(subAddr, STRUCT_1_SUB_11_PATH);
		ActionContext context = getContext(subAddr, STRUCT_1_SUB_11_PATH);
		performAction(toggleExpand, context, true);
		assertDataOpen(subAddr);
		performAction(toggleExpand, context, true);
		assertDataClosed(subAddr, STRUCT_1_SUB_11_PATH);
	}

	@Test
	public void testToggleActionEnablement() {
		// should be enabled on any expandable data
		assertTrue(toggleExpand.isEnabledForContext(getContext(addr(STRUCT_1), null)));

		// should be disabled on any non-expandable data  (50 is a non-structure address
		assertTrue(!toggleExpand.isEnabledForContext(getContext(addr(0x50), null)));

		Address topAddr = addr(STRUCT_1);
		performAction(toggleExpand, getContext(topAddr, null), true);

		// should be on for any data inside an expandable data (if it is expandable, it will
		// affect that data, otherwise it will collapse the parent
		assertTrue(toggleExpand.isEnabledForContext(getContext(addr(STRUCT_1), STRUCT_1_PATH)));
		assertTrue(
			toggleExpand.isEnabledForContext(getContext(addr(STRUCT_1), STRUCT_1_SUB_0_PATH)));

		assertTrue(toggleExpand.isEnabledForContext(getContext(addr(0x2d), getPath(10))));

		assertTrue(toggleExpand.isEnabledForContext(
			getContext(addr(STRUCT_1_SUB_11), STRUCT_1_SUB_11_PATH)));
	}

	@Test
	public void testExpandAllActionEnablement() {
		// Expand all is enabled for expandable elements and not for non-expandable elements
		assertTrue(expandAll.isEnabledForContext(getContext(addr(STRUCT_1), null)));
		assertTrue(!expandAll.isEnabledForContext(getContext(addr(0x50), null)));

		Address topAddr = addr(STRUCT_1);
		performAction(expandAll, getContext(topAddr, null), true);

		// Expand all is enabled even if the current expandable data is open (so it can open any closed sub items)
		assertTrue(expandAll.isEnabledForContext(getContext(addr(STRUCT_1), null)));

		// Expand all is enabled for sub expandable elements.
		assertTrue(expandAll.isEnabledForContext(getContext(addr(STRUCT_1), STRUCT_1_SUB_0_PATH)));

		// Expand all is not enabled for non expandable sub elements.
		assertTrue(!expandAll.isEnabledForContext(
			getContext(addr(STRUCT_1_SUB_11).subtract(1), getPath(10))));

		// Expand all is enabled for sub epandable elements;
		assertTrue(
			expandAll.isEnabledForContext(getContext(addr(STRUCT_1_SUB_11), STRUCT_1_SUB_11_PATH)));

	}

	@Test
	public void testCollapseAllActionEnablement() {
		// Collapse all is not enabled for closed expandable elements
		assertTrue(!collapseAll.isEnabledForContext(getContext(addr(STRUCT_1), null)));

		// Collapse all is not enabled for non-expandable top level elements
		assertTrue(!collapseAll.isEnabledForContext(getContext(addr(0x50), null)));

		Address topAddr = addr(STRUCT_1);
		performAction(expandAll, getContext(topAddr, null), true);

		// Collapse all is enabled for open top level expandable elements
		assertTrue(collapseAll.isEnabledForContext(getContext(addr(STRUCT_1), null)));

		// Collapse all is enabled for all elements in a structure
		assertTrue(
			collapseAll.isEnabledForContext(getContext(addr(STRUCT_1), STRUCT_1_SUB_0_PATH)));
		assertTrue(collapseAll.isEnabledForContext(getContext(addr(0x2d), STRUCT_1_SUB_0_PATH)));
		assertTrue(collapseAll.isEnabledForContext(
			getContext(addr(STRUCT_1_SUB_11), STRUCT_1_SUB_11_PATH)));

	}

	@Test
	public void testExpandAllInSelectionEnablement() {
		// Expand All In Selection is enabled whenever there is a selection
		ProgramSelection selection = new ProgramSelection(addr(0), addr(10));
		assertTrue(!expandAll.isEnabledForContext(getContext(addr(0x0), null)));
		assertEquals("Expand All Data", expandAll.getPopupMenuData().getMenuPath()[0]);

		assertTrue(
			expandAll.isEnabledForContext(getContextWithSelection(addr(STRUCT_1), selection)));
		// When there is a selection, the pop-up menu changes
		assertEquals("Expand All Data In Selection", expandAll.getPopupMenuData().getMenuPath()[0]);
	}

	@Test
	public void testExpandAll() {
		Address addr = addr(STRUCT_1);
		assertDataClosed(addr);
		assertDataClosed(addr, STRUCT_1_SUB_0_PATH);
		assertDataClosed(addr, STRUCT_1_SUB_0_SUB_0_PATH);
		assertDataClosed(addr(STRUCT_1_SUB_11), STRUCT_1_SUB_11_PATH);

		performAction(expandAll, getContext(addr, null), true);
		assertDataOpen(addr);
		assertDataOpen(addr, STRUCT_1_SUB_0_PATH);
		assertDataOpen(addr, STRUCT_1_SUB_0_SUB_0_PATH);
		assertDataOpen(addr(STRUCT_1_SUB_11), STRUCT_1_SUB_11_PATH);
	}

	@Test
	public void testExpandAllInSubData() {
		Address addr = addr(STRUCT_1);
		performAction(toggleExpand, getContext(addr, null), true);
		assertDataOpen(addr);
		assertDataClosed(addr, STRUCT_1_SUB_0_PATH);
		assertDataClosed(addr, STRUCT_1_SUB_0_SUB_0_PATH);
		assertDataClosed(addr(STRUCT_1_SUB_11), STRUCT_1_SUB_11_PATH);

		performAction(expandAll, getContext(addr, getPath(0)), true);

		assertDataOpen(addr);
		assertDataOpen(addr, STRUCT_1_SUB_0_PATH);
		assertDataOpen(addr, STRUCT_1_SUB_0_SUB_0_PATH);
		assertDataClosed(addr(STRUCT_1_SUB_11), STRUCT_1_SUB_11_PATH);
	}

	@Test
	public void testCollapseAllAtTopLevel() {
		Address addr = addr(STRUCT_1);

		performAction(expandAll, getContext(addr, null), true);

		assertDataOpen(addr);
		assertDataOpen(addr, STRUCT_1_SUB_0_PATH);
		assertDataOpen(addr, STRUCT_1_SUB_0_SUB_0_PATH);
		assertDataOpen(addr(STRUCT_1_SUB_11), STRUCT_1_SUB_11_PATH);

		performAction(collapseAll, getContext(addr, null), true);

		assertDataClosed(addr);
		assertDataClosed(addr, STRUCT_1_SUB_0_PATH);
		assertDataClosed(addr, STRUCT_1_SUB_0_SUB_0_PATH);
		assertDataClosed(addr(STRUCT_1_SUB_11), STRUCT_1_SUB_11_PATH);
	}

	@Test
	public void testCollapseAllAtLowerLevel() {
		Address addr = addr(STRUCT_1);

		performAction(expandAll, getContext(addr, null), true);

		assertDataOpen(addr);
		assertDataOpen(addr, STRUCT_1_SUB_0_PATH);
		assertDataOpen(addr, STRUCT_1_SUB_0_SUB_0_PATH);
		assertDataOpen(addr(STRUCT_1_SUB_11), STRUCT_1_SUB_11_PATH);

		performAction(collapseAll, getContext(addr(STRUCT_1_SUB_11), STRUCT_1_SUB_11_PATH), true);

		assertDataClosed(addr);
		assertDataClosed(addr, STRUCT_1_SUB_0_PATH);
		assertDataClosed(addr, STRUCT_1_SUB_0_SUB_0_PATH);
		assertDataClosed(addr(STRUCT_1_SUB_11), STRUCT_1_SUB_11_PATH);
	}

	@Test
	public void testExpandAllCollapseAllInSelection() {
		ProgramSelection selection = new ProgramSelection(addr(0), addr(0x500));

		assertDataClosed(addr(STRUCT_1));
		assertDataClosed(addr(STRUCT_2));
		assertDataClosed(addr(STRUCT_3));

		performAction(expandAll, getContextWithSelection(addr(STRUCT_1), selection), true);

		assertDataOpen(addr(STRUCT_1));
		assertDataOpen(addr(STRUCT_2));
		assertDataOpen(addr(STRUCT_3));

		performAction(collapseAll, getContextWithSelection(addr(STRUCT_1), selection), true);

		assertDataClosed(addr(STRUCT_1));
		assertDataClosed(addr(STRUCT_2));
		assertDataClosed(addr(STRUCT_3));
	}

	private int[] getPath(int... componentPath) {
		return componentPath;
	}

	private ActionContext getContextWithSelection(Address addr, ProgramSelection selection) {
		return new ProgramLocationActionContext(provider, program,
			new ProgramLocation(program, addr, null, null, 0, 0, 0), selection, null);
	}

	private ActionContext getContext(Address addr, int[] componentPath) {
		return new ProgramLocationActionContext(provider, program,
			new ProgramLocation(program, addr, componentPath, null, 0, 0, 0), null, null);
	}

	private Address addr(int offset) {
		return addrFactory.getDefaultAddressSpace().getAddress(offset);
	}

	private Address addr(String offset) {
		return addrFactory.getAddress(offset);
	}

	private void assertDataClosed(Address addr) {
		assertDataClosed(addr, null);
	}

	private void assertDataOpen(Address addr) {
		assertDataOpen(addr, null);
	}

	private void assertDataOpen(Address addr, int[] componentPath) {
		Data data = getData(addr);
		assertTrue(listingModel.isOpen(data));
	}

	private void assertDataClosed(Address addr, int[] componentPath) {
		Data data = getData(addr, componentPath);
		assertTrue(!listingModel.isOpen(data));
	}

	private Data getData(Address addr, int[] componentPath) {
		ProgramLocation loc = new ProgramLocation(program, addr, componentPath, null, 0, 0, 0);
		return DataUtilities.getDataAtLocation(loc);
	}

	private Data getData(Address addr) {
		Data data = program.getListing().getDataContaining(addr);
		if (!data.getAddress().equals(addr)) {
			data = data.getComponentAt((int) addr.subtract(data.getAddress()));
		}
		return data;
	}

}
