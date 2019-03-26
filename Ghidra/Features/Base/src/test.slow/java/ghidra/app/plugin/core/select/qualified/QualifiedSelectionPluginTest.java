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
/*
 * Created on Dec 28, 2005
 */
package ghidra.app.plugin.core.select.qualified;

import static org.junit.Assert.*;

import javax.swing.JTree;
import javax.swing.tree.TreePath;

import org.junit.*;

import docking.ComponentProvider;
import docking.action.DockingActionIf;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.marker.MarkerManagerPlugin;
import ghidra.app.plugin.core.navigation.GoToAddressLabelPlugin;
import ghidra.app.plugin.core.programtree.ProgramTreePlugin;
import ghidra.app.plugin.core.select.programtree.ProgramTreeSelectionPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.util.ProgramSelection;
import ghidra.test.*;

public class QualifiedSelectionPluginTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private Program program;
	private AddressFactory addrFactory;
	private CodeBrowserPlugin cb;
	private CodeViewerProvider provider;
	private QualifiedSelectionPlugin qSelectPlugin;
	private DockingActionIf selectDataAction;
	private DockingActionIf selectInstructionAction;
	private DockingActionIf selectUndefinedAction;
	private ProgramTreePlugin pt;
	private ComponentProvider programTreeProvider;
	private DockingActionIf replaceView;
	private ToyProgramBuilder builder;

	@Before
	public void setUp() throws Exception {

		env = new TestEnv();
		tool = env.showTool();
		setUpCodeBrowser(tool);
		setUpProgramTree(tool);
		setUpQualifiedSelection(tool);
		loadProgram("notepad");
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	private void setUpCodeBrowser(PluginTool tool) throws Exception {
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(GoToAddressLabelPlugin.class.getName());
		tool.addPlugin(MarkerManagerPlugin.class.getName());
		cb = getPlugin(tool, CodeBrowserPlugin.class);
		provider = cb.getProvider();
	}

	private void setUpProgramTree(PluginTool tool) throws Exception {
		tool.addPlugin(ProgramTreePlugin.class.getName());
		pt = env.getPlugin(ProgramTreePlugin.class);
		replaceView = getAction(pt, "Replace View");
		showProgramTree();
		tool.addPlugin(ProgramTreeSelectionPlugin.class.getName());
	}

	private void showProgramTree() {

		ProgramTreePlugin ptree = env.getPlugin(ProgramTreePlugin.class);
		programTreeProvider = (ComponentProvider) getInstanceField("viewProvider", pt);
		tool.showComponentProvider(programTreeProvider, true);
	}

	protected void setUpQualifiedSelection(PluginTool tool) throws Exception {
		tool.addPlugin(QualifiedSelectionPlugin.class.getName());
		qSelectPlugin = getPlugin(tool, QualifiedSelectionPlugin.class);
		selectDataAction = getAction(qSelectPlugin, "Data");
		selectInstructionAction = getAction(qSelectPlugin, "Instructions");
		selectUndefinedAction = getAction(qSelectPlugin, "Undefined");
	}

	@Test
	public void testSelectFromEntireProgram() throws Exception {
		assertTrue(getCurrentSelection().isEmpty());

		// Select All Instructions.
		performAction(selectInstructionAction, provider, true);
		ProgramSelection instructionSet = getCurrentSelection();
		assertTrue(!instructionSet.isEmpty());

		// Select No Data (because there is a selection of all instructions).
		performAction(selectDataAction, provider, true);
		assertTrue(getCurrentSelection().isEmpty());

		// Select All Data.
		performAction(selectDataAction, provider, true);
		ProgramSelection dataSet = getCurrentSelection();
		assertTrue(!dataSet.isEmpty());

		// Select No Undefined.
		performAction(selectUndefinedAction, provider, true);
		assertTrue(getCurrentSelection().isEmpty());

		// Select All Undefined.
		performAction(selectUndefinedAction, provider, true);
		ProgramSelection undefinedSet = getCurrentSelection();
		assertTrue(!undefinedSet.isEmpty());

		// Select No Instructions.
		performAction(selectInstructionAction, provider, true);
		assertTrue(getCurrentSelection().isEmpty());

		// Check that none of the sets overlap.
		assertTrue(instructionSet.intersect(dataSet).isEmpty());
		assertTrue(dataSet.intersect(undefinedSet).isEmpty());
		assertTrue(undefinedSet.intersect(instructionSet).isEmpty());

		// Check that memory = instructions + data + undefined
		AddressSet codeUnitSet = new AddressSet();
		codeUnitSet.add(instructionSet);
		codeUnitSet.add(dataSet);
		codeUnitSet.add(undefinedSet);
		assertEquals(new AddressSet(program.getMemory()), codeUnitSet);

		// Check that the expected type of code unit is at each address.
		checkForInstructions(instructionSet);
		checkForDefinedData(dataSet);
		checkForUndefined(undefinedSet);
	}

	@Test
	public void testSelectFromASelection() throws Exception {
		assertTrue(getCurrentSelection().isEmpty());

		AddressSet selectSet = new AddressSet(addr("010012d2"), addr("01001960"));

		// Select 010012d2 to 01001960.
		setSelection(selectSet);// 010012d2 - 01001960
		assertEquals(selectSet, new AddressSet(getCurrentSelection()));

		// Select Instructions.
		performAction(selectInstructionAction, provider, true);
		ProgramSelection instructionSet = getCurrentSelection();
		assertTrue(!instructionSet.isEmpty());
		assertTrue(instructionSet.getMinAddress().compareTo(addr("010012d2")) >= 0);
		assertTrue(instructionSet.getMaxAddress().compareTo(addr("01001960")) <= 0);

		// Select 010012d2 to 01001960.
		setSelection(selectSet);// 010012d2 - 01001960
		assertEquals(selectSet, new AddressSet(getCurrentSelection()));

		// Select Data.
		performAction(selectDataAction, provider, true);
		waitForSwing();
		ProgramSelection dataSet = getCurrentSelection();
		assertTrue(!dataSet.isEmpty());
		assertTrue(dataSet.getMinAddress().compareTo(addr("010012d2")) >= 0);
		assertTrue(dataSet.getMaxAddress().compareTo(addr("01001960")) <= 0);

		// Select 010012d2 to 01001960.
		setSelection(selectSet);// 010012d2 - 01001960
		assertEquals(selectSet, new AddressSet(getCurrentSelection()));

		// Select Undefined.
		performAction(selectUndefinedAction, provider, true);
		waitForSwing();
		ProgramSelection undefinedSet = getCurrentSelection();
		assertTrue(!undefinedSet.isEmpty());
		assertTrue(undefinedSet.getMinAddress().compareTo(addr("010012d2")) >= 0);
		assertTrue(undefinedSet.getMaxAddress().compareTo(addr("01001960")) <= 0);

		// Check that none of the sets overlap.
		assertTrue(instructionSet.intersect(dataSet).isEmpty());
		assertTrue(dataSet.intersect(undefinedSet).isEmpty());
		assertTrue(undefinedSet.intersect(instructionSet).isEmpty());

		// Check that selection = instructions + data + undefined
		AddressSet codeUnitSet = new AddressSet();
		codeUnitSet.add(instructionSet);
		codeUnitSet.add(dataSet);
		codeUnitSet.add(undefinedSet);
		assertEquals(selectSet, codeUnitSet);

		// Check that the expected type of code unit is at each address.
		checkForInstructions(instructionSet);
		checkForDefinedData(dataSet);
		checkForUndefined(undefinedSet);
	}

	@Test
	public void testSelectWithView() throws Exception {
		AddressSet rsrcSet = new AddressSet(addr("0100a000"), addr("0100f3ff"));
		JTree tree = findComponent(tool.getToolFrame(), JTree.class);

		// Replace view with .rsrc
		selectTreeNodeByText(tree, ".rsrc", true);
		performAction(replaceView, provider, true);

		ProgramSelection rsrcInstructionSet = getCurrentSelection();
		assertTrue(rsrcInstructionSet.isEmpty());

		// Select All Instructions.
		performAction(selectInstructionAction, provider, true);
		waitForSwing();
		assertTrue(getCurrentSelection().isEmpty());

		// Change to program view and make sure the previously selected (but not visible in
		// the current view) instructions are selected in the new view.
		selectTreeNodeByText(tree, "Test", true);
		performAction(replaceView, provider, true);
		ProgramSelection instructionSet = getCurrentSelection();
		assertFalse("Instructions selection should have been restored when the view changed",
			instructionSet.isEmpty());

		// Select No Data.
		performAction(selectDataAction, provider, true);
		waitForSwing();
		assertTrue(getCurrentSelection().isEmpty());

		// Replace view with .rsrc
		selectTreeNodeByText(tree, ".rsrc", true);
		performAction(replaceView, provider, true);
		assertTrue(getCurrentSelection().isEmpty());
		// Select All Data.
		performAction(selectDataAction, provider, true);
		waitForSwing();
		ProgramSelection rsrcDataSet = getCurrentSelection();
		assertTrue(!rsrcDataSet.isEmpty());
		// Change to program view
		selectTreeNodeByText(tree, "Test", true);
		performAction(replaceView, provider, true);
		ProgramSelection dataSet = getCurrentSelection();
		assertTrue(!dataSet.isEmpty());

		// Select No Undefined.
		performAction(selectUndefinedAction, provider, true);
		waitForSwing();
		assertTrue(getCurrentSelection().isEmpty());

		// Replace view with .rsrc
		selectTreeNodeByText(tree, ".rsrc", true);
		performAction(replaceView, provider, true);
		assertTrue(getCurrentSelection().isEmpty());
		// Select All Undefined.
		performAction(selectUndefinedAction, provider, true);
		waitForSwing();
		ProgramSelection rsrcUndefinedSet = getCurrentSelection();
		assertTrue(!rsrcUndefinedSet.isEmpty());
		// Change to program view
		selectTreeNodeByText(tree, "Test", true);
		performAction(replaceView, provider, true);
		ProgramSelection undefinedSet = getCurrentSelection();
		assertTrue(!undefinedSet.isEmpty());

		// Select No Instructions.
		performAction(selectInstructionAction, provider, true);
		waitForSwing();
		assertTrue(getCurrentSelection().isEmpty());

		// Check that none of the .rsrc sets overlap.
		assertTrue(rsrcInstructionSet.intersect(dataSet).isEmpty());
		assertTrue(rsrcDataSet.intersect(undefinedSet).isEmpty());
		assertTrue(rsrcUndefinedSet.intersect(instructionSet).isEmpty());

		// Check that memory = instructions + data + undefined
		AddressSet rsrcCuSet = new AddressSet();
		rsrcCuSet.add(rsrcInstructionSet);
		rsrcCuSet.add(rsrcDataSet);
		rsrcCuSet.add(rsrcUndefinedSet);
		assertEquals(rsrcSet, rsrcCuSet);

		// Check that none of the sets overlap.
		assertTrue(instructionSet.intersect(dataSet).isEmpty());
		assertTrue(dataSet.intersect(undefinedSet).isEmpty());
		assertTrue(undefinedSet.intersect(instructionSet).isEmpty());

		// Check that memory = instructions + data + undefined
		AddressSet codeUnitSet = new AddressSet();
		codeUnitSet.add(instructionSet);
		codeUnitSet.add(dataSet);
		codeUnitSet.add(undefinedSet);
		assertEquals(new AddressSet(program.getMemory()), codeUnitSet);

		// Check that the expected type of code unit is at each address.
		checkForInstructions(rsrcInstructionSet);
		checkForDefinedData(rsrcDataSet);
		checkForUndefined(rsrcUndefinedSet);

		// Check that the expected type of code unit is at each address.
		checkForInstructions(instructionSet);
		checkForDefinedData(dataSet);
		checkForUndefined(undefinedSet);
	}

	private ProgramSelection getCurrentSelection() {
		return runSwing(() -> cb.getCurrentSelection());
	}

	private void createIMM(long address) throws MemoryAccessException {
		builder.addBytesMoveImmediate(address, (short) 5);
		builder.disassemble(Long.toHexString(address), 2);
	}

	private void createFallThru(long address) throws MemoryAccessException {
		builder.addBytesFallthrough(address);
		builder.disassemble(Long.toHexString(address), 2);
	}

	private void loadProgram(String programName) throws Exception {
		builder = new ToyProgramBuilder("Test", false);
		program = builder.getProgram();

		builder.createMemory(".text", "0x1001000", 0x1000);
		builder.createMemory(".text", "0x1005000", 0x1000);
		builder.createMemory(".rsrc", "0x100a000", 0x5400);

		createFallThru(0x1001010);
		createIMM(0x1001100);
		createFallThru(0x1001150);
		createIMM(0x1001200);
		createFallThru(0x1005f00);
		createIMM(0x1005f3e);
		createFallThru(0x1005f50);
		createIMM(0x1005f41);
		createFallThru(0x1005ff0);

		createFallThru(0x10012d2);

		builder.applyDataType("0x1001300", new ByteDataType());
		builder.applyDataType("0x100a100", new ByteDataType());

		program = builder.getProgram();
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());
		addrFactory = program.getAddressFactory();
	}

	private void setSelection(AddressSetView addrSet) {
		ProgramSelection ps = new ProgramSelection(addrSet);
		ProgramSelectionPluginEvent pspe =
			new ProgramSelectionPluginEvent("Selection", ps, program);
		pt.firePluginEvent(pspe);
	}

	private Address addr(String address) {
		return addrFactory.getAddress(address);
	}

	private void selectTreeNodeByText(final JTree tree, final String text, final boolean wait)
			throws Exception {
		runSwing(() -> {
			TreePath path = findTreePathToText(tree, text);
			if (path == null) {
				throw new RuntimeException("tree path is null.");
			}
			tree.expandPath(path);
		}, wait);

		waitForSwing();

		runSwing(() -> {
			TreePath path = findTreePathToText(tree, text);
			if (path == null) {
				throw new RuntimeException("tree path is null.");
			}
			tree.getSelectionModel().setSelectionPath(path);
		}, wait);
	}

	/**
	 * @param instructionSet
	 */
	private void checkForInstructions(ProgramSelection instructionSet) {
		Listing listing = program.getListing();
		AddressIterator iter = instructionSet.getAddresses(true);
		while (iter.hasNext()) {
			Address addr = iter.next();
			assertNotNull("Expected instruction at " + addr + ".",
				listing.getInstructionContaining(addr));
		}
	}

	/**
	 * @param dataSet
	 */
	private void checkForDefinedData(ProgramSelection dataSet) {
		Listing listing = program.getListing();
		AddressIterator iter = dataSet.getAddresses(true);
		while (iter.hasNext()) {
			Address addr = iter.next();
			assertNotNull("Expected defined data at " + addr + ".",
				listing.getDataContaining(addr));
		}
	}

	/**
	 * @param undefinedSet
	 */
	private void checkForUndefined(ProgramSelection undefinedSet) {
		Listing listing = program.getListing();
		AddressIterator iter = undefinedSet.getAddresses(true);
		while (iter.hasNext()) {
			Address addr = iter.next();
			assertNotNull("Expected undefined at " + addr + ".", listing.getUndefinedDataAt(addr));
		}
	}

}
