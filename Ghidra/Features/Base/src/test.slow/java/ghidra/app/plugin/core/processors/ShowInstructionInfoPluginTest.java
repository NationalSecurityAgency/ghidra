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
package ghidra.app.plugin.core.processors;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.*;

import org.junit.*;

import docking.ComponentProvider;
import docking.DialogComponentProvider;
import docking.action.DockingActionIf;
import ghidra.app.context.ListingActionContext;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.disassembler.DisassemblerPlugin;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.util.AddressFieldLocation;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.ManualEntry;

/**
 * Tests the {@link ShowInstructionInfoPlugin} class.
 * 
 * 
 */
public class ShowInstructionInfoPluginTest extends AbstractGhidraHeadedIntegrationTest {
	private static final String startAddressString = "1000000";
	private static final String beyondAddressString = "100000a";
	private static final byte[] BYTES =
		new byte[] { (byte) 0xff, 0x15, 0x10, 0x32, 0x00, 0x01, (byte) 0xff, 0x75, 0x14, 0x5f };

	private TestEnv env;
	private PluginTool tool;
	private ProgramBuilder builder;
	private Program program;
	private ShowInstructionInfoPlugin plugin;
	private CodeBrowserPlugin cb;

	@Before
	public void setUp() throws Exception {

		env = new TestEnv();
		tool = env.getTool();
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(DisassemblerPlugin.class.getName());
		tool.addPlugin(ShowInstructionInfoPlugin.class.getName());

		plugin = env.getPlugin(ShowInstructionInfoPlugin.class);
		cb = env.getPlugin(CodeBrowserPlugin.class);
		env.showTool();

		builder = new ProgramBuilder("test", ProgramBuilder._X86);
		builder.createMemory(".text", startAddressString, 0x1000);
		builder.setBytes(startAddressString, BYTES);
		builder.disassemble(startAddressString, BYTES.length);
		program = builder.getProgram();
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testGetProcessorManualEntry() throws Exception {

		changeLocationToAddress(beyondAddressString);

		ManualEntry manualEntry = plugin.locateManualEntry(null, null);
		assertNull(manualEntry);

		ListingActionContext context = getCurrentContext();
		Instruction currentInstruction = plugin.getInstructionForContext(context);
		assertNull("The current Instruction is not null as expected", currentInstruction);

		// now try the calling the method with an invalid Instruction - 
		Language language = program.getLanguage();
		manualEntry = plugin.locateManualEntry(context, language);
		assertNotNull(manualEntry);
		assertNull(manualEntry.getPageNumber()); // default entry has no page number

		// now move to a valid Instruction to test that condition
		currentInstruction = changeLocationToAddress("01000000");
		assertNotNull("Found a null Instruction at a point in the program " +
			"where we expected a valid Instruction.", currentInstruction);

		// now try the calling the method with an valid Instruction
		context = getCurrentContext();
		manualEntry = plugin.locateManualEntry(context, language);
		assertNotNull(manualEntry);
		assertNotNull(manualEntry.getPageNumber());
	}

//	@Test
	public void testShowProcessorManual_ErrorDialog() throws Exception {

		// FIXME: This test is bogus and needs to be corrected by refering to
		// an instruction whose manual is missing.  Test apepars to work with 
		// CI test environment because none of the manuals are found

		changeLocationToAddress(beyondAddressString);

		Language language = program.getLanguage();
		ListingActionContext context = getCurrentContext();
		context = getCurrentContext();
		callGetUrl(context, language);
		DialogComponentProvider dialog = waitForDialogComponent("Missing Processor Manual");
		close(dialog);
	}

	@Test
	public void testInstructionInfo() throws Exception {
		// test the models to make sure no errors are encountered on valid 
		// and invalid instructions by exercising the Java model's public
		// API

		changeLocationToAddress(beyondAddressString);

		// get the action that will show the window for the Instruction info
		DockingActionIf infoAction = getAction(plugin, "Show Instruction Info");
		// show the window
		performAction(infoAction, cb.getProvider(), true);

		// make sure we are at an invalid Instruction
		ListingActionContext context = getCurrentContext();
		Instruction currentInstruction =
			(Instruction) invokeInstanceMethod("getInstructionForContext", plugin,
				new Class[] { ListingActionContext.class }, new Object[] { context });
		// make sure that the current instruction is null
		assertNull("The current Instruction is not null as expected.", currentInstruction);
		assertTrue(
			"The tables of the component provider have data even " +
				"though there is not Instruction selected in the proram.",
			!componentProviderTablesHaveData());

		// change to a valid instruction        
		currentInstruction = changeLocationToAddress("01000000");
		assertNotNull("Found a null Instruction at a point in the program " +
			"where we expected a valid Instruction.", currentInstruction);

		// make sure that there is some data
		Object[] data = getComponentProviderTableData(true);
		assertTrue(
			"There is not data in the component provider " +
				"even though there is a valid instruction selected in the " + "program",
			componentProviderTablesHaveData());

		// verify dynamic update has changed the window's contents
		ComponentProvider componentProvider = getCurrentComponentProviderFromPlugin();
		JComponent comp = componentProvider.getComponent();

		final JCheckBox dynamicCheckBox = findComponent(comp, JCheckBox.class);
		// make sure dynamic update is enabled
		if (!dynamicCheckBox.isSelected()) {
			runSwing(() -> dynamicCheckBox.doClick());
		}

		// change to another valid Instruction
		currentInstruction = changeLocationToAddress("01000006");
		assertNotNull("Found a null Instruction at a point in the program " +
			"where we expected a valid Instruction.", currentInstruction);

		Object[] newData = getComponentProviderTableData(true);
		boolean differentData = !(data[0].equals(newData[0]) && data[1].equals(newData[1]));
		assertTrue("The data of the component provider is not different " +
			"than it was after changing instructions.", differentData);

		// verify the Instruction data is that of the Instruction
		// selected in the plugin            
		verifyAddressWithTableModels(currentInstruction.getMinAddress(), true, true);

		// turn off dynamic update
		runSwing(() -> dynamicCheckBox.doClick());

		// change to another valid Instruction
		currentInstruction = changeLocationToAddress("01000009");
		assertNotNull("Found a null Instruction at a point in the program " +
			"where we expected a valid Instruction.", currentInstruction);

		// verify that the contents have NOT changed
		Object[] newData2 = getComponentProviderTableData(false);
		differentData = data[0].equals(newData2[0]) && data[1].equals(newData2[1]);
		assertTrue("The data of the component provider is different " +
			"than it was after changing instructions even though dynamic " + "update is disabled.",
			!differentData);

		// verify the Instruction data is NOT that of the Instruction
		// selected in the plugin
		verifyAddressWithTableModels(currentInstruction.getMinAddress(), false, false);

		// Now test moving from a valid, non-decompiled address will cause
		// the update of the display when the decompilation process takes 
		// place

		// turn dynamic update back on
		runSwing(() -> dynamicCheckBox.doClick());

		// move to a valid location that has yet to be disassembled
		currentInstruction = changeLocationToAddress("01000ffe");
		assertNull("The current Instruction is not null when the selected " +
			"program address has not been disassembled.", currentInstruction);

		// make sure there are no contents in the display
		assertTrue(
			"The tables of the component provider have data even " +
				"though there is not Instruction selected in the proram.",
			!componentProviderTablesHaveData());

		// decompile at the location
		Plugin disassemblePlugin = env.getPlugin(DisassemblerPlugin.class);
		DockingActionIf disassembleAction = getAction(disassemblePlugin, "Disassemble");
		performAction(disassembleAction, cb.getProvider(), false);
		waitForBusyTool(tool);
		waitForTasks();
		waitForProgram(program);

		currentInstruction = changeLocationToAddress("01000ffe");
		assertNotNull("Found a null Instruction at a point in the program " +
			"where we expected a valid Instruction.", currentInstruction);

		// make sure that the contents now display the current Instruction
		assertTrue("There is not data in the component provider even " +
			"though there is a valid instruction selected in the " + "program after we decompile.",
			componentProviderTablesHaveData());

		currentInstruction = changeLocationToAddress("01000ffe");
		context = getCurrentContext();
		// verify the Instruction data is that of the Instruction
		// selected in the plugin
		currentInstruction = (Instruction) invokeInstanceMethod("getInstructionForContext", plugin,
			new Class[] { ListingActionContext.class }, new Object[] { context });
	}

	@Test
	public void testCloseProgram() throws Exception {
		changeLocationToAddress("01000000");

		// get the action that will show the window for the Instruction info
		DockingActionIf infoAction = getAction(plugin, "Show Instruction Info");
		// show the window
		performAction(infoAction, cb.getProvider(), true);

		ComponentProvider componentProvider = getCurrentComponentProviderFromPlugin();
		JComponent comp = componentProvider.getComponent();

		final JCheckBox dynamicCheckBox = findComponent(comp, JCheckBox.class);
		// turn off the checkbox
		runSwing(() -> dynamicCheckBox.setSelected(false));

		changeLocationToAddress("01000006");
		performAction(infoAction, cb.getProvider(), true);

		List<?> list = getDisconnectedProviderList();
		assertEquals(1, list.size());
		assertNotNull(getCurrentComponentProviderFromPlugin());

		final ProgramManager pm = tool.getService(ProgramManager.class);
		runSwing(() -> pm.closeProgram());
		list = getDisconnectedProviderList();
		//should only be the dynamic provider left
		assertEquals(0, list.size());
	}

	@Test
	public void testUpdates() throws Exception {
		// display a provider, clear the instruction, 
		// make sure the the provider is cleared, etc. 

		changeLocationToAddress("01000000");

		// get the action that will show the window for the Instruction info
		DockingActionIf infoAction = getAction(plugin, "Show Instruction Info");
		// show the window
		performAction(infoAction, cb.getProvider(), true);
		ComponentProvider provider = getCurrentComponentProviderFromPlugin();

		clearAt100000();

		assertNull(((InstructionInfoProvider) provider).getInstruction());
		assertTrue(!componentProviderTablesHaveData());
	}

	private void clearAt100000() {
		int transactionID = program.startTransaction("Test");
		Address start = addr(0x01000000);
		Instruction inst = program.getListing().getInstructionAt(start);
		try {
			program.getListing().clearCodeUnits(start, inst.getMaxAddress(), false);
		}
		finally {
			program.endTransaction(transactionID, true);
		}

		waitForProgram(program);
	}

	@Test
	public void testUndoRedo() throws Exception {
		String addrString = "01000000";
		changeLocationToAddress(addrString);

		// get the action that will show the window for the Instruction info
		DockingActionIf infoAction = getAction(plugin, "Show Instruction Info");
		// show the window
		performAction(infoAction, cb.getProvider(), true);
		ComponentProvider provider = getCurrentComponentProviderFromPlugin();

		clearAt100000();
		assertNull(((InstructionInfoProvider) provider).getInstruction());

		// undo
		undo(program);

		verifyAddressWithTableModels(addr(0x1000000), true, true);

		// redo
		redo(program);

		assertNull(((InstructionInfoProvider) provider).getInstruction());
		assertTrue(!componentProviderTablesHaveData());
	}

	private void callGetUrl(ListingActionContext context, Language language) {
		runSwing(() -> {
	
			try {
				plugin.getValidUrl(context, language);
			}
			catch (IOException e) {
				throw new RuntimeException(e);
			}
		}, false);
	}

	/**
	 * Moves the program location to the given address and returns the 
	 * instruction at that location.
	 * 
	 * @param addressString The address location to move to.
	 * @return The instruction at the new location or null if there is no
	 *         instruction.
	 */
	private Instruction changeLocationToAddress(String addressString) throws Exception {
		CodeBrowserPlugin cbp = env.getPlugin(CodeBrowserPlugin.class);
		final Address address = program.getAddressFactory().getAddress(addressString);
		final GoToService goToService = tool.getService(GoToService.class);
		runSwing(() -> goToService.goTo(new AddressFieldLocation(program, address)));

		waitForPostedSwingRunnables();
		cbp.updateNow();

		ListingActionContext context =
			(ListingActionContext) cbp.getProvider().getActionContext(null);
		return (Instruction) invokeInstanceMethod("getInstructionForContext", plugin,
			new Class[] { ListingActionContext.class }, new Object[] { context });
	}

	private ListingActionContext getCurrentContext() {
		CodeBrowserPlugin cbp = env.getPlugin(CodeBrowserPlugin.class);
		return (ListingActionContext) cbp.getProvider().getActionContext(null);
	}

	private Address addr(long offset) {
		return program.getMinAddress().getNewAddress(offset);
	}

	/**
	 * Tests the addresses of the table models of the "Instruction Info" dialog.
	 * The method will fail the current test if the result is not as 
	 * expected by the caller of this method.  For example, if 
	 * <tt>expectedSame</tt> is true, then the method expects the values to
	 * be the same when compared with the given address and will fail if 
	 * they are not.  If <tt>expectedSame</tt> is false, then the method will
	 * fail if the test values are the same.
	 * 
	 * @param instructionAddress The address to compare against the address
	 *        stored in the table model of the dialog.
	 * @param expectedSame True means a match is expected; false means a 
	 *        match is not expected.
	 */
	private void verifyAddressWithTableModels(Address instructionAddress, boolean fromConnected,
			boolean expectedSame) {
		ComponentProvider provider = fromConnected ? getCurrentComponentProviderFromPlugin()
				: getFirstDisconnectedProviderFromPlugin();

		JTextArea instructionText = (JTextArea) getInstanceField("instructionText", provider);
		JTable opTable = (JTable) getInstanceField("opTable", provider);

		// get the instruction address from each table model and make sure that
		// it is the same as the current instruction
		String stateString = expectedSame ? "is not" : "is";
		String text = instructionText.getText();

		String address = instructionAddress.toString(true);
		Pattern pattern = Pattern.compile("Address\\s*:\\s*" + address);
		Matcher matcher = pattern.matcher(text);
		boolean comparisonResult = matcher.find();

		// if the caller of this method expects the results to be NOT equal, 
		// then toggle the comparison result
		if (!expectedSame) {
			comparisonResult = !comparisonResult;
		}

		assertTrue("The address of the mnemonic table " + stateString +
			" the same as that of the current program instruction.", comparisonResult);

		Instruction opInstr = (Instruction) getInstanceField("instruction", opTable.getModel());
		comparisonResult = instructionAddress.equals(opInstr.getMinAddress());

		if (!expectedSame) {
			comparisonResult = !comparisonResult;
		}

		assertTrue("The address of the op table " + stateString +
			" the same as that of the current program instruction.", comparisonResult);
	}

	/**
	 * A simple method to test that the tables of the "Instruction Info"
	 * dialog contain data.
	 * 
	 * @return True if either of the tables have data.
	 */
	private boolean componentProviderTablesHaveData() {
		Object[] data = getComponentProviderTableData(true);

		return ((data[0] != null) && !"-- No Instruction --".equals(data[0])) || (data[1] != null);
	}

	/**
	 * Gets data from the two tables of the "Instruction Info" dialog. 
	 * 
	 * @return data from the two tables of the "Instruction Info" dialog. 
	 */
	private Object[] getComponentProviderTableData(boolean fromConnected) {
		ComponentProvider provider = fromConnected ? getCurrentComponentProviderFromPlugin()
				: getFirstDisconnectedProviderFromPlugin();

		JTextArea instructionText = (JTextArea) getInstanceField("instructionText", provider);
		JTable opTable = (JTable) getInstanceField("opTable", provider);

		Object[] data = new Object[2];

		// the following two values are based upon the objString() method of 
		// each table model
		data[0] = instructionText.getText();
		data[1] = opTable.getColumnCount() != 0 ? opTable.getValueAt(6, 0) : null;

		return data;
	}

	private ComponentProvider getFirstDisconnectedProviderFromPlugin() {
		List<?> disconnectedProviderList = getDisconnectedProviderList();
		return (ComponentProvider) disconnectedProviderList.get(0);
	}

	/**
	 * Returns the current ComponentProvider in use by the plugin.
	 * 
	 * @return the current ComponentProvider in use by the plugin.
	 */
	private ComponentProvider getCurrentComponentProviderFromPlugin() {

		return (ComponentProvider) getInstanceField("connectedProvider", plugin);
	}

	private List<?> getDisconnectedProviderList() {
		return (List<?>) getInstanceField("disconnectedProviders", plugin);
	}
}
