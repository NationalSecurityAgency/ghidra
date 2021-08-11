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
package ghidra.app.plugin.core.searchtext;

import static org.junit.Assert.*;

import java.awt.Component;
import java.awt.Container;

import javax.swing.*;

import org.junit.*;

import docking.action.DockingActionIf;
import docking.tool.ToolConstants;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.table.TableServicePlugin;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ProgramLocation;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

public class SearchTextPlugin2Test extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private Program program;
	private SearchTextPlugin plugin;
	private DockingActionIf searchAction;
	private CodeBrowserPlugin cbPlugin;
	private GoToService goToService;
	private SearchTextDialog dialog;
	private JComponent container;
	private CodeViewerProvider provider;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();

		program = buildProgram();
		tool = env.launchDefaultTool(program);

		plugin = env.getPlugin(SearchTextPlugin.class);
		goToService = tool.getService(GoToService.class);

		searchAction = getAction(plugin, "Search Text");
		cbPlugin = env.getPlugin(CodeBrowserPlugin.class);
		provider = cbPlugin.getProvider();
		env.getPlugin(TableServicePlugin.class);

		dialog = getDialog();
		container = dialog.getComponent();
	}

	private Program buildProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("TestX86", ProgramBuilder._X86);
		builder.createMemory(".text", Long.toHexString(0x1001000), 0x6600);
		builder.createMemory(".data", Long.toHexString(0x1008000), 0x600);
		builder.createMemory(".rsrc", Long.toHexString(0x100A000), 0x5400);
		builder.createMemory(".bound_import_table", Long.toHexString(0xF0000248), 0xA8);
		builder.createMemory(".debug_data", Long.toHexString(0xF0001300), 0x1C);
		builder.createComment("0x100415a", "scanf, fscanf, sscanf ...", CodeUnit.PRE_COMMENT);
		//create and disassemble a function

		builder.setBytes("0x0100415a",
			"55 8b ec 83 ec 0c 33 c0 c7 45 f8 01 00 00 00 21 45 fc 39 45 08 c7 45 f4 04" +
				" 00 00 00 74 1a 8d 45 f4 50 8d 45 f8 50 8d 45 fc 50 6a 00 ff 75 0c ff 75 08 " +
				"ff 15 08 10 00 01 85 c0 75 06 83 7d fc 04 74 05 8b 45 10 eb 03 8b 45 f8 c9 " +
				"c2 0c 00");
		builder.disassemble("0x0100415a", 0x4d, true);
		Function function =
			builder.createEmptyFunction("sscanf", "0x0100415a", 77, DataType.DEFAULT);

		builder.createLocalVariable(function, "formatCount", new ByteDataType(), -12);
		builder.createStackReference("100416f", RefType.DATA, -12, SourceType.USER_DEFINED, 0);
		builder.createStackReference("1004178", RefType.DATA, -12, SourceType.USER_DEFINED, 1);

		builder.setBytes("0100448f", "e8 c6 fc ff ff", true);

		builder.createMemoryReference("1001000", "1004000", RefType.COMPUTED_JUMP,
			SourceType.ANALYSIS);
		builder.createMemoryReference("1001000", "1004010", RefType.COMPUTED_JUMP,
			SourceType.ANALYSIS);
		builder.createMemoryReference("1001000", "1004020", RefType.COMPUTED_JUMP,
			SourceType.ANALYSIS);
		builder.createMemoryReference("1001000", "1004030", RefType.COMPUTED_JUMP,
			SourceType.ANALYSIS);
		builder.createMemoryReference("1001000", "1004040", RefType.COMPUTED_JUMP,
			SourceType.ANALYSIS);
		builder.createMemoryReference("1001000", "1004050", RefType.COMPUTED_JUMP,
			SourceType.ANALYSIS);
		builder.createMemoryReference("1001000", "1004060", RefType.COMPUTED_JUMP,
			SourceType.ANALYSIS);
		builder.createMemoryReference("1001000", "1004070", RefType.COMPUTED_JUMP,
			SourceType.ANALYSIS);
		builder.applyDataType("1001000", new PointerDataType());
		builder.applyDataType("1001004", new PointerDataType());
		builder.applyDataType("1001008", new PointerDataType());
		builder.applyDataType("100100c", new PointerDataType());
		builder.applyDataType("1001010", new PointerDataType());
		builder.applyDataType("1001014", new PointerDataType());
		builder.applyDataType("1001018", new PointerDataType());

		builder.setBytes("0x01002cf5",
			"55 8b ec 83 7d 14 00 56 8b 35 e0 10 00 01 57 74 09 ff 75 14 ff d6 8b f8 " +
				"eb 02 33 ff ff 75 10 ff d6 03 c7 8d 44 00 02 50 6a 40 ff 15 dc 10 00 01 8b " +
				"f0 85 f6 74 27 56 ff 75 14 ff 75 10 e8 5c ff ff ff ff 75 18 ff 75 0c 56 ff 75" +
				" 08 ff 15 04 12 00 01 56 8b f8 ff 15 c0 10 00 01 eb 14 ff 75 18 ff 75 0c ff " +
				"10 ff 75 08 ff 15 04 12 00 01 8b f8 8b c7 5f 5e 5d c2 14");
		builder.disassemble("0x01002cf5", 0x121, true);
		ParameterImpl param = new ParameterImpl(null, new WordDataType(), builder.getProgram());
		builder.createEmptyFunction("ghidra", "0x01002cf5", 60, DataType.DEFAULT, param, param,
			param, param);
		return builder.getProgram();
	}

	@After
	public void tearDown() throws Exception {
		env.release(program);
		env.dispose();
	}

	@Test
	public void testRadioButtonEnablement() throws Exception {

		JRadioButton quickRB =
			(JRadioButton) findAbstractButtonByText(container, SearchTextPlugin1Test.QUICK_SEARCH);
		assertNotNull(quickRB);
		assertTrue(quickRB.isSelected());

		JRadioButton exactRB = (JRadioButton) findAbstractButtonByText(container,
			SearchTextPlugin1Test.EXACT_MATCH_SEARCH);
		assertNotNull(exactRB);
		assertFalse(exactRB.isSelected());

		JRadioButton searchFieldsRB =
			(JRadioButton) findAbstractButtonByText(container, "Selected Fields");
		assertTrue(searchFieldsRB.isSelected());
		JCheckBox functionCB = (JCheckBox) findAbstractButtonByText(container, "Functions");
		assertTrue(functionCB.isEnabled());

		JCheckBox commentsCB = (JCheckBox) findAbstractButtonByText(container, "Comments");
		assertTrue(commentsCB.isEnabled());

		JCheckBox labelCB = (JCheckBox) findAbstractButtonByText(container, "Labels");
		assertTrue(labelCB.isEnabled());

		JCheckBox instMnemonicCB =
			(JCheckBox) findAbstractButtonByText(container, "Instruction Mnemonics");
		assertTrue(instMnemonicCB.isEnabled());

		JCheckBox instOpCB =
			(JCheckBox) findAbstractButtonByText(container, "Instruction Operands");
		assertTrue(instOpCB.isEnabled());

		JCheckBox dataMnemonicCB =
			(JCheckBox) findAbstractButtonByText(container, "Defined Data Mnemonics");
		assertTrue(dataMnemonicCB.isEnabled());

		JCheckBox dataOpCB = (JCheckBox) findAbstractButtonByText(container, "Defined Data Values");
		assertTrue(dataOpCB.isEnabled());

		// select "Search All Fields" --> Exact Match Search should be selected

		JRadioButton searchAllRB = (JRadioButton) findAbstractButtonByText(container, "All Fields");
		assertNotNull(searchAllRB);
		assertFalse(searchAllRB.isSelected());
		setSelected(searchAllRB);

		assertTrue(exactRB.isSelected());

		assertFalse(functionCB.isEnabled());
		assertFalse(commentsCB.isEnabled());
		assertFalse(labelCB.isEnabled());
		assertFalse(instMnemonicCB.isEnabled());
		assertFalse(instOpCB.isEnabled());
		assertFalse(dataMnemonicCB.isEnabled());
		assertFalse(dataOpCB.isEnabled());

		// Select Quick Search --> Search Fields is selected
		setSelected(quickRB);

		assertTrue(searchFieldsRB.isSelected());
		assertFalse(searchAllRB.isSelected());

		assertTrue(functionCB.isEnabled());
		assertTrue(commentsCB.isEnabled());
		assertTrue(labelCB.isEnabled());
		assertTrue(instMnemonicCB.isEnabled());
		assertTrue(instOpCB.isEnabled());
		assertTrue(dataMnemonicCB.isEnabled());
		assertTrue(dataOpCB.isEnabled());

		// Select exact match --> search fields should still be selected
		setSelected(exactRB);
		assertTrue(searchFieldsRB.isSelected());

	}

	private void setSelected(JToggleButton button) throws Exception {
		setToggleButtonSelected(button, true);
	}

	private SearchTextDialog getDialog() throws Exception {
		runSwing(() -> searchAction.actionPerformed(provider.getActionContext(null)));
		return plugin.getSearchDialog();
	}

	private Address getAddr(int offset) {
		return program.getMinAddress().getNewAddress(offset);
	}

	@Test
	public void testSaveState() {
		Options options = tool.getOptions("Search");
		options.setInt("Search Limit", 20);
		env.saveRestoreToolState();
		assertEquals(20, plugin.getResultsLimit());
	}

	@Test
	public void testCloseToolDuringSearch() throws Exception {
		closeToolDuringSearch(SearchTextPlugin1Test.EXACT_MATCH_SEARCH);
	}

	@Test
	public void testCloseToolDuringSearchQuick() throws Exception {
		closeToolDuringSearch(SearchTextPlugin1Test.QUICK_SEARCH);
	}

	@Test
	public void testCloseToolDuringSearch2() throws Exception {
		closeToolDuringSearch2(SearchTextPlugin1Test.EXACT_MATCH_SEARCH);
	}

	@Test
	public void testCloseToolDuringSearchQuick2() throws Exception {
		closeToolDuringSearch2(SearchTextPlugin1Test.QUICK_SEARCH);
	}

	@Test
	public void testDismissDuringSearch() throws Exception {
		dismissDuringSearch(SearchTextPlugin1Test.EXACT_MATCH_SEARCH);
	}

	@Test
	public void testDismissDuringSearchQuick() throws Exception {
		dismissDuringSearch(SearchTextPlugin1Test.QUICK_SEARCH);
	}

	@Test
	public void testRemovePluginDuringSearch() throws Exception {
		removePluginDuringSearch(SearchTextPlugin1Test.EXACT_MATCH_SEARCH);
	}

	@Test
	public void testRemovePluginDuringSearchQuick() throws Exception {
		removePluginDuringSearch(SearchTextPlugin1Test.QUICK_SEARCH);
	}

	private void setTextAndPressEnter(JTextField tf, String text) {
		setText(tf, text);
		triggerEnter(tf);
	}

	@Test
	public void testWilcardEntry() throws Exception {

		JTextField tf = findComponent(container, JTextField.class);
		assertNotNull(tf);

		setTextAndPressEnter(tf, "********** entry Exit **********");

		waitForSearchTasks(dialog);

		waitForSwing();
		assertEquals("Not found", dialog.getStatusText());

	}

	@Test
	public void testWilcardEntry2() throws Exception {

		Address addr = getAddr(0x1002d6d);
		int transactionID = program.startTransaction("test");
		CodeUnit cu = program.getListing().getCodeUnitAt(addr);
		try {
			cu.setComment(CodeUnit.POST_COMMENT, "********** my entry Exit **********");
		}
		finally {
			program.endTransaction(transactionID, true);
		}

		JTextField tf = findComponent(container, JTextField.class);
		assertNotNull(tf);

		setTextAndPressEnter(tf, "********** entry Exit **********");

		waitForSearchTasks(dialog);

		waitForSwing();
		cbPlugin.updateNow();
		ProgramLocation loc = cbPlugin.getCurrentLocation();
		assertEquals(addr, loc.getAddress());

		pressSearchButton();

		assertEquals("Not found", dialog.getStatusText());

	}

	@Test
	public void testWilcardEntry3() throws Exception {

		Address addr = getAddr(0x1002d6d);
		int transactionID = program.startTransaction("test");
		CodeUnit cu = program.getListing().getCodeUnitAt(addr);
		try {
			cu.setComment(CodeUnit.POST_COMMENT, "********** ___sbh_find_block Exit **********");
		}
		finally {
			program.endTransaction(transactionID, true);
		}

		JTextField tf = findComponent(container, JTextField.class);
		assertNotNull(tf);
		setTextAndPressEnter(tf, "********** Exit **********");

		waitForSearchTasks(dialog);

		waitForSwing();
		cbPlugin.updateNow();
		ProgramLocation loc = cbPlugin.getCurrentLocation();
		assertEquals(addr, loc.getAddress());

		pressSearchButton();

		assertEquals("Not found", dialog.getStatusText());
	}

	@Test
	public void testWilcardEntry4() throws Exception {

		Address addr = getAddr(0x1002d6d);
		int transactionID = program.startTransaction("test");
		CodeUnit cu = program.getListing().getCodeUnitAt(addr);
		try {
			cu.setComment(CodeUnit.POST_COMMENT, "********** ___sbh_find_block Exit **********");
		}
		finally {
			program.endTransaction(transactionID, true);
		}

		JTextField tf = findComponent(container, JTextField.class);
		assertNotNull(tf);
		setTextAndPressEnter(tf, "*Ex**t**********");

		waitForSearchTasks(dialog);
		waitForSwing();
		cbPlugin.updateNow();
		ProgramLocation loc = cbPlugin.getCurrentLocation();
		assertEquals(addr, loc.getAddress());
	}

	@Test
	public void testEscapingWildcardCharacter() throws Exception {
		ProgramLocation startLocation = cbPlugin.getCurrentLocation();

		// set a comment to contain an asterisk
		Address addr = getAddr(0x1002d6d);
		int transactionID = program.startTransaction("test");
		CodeUnit cu = program.getListing().getCodeUnitAt(addr);
		try {
			cu.setComment(CodeUnit.POST_COMMENT, "Comment test * with an asterisk");
		}
		finally {
			program.endTransaction(transactionID, true);
		}

		// search with an escaped asterisk and make sure a hit is found
		JTextField tf = findComponent(container, JTextField.class);
		assertNotNull(tf);
		setTextAndPressEnter(tf, "\\*");

		waitForSearchTasks(dialog);

		waitForSwing();
		cbPlugin.updateNow();
		ProgramLocation loc = cbPlugin.getCurrentLocation();
		assertEquals(addr, loc.getAddress());

		cbPlugin.goTo(startLocation);

		setTextAndPressEnter(tf, "test*\\*");

		waitForSearchTasks(dialog);

		waitForSwing();
		cbPlugin.updateNow();
		loc = cbPlugin.getCurrentLocation();
		assertEquals(addr, loc.getAddress());

		cbPlugin.goTo(startLocation);

		// make sure that searching for multiple asterisks does not find a match
		setTextAndPressEnter(tf, "test*\\*\\*");

		waitForSearchTasks(dialog);

		waitForSwing();
		cbPlugin.updateNow();
		loc = cbPlugin.getCurrentLocation();
		assertFalse((addr.equals(loc.getAddress())));
	}

	@Test
	public void testInvalidWildCardEntry() throws Exception {

		JTextField tf = findComponent(container, JTextField.class);
		assertNotNull(tf);
		setTextAndPressEnter(tf, "********************");

		waitForSearchTasks(dialog);

		waitForSwing();
		assertEquals("Pattern must contain a non-wildcard character.", dialog.getStatusText());

	}

	private void pressSearchButton() throws InterruptedException {
		JButton searchButton = findButtonByText(container, "Next");
		pressButton(searchButton);

		waitForSearchTasks(dialog);
		cbPlugin.updateNow();
	}

	private void dismissDuringSearch(String buttonText) throws Exception {

		SearchTextDialog tempDialog = getDialog();
		JComponent tempContainer = tempDialog.getComponent();
		selectRadioButton(tempContainer, buttonText);

		JTextField tf = findTextField(tempContainer);

		JButton dismissButton = (JButton) findButton(tempContainer, "Dismiss");

		JCheckBox cb = (JCheckBox) findButton(tempContainer, "Functions");
		setSelected(cb);

		cb = (JCheckBox) findButton(tempContainer, "Labels");
		setSelected(cb);

		cb = (JCheckBox) findButton(tempContainer, "Instruction Mnemonics");
		setSelected(cb);

		cb = (JCheckBox) findButton(tempContainer, "Instruction Operands");
		setSelected(cb);

		cb = (JCheckBox) findButton(tempContainer, "Defined Data Mnemonics");
		setSelected(cb);

		cb = (JCheckBox) findButton(tempContainer, "Defined Data Values");
		setSelected(cb);

		setTextAndPressEnter(tf, "hello");

		runSwing(() -> dismissButton.getActionListeners()[0].actionPerformed(null));
		waitForSearchTasks(tempDialog);
		assertFalse(tempDialog.isVisible());
	}

	private AbstractButton findButton(Container guiContainer, String text) {
		Component[] comp = guiContainer.getComponents();
		for (Component element : comp) {
			if ((element instanceof AbstractButton) &&
				((AbstractButton) element).getText().equals(text)) {
				return (AbstractButton) element;
			}
			else if (element instanceof Container) {
				AbstractButton b = findButton((Container) element, text);
				if (b != null) {
					return b;
				}
			}
		}
		return null;
	}

	private JTextField findTextField(Container guiContainer) {
		Component[] c = guiContainer.getComponents();
		for (Component element : c) {
			if (element instanceof JTextField) {
				return (JTextField) element;
			}
			if (element instanceof Container) {
				JTextField tf = findTextField((Container) element);
				if (tf != null) {
					return tf;
				}
			}
		}
		return null;
	}

	private void removePluginDuringSearch(String buttonText) throws Exception {

		SearchTextDialog tempDialog = getDialog();
		JComponent tempContainer = tempDialog.getComponent();
		JTextField tf = findTextField(tempContainer);
		selectRadioButton(tempContainer, buttonText);

		JCheckBox cb = (JCheckBox) findButton(tempContainer, "Functions");
		setSelected(cb);

		cb = (JCheckBox) findButton(tempContainer, "Labels");
		setSelected(cb);

		cb = (JCheckBox) findButton(tempContainer, "Instruction Mnemonics");
		setSelected(cb);

		cb = (JCheckBox) findButton(tempContainer, "Instruction Operands");
		setSelected(cb);

		cb = (JCheckBox) findButton(tempContainer, "Defined Data Mnemonics");
		setSelected(cb);

		cb = (JCheckBox) findButton(tempContainer, "Defined Data Values");
		setSelected(cb);

		setTextAndPressEnter(tf, "hello");

		runSwing(() -> tool.removePlugins(new Plugin[] { plugin }));
		assertFalse(tempDialog.isVisible());
	}

	private void closeToolDuringSearch(String buttonText) throws Exception {

		SearchTextDialog tempDialog = getDialog();
		JComponent tempContainer = tempDialog.getComponent();
		JTextField tf = findTextField(tempContainer);
		selectRadioButton(tempContainer, buttonText);

		JCheckBox cb = (JCheckBox) findButton(tempContainer, "Functions");
		setSelected(cb);

		cb = (JCheckBox) findButton(tempContainer, "Labels");
		setSelected(cb);

		cb = (JCheckBox) findButton(tempContainer, "Instruction Mnemonics");
		setSelected(cb);

		cb = (JCheckBox) findButton(tempContainer, "Instruction Operands");
		setSelected(cb);

		cb = (JCheckBox) findButton(tempContainer, "Defined Data Mnemonics");
		setSelected(cb);

		cb = (JCheckBox) findButton(tempContainer, "Defined Data Values");
		setSelected(cb);

		setTextAndPressEnter(tf, "hello");

		env.restartTool();

		waitForSearchTasks(tempDialog);
		assertFalse(tempDialog.isVisible());
	}

	private void closeToolDuringSearch2(String buttonText) throws Exception {
		SearchTextDialog tempDialog = getDialog();
		JComponent tempContainer = tempDialog.getComponent();
		JTextField tf = findTextField(tempContainer);
		selectRadioButton(tempContainer, buttonText);

		JCheckBox cb = (JCheckBox) findButton(tempContainer, "Functions");
		setSelected(cb);

		cb = (JCheckBox) findButton(tempContainer, "Labels");
		setSelected(cb);

		cb = (JCheckBox) findButton(tempContainer, "Instruction Mnemonics");
		setSelected(cb);

		cb = (JCheckBox) findButton(tempContainer, "Instruction Operands");
		setSelected(cb);

		cb = (JCheckBox) findButton(tempContainer, "Defined Data Mnemonics");
		setSelected(cb);

		cb = (JCheckBox) findButton(tempContainer, "Defined Data Values");
		setSelected(cb);

		goToService.goTo(new ProgramLocation(program, getAddr(0x01002c92)));

		Options options = tool.getOptions(ToolConstants.TOOL_OPTIONS);
		options.setInt("Search Limit", 20);

		setTextAndPressEnter(tf, "eax");

		waitForSearchTasks(tempDialog);

		ProgramManager pm = tool.getService(ProgramManager.class);
		runSwing(() -> pm.closeProgram(), true);
		env.restartTool();

		waitForSearchTasks(tempDialog);
		waitForSwing();
		assertFalse(tempDialog.isVisible());

		assertFalse(isEnabled(searchAction));
	}

	private void waitForSearchTasks(SearchTextDialog dialog1) throws InterruptedException {
		waitForSwing();
		Thread t = dialog1.getTaskScheduler().getCurrentThread();
		if (t == null) {
			// just in case we missed the thread and the callback hasn't happened yet
			waitForSwing();
			t = dialog1.getTaskScheduler().getCurrentThread();
		}

		while (t != null) {
			t.join();
			waitForSwing();
			t = dialog1.getTaskScheduler().getCurrentThread();
		}
		waitForSwing();
	}

	private void selectRadioButton(Container guiContainer, String buttonText) throws Exception {
		JRadioButton rb = (JRadioButton) findButton(guiContainer, buttonText);
		runSwing(() -> rb.setSelected(true), true);
	}

}
