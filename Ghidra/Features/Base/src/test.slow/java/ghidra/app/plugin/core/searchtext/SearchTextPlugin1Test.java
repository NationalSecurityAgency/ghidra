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
import java.awt.event.*;
import java.lang.reflect.InvocationTargetException;
import java.util.Date;
import java.util.Random;

import javax.swing.*;

import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.tool.ToolConstants;
import docking.widgets.OkDialog;
import docking.widgets.table.GTable;
import docking.widgets.table.threaded.GThreadedTablePanel;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.marker.MarkerManagerPlugin;
import ghidra.app.plugin.core.programtree.ProgramTreePlugin;
import ghidra.app.plugin.core.table.TableComponentProvider;
import ghidra.app.plugin.core.table.TableServicePlugin;
import ghidra.app.services.*;
import ghidra.app.util.viewer.field.VariableTypeFieldFactory;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.PreviewTableCellData;
import ghidra.util.table.field.*;

/**
 * Tests for the search text plugin.
 */
public class SearchTextPlugin1Test extends AbstractGhidraHeadedIntegrationTest {

	final static String QUICK_SEARCH = "Program Database";
	final static String EXACT_MATCH_SEARCH = "Listing Display";

	private TestEnv env;
	private PluginTool tool;
	private Program program;
	private SearchTextPlugin plugin;
	private DockingActionIf searchAction;
	private Listing listing;
	private CodeBrowserPlugin cbPlugin;
	private CodeViewerProvider provider;
	private TableServicePlugin tableServicePlugin;
	private GoToService goToService;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		tool.addPlugin(ProgramTreePlugin.class.getName());
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(SearchTextPlugin.class.getName());
		tool.addPlugin(MarkerManagerPlugin.class.getName());
		plugin = env.getPlugin(SearchTextPlugin.class);

		goToService = tool.getService(GoToService.class);

		program = buildProgram();
		listing = program.getListing();

		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());

		searchAction = getAction(plugin, "Search Text");
		cbPlugin = env.getPlugin(CodeBrowserPlugin.class);
		provider = cbPlugin.getProvider();

		tableServicePlugin = env.getPlugin(TableServicePlugin.class);
		env.showTool();
	}

	private Program buildProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("TestX86", ProgramBuilder._X86);
		builder.createMemory(".text", Long.toHexString(0x1001000), 0x6600);
		builder.createMemory(".data", Long.toHexString(0x1008000), 0x600);
		builder.createMemory(".rsrc", Long.toHexString(0x100A000), 0x5400);
		builder.createMemory(".bound_import_table", Long.toHexString(0xF0000248), 0xA8);
		builder.createMemory(".debug_data", Long.toHexString(0xF0001300), 0x1C);
		builder.createOverlayMemory("otherOverlay", "OTHER:0", 100);

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
				" 08 ff 15 04 12 00 01 56 8b f8 ff 15 c0 10 00 01 eb 14 ff 75 18 ff 75 0c ff 75" +
				"10 ff 75 08 ff 15 04 12 00 01 8b f8 8b c7 5f 5e 5d c2 14");
		builder.disassemble("0x01002cf5", 0x121, true);
		ParameterImpl param = new ParameterImpl(null, new WordDataType(), builder.getProgram());
		builder.createEmptyFunction("ghidra", "0x01002cf5", 60, DataType.DEFAULT, param, param,
			param, param);

		builder.createComment("otherOverlay:4", "This is a comment in the other overlay",
			CodeUnit.EOL_COMMENT);
		return builder.getProgram();
	}

	@After
	public void tearDown() throws Exception {
		env.release(program);
		env.dispose();
	}

	@Test
	public void testDisplayDialog() throws Exception {
		assertTrue(searchAction.isEnabledForContext(provider.getActionContext(null)));

		SearchTextDialog dialog = getDialog();

		// verify that the comments checkbox is selected
		JCheckBox commentsCB = (JCheckBox) findButton(dialog.getComponent(), "Comments");
		assertNotNull(commentsCB);
		assertSelected(commentsCB);

		// verify that the case sensitive checkbox is not selected				
		JCheckBox csCB = (JCheckBox) findButton(dialog.getComponent(), "Case Sensitive");
		assertNotNull(csCB);
		assertNotSelected(csCB);

		JCheckBox cb = (JCheckBox) findButton(dialog.getComponent(), "Search Selection");
		assertNotEnabled(cb);
		assertNotSelected(cb);
	}

	private void assertSelected(JCheckBox cb) {
		assertTrue(runSwing(() -> cb.isSelected()));
	}

	private void assertEnabled(JCheckBox cb) {
		assertTrue(runSwing(() -> cb.isSelected()));
	}

	private void assertNotSelected(JCheckBox cb) {
		assertFalse(runSwing(() -> cb.isSelected()));
	}

	private void assertNotEnabled(JCheckBox cb) {
		assertFalse(runSwing(() -> cb.isEnabled()));
	}

	@Test
	public void testSearchOptions() throws Exception {
		// verify that the search dialog allows for searching Functions,
		// Comments, labels, instruction mnemonics and operands, defined data 
		// mnemonics and values.
		SearchTextDialog dialog = getDialog();
		JCheckBox cb = (JCheckBox) findButton(dialog.getComponent(), "Functions");
		assertNotNull(cb);

		cb = (JCheckBox) findButton(dialog.getComponent(), "Labels");
		assertNotNull(cb);

		cb = (JCheckBox) findButton(dialog.getComponent(), "Instruction Mnemonics");
		assertNotNull(cb);

		cb = (JCheckBox) findButton(dialog.getComponent(), "Instruction Operands");
		assertNotNull(cb);

		cb = (JCheckBox) findButton(dialog.getComponent(), "Defined Data Mnemonics");
		assertNotNull(cb);

		cb = (JCheckBox) findButton(dialog.getComponent(), "Defined Data Values");
		assertNotNull(cb);

	}

	@Test
	public void testSearchStringEntry() throws Exception {
		// verify that a string string must be entered

		SearchTextDialog dialog = getDialog();

		JButton searchButton = (JButton) findButton(dialog.getComponent(), "Next");
		pressButton(searchButton);
		String status = dialog.getStatusText();
		assertTrue(status.length() > 1);

		final JTextField tf = findTextField(dialog.getComponent());
		runSwing(() -> {
			KeyListener[] kl = tf.getKeyListeners();
			kl[0].keyPressed(new KeyEvent(tf, 0, new Date().getTime(), 0, KeyEvent.VK_B, 'b'));
		});
		status = dialog.getStatusText();
		assertTrue(status.length() <= 1);
	}

	@Test
	public void testProgramLocationChanges() throws Exception {
		programLocationChange(EXACT_MATCH_SEARCH);
	}

	@Test
	public void testProgramLocationChangesQuick() throws Exception {
		programLocationChange(QUICK_SEARCH);
	}

	@Test
	public void testProgramLocationChanges2() throws Exception {
		programLocationChange2(EXACT_MATCH_SEARCH);
	}

	@Test
	public void testProgramLocationChanges2Quick() throws Exception {
		programLocationChange2(QUICK_SEARCH);
	}

	@Test
	public void testSearchBackward() throws Exception {
		searchBackward(EXACT_MATCH_SEARCH);
	}

	@Test
	public void testSearchBackwardQuick() throws Exception {
		searchBackward(QUICK_SEARCH);
	}

	@Test
	public void testSearchBackwardSameField() throws Exception {
		searchBackwardSameField(EXACT_MATCH_SEARCH);
	}

	@Test
	public void testSearchBackwardSameFieldQuick() throws Exception {
		searchBackwardSameField(QUICK_SEARCH);
	}

	@Test
	public void testCaseSensitive() throws Exception {
		setCaseSensitive(EXACT_MATCH_SEARCH);
	}

	@Test
	public void testCaseSensitiveQuick() throws Exception {
		setCaseSensitive(QUICK_SEARCH);
	}

	@Test
	public void testSearchAll() throws Exception {
		searchAll(EXACT_MATCH_SEARCH, "Exact Match");
	}

	@Test
	public void testSearchAllQuick() throws Exception {
		searchAll(QUICK_SEARCH, "Quick");
	}

	@Test
	public void testPreview() throws Exception {
		searchAllForPreview(EXACT_MATCH_SEARCH);
	}

	@Test
	public void testPreviewQuick() throws Exception {
		searchAllForPreview(QUICK_SEARCH);
	}

	@Test
	public void testPreview2() throws Exception {
		searchAllForPreview2(EXACT_MATCH_SEARCH);
	}

	@Test
	public void testPreview2Quick() throws Exception {
		searchAllForPreview2(QUICK_SEARCH);
	}

	@Test
	public void testSearchSelection() throws Exception {
		searchSelection(EXACT_MATCH_SEARCH);
	}

	@Test
	public void testSearchSelectionQuick() throws Exception {
		searchSelection(QUICK_SEARCH);
	}

	@Test
	public void testSearchSelectionInFunction() throws Exception {
		searchSelectionInFunction(EXACT_MATCH_SEARCH);
	}

	@Test
	public void testSearchSelectionInFunctionQuick() throws Exception {
		searchSelectionInFunction(QUICK_SEARCH);
	}

	@Test
	public void testOtherBlock() throws Exception {
		searchInOtherBlock(EXACT_MATCH_SEARCH);
	}

	@Test
	public void testOtherBlockQuick() throws Exception {
		searchInOtherBlock(QUICK_SEARCH);
	}

	private void programLocationChange(String buttonText) throws Exception {
		// create Plate, pre, end of line, post and repeatable comments
		// that contain a hit for a search

		CodeUnit cu = listing.getCodeUnitAt(getAddr(0x0100416f));
		int transactionID = program.startTransaction("test");
		cu.setComment(CodeUnit.EOL_COMMENT, "call sscanf");

		cu = listing.getCodeUnitAt(getAddr(0x01004178));
		cu.setComment(CodeUnit.REPEATABLE_COMMENT, "make a reference to sscanf");

		cu = listing.getCodeUnitAt(getAddr(0x01004192));
		cu.setComment(CodeUnit.PLATE_COMMENT, "another ref to sscanf");
		cu.setComment(CodeUnit.POST_COMMENT, "sscanf in a post comment");

		cu = listing.getCodeUnitAt(getAddr(0x0100467b));
		cu.setComment(CodeUnit.PRE_COMMENT, "call sscanf here");

		program.endTransaction(transactionID, true);

		SearchTextDialog dialog = getDialog();
		JTextField tf = findTextField(dialog.getComponent());
		selectRadioButton(dialog.getComponent(), buttonText);

		goToService.goTo(new ProgramLocation(program, getAddr(0x01004160)));

		setText(tf, "sscanf");
		searchOnce(tf);
		waitForSearchTasks(dialog);

		ProgramLocation loc = cbPlugin.getCurrentLocation();
		assertEquals(getAddr(0x0100416f), loc.getAddress());
		assertTrue(loc instanceof CommentFieldLocation);
		assertEquals(CodeUnit.EOL_COMMENT, ((CommentFieldLocation) loc).getCommentType());

		JButton searchButton = (JButton) findButton(dialog.getComponent(), "Next");
		pressButton(searchButton);
		waitForSearchTasks(dialog);

		loc = cbPlugin.getCurrentLocation();
		assertEquals(getAddr(0x01004178), loc.getAddress());
		assertTrue(loc instanceof CommentFieldLocation);
		assertEquals(CodeUnit.REPEATABLE_COMMENT, ((CommentFieldLocation) loc).getCommentType());

		pressButton(searchButton);
		waitForSearchTasks(dialog);

		loc = cbPlugin.getCurrentLocation();
		assertEquals(getAddr(0x01004192), loc.getAddress());
		assertTrue(loc instanceof CommentFieldLocation);
		assertEquals(CodeUnit.PLATE_COMMENT, ((CommentFieldLocation) loc).getCommentType());

		pressButton(searchButton);
		waitForSearchTasks(dialog);

		loc = cbPlugin.getCurrentLocation();
		assertEquals(getAddr(0x01004192), loc.getAddress());
		assertTrue(loc instanceof CommentFieldLocation);
		assertEquals(CodeUnit.POST_COMMENT, ((CommentFieldLocation) loc).getCommentType());

		pressButton(searchButton);
		waitForSearchTasks(dialog);

		goToService.goTo(new ProgramLocation(program, getAddr(0x01004100)));

		pressButton(searchButton);
		waitForSearchTasks(dialog);

		loc = cbPlugin.getCurrentLocation();
		assertEquals(getAddr(0x0100415a), loc.getAddress());
		assertTrue(loc instanceof CommentFieldLocation);
		assertEquals(CodeUnit.PRE_COMMENT, ((CommentFieldLocation) loc).getCommentType());
	}

	private void programLocationChange2(String buttonText) throws Exception {
		// search functions and instructions for "formatCount"
		SearchTextDialog dialog = getDialog();
		JComponent container = dialog.getComponent();
		JTextField tf = findTextField(container);
		selectRadioButton(container, buttonText);

		selectCheckBox(container, "Functions");
		selectCheckBox(container, "Instruction Mnemonics");
		selectCheckBox(container, "Instruction Operands");
		deSelectCheckBox(container, "Comments");

		goToService.goTo(new ProgramLocation(program, getAddr(0x01004158)));

		setText(tf, "formatCount");
		searchOnce(tf);
		waitForSearchTasks(dialog);

		ProgramLocation loc = cbPlugin.getCurrentLocation();
		assertTrue(loc instanceof VariableNameFieldLocation);
		assertEquals(getAddr(0x0100415a), loc.getAddress());

		searchOnce(tf);
		waitForSearchTasks(dialog);

		loc = cbPlugin.getCurrentLocation();
		assertTrue(loc instanceof OperandFieldLocation);
		assertEquals(0, ((OperandFieldLocation) loc).getOperandIndex());
		assertEquals(getAddr(0x0100416f), loc.getAddress());

		searchOnce(tf);
		waitForSearchTasks(dialog);

		loc = cbPlugin.getCurrentLocation();
		assertTrue(loc instanceof OperandFieldLocation);
		assertEquals(1, ((OperandFieldLocation) loc).getOperandIndex());
		assertEquals(getAddr(0x01004178), loc.getAddress());

		searchOnce(tf);
		waitForSearchTasks(dialog);

		loc = cbPlugin.getCurrentLocation();
		assertTrue(loc instanceof OperandFieldLocation);
		assertEquals(1, ((OperandFieldLocation) loc).getOperandIndex());
		assertEquals(getAddr(0x01004178), loc.getAddress());
		assertEquals("Not found", dialog.getStatusText());
	}

	private void searchBackward(String buttonText) throws Exception {
		SearchTextDialog dialog = getDialog();
		JComponent container = dialog.getComponent();
		JTextField tf = findTextField(container);
		selectRadioButton(container, buttonText);

		selectCheckBox(container, "Functions");
		selectCheckBox(container, "Instruction Mnemonics");
		selectCheckBox(container, "Instruction Operands");
		deSelectCheckBox(container, "Comments");

		goToService.goTo(new ProgramLocation(program, getAddr(0x0100417f)));

		setText(tf, "formatCount");
		searchBackOnce(dialog);
		waitForSearchTasks(dialog);

		ProgramLocation loc = cbPlugin.getCurrentLocation();
		assertTrue(loc instanceof OperandFieldLocation);
		assertEquals(1, ((OperandFieldLocation) loc).getOperandIndex());
		assertEquals(getAddr(0x01004178), loc.getAddress());

		searchBackOnce(dialog);
		waitForSearchTasks(dialog);

		loc = cbPlugin.getCurrentLocation();

		assertTrue(loc instanceof OperandFieldLocation);
		assertEquals(0, ((OperandFieldLocation) loc).getOperandIndex());
		assertEquals(getAddr(0x0100416f), loc.getAddress());

		searchBackOnce(dialog);
		waitForSearchTasks(dialog);

		loc = cbPlugin.getCurrentLocation();
		assertTrue(loc instanceof VariableNameFieldLocation);
		assertEquals(getAddr(0x0100415a), loc.getAddress());

		searchBackOnce(dialog);
		waitForSearchTasks(dialog);

		loc = cbPlugin.getCurrentLocation();
		assertTrue(loc instanceof VariableNameFieldLocation);
		assertEquals(getAddr(0x0100415a), loc.getAddress());
		assertEquals("Not found", dialog.getStatusText());
	}

	private void searchBackwardSameField(String buttonText) throws Exception {
		SearchTextDialog dialog = getDialog();
		JComponent container = dialog.getComponent();
		JTextField tf = findTextField(container);
		selectRadioButton(container, buttonText);

		selectCheckBox(container, "Functions");
		selectCheckBox(container, "Instruction Mnemonics");
		selectCheckBox(container, "Instruction Operands");
		deSelectCheckBox(container, "Comments");

		goToService.goTo(new ProgramLocation(program, getAddr(0x01004194)));

		setText(tf, "EAX");
		searchBackOnce(dialog);
		waitForSearchTasks(dialog);

		ProgramLocation loc = cbPlugin.getCurrentLocation();
		assertTrue(loc instanceof OperandFieldLocation);
		assertEquals(1, ((OperandFieldLocation) loc).getOperandIndex());
		assertEquals(getAddr(0x01004192), loc.getAddress());

		searchBackOnce(dialog);
		waitForSearchTasks(dialog);

		loc = cbPlugin.getCurrentLocation();

		assertTrue(loc instanceof OperandFieldLocation);
		assertEquals(0, ((OperandFieldLocation) loc).getOperandIndex());
		assertEquals(getAddr(0x01004192), loc.getAddress());

		searchBackOnce(dialog);
		waitForSearchTasks(dialog);

		loc = cbPlugin.getCurrentLocation();
		assertTrue(loc instanceof OperandFieldLocation);
		assertEquals(getAddr(0x01004183), loc.getAddress());
	}

	private void setCaseSensitive(String buttonText)
			throws Exception, InterruptedException, InvocationTargetException {
		SearchTextDialog dialog = getDialog();
		JComponent container = dialog.getComponent();
		JTextField tf = findTextField(container);
		selectRadioButton(container, buttonText);

		selectCheckBox(container, "Functions");
		selectCheckBox(container, "Instruction Mnemonics");
		selectCheckBox(container, "Instruction Operands");
		deSelectCheckBox(container, "Comments");
		selectCheckBox(container, "Case Sensitive");

		goToService.goTo(new ProgramLocation(program, getAddr(0x01004158)));

		setText(tf, "FORMATCount");
		searchOnce(tf);
		waitForSearchTasks(dialog);

		assertEquals("Not found", dialog.getStatusText());
		ProgramLocation loc = cbPlugin.getCurrentLocation();
		assertEquals(getAddr(0x01004158), loc.getAddress());
	}

	private void searchInOtherBlock(String buttonText)
			throws Exception, InterruptedException, InvocationTargetException {
		SearchTextDialog dialog = getDialog();
		JComponent container = dialog.getComponent();
		JTextField tf = findTextField(container);
		selectRadioButton(container, buttonText);

		goToService.goTo(new ProgramLocation(program, getAddr(0x0100417f)));

		setText(tf, "other overlay");
		searchOnce(tf);
		waitForSearchTasks(dialog);

		assertEquals("Not found", dialog.getStatusText());
		ProgramLocation loc = cbPlugin.getCurrentLocation();
		assertEquals(getAddr(0x0100417f), loc.getAddress());

		selectRadioButton(container, "All Blocks");
		searchOnce(tf);
		waitForSearchTasks(dialog);

		searchBackOnce(dialog);
		waitForSearchTasks(dialog);

		loc = cbPlugin.getCurrentLocation();
		assertEquals("otherOverlay::00000004", loc.getAddress().toString());

	}

	@SuppressWarnings("unchecked")
	private void searchAll(String buttonText, String searchType) throws Exception {
		SearchTextDialog dialog = getDialog();
		JComponent container = dialog.getComponent();

		selectRadioButton(container, buttonText);
		selectCheckBox(container, "Instruction Mnemonics");
		selectCheckBox(container, "Instruction Operands");
		selectCheckBox(container, "Labels");
		Options options = tool.getOptions("Search");
		options.setInt("Search Limit", 5);

		JTextField tf = findTextField(container);

		setText(tf, "LAB");
		searchAll(container);

		closeMaxSearchResultsDialog();

		TableComponentProvider<?>[] providers = tableServicePlugin.getManagedComponents();
		assertEquals(1, providers.length);

		AddressBasedTableModel<ProgramLocation> model =
			(AddressBasedTableModel<ProgramLocation>) providers[0].getModel();
		waitForTableModel(model);

		assertTrue(tool.isVisible(providers[0]));
		assertEquals(5, model.getRowCount());
		waitForSwing();

		//
		// Test that we can delete rows
		//
		doTestDeleteRow(providers, model);

		//
		// test marker stuff
		// 
		AddressSet set = getAddressesFromModel(model);
		MarkerService markerService = tool.getService(MarkerService.class);
		MarkerSet markerSet = markerService.getMarkerSet("Search", program);
		assertNotNull(markerSet);
		AddressSet addresses = runSwing(() -> markerSet.getAddressSet());
		assertTrue(set.hasSameAddresses(addresses));
	}

	@SuppressWarnings("unchecked")
	private void doTestDeleteRow(TableComponentProvider<?>[] providers,
			AddressBasedTableModel<ProgramLocation> model) {
		GThreadedTablePanel<ProgramLocation> threadedTablePanel =
			(GThreadedTablePanel<ProgramLocation>) providers[0].getThreadedTablePanel();
		final GTable table = threadedTablePanel.getTable();
		Random random = new Random();
		final int randomRow = random.nextInt(model.getRowCount());

		DockingActionIf deleteRowAction = getAction(tool, "TableServicePlugin", "Remove Items");
		ProgramLocation toBeDeleted = model.getRowObject(randomRow);
		runSwing(() -> table.setRowSelectionInterval(randomRow, randomRow));
		performAction(deleteRowAction, true);
		waitForTableModel(model);

		int currentIndex = model.getRowIndex(toBeDeleted);
		assertTrue(
			"Failed to delete object: " + toBeDeleted + ".  In the table at row: " + currentIndex,
			currentIndex < 0);
	}

	private void searchAllForPreview(String buttonText)
			throws Exception, InterruptedException, InvocationTargetException {
		SearchTextDialog dialog = getDialog();
		JComponent container = dialog.getComponent();
		JTextField tf = findTextField(container);

		selectRadioButton(container, buttonText);
		selectCheckBox(container, "Functions");
		selectCheckBox(container, "Instruction Mnemonics");
		selectCheckBox(container, "Instruction Operands");
		deSelectCheckBox(container, "Comments");

		Options options = tool.getOptions(ToolConstants.TOOL_OPTIONS);
		options.setInt("Search Limit", 50);

		setText(tf, "sscanf");
		searchAll(container);

		TableComponentProvider<?>[] providers = tableServicePlugin.getManagedComponents();
		assertEquals(1, providers.length);
		AddressBasedTableModel<?> model = (AddressBasedTableModel<?>) providers[0].getModel();
		assertTrue(tool.isVisible(providers[0]));

		String expectedString = "undefined sscanf";
		String previewString = getPreviewString(model, 0);
		boolean containsString = previewString.contains(expectedString);
		if (!containsString) {
			printDebug(model);
		}
		assertTrue("Did not find expected preview string in table.  Expected to contain \"" +
			expectedString + "\", but found: " + previewString, containsString);

		expectedString = "CALL sscanf";
		previewString = getPreviewString(model, 1);
		containsString = previewString.contains(expectedString);
		if (!containsString) {
			printDebug(model);
		}
		assertTrue("Did not find expected preview string in table.  Expected to contain \"" +
			expectedString + "\", but found: " + previewString, containsString);
	}

	private void searchAllForPreview2(String buttonText)
			throws Exception, InterruptedException, InvocationTargetException {
		SearchTextDialog dialog = getDialog();
		JComponent container = dialog.getComponent();
		JTextField tf = findTextField(container);

		selectRadioButton(container, buttonText);
		selectCheckBox(container, "Functions");
		selectCheckBox(container, "Instruction Mnemonics");
		selectCheckBox(container, "Instruction Operands");
		deSelectCheckBox(container, "Comments");

		Options options = tool.getOptions("Tool");
		options.setInt("Search Limit", 50);

		setText(tf, "formatCount");
		searchAll(container);

		TableComponentProvider<?>[] providers = tableServicePlugin.getManagedComponents();
		assertEquals(1, providers.length);
		AddressBasedTableModel<?> model = (AddressBasedTableModel<?>) providers[0].getModel();
		assertTrue(tool.isVisible(providers[0]));
		assertTrue(getPreviewString(model, 0).startsWith("byte Stack[-0xc]:1 formatCount"));
		assertTrue(getPreviewString(model, 1).startsWith("MOV dword ptr [EBP + formatCount]"));
		assertTrue(getPreviewString(model, 2).startsWith("LEA EAX,[EBP + formatCount]"));
	}

	private void searchAll(final JComponent container) {
		runSwing(() -> {
			JButton searchAllButton = findButtonByText(container, "Search All");
			searchAllButton.getActionListeners()[0].actionPerformed(null);
		});

		waitForSearchAll();
	}

	private void searchSelectionInFunction(String buttonText) throws Exception {
		// make a selection
		final AddressSet set = new AddressSet();
		set.addRange(getAddr(0x01002cf0), getAddr(0x01002cf8));
		tool.firePluginEvent(new ProgramSelectionPluginEvent(tableServicePlugin.getName(),
			new ProgramSelection(set), program));

		waitForSwing();

		assertTrue(
			cbPlugin.goToField(getAddr(0x1002cf5), VariableTypeFieldFactory.FIELD_NAME, 0, 3));
		SearchTextDialog dialog = getDialog();
		JComponent container = dialog.getComponent();
		JTextField tf = findTextField(container);

		selectRadioButton(container, buttonText);
		selectCheckBox(container, "Functions");
		setText(tf, "param");

		searchOnce(tf);
		waitForSearchTasks(dialog);

		cbPlugin.updateNow();

		ProgramLocation loc = cbPlugin.getCurrentLocation();
		assertEquals(getAddr(0x1002cf5), loc.getAddress());
		assertTrue(loc instanceof VariableNameFieldLocation);
		assertEquals("param_1", ((VariableNameFieldLocation) loc).getName());

		//
		// Search three more times, then go backwards
		//
		JButton searchButton = findButtonByText(container, "Next");
		pressSearchButton(dialog, searchButton);

		loc = cbPlugin.getCurrentLocation();
		assertEquals("param_2", ((VariableNameFieldLocation) loc).getName());

		pressSearchButton(dialog, searchButton);

		loc = cbPlugin.getCurrentLocation();
		assertEquals("param_3", ((VariableNameFieldLocation) loc).getName());

		pressSearchButton(dialog, searchButton);

		loc = cbPlugin.getCurrentLocation();
		assertEquals("param_4", ((VariableNameFieldLocation) loc).getName());

		searchButton = findButtonByText(container, "Previous");
		pressSearchButton(dialog, searchButton);

		// Unusual code alert!  Doing a reverse above triggers an odd condition where the next
		// action in the plugin is actually processed twice--yes twice!...so wait again
		dialog.getTaskScheduler().waitForCurrentTask();
		cbPlugin.updateNow();

		loc = cbPlugin.getCurrentLocation();
		assertEquals("param_3", ((VariableNameFieldLocation) loc).getName());

		pressSearchButton(dialog, searchButton);

		loc = cbPlugin.getCurrentLocation();
		assertEquals("param_2", ((VariableNameFieldLocation) loc).getName());

		pressSearchButton(dialog, searchButton);

		loc = cbPlugin.getCurrentLocation();
		assertEquals("param_1", ((VariableNameFieldLocation) loc).getName());
	}

	private void searchSelection(String buttonText) throws Exception {
		SearchTextDialog dialog = getDialog();
		JComponent container = dialog.getComponent();
		JTextField tf = findTextField(container);
		selectRadioButton(container, buttonText);

		AddressSet set = new AddressSet();
		set.addRange(getAddr(0x01001010), getAddr(0x0100101f));
		set.addRange(getAddr(0x0100107c), getAddr(0x0100107f));

		triggerSelection(set);

		ProgramSelection sel = cbPlugin.getCurrentSelection();
		assertNotNull(sel);
		assertTrue(!sel.isEmpty());
		assertEquals(set, sel);

		JCheckBox cb = (JCheckBox) findButton(container, "Search Selection");
		assertSelected(cb);
		assertEnabled(cb);

		selectCheckBox(container, "Defined Data Mnemonics");

		setText(tf, "addr");

		searchOnce(tf);
		waitForSearchTasks(dialog);

		ProgramLocation loc = cbPlugin.getCurrentLocation();
		assertEquals(getAddr(0x1001010), loc.getAddress());
		assertTrue(loc instanceof MnemonicFieldLocation);
		assertTrue(((MnemonicFieldLocation) loc).getMnemonic().equals("addr"));

		searchOnce(tf);
		waitForSearchTasks(dialog);

		loc = cbPlugin.getCurrentLocation();
		assertEquals(getAddr(0x1001014), loc.getAddress());
		assertTrue(loc instanceof MnemonicFieldLocation);
		assertTrue(((MnemonicFieldLocation) loc).getMnemonic().equals("addr"));

		searchOnce(tf);
		waitForSearchTasks(dialog);

		loc = cbPlugin.getCurrentLocation();
		assertEquals(getAddr(0x1001018), loc.getAddress());
		assertTrue(loc instanceof MnemonicFieldLocation);
		assertTrue(((MnemonicFieldLocation) loc).getMnemonic().equals("addr"));

		searchOnce(tf);
		waitForSearchTasks(dialog);

		loc = cbPlugin.getCurrentLocation();
		assertEquals(getAddr(0x1001018), loc.getAddress());
		assertTrue(loc instanceof MnemonicFieldLocation);
		assertTrue(((MnemonicFieldLocation) loc).getMnemonic().equals("addr"));
		assertEquals("Not found", dialog.getStatusText());
	}

	private void triggerSelection(AddressSet set) {

		tool.firePluginEvent(new ProgramSelectionPluginEvent(tableServicePlugin.getName(),
			new ProgramSelection(set), program));
		waitForSwing();

		//
		// Note: the SearchTextPlugin does not listen for program selections.  Rather, it listens
		//       to context changes.  Unfortunately, in the test environment, context updating
		//       fails due to its dependency on focus.  So, update the plugin so it knows to
		//       check for selection updates.
		//
		runSwing(() -> {

			ActionContext actionContext = provider.getActionContext(null);
			plugin.contextChanged(actionContext);
		});
	}

	private void selectCheckBox(Container parent, String name) throws Exception {
		JCheckBox cb = (JCheckBox) findButton(parent, name);
		runSwing(() -> {
			if (cb.isSelected()) {
				return;
			}
			cb.doClick();
		});
	}

	private void deSelectCheckBox(Container parent, String name) throws Exception {
		JCheckBox cb = (JCheckBox) findButton(parent, name);
		runSwing(() -> {
			if (!cb.isSelected()) {
				return;
			}
			cb.doClick();
		});
	}

	private void selectRadioButton(Container container, String buttonText) throws Exception {
		JRadioButton rb = (JRadioButton) findButton(container, buttonText);
		runSwing(() -> {
			if (!rb.isSelected()) {
				rb.setSelected(true);
			}
		});
	}

	private void closeMaxSearchResultsDialog() throws Exception {
		OkDialog d = waitForInfoDialog();
		assertTrue(d.getMessage().contains("Stopped search"));
		close(d);
		waitForSwing();
	}

	private AddressSet getAddressesFromModel(AddressBasedTableModel<ProgramLocation> model) {
		AddressSet set = new AddressSet();
		int rowCount = model.getRowCount();
		for (int i = 0; i < rowCount; i++) {
			AddressBasedLocation location = (AddressBasedLocation) model.getValueAt(i,
				model.getColumnIndex(AddressTableColumn.class));
			Address addr = location.getAddress();
			set.addRange(addr, addr);
		}
		return set;
	}

	private void searchOnce(JTextField tf) throws Exception {
		final ActionListener listener = tf.getActionListeners()[0];
		runSwing(() -> listener.actionPerformed(null));
	}

	private void searchBackOnce(SearchTextDialog dialog) throws Exception {
		JButton searchButton = (JButton) findButton(dialog.getComponent(), "Previous");
		pressButton(searchButton);
	}

	private void pressSearchButton(SearchTextDialog dialog, JButton searchButton)
			throws InterruptedException {
		pressButton(searchButton);
		waitForSearchTasks(dialog);
		cbPlugin.updateNow();
	}

	private void waitForSearchAll() {
		waitForSwing();

		int totalTime = 0;
		while (plugin.isWaitingForSearchAll() && totalTime < DEFAULT_WINDOW_TIMEOUT) {
			sleep(DEFAULT_WAIT_DELAY);
			totalTime += DEFAULT_WAIT_DELAY;
		}

		assertTrue("Timed-out waiting for 'search all' to finish",
			totalTime < DEFAULT_WINDOW_TIMEOUT);

		waitForSwing();
	}

	private void printDebug(AddressBasedTableModel<?> model) {
		int rowCount = model.getRowCount();
		rowCount = Math.min(rowCount, 20);
		for (int i = 0; i < rowCount; i++) {
			System.err.println("preview for row " + i + ": " + getPreviewString(model, i));
		}
	}

	private String getPreviewString(AddressBasedTableModel<?> model, int i) {
		int columnIndex = model.getColumnIndex(PreviewTableColumn.class);
		Object valueAt = model.getValueAt(i, columnIndex);
		return ((PreviewTableCellData) valueAt).getDisplayString();
	}

	private void waitForSearchTasks(SearchTextDialog dialog) throws InterruptedException {
		waitForSwing();
		Thread t = dialog.getTaskScheduler().getCurrentThread();
		if (t == null) {
			// just in case we missed the thread and the callback hasn't happened yet
			waitForSwing();
			t = dialog.getTaskScheduler().getCurrentThread();
		}

		while (t != null) {
			t.join(DEFAULT_WAIT_TIMEOUT);
			waitForSwing();
			t = dialog.getTaskScheduler().getCurrentThread();
		}
		waitForSwing();
	}

	private AbstractButton findButton(Container container, String text) {
		Component[] comp = container.getComponents();
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

	private JTextField findTextField(Container container) {
		Component[] c = container.getComponents();
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

	private SearchTextDialog getDialog() throws Exception {
		runSwing(() -> searchAction.actionPerformed(provider.getActionContext(null)));
		return plugin.getSearchDialog();
	}

	private Address getAddr(int offset) {
		return program.getMinAddress().getNewAddress(offset);
	}

}
