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
import java.awt.event.ActionListener;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.*;

import org.junit.*;

import docking.action.DockingActionIf;
import docking.widgets.fieldpanel.support.Highlight;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.marker.MarkerManagerPlugin;
import ghidra.app.plugin.core.programtree.ProgramTreePlugin;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.viewer.field.*;
import ghidra.app.util.viewer.format.*;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorComponent;
import utilities.util.reflection.ReflectionUtilities;

public class SearchTextPlugin3Test extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private Program program;
	private SearchTextPlugin plugin;
	private DockingActionIf searchAction;
	private Listing listing;
	private CodeBrowserPlugin cbPlugin;
	private CodeViewerProvider provider;
	private GoToService goToService;

	public SearchTextPlugin3Test() {
		super();
	}

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
		env.showTool();
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

		builder.createLocalVariable(function, "i", new WordDataType(), -4);
		builder.createLocalVariable(function, "count", new FloatDataType(), -8);
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

		builder.setBytes("1002c93", "8b 4c 24 04 8b 44 24 0c 56 57");
		builder.disassemble("1002c93", 10);
		builder.createEmptyFunction("foo", "0x01002c9c", 10, DataType.DEFAULT);
		return builder.getProgram();
	}

	@After
	public void tearDown() throws Exception {

		runSwing(() -> tool.close());

		env.release(program);
		env.dispose();
	}

	@Test
	public void testCancelSearch() throws Exception {
		cancelSearch(SearchTextPlugin1Test.EXACT_MATCH_SEARCH);
	}

	@Test
	public void testCancelSearchQuick() throws Exception {
		cancelSearch(SearchTextPlugin1Test.QUICK_SEARCH);
	}

	@Test
	public void testSearchOrder() throws Exception {
		// Only for the Quick Search...

		// put hits on search in comments
		CodeUnit cu = listing.getCodeUnitAt(getAddr(0x01002c97));

		int transactionID = program.startTransaction("test");
		cu.setComment(CodeUnit.PLATE_COMMENT, "find hit for eax");
		cu.setComment(CodeUnit.PRE_COMMENT, "find another hit for eax");
		SymbolTable st = program.getSymbolTable();
		st.createLabel(cu.getMinAddress(), "My_EAX", SourceType.USER_DEFINED);
		cu.setComment(CodeUnit.EOL_COMMENT, "eol comment for eax");

		cu.setComment(CodeUnit.POST_COMMENT, "last comment for eax");
		program.endTransaction(transactionID, true);

		SearchTextDialog dialog = getDialog();
		JComponent container = dialog.getComponent();
		JTextField tf = findTextField(container);

		JCheckBox cb = (JCheckBox) findAbstractButtonByText(container, "Functions");
		cb.setSelected(true);

		cb = (JCheckBox) findAbstractButtonByText(container, "Labels");
		setToggleButtonSelected(cb, true);

		cb = (JCheckBox) findAbstractButtonByText(container, "Instruction Mnemonics");
		setToggleButtonSelected(cb, true);

		cb = (JCheckBox) findAbstractButtonByText(container, "Instruction Operands");
		setToggleButtonSelected(cb, true);

		cb = (JCheckBox) findAbstractButtonByText(container, "Defined Data Mnemonics");
		setToggleButtonSelected(cb, true);

		cb = (JCheckBox) findAbstractButtonByText(container, "Defined Data Values");
		setToggleButtonSelected(cb, true);

		goToService.goTo(new ProgramLocation(program, getAddr(0x01002c92)));

		ActionListener listener = tf.getActionListeners()[0];
		runSwing(() -> {
			tf.setText("eax");
			listener.actionPerformed(null);
		});
		waitForSearchTasks(dialog);
		ProgramLocation loc = cbPlugin.getCurrentLocation();
		assertTrue(loc instanceof CommentFieldLocation);
		assertEquals(CodeUnit.PLATE_COMMENT, ((CommentFieldLocation) loc).getCommentType());
		assertEquals(cu.getMinAddress(), loc.getAddress());

		runSwing(() -> listener.actionPerformed(null));
		waitForSearchTasks(dialog);

		loc = cbPlugin.getCurrentLocation();
		assertTrue(loc instanceof CommentFieldLocation);
		assertEquals(CodeUnit.PRE_COMMENT, ((CommentFieldLocation) loc).getCommentType());

		runSwing(() -> listener.actionPerformed(null));
		waitForSearchTasks(dialog);
		loc = cbPlugin.getCurrentLocation();
		assertTrue(loc instanceof LabelFieldLocation);
		assertEquals(3, ((LabelFieldLocation) loc).getCharOffset());

		runSwing(() -> listener.actionPerformed(null));
		waitForSearchTasks(dialog);

		loc = cbPlugin.getCurrentLocation();
		assertTrue(loc instanceof OperandFieldLocation);
		assertEquals(0, ((OperandFieldLocation) loc).getOperandIndex());
		assertEquals(cu.getMinAddress(), loc.getAddress());

		runSwing(() -> listener.actionPerformed(null));
		waitForSearchTasks(dialog);
		loc = cbPlugin.getCurrentLocation();
		assertTrue(loc instanceof CommentFieldLocation);
		assertEquals(CodeUnit.EOL_COMMENT, ((CommentFieldLocation) loc).getCommentType());
		assertEquals(cu.getMinAddress(), loc.getAddress());

		runSwing(() -> listener.actionPerformed(null));
		waitForSearchTasks(dialog);
		loc = cbPlugin.getCurrentLocation();
		assertTrue(loc instanceof CommentFieldLocation);
		assertEquals(CodeUnit.POST_COMMENT, ((CommentFieldLocation) loc).getCommentType());
		assertEquals(cu.getMinAddress(), loc.getAddress());

	}

	@Test
	public void testSearchOrderForFunction() throws Exception {
		// ONLY for the Quick Search...

		// put "sscanf" in function comments
		int transactionID = program.startTransaction("test");
		List<Function> globalFunctions = listing.getGlobalFunctions("sscanf");
		assertEquals(1, globalFunctions.size());
		Function f = globalFunctions.get(0);
		f.setComment("Function comment for sscanf");
		StackFrame frame = f.getStackFrame();
		Variable[] vars = frame.getStackVariables();
		vars[1].setComment("this is a comment for sscanf");
		program.endTransaction(transactionID, true);

		SearchTextDialog dialog = getDialog();
		JComponent container = dialog.getComponent();
		JTextField tf = findTextField(container);
		JButton searchButton = (JButton) findAbstractButtonByText(container, "Next");
		JCheckBox cb = (JCheckBox) findAbstractButtonByText(container, "Functions");
		setToggleButtonSelected(cb, true);

		runSwing(() -> {
			tf.setText("sscanf");
			searchButton.getActionListeners()[0].actionPerformed(null);
		});

		waitForSearchTasks(dialog);

		ProgramLocation loc = cbPlugin.getCurrentLocation();
		assertTrue(loc instanceof CommentFieldLocation);
		assertEquals(CodeUnit.PLATE_COMMENT, ((CommentFieldLocation) loc).getCommentType());

		ActionListener listener = searchButton.getActionListeners()[0];
		runSwing(() -> listener.actionPerformed(null));

		waitForSearchTasks(dialog);
		loc = cbPlugin.getCurrentLocation();
		assertTrue(loc instanceof FunctionSignatureFieldLocation);

		runSwing(() -> listener.actionPerformed(null));

		waitForSearchTasks(dialog);
		loc = cbPlugin.getCurrentLocation();
		assertTrue(loc instanceof VariableCommentFieldLocation);

		runSwing(() -> listener.actionPerformed(null));

		waitForSearchTasks(dialog);
		loc = cbPlugin.getCurrentLocation();
		assertTrue(loc instanceof CommentFieldLocation);
		assertEquals(CodeUnit.PRE_COMMENT, ((CommentFieldLocation) loc).getCommentType());
	}

	@Test
	public void testSaveState() {
		Options options = tool.getOptions("Search");
		options.setInt("Search Limit", 20);
		env.saveRestoreToolState();
		assertEquals(20, plugin.getResultsLimit());
	}

	@Test
	public void testExactSearchMnemonicOperandBackward() throws Exception {
		DockingActionIf toggleAction = getAction(cbPlugin, "Toggle Header");
		performAction(toggleAction, provider, true);

		ListingPanel listingPanel = cbPlugin.getListingPanel();
		FieldHeader headerPanel = listingPanel.getFieldHeader();
		assertNotNull(provider);
		assertTrue(cbPlugin.goToField(getAddr(0x10018f4), OperandFieldFactory.FIELD_NAME, 0, 0));
		FieldHeaderComp header = headerPanel.getHeaderTab();

		FieldFormatModel model = header.getModel();
		assertEquals("Instruction/Data", model.getName());
		runSwing(() -> model.removeAllFactories());

		addField(model, AddressFieldFactory.FIELD_NAME, 0);
		addField(model, MnemonicFieldFactory.FIELD_NAME, 1);
		addField(model, OperandFieldFactory.FIELD_NAME, 2);
		// create Plate, pre, end of line, post and repeatable comments
		// that contain a hit for a search

		CodeUnit cu = listing.getCodeUnitAt(getAddr(0x0100416f));
		int transactionID = program.startTransaction("test");
		cu.setComment(CodeUnit.EOL_COMMENT, "call sscanf");

		cu = listing.getCodeUnitAt(getAddr(0x01004178));
		cu.setComment(CodeUnit.REPEATABLE_COMMENT, "make a reference to sscanf");

		cu = listing.getCodeUnitAt(getAddr(0x01004192));
		cu.setComment(CodeUnit.POST_COMMENT, "sscanf in a post comment");

		cu = listing.getCodeUnitAt(getAddr(0x0100467b));
		cu.setComment(CodeUnit.PRE_COMMENT, "call sscanf here");

		program.endTransaction(transactionID, true);

		SearchTextDialog dialog = getDialog();
		JComponent container = dialog.getComponent();
		JTextField tf = findTextField(container);
		selectRadioButton(container, SearchTextPlugin1Test.EXACT_MATCH_SEARCH);
		JCheckBox cb = (JCheckBox) findAbstractButtonByText(container, "Instruction Mnemonics");
		setToggleButtonSelected(cb, true);

		cb = (JCheckBox) findAbstractButtonByText(container, "Instruction Operands");
		setToggleButtonSelected(cb, true);

		cb = (JCheckBox) findAbstractButtonByText(container, "Comments");
		setToggleButtonSelected(cb, false);

		goToService.goTo(new ProgramLocation(program, getAddr(0x01004160)));
		runSwing(() -> tf.setText("sscanf"));
		JButton searchButton = (JButton) findAbstractButtonByText(container, "Previous");
		pressButton(searchButton);
		waitForSearchTasks(dialog);

		Symbol symbol = getUniqueSymbol(program, "sscanf");

		ReferenceManager refMgr = program.getReferenceManager();
		ReferenceIterator iter = refMgr.getReferencesTo(symbol.getAddress());
		List<Address> list = new ArrayList<>();
		while (iter.hasNext()) {
			Reference ref = iter.next();
			list.add(ref.getFromAddress());
		}
		// go to the end of the program
		assertTrue(
			cbPlugin.goToField(program.getMaxAddress(), OperandFieldFactory.FIELD_NAME, 0, 0));

		Collections.sort(list);
		Collections.reverse(list);
		for (int i = 0; i < list.size(); i++) {
			Address addr = list.get(i);
			pressSearchButton(dialog, searchButton);
			ProgramLocation loc = cbPlugin.getCurrentLocation();
			assertEquals(addr, loc.getAddress());
			assertTrue(loc instanceof OperandFieldLocation);
		}
	}

	private void addField(FieldFormatModel model, String fieldName, int column) {
		FieldFactory[] allFactories = model.getAllFactories();
		for (FieldFactory fieldFactory : allFactories) {
			if (fieldFactory.getFieldName().equals(fieldName)) {
				runSwing(() -> model.addFactory(fieldFactory, 0, column));
				return;
			}
		}
	}

	@Test
	public void testExactSearchMnemonicOperandForward() throws Exception {
		DockingActionIf toggleAction = getAction(cbPlugin, "Toggle Header");
		performAction(toggleAction, provider, true);

		ListingPanel listingPanel = cbPlugin.getListingPanel();
		FieldHeader headerPanel = listingPanel.getFieldHeader();
		assertTrue(cbPlugin.goToField(getAddr(0x10018f4), OperandFieldFactory.FIELD_NAME, 0, 0));
		FieldHeaderComp header = headerPanel.getHeaderTab();

		FieldFormatModel model = header.getModel();
		assertEquals("Instruction/Data", model.getName());
		runSwing(() -> model.removeAllFactories());

		addField(model, AddressFieldFactory.FIELD_NAME, 0);
		addField(model, OperandFieldFactory.FIELD_NAME, 1);

		// create Plate, pre, end of line, post and repeatable comments
		// that contain a hit for a search

		CodeUnit cu = listing.getCodeUnitAt(getAddr(0x0100416f));
		int transactionID = program.startTransaction("test");
		cu.setComment(CodeUnit.EOL_COMMENT, "call sscanf");

		cu = listing.getCodeUnitAt(getAddr(0x01004178));
		cu.setComment(CodeUnit.REPEATABLE_COMMENT, "make a reference to sscanf");

		cu = listing.getCodeUnitAt(getAddr(0x01004192));
		cu.setComment(CodeUnit.POST_COMMENT, "sscanf in a post comment");

		cu = listing.getCodeUnitAt(getAddr(0x0100467b));
		cu.setComment(CodeUnit.PRE_COMMENT, "call sscanf here");

		program.endTransaction(transactionID, true);

		SearchTextDialog dialog = getDialog();
		JComponent container = dialog.getComponent();
		final JTextField tf = findTextField(container);
		selectRadioButton(container, SearchTextPlugin1Test.EXACT_MATCH_SEARCH);
		JCheckBox cb = (JCheckBox) findAbstractButtonByText(container, "Instruction Mnemonics");
		setToggleButtonSelected(cb, true);

		cb = (JCheckBox) findAbstractButtonByText(container, "Instruction Operands");
		setToggleButtonSelected(cb, true);

		cb = (JCheckBox) findAbstractButtonByText(container, "Comments");
		setToggleButtonSelected(cb, true);

		// Backwards
		goToService.goTo(new ProgramLocation(program, getAddr(0x01004160)));
		runSwing(() -> tf.setText("call sscanf"));
		JButton searchButton = (JButton) findAbstractButtonByText(container, "Previous");
		pressButton(searchButton);
		waitForSearchTasks(dialog);

		Symbol symbol = getUniqueSymbol(program, "sscanf");

		ReferenceManager refMgr = program.getReferenceManager();
		ReferenceIterator iter = refMgr.getReferencesTo(symbol.getAddress());
		List<Address> list = new ArrayList<>();
		while (iter.hasNext()) {
			Reference ref = iter.next();
			list.add(ref.getFromAddress());
		}
		// go to the end of the program
		assertTrue(
			cbPlugin.goToField(program.getMinAddress(), OperandFieldFactory.FIELD_NAME, 0, 0));
		pressSearchButton(dialog, searchButton);
		ProgramLocation loc = cbPlugin.getCurrentLocation();
		assertEquals(program.getMinAddress(), loc.getAddress());
		assertEquals("Not found", dialog.getStatusText());

	}

	@Test
	public void testHighlights() throws Exception {

		SearchTextDialog dialog = getDialog();
		JComponent container = dialog.getComponent();
		JTextField tf = findTextField(container);
		JCheckBox cb = (JCheckBox) findAbstractButtonByText(container, "Instruction Mnemonics");
		setToggleButtonSelected(cb, true);

		cb = (JCheckBox) findAbstractButtonByText(container, "Instruction Operands");
		setToggleButtonSelected(cb, true);

		cb = (JCheckBox) findAbstractButtonByText(container, "Functions");
		setToggleButtonSelected(cb, true);

		String searchText = "param_";
		runSwing(() -> {
			tf.setText(searchText);
			ActionListener[] listeners = tf.getActionListeners();
			listeners[0].actionPerformed(null);
		});
		waitForSearchTasks(dialog);

		ProgramLocation loc = plugin.getNavigatable().getLocation();
		assertTrue(loc instanceof FunctionSignatureFieldLocation);
		assertEquals(0x1002cf5, loc.getAddress().getOffset());
		verifyPluginHighlightText(searchText);

		String signature = ((FunctionSignatureFieldLocation) loc).getSignature();

		Function function = listing.getFunctionAt(loc.getAddress());
		HighlightProvider highlightProvider =
			cbPlugin.getFormatManager().getFormatHighlightProvider();
		Highlight[] h = highlightProvider.getHighlights(signature, function,
			FunctionSignatureFieldFactory.class, signature.indexOf(searchText));
		assertEquals(1, h.length);

		runSwing(() -> dialog.close());

		// highlights should be gone
		h = highlightProvider.getHighlights(signature, function,
			FunctionSignatureFieldFactory.class, -1);
		assertEquals(0, h.length);

	}

	private void verifyPluginHighlightText(String text) {
		final AtomicReference<String> ref = new AtomicReference<>();
		runSwing(() -> ref.set(plugin.getLastSearchText()));
		assertEquals("Plugin does not have current search text", text, ref.get());
	}

	@Test
	public void testHighlightsWithMultipleProviders() throws Exception {
		SearchTextDialog dialog = getDialog();
		JComponent container = dialog.getComponent();
		JTextField tf = findTextField(container);
		JCheckBox cb = (JCheckBox) findAbstractButtonByText(container, "Instruction Mnemonics");
		setToggleButtonSelected(cb, true);

		cb = (JCheckBox) findAbstractButtonByText(container, "Instruction Operands");
		setToggleButtonSelected(cb, true);

		cb = (JCheckBox) findAbstractButtonByText(container, "Functions");
		setToggleButtonSelected(cb, true);

		JButton searchAllButton = (JButton) getInstanceField("allButton", dialog);
		runSwing(() -> {
			tf.setText("param_");
			searchAllButton.doClick();
		});
		while (plugin.isWaitingForSearchAll()) {
			Thread.sleep(20);
		}
		waitForSwing();

		// first match at: 0x01002cf5
		Address addr = getAddr(0x01002cf5);
		cbPlugin.goToField(addr, "Function Signature", 0, 32);
		waitForSwing();
		ProgramLocation loc = plugin.getNavigatable().getLocation();
		assertTrue(loc instanceof FunctionSignatureFieldLocation);

		String signature = ((FunctionSignatureFieldLocation) loc).getSignature();
		Function function = listing.getFunctionAt(loc.getAddress());
		HighlightProvider highlightProvider =
			cbPlugin.getFormatManager().getFormatHighlightProvider();
		Highlight[] h = highlightProvider.getHighlights(signature, function,
			FunctionSignatureFieldFactory.class, -1);
		int numberOfHighlights = h.length;
		assertTrue("Did not find highlights at expected field.", (numberOfHighlights > 0));

		// re-show the dialog to perform a new search
		SearchTextDialog dialogTwo = getDialog();
		container = dialogTwo.getComponent();
		JTextField tfTwo = findTextField(container);
		JButton searchAllButtonTwo = (JButton) getInstanceField("allButton", dialog);
		runSwing(() -> {
			tfTwo.setText("text");
			searchAllButtonTwo.doClick();
		});
		while (plugin.isWaitingForSearchAll()) {
			Thread.sleep(20);
		}
		waitForSwing();

		// first match at: 0x01002b39
		addr = getAddr(0x01002b39);
		cbPlugin.goToField(addr, "Operands", 0, 2);
		waitForSwing();
		loc = plugin.getNavigatable().getLocation();

		assertTrue(loc instanceof OperandFieldLocation);
		OperandFieldLocation operandLocation = (OperandFieldLocation) loc;
		Instruction instruction = listing.getInstructionAt(addr);

		h = highlightProvider.getHighlights(operandLocation.getOperandRepresentation(), instruction,
			OperandFieldFactory.class, 0);
		assertTrue("Did not update highlights for new search.", (numberOfHighlights != h.length));
	}

	private void cancelSearch(String buttonText) throws Exception {

		SearchTextDialog dialog = getDialog();
		JComponent container = dialog.getComponent();
		JTextField tf = findTextField(container);
		selectRadioButton(container, buttonText);

		JCheckBox cb = (JCheckBox) findAbstractButtonByText(container, "Functions");
		setToggleButtonSelected(cb, true);

		cb = (JCheckBox) findAbstractButtonByText(container, "Labels");
		setToggleButtonSelected(cb, true);

		cb = (JCheckBox) findAbstractButtonByText(container, "Instruction Mnemonics");
		setToggleButtonSelected(cb, true);

		cb = (JCheckBox) findAbstractButtonByText(container, "Instruction Operands");
		setToggleButtonSelected(cb, true);

		cb = (JCheckBox) findAbstractButtonByText(container, "Defined Data Mnemonics");
		setToggleButtonSelected(cb, true);

		cb = (JCheckBox) findAbstractButtonByText(container, "Defined Data Values");
		setToggleButtonSelected(cb, true);

		// install our own task monitor so we can cancel before the task finishes
		CancellingStubTaskMonitorComponent testMonitor = new CancellingStubTaskMonitorComponent();
		setInstanceField("taskMonitorComponent", dialog, testMonitor);

		setText(tf, "hello");
		triggerEnter(tf);
		waitForSearchTasks(dialog);

		String text = runSwing(() -> dialog.getStatusText());
		assertTrue("expected:<Search cancelled> or <operation canceled> but was:<" + text + ">",
			text != null && (text.equals("Search cancelled") || text.equals("operation canceled")));
	}

	private void selectRadioButton(Container container, String buttonText) throws Exception {
		final JRadioButton rb = (JRadioButton) findAbstractButtonByText(container, buttonText);
		runSwing(() -> rb.setSelected(true));
	}

	private SearchTextDialog getDialog() throws Exception {
		runSwing(() -> searchAction.actionPerformed(provider.getActionContext(null)));
		return plugin.getSearchDialog();
	}

	private Address getAddr(int offset) {
		return program.getMinAddress().getNewAddress(offset);
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

	private void pressSearchButton(SearchTextDialog dialog, JButton searchButton)
			throws InterruptedException {
		pressButton(searchButton);
		waitForSearchTasks(dialog);
		cbPlugin.updateNow();
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

	/*
	 * A task monitor class that will cancel itself when it is run from the SearchTask
	 */
	private class CancellingStubTaskMonitorComponent extends TaskMonitorComponent {

		@Override
		public void checkCanceled() throws CancelledException {
			if (calledFromSearchTask()) {
				throw new CancelledException();
			}
		}

		@Override
		public boolean isCancelled() {
			return calledFromSearchTask();
		}

		private boolean calledFromSearchTask() {
			String s = ReflectionUtilities.stackTraceToString(new Throwable());
			return s.contains(SearchTask.class.getSimpleName());
		}

	}
}
