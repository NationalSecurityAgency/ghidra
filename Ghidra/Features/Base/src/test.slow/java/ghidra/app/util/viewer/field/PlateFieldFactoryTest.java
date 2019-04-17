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
package ghidra.app.util.viewer.field;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import javax.swing.SwingUtilities;

import org.junit.*;

import docking.widgets.table.GTable;
import docking.widgets.table.threaded.GThreadedTablePanel;
import generic.test.TestUtils;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.core.blockmodel.BlockModelServicePlugin;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.gotoquery.GoToServicePlugin;
import ghidra.app.plugin.core.navigation.NextPrevAddressPlugin;
import ghidra.app.plugin.core.table.TableComponentProvider;
import ghidra.app.plugin.core.table.TableServicePlugin;
import ghidra.app.services.GoToService;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.test.*;
import ghidra.util.exception.AssertException;
import ghidra.util.table.GhidraProgramTableModel;

public class PlateFieldFactoryTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private CodeBrowserPlugin cb;
	private Options fieldOptions;
	private Program program;
	private GoToService goToService;

	public PlateFieldFactoryTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		program = buildProgram();

		env = new TestEnv();
		tool = env.showTool(program);
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(NextPrevAddressPlugin.class.getName());
		cb = env.getPlugin(CodeBrowserPlugin.class);
		tool.addPlugin(BlockModelServicePlugin.class.getName());
		tool.addPlugin(GoToServicePlugin.class.getName());

		fieldOptions = cb.getFormatManager().getFieldOptions();
		resetOptions();
		goToService = tool.getService(GoToService.class);
	}

	private ProgramDB buildProgram() throws Exception {
		ToyProgramBuilder builder = new ToyProgramBuilder("notepad", true);

		builder.createMemory(".text", "0x1001000", 0x6600);
		builder.createEntryPoint("0x1001100", "entry");
		builder.addBytesNOP("0x1001100", 4);
		builder.disassemble("0x1001100", 4);
		builder.createFunction("0x1001100");

		builder.addBytesNOP("0x1001110", 4);
		builder.disassemble("0x1001110", 4);

		builder.addBytesReturn("0x1001200");
		builder.disassemble("0x1001200", 4);

		builder.createMemoryCallReference("1001000", "1001200");

		builder.addBytesReturn("1001300");
		builder.disassemble("1001300", 4);
		builder.createFunction("1001300");

		builder.createLabel("1001400", "bob");
		builder.createComment("1001400", "my comment", CodeUnit.PLATE_COMMENT);

		builder.addBytesReturn("1001500");
		builder.disassemble("1001500", 4);
		builder.createFunction("1001500");

		return builder.getProgram();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testShowFunctionPlates() throws Exception {
		Symbol symbol = getUniqueSymbol(program, "entry");
		Address addr = symbol.getAddress();
		Function function = program.getFunctionManager().getFunctionAt(addr);
		CodeUnit cu = program.getListing().getCodeUnitAt(function.getEntryPoint());
		int transactionID = program.startTransaction("test");
		try {
			cu.setComment(CodeUnit.PLATE_COMMENT, null);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		program.flushEvents();
		waitForPostedSwingRunnables();

		goToService.goTo(addr);

		setBooleanOption(PlateFieldFactory.SHOW_FUNCTION_PLATES_OPTION, true);

		assertTrue(cb.goToField(addr, PlateFieldFactory.FIELD_NAME, 1, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertEquals(3, tf.getNumRows());
		assertTrue(tf.getText().indexOf(PlateFieldFactory.FUNCTION_PLATE_COMMENT) > 0);
	}

	@Test
	public void testExistingPlateComment() throws Exception {
		Symbol symbol = getUniqueSymbol(program, "entry");
		Address addr = symbol.getAddress();
		int transactionID = program.startTransaction("test");
		try {
			CodeUnit cu = program.getListing().getCodeUnitAt(addr);
			cu.setCommentAsArray(CodeUnit.PLATE_COMMENT,
				new String[] { "this is", "a plate comment" });
			// create a reference to addr
			program.getReferenceManager().addMemoryReference(getAddr(0x010023ee), addr,
				RefType.DATA, SourceType.USER_DEFINED, 0);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		program.flushEvents();
		waitForPostedSwingRunnables();
		cb.updateNow();

		Function function = program.getFunctionManager().getFunctionAt(addr);
		CodeUnit cu = program.getListing().getCodeUnitAt(function.getEntryPoint());
		String[] plateComments = cu.getCommentAsArray(CodeUnit.PLATE_COMMENT);

		goToService.goTo(addr);

		setBooleanOption(PlateFieldFactory.SHOW_FUNCTION_PLATES_OPTION, true);

		assertTrue(cb.goToField(addr, PlateFieldFactory.FIELD_NAME, 1, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		// did not change the display of the plate comments
		assertEquals(4, tf.getNumRows());
		assertTrue(tf.getFieldElement(1, 4).getText().indexOf(plateComments[0]) >= 0);
		assertTrue(tf.getFieldElement(2, 4).getText().indexOf(plateComments[1]) >= 0);
	}

	@Test
	public void testPlateCommentEllipsesAndTooltip() throws Exception {
		Symbol symbol = getUniqueSymbol(program, "entry");
		Address addr = symbol.getAddress();
		String originalText =
			"this is a plate comment that is meant to be longer than the available " +
				"width, as to trigger clipping";
		int transactionID = program.startTransaction("test");
		try {
			CodeUnit cu = program.getListing().getCodeUnitAt(addr);
			cu.setCommentAsArray(CodeUnit.PLATE_COMMENT, new String[] { originalText });
			// create a reference to addr
			program.getReferenceManager().addMemoryReference(getAddr(0x010023ee), addr,
				RefType.DATA, SourceType.USER_DEFINED, 0);
		}
		finally {
			program.endTransaction(transactionID, true);
		}

		program.flushEvents();
		waitForPostedSwingRunnables();
		cb.updateNow();

		goToService.goTo(addr);

		setBooleanOption(PlateFieldFactory.SHOW_FUNCTION_PLATES_OPTION, true);

		assertTrue(cb.goToField(addr, PlateFieldFactory.FIELD_NAME, 1, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertEquals(3, tf.getNumRows());
		String text = tf.getText();
		assertTrue("Text does not have ellipses: " + text, text.indexOf("... *") != -1);

		// check tooltip
		String fullText = tf.getTextWithLineSeparators();
		assertEquals(originalText, fullText);
	}

	@Test
	public void testShowExternalPlates() throws Exception {
		Symbol symbol = getUniqueSymbol(program, "entry");
		Address addr = symbol.getAddress();
		CodeUnit cu = program.getListing().getCodeUnitAt(addr);
		int transactionID = program.startTransaction("test");
		try {
			CreateFunctionCmd cmd = new CreateFunctionCmd(addr);
			cmd.applyTo(program);
			cu.setComment(CodeUnit.PLATE_COMMENT, null);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		program.flushEvents();
		waitForPostedSwingRunnables();
		cb.updateNow();

		goToService.goTo(addr);

		setBooleanOption(PlateFieldFactory.SHOW_EXT_ENTRY_PLATES_OPTION, true);

		assertTrue(cb.goToField(addr, PlateFieldFactory.FIELD_NAME, 1, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertEquals(3, tf.getNumRows());
		assertTrue(tf.getText().indexOf(PlateFieldFactory.EXT_ENTRY_PLATE_COMMENT) > 0);
	}

	@Test
	public void testShowTransitionPlates() throws Exception {

		// no plate comment
		assertTrue(!cb.goToField(getAddr(0x1001100), PlateFieldFactory.FIELD_NAME, 1, 1));

		setBooleanOption(PlateFieldFactory.SHOW_TRANSITION_PLATES_OPTION, true);

		// now there is a plate comment
		assertTrue(cb.goToField(getAddr(0x1001100), PlateFieldFactory.FIELD_NAME, 1, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertEquals(3, tf.getNumRows());
		assertTrue(tf.getText().indexOf(PlateFieldFactory.DEFAULT_PLATE_COMMENT) >= 0);

	}

	@Test
	public void testDeadCodePlate() throws Exception {
		Address addr = getAddr(0x01004e2e);
		DisassembleCommand cmd =
			new DisassembleCommand(addr, new AddressSet(addr, getAddr(0x01004e39)), true);
		tool.execute(cmd, program);
		program.flushEvents();
		waitForPostedSwingRunnables();

		setBooleanOption(PlateFieldFactory.SHOW_TRANSITION_PLATES_OPTION, true);
		assertTrue(cb.goToField(addr, PlateFieldFactory.FIELD_NAME, 1, 1));

		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertEquals(3, tf.getNumRows());
		assertTrue(cb.goToField(addr, PlateFieldFactory.FIELD_NAME, 1, 1));
		assertEquals(3, tf.getNumRows());
		assertTrue(tf.getText().indexOf(PlateFieldFactory.DEAD_CODE_PLATE_COMMENT) >= 0);
	}

	@Test
	public void testShowSubroutinePlates() throws Exception {

		// no subroutine plate comment
		assertTrue(!cb.goToField(getAddr(0x1001200), PlateFieldFactory.FIELD_NAME, 1, 1));

		setBooleanOption(PlateFieldFactory.SHOW_SUBROUTINE_PLATES_OPTION, true);

		// now there is a subroutine plate comment
		assertTrue(cb.goToField(getAddr(0x1001200), PlateFieldFactory.FIELD_NAME, 1, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertEquals(3, tf.getNumRows());
		assertTrue(tf.getText().indexOf(PlateFieldFactory.SUBROUTINE_PLATE_COMMENT) >= 0);

	}

	@Test
	public void testLinesBeforeFunction() throws Exception {

		assertTrue(!cb.goToField(getAddr(0x1001300), PlateFieldFactory.FIELD_NAME, 1, 1));

		setIntOption(PlateFieldFactory.LINES_BEFORE_FUNCTIONS_OPTION, 2);

		assertTrue(cb.goToField(getAddr(0x1001300), PlateFieldFactory.FIELD_NAME, 1, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertEquals(2, tf.getNumRows());
//		list.add(cu.getMinAddress());
//
//		ArrayList<Address> list = new ArrayList<Address>();
//		Listing listing = program.getListing();
//
//		FunctionIterator iter = listing.getFunctions(true);
//		while (iter.hasNext()) {
//			Function f = iter.next();
//			CodeUnit cu = listing.getCodeUnitAt(f.getEntryPoint());
//			assertTrue(cbPlugin.goToField(cu.getMinAddress(), PlateFieldFactory.FIELD_NAME, 1, 1));
//			ListingTextField tf = (ListingTextField) cbPlugin.getCurrentField();
//			assertEquals(5, tf.getNumRows());
//			list.add(cu.getMinAddress());
//		}
//		assertEquals(66, list.size());
	}

	@Test
	public void testLinesBeforeLabels() throws Exception {

		setIntOption(PlateFieldFactory.LINES_BEFORE_LABELS_OPTION, 3);
		Listing listing = program.getListing();
		SymbolIterator symIter = program.getSymbolTable().getSymbolIterator();
		while (symIter.hasNext()) {
			Symbol symbol = symIter.next();
			Address addr = symbol.getAddress();
			if (addr.isExternalAddress()) {
				continue;
			}

			CodeUnit cu = listing.getCodeUnitAt(addr);
			String[] plates = cu.getCommentAsArray(CodeUnit.PLATE_COMMENT);
			assertTrue("Failed to navigate to plate field at address: " + cu.getMinAddress(),
				cb.goToField(cu.getMinAddress(), PlateFieldFactory.FIELD_NAME, 1, 1));
			ListingTextField tf = (ListingTextField) cb.getCurrentField();
			if (plates == null || plates.length == 0) {
				assertEquals(3, tf.getNumRows());
			}
			else {
				assertEquals(plates.length + 5, tf.getNumRows());
			}
		}

	}

	@Test
	public void testLinesBeforePlates() throws Exception {
		Listing listing = program.getListing();

		CodeUnit cu = listing.getCodeUnitAt(getAddr(0x1001500));
		assertTrue(!cb.goToField(cu.getMinAddress(), PlateFieldFactory.FIELD_NAME, 1, 1));

		createPlateComment(cu, "This is a plate comment");

		assertTrue(cb.goToField(cu.getMinAddress(), PlateFieldFactory.FIELD_NAME, 1, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertEquals(3, tf.getNumRows());

		setIntOption(PlateFieldFactory.LINES_BEFORE_PLATES_OPTION, 2);

		assertTrue(cb.goToField(cu.getMinAddress(), PlateFieldFactory.FIELD_NAME, 1, 1));
		tf = (ListingTextField) cb.getCurrentField();
		assertEquals(5, tf.getNumRows());

	}

	private void createPlateComment(CodeUnit cu, String text) {
		int transactionID = program.startTransaction("test");
		try {
			cu.setComment(CodeUnit.PLATE_COMMENT, text);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		program.flushEvents();
		waitForPostedSwingRunnables();
		cb.updateNow();
	}

	@Test
	public void testLinesBeforeFunctionsPlates() throws Exception {

		setIntOption(PlateFieldFactory.LINES_BEFORE_FUNCTIONS_OPTION, 2);
		setIntOption(PlateFieldFactory.LINES_BEFORE_PLATES_OPTION, 5);

		Listing listing = program.getListing();

		// lines before functions should take precedence
		Function f = program.getFunctionManager().getFunctionAt(getAddr(0x1001300));
		CodeUnit cu = listing.getCodeUnitAt(f.getEntryPoint());
		assertTrue(cb.goToField(cu.getMinAddress(), PlateFieldFactory.FIELD_NAME, 1, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertEquals(2, tf.getNumRows());
	}

	@Test
	public void testLinesBeforePlatesLabels() throws Exception {

		setIntOption(PlateFieldFactory.LINES_BEFORE_PLATES_OPTION, 2);
		setIntOption(PlateFieldFactory.LINES_BEFORE_LABELS_OPTION, 7);

		// lines before plates should take precedence
		Listing listing = program.getListing();

		CodeUnit cu = listing.getCodeUnitAt(getAddr(0x1001400));
		assertTrue(cb.goToField(cu.getMinAddress(), PlateFieldFactory.FIELD_NAME, 1, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertEquals(5, tf.getNumRows());

	}

	@Test
	public void testLinesBeforeFunctionsLabels() throws Exception {

		setIntOption(PlateFieldFactory.LINES_BEFORE_FUNCTIONS_OPTION, 2);
		setIntOption(PlateFieldFactory.LINES_BEFORE_LABELS_OPTION, 6);

		Listing listing = program.getListing();

		// lines before functions should take precedence
		Function f = program.getFunctionManager().getFunctionAt(getAddr(0x1001300));
		CodeUnit cu = listing.getCodeUnitAt(f.getEntryPoint());
		assertTrue(cb.goToField(cu.getMinAddress(), PlateFieldFactory.FIELD_NAME, 1, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertEquals(2, tf.getNumRows());

	}

	@Test
	public void testNavigationOnAddress() throws Exception {
		// add a plate comment that has an address in it
		Address addr = getAddr(0x01002911);

		int transactionID = program.startTransaction("test");
		CodeUnit cu = program.getListing().getCodeUnitAt(addr);
		try {
			cu.setComment(CodeUnit.PLATE_COMMENT,
				"this is a comment\ngo to the address 0x010028de");
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertTrue(cb.goToField(cu.getMinAddress(), PlateFieldFactory.FIELD_NAME, 2, 23));
		click(cb, 2);

		assertEquals(getAddr(0x010028de), cb.getCurrentAddress());
	}

	@Test
	public void testNavigationOnAddress_WithBlankLinesBeforeHeader() throws Exception {

		int precedingBlankLines = 6;
		setIntOption(PlateFieldFactory.LINES_BEFORE_FUNCTIONS_OPTION, precedingBlankLines);
		setIntOption(PlateFieldFactory.LINES_BEFORE_LABELS_OPTION, precedingBlankLines);

		// add a plate comment that has an address in it
		Address addr = getAddr(0x01002911);

		int transactionID = program.startTransaction("test");
		CodeUnit cu = program.getListing().getCodeUnitAt(addr);
		try {
			program.getSymbolTable().createLabel(addr, testName.getMethodName(),
				SourceType.USER_DEFINED);
			cu.setComment(CodeUnit.PLATE_COMMENT,
				"this is a comment\ngo to the address 0x010028de");
		}
		finally {
			program.endTransaction(transactionID, true);
		}

		int nonCommentHeader = precedingBlankLines + 1; // +1 for the '***' line
		int row = nonCommentHeader + 1; // 1 is the second comment row

		assertTrue(cb.goToField(cu.getMinAddress(), PlateFieldFactory.FIELD_NAME, row, 23));
		click(cb, 2);

		assertEquals(getAddr(0x010028de), cb.getCurrentAddress());
	}

	@Test
	public void testNavigationOnLabel() throws Exception {
		// add a plate comment that has "entry" in it
		int transactionID = program.startTransaction("test");
		CodeUnit cu = program.getListing().getCodeUnitAt(getAddr(0x0100292b));
		try {
			cu.setComment(CodeUnit.PLATE_COMMENT, "go to entry");
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertTrue(cb.goToField(cu.getMinAddress(), PlateFieldFactory.FIELD_NAME, 1, 8));
		click(cb, 2);

		Symbol symbol = getUniqueSymbol(program, "entry");
		assertEquals(symbol.getAddress(), cb.getCurrentAddress());
	}

	@Test
	public void testNavigationOnLabelWildcard() throws Exception {
		// add a plate comment that has "entry" in it
		int transactionID = program.startTransaction("test");
		CodeUnit cu = program.getListing().getCodeUnitAt(getAddr(0x01001100));
		try {
			cu.setComment(CodeUnit.PLATE_COMMENT, "go to FUN*");
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertTrue(cb.goToField(cu.getMinAddress(), PlateFieldFactory.FIELD_NAME, 1, 8));
		click(cb, 2);
		waitForSwing();

		// should get the query results dialog that shows all the default function labels.
		List<TableComponentProvider<?>> providers = waitForResultsTable();
		assertEquals(1, providers.size());
		GhidraProgramTableModel<?> model = waitForModel(providers.get(0));
		assertEquals("01001300", model.getValueAt(0, 0).toString());
		assertEquals("01001500", model.getValueAt(1, 0).toString());
	}

	private List<TableComponentProvider<?>> waitForResultsTable() {

		List<TableComponentProvider<?>> providers = getNavigationResultsTables();

		waitForSwing();
		int nWaits = 0;
		while (providers.isEmpty() && nWaits < 200) {
			sleep(DEFAULT_WAIT_DELAY);
			providers = getNavigationResultsTables();
		}

		if (nWaits >= 200) {
			throw new AssertException("Timed out waiting for table model to load");
		}

		return providers;
	}

	private List<TableComponentProvider<?>> getNavigationResultsTables() {
		TableServicePlugin plugin = getPlugin(tool, TableServicePlugin.class);

		List<TableComponentProvider<?>> providers = new ArrayList<>();
		runSwing(() -> {
			TableComponentProvider<?>[] managedComponents = plugin.getManagedComponents();
			for (TableComponentProvider<?> tableComponentProvider : managedComponents) {
				providers.add(tableComponentProvider);
			}
		});
		return providers;
	}

	@Test
	public void testClickOnAsterisks() throws Exception {
		// click on first row of asterisks in the plate comment
		int transactionID = program.startTransaction("test");
		CodeUnit cu = program.getListing().getCodeUnitAt(getAddr(0x0100292b));
		try {
			cu.setComment(CodeUnit.PLATE_COMMENT, "go to FUN*");
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertTrue(cb.goToField(cu.getMinAddress(), PlateFieldFactory.FIELD_NAME, 0, 8));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertTrue(tf.getText().startsWith("*****"));
	}

	private GhidraProgramTableModel<?> waitForModel(TableComponentProvider<?> provider)
			throws Exception {
		GThreadedTablePanel<?> panel =
			(GThreadedTablePanel<?>) TestUtils.getInstanceField("threadedPanel", provider);
		GTable table = panel.getTable();
		while (panel.isBusy()) {
			Thread.sleep(50);
		}
		return (GhidraProgramTableModel<?>) table.getModel();
	}

	private Address getAddr(int offset) {
		return program.getMinAddress().getNewAddress(offset);
	}

	private void setBooleanOption(final String name, final boolean value) throws Exception {
		SwingUtilities.invokeAndWait(() -> fieldOptions.setBoolean(name, value));
		waitForPostedSwingRunnables();
		cb.updateNow();
	}

	private void setIntOption(final String name, final int value) throws Exception {
		SwingUtilities.invokeAndWait(() -> fieldOptions.setInt(name, value));
		waitForPostedSwingRunnables();
		cb.updateNow();
	}

	private void resetOptions() {
		List<String> names = fieldOptions.getOptionNames();
		for (int i = 0; i < names.size(); i++) {
			String name = names.get(i);
			if (!name.startsWith("Format Code")) {
				continue;
			}
			if (name.indexOf("Show ") >= 0 || name.indexOf("Flag ") >= 0) {
				fieldOptions.setBoolean(name, false);
			}
			else if (name.indexOf("Lines") >= 0) {
				fieldOptions.setInt(name, 0);
			}
		}
		waitForPostedSwingRunnables();
		cb.updateNow();
	}

}
