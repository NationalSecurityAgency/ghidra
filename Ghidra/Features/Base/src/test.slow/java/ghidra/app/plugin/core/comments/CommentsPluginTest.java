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
package ghidra.app.plugin.core.comments;

import static org.junit.Assert.*;

import java.util.List;

import javax.swing.*;

import org.junit.*;

import docking.action.DockingActionIf;
import docking.widgets.OptionDialog;
import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.table.GTable;
import docking.widgets.table.threaded.GThreadedTablePanel;
import generic.test.TestUtils;
import ghidra.GhidraOptions;
import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.navigation.GoToAddressLabelPlugin;
import ghidra.app.plugin.core.navigation.NextPrevAddressPlugin;
import ghidra.app.plugin.core.table.TableComponentProvider;
import ghidra.app.plugin.core.table.TableServicePlugin;
import ghidra.app.services.GoToService;
import ghidra.app.services.QueryData;
import ghidra.app.util.viewer.field.*;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.SystemUtilities;
import ghidra.util.table.GhidraProgramTableModel;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

public class CommentsPluginTest extends AbstractGhidraHeadedIntegrationTest {

	private final static int[] TYPES = new int[] { CodeUnit.EOL_COMMENT, CodeUnit.PRE_COMMENT,
		CodeUnit.POST_COMMENT, CodeUnit.PLATE_COMMENT, CodeUnit.REPEATABLE_COMMENT, };

	private final static String PRE = "This is a PRE comment.";
	private final static String POST = "This is a POST comment.";
	private final static String EOL = "This is a EOL comment.";
	private final static String PLATE = "This is a PLATE comment.";
	private final static String REPEAT = "This is a REPEATABLE comment.";

	private final static String PRE_U = PRE + "\n\nUPDATED";
	private final static String EOL_U = EOL + "\n\nUPDATED";

	private TestEnv env;
	private PluginTool tool;
	private CodeBrowserPlugin browser;
	private CommentsPlugin plugin;
	private DockingActionIf editAction;
	private DockingActionIf deleteAction;
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();

		tool = env.getTool();
		configureTool(tool);

		browser = env.getPlugin(CodeBrowserPlugin.class);
		plugin = env.getPlugin(CommentsPlugin.class);

		editAction = getAction(plugin, "Edit Comments");
		deleteAction = getAction(plugin, "Delete Comments");
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	/*******************************************************/

	@Test
	public void testStructures() throws Exception {
		openX86ProgramInTool();

		StructureDataType inner = new StructureDataType("INNER", 0);
		inner.add(new FloatDataType());
		inner.add(new CharDataType());

		StructureDataType outer = new StructureDataType("OUTER", 0);
		outer.add(new WordDataType());
		outer.add(inner);
		outer.add(new QWordDataType());

		Address addr = addr(0x010080a0);

		applyCmd(program, new CreateDataCmd(addr, outer));
		program.flushEvents();
		waitForSwing();

		Data data = program.getListing().getDataAt(addr);
		assertNotNull(data);

		browser.goToField(addr, "+", 0, 0);
		click(browser, 1);
		waitForSwing();

		FieldPanel fp = browser.getFieldPanel();
		fp.cursorDown();

		Data subData1 = data.getComponent(0);
		assertEquals(new WordDataType().getName(), subData1.getDataType().getName());
		String comment1 = "aaa bbb ccc ddd eee";
		setAt(addr, CodeUnit.EOL_COMMENT, comment1, "OK");
		assertEquals(comment1, subData1.getComment(CodeUnit.EOL_COMMENT));

		browser.goToField(addr(0x10080a2), "+", 0, 0);

		click(browser, 1);
		waitForSwing();

		addr = browser.getCurrentAddress();
		assertEquals(0x010080a2, addr.getOffset());

		Data subData = data.getComponent(1).getComponent(0);
		assertEquals(new FloatDataType().getName(), subData.getDataType().getName());
		String comment = "This is a comment on a structure element.";
		setAt(addr, CodeUnit.EOL_COMMENT, comment, "OK");
		assertEquals(comment, subData.getComment(CodeUnit.EOL_COMMENT));

		browser.goToField(addr(0x010080a2), EolCommentFieldFactory.FIELD_NAME, 0, 0);
		assertEquals(comment, browser.getCurrentFieldText());

		performAction(editAction, browser.getProvider(), false);
		waitForSwing();

		CommentsDialog commentsDialog = waitForDialogComponent(CommentsDialog.class);
		assertNotNull(commentsDialog);
		JDialog dialog = (JDialog) getInstanceField("dialog", commentsDialog);
		dialog.toFront();//need for running in eclipse...
		JTabbedPane tab = findComponent(dialog, JTabbedPane.class);
		assertNotNull(tab);
		JScrollPane scroll = (JScrollPane) tab.getSelectedComponent();
		JTextArea commentTextArea = (JTextArea) scroll.getViewport().getView();
		String str = commentTextArea.getText();
		setText(commentTextArea, str + "\n\nHI, MOM");

		pressButtonByText(dialog, "OK");
		program.flushEvents();
		waitForSwing();

		comment += "\n\nHI, MOM";
		assertEquals(comment, subData.getComment(CodeUnit.EOL_COMMENT));

		performAction(deleteAction, browser.getProvider(), false);
		waitForSwing();
		assertNull(subData.getComment(CodeUnit.EOL_COMMENT));
	}

	@Test
	public void testActiveTab() throws Exception {
		openX86ProgramInTool();
		Address addr = addr(0x01006420);

		for (int element : TYPES) {

			int txId = program.startTransaction("TEST");
			try {
				program.getListing().setComment(addr, element, "Test" + element);
			}
			finally {
				program.endTransaction(txId, true);
			}

			program.flushEvents();

			sendProgramLocation(addr, element);

			performAction(editAction, browser.getProvider(), false);
			waitForSwing();

			CommentsDialog dialog = waitForDialogComponent(CommentsDialog.class);
			assertNotNull(dialog);

			JTabbedPane tab = findComponent(dialog.getComponent(), JTabbedPane.class);
			assertNotNull(tab);

			assertEquals(element, tab.getSelectedIndex());

			pressButtonByText(dialog.getComponent(), "Dismiss", false);
			waitForSwing();
			undo(program);
		}
	}

	private static void setFieldWidth(CodeBrowserPlugin browser, String name, int width) {
		FieldFormatModel model =
			browser.getFormatManager().getModel(FieldFormatModel.INSTRUCTION_OR_DATA);
		int cnt = model.getNumRows();
		for (int r = 0; r < cnt; r++) {
			FieldFactory[] factories = model.getFactorys(r);
			for (FieldFactory f : factories) {
				if (name.equals(f.getFieldName())) {
					f.setWidth(width);
					model.modelChanged();
					return;
				}
			}
		}
	}

	@Test
	public void testEolFieldToolInteraction() throws Exception {

		openX86ProgramInTool();

		PluginTool tool2 = env.launchAnotherDefaultTool();
		configureTool(tool2);

		env.connectTools(tool, tool2);
		env.connectTools(tool2, tool);
		env.open(program); // do this again now that the tools are in-sync

		Address addr = addr(0x01006420);
		sendProgramLocation(addr, CodeUnit.EOL_COMMENT);

		String comment = "Drag and Drop is a direct manipulation gesture\n" +
			"found in many Graphical User Interface\n" +
			"systems that provides a mechanism to transfer information\n" +
			"between two entities logically associated with\n" +
			"presentation elements in the GUI.\n";

		setAt(addr, CodeUnit.EOL_COMMENT, comment, "OK");

		setFieldWidth(browser, EolCommentFieldFactory.FIELD_NAME, 100);

		Options options = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
		options.setBoolean(EolCommentFieldFactory.ENABLE_WORD_WRAP_MSG, true);
		options.setInt(EolCommentFieldFactory.MAX_DISPLAY_LINES_MSG, 100);

		runSwing(() -> tool.getToolFrame().setSize(800, 800));

		CodeBrowserPlugin browser2 = getPlugin(tool2, CodeBrowserPlugin.class);
		setFieldWidth(browser2, EolCommentFieldFactory.FIELD_NAME, 400);

		runSwing(() -> tool2.getToolFrame().setSize(1200, 800));

		browser.goToField(addr, EolCommentFieldFactory.FIELD_NAME, 17, 4);

		assertEquals(17, browser.getCurrentFieldLoction().getRow());
		assertEquals(4, browser.getCurrentFieldLoction().getCol());

		assertEquals(3, browser2.getCurrentFieldLoction().getRow());
		assertEquals(46, browser2.getCurrentFieldLoction().getCol());
	}

	@Test
	public void testSetPre() throws Exception {
		openX86ProgramInTool();
		Address addr = addr(0x01006420);
		CodeUnit cu = program.getListing().getCodeUnitAt(addr);
		setAt(addr, CodeUnit.PRE_COMMENT, PRE, "OK");
		assertEquals(PRE, cu.getComment(CodeUnit.PRE_COMMENT));
		undo(program);
		assertNull(cu.getComment(CodeUnit.PRE_COMMENT));
		redo(program);
		assertEquals(PRE, cu.getComment(CodeUnit.PRE_COMMENT));
		browser.goToField(addr, PreCommentFieldFactory.FIELD_NAME, 0, 0);
		assertEquals(PRE, browser.getCurrentFieldText());
	}

	@Test
	public void testSetPost() throws Exception {
		openX86ProgramInTool();
		Address addr = addr(0x01006420);
		CodeUnit cu = program.getListing().getCodeUnitAt(addr);
		setAt(addr, CodeUnit.POST_COMMENT, POST, "OK");
		assertEquals(POST, cu.getComment(CodeUnit.POST_COMMENT));
		undo(program);
		assertNull(cu.getComment(CodeUnit.POST_COMMENT));
		redo(program);
		assertEquals(POST, cu.getComment(CodeUnit.POST_COMMENT));
		browser.goToField(addr, PostCommentFieldFactory.FIELD_NAME, 0, 0);
		assertEquals(POST, browser.getCurrentFieldText());
	}

	@Test
	public void testSetEol() throws Exception {
		openX86ProgramInTool();
		Address addr = addr(0x01006420);
		CodeUnit cu = program.getListing().getCodeUnitAt(addr);
		setAt(addr, CodeUnit.EOL_COMMENT, EOL, "OK");
		assertEquals(EOL, cu.getComment(CodeUnit.EOL_COMMENT));
		undo(program);
		assertNull(cu.getComment(CodeUnit.EOL_COMMENT));
		redo(program);
		assertEquals(EOL, cu.getComment(CodeUnit.EOL_COMMENT));
		browser.goToField(addr, EolCommentFieldFactory.FIELD_NAME, 0, 0);
		assertEquals(EOL, browser.getCurrentFieldText());
	}

	@Test
	public void testSetPlate() throws Exception {
		openX86ProgramInTool();
		resetFormatOptions(browser);
		Address addr = addr(0x01006420);
		CodeUnit cu = program.getListing().getCodeUnitAt(addr);
		setAt(addr, CodeUnit.PLATE_COMMENT, PLATE, "OK");
		assertEquals(PLATE, cu.getComment(CodeUnit.PLATE_COMMENT));
		undo(program);
		assertNull(cu.getComment(CodeUnit.PLATE_COMMENT));
		redo(program);
		assertEquals(PLATE, cu.getComment(CodeUnit.PLATE_COMMENT));
		browser.goToField(addr, PlateFieldFactory.FIELD_NAME, 0, 0);
		//allow for the "*" that get added to the plate
		assertEquals(65, browser.getCurrentFieldText().indexOf(PLATE));
	}

	@Test
	public void testSetRepeatable() throws Exception {
		openX86ProgramInTool();
		Address addr = addr(0x01006420);
		CodeUnit cu = program.getListing().getCodeUnitAt(addr);
		setAt(addr, CodeUnit.REPEATABLE_COMMENT, REPEAT, "OK");
		assertEquals(REPEAT, cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		undo(program);
		assertNull(cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		redo(program);
		assertEquals(REPEAT, cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		browser.goToField(addr, EolCommentFieldFactory.FIELD_NAME, 0, 0);
		assertEquals(REPEAT, browser.getCurrentFieldText());
	}

	@Test
	public void testReallyLongRepeatableComment_SCR_8554() throws Exception {
		openX86ProgramInTool();
		Address addr = addr(0x01006420);
		CodeUnit cu = program.getListing().getCodeUnitAt(addr);

		String longComment = "Line 1\nLine 2\nLine 3\nLine 4\nLine 5\nLine 6\nLine 7\nLine 8\n";
		setAt(addr, CodeUnit.REPEATABLE_COMMENT, longComment, "OK");
		assertEquals(longComment, cu.getComment(CodeUnit.REPEATABLE_COMMENT));

		// this fails when excepting
		assertTrue(browser.goToField(addr, EolCommentFieldFactory.FIELD_NAME, 0, 0));
	}

	/*******************************************************/

	@Test
	public void testSetAll() throws Exception {
		openX86ProgramInTool();
		Address addr = addr(0x01006420);
		CodeUnit cu = program.getListing().getCodeUnitAt(addr);

		setAt(addr, CodeUnit.PRE_COMMENT, PRE, "OK");
		setAt(addr, CodeUnit.POST_COMMENT, POST, "OK");
		setAt(addr, CodeUnit.EOL_COMMENT, EOL, "OK");
		setAt(addr, CodeUnit.PLATE_COMMENT, PLATE, "OK");
		setAt(addr, CodeUnit.REPEATABLE_COMMENT, REPEAT, "OK");

		assertEquals(PRE, cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals(POST, cu.getComment(CodeUnit.POST_COMMENT));
		assertEquals(EOL, cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals(PLATE, cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals(REPEAT, cu.getComment(CodeUnit.REPEATABLE_COMMENT));

		undo(program, 5);

		assertNull(cu.getComment(CodeUnit.PRE_COMMENT));
		assertNull(cu.getComment(CodeUnit.POST_COMMENT));
		assertNull(cu.getComment(CodeUnit.EOL_COMMENT));
		assertNull(cu.getComment(CodeUnit.PLATE_COMMENT));
		assertNull(cu.getComment(CodeUnit.REPEATABLE_COMMENT));

		redo(program, 5);

		assertEquals(PRE, cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals(POST, cu.getComment(CodeUnit.POST_COMMENT));
		assertEquals(EOL, cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals(PLATE, cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals(REPEAT, cu.getComment(CodeUnit.REPEATABLE_COMMENT));
	}

	/*******************************************************/

	@Test
	public void testApplyButton() throws Exception {
		openX86ProgramInTool();
		Address addr = addr(0x01006000);
		CodeUnit cu = program.getListing().getCodeUnitAt(addr);
		setAt(addr, CodeUnit.REPEATABLE_COMMENT, "Bla bla bla", "Apply");
		final CommentsDialog commentsDialog = waitForDialogComponent(CommentsDialog.class);
		assertNotNull(commentsDialog);
		pressButtonByText(commentsDialog.getComponent(), "Dismiss", false);
		waitForSwing();
		assertEquals("Bla bla bla", cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertTrue(!commentsDialog.isVisible());
	}

	/*******************************************************/

	@Test
	public void testModify() throws Exception {
		openX86ProgramInTool();
		Address addr = addr(0xf0001300);
		CodeUnit cu = program.getListing().getCodeUnitAt(addr);
		setAt(addr, CodeUnit.PRE_COMMENT, PRE, "OK");
		setAt(addr, CodeUnit.PRE_COMMENT, PRE_U, "OK");
		undo(program);
		assertEquals(PRE, cu.getComment(CodeUnit.PRE_COMMENT));
		redo(program);
		assertEquals(PRE_U, cu.getComment(CodeUnit.PRE_COMMENT));
	}

	/*******************************************************/

	@Test
	public void testPromptForSaveChangesYes() throws Exception {
		openX86ProgramInTool();
		Address addr = addr(0x01006000);
		CodeUnit cu = program.getListing().getCodeUnitAt(addr);
		setAt(addr, CodeUnit.POST_COMMENT, "Bla bla bla", "Dismiss");
		CommentsDialog commentsDialog = waitForDialogComponent(CommentsDialog.class);
		OptionDialog saveDialog = waitForDialogComponent(OptionDialog.class);
		assertNotNull(saveDialog);
		assertEquals("Save Changes?", saveDialog.getTitle());

		JButton button = findButtonByText(saveDialog.getComponent(), "Yes");
		assertNotNull(button);
		pressButton(button, false);
		waitForSwing();

		assertEquals("Bla bla bla", cu.getComment(CodeUnit.POST_COMMENT));
		assertFalse(commentsDialog.isVisible());
	}

	@Test
	public void testPromptForSaveChangesNo() throws Exception {
		openX86ProgramInTool();
		Address addr = addr(0x01006000);
		CodeUnit cu = program.getListing().getCodeUnitAt(addr);
		setAt(addr, CodeUnit.POST_COMMENT, "Bla bla bla", "Dismiss");
		CommentsDialog commentsDialog = waitForDialogComponent(CommentsDialog.class);
		assertNotNull(commentsDialog);
		OptionDialog saveDialog = waitForDialogComponent(OptionDialog.class);
		assertNotNull(saveDialog);
		assertEquals("Save Changes?", saveDialog.getTitle());

		JButton button = findButtonByText(saveDialog.getComponent(), "No");
		assertNotNull(button);
		pressButton(button, false);
		waitForSwing();

		assertNull(cu.getComment(CodeUnit.POST_COMMENT));
		assertFalse(commentsDialog.isVisible());
	}

	@Test
	public void testPromptForSaveChangesCancel() throws Exception {
		openX86ProgramInTool();
		Address addr = addr(0x01006000);
		CodeUnit cu = program.getListing().getCodeUnitAt(addr);
		setAt(addr, CodeUnit.POST_COMMENT, "Bla bla bla", "Dismiss");
		CommentsDialog commentsDialog = waitForDialogComponent(CommentsDialog.class);
		assertNotNull(commentsDialog);

		OptionDialog saveDialog = waitForDialogComponent(OptionDialog.class);
		assertNotNull(saveDialog);
		assertEquals("Save Changes?", saveDialog.getTitle());

		JButton button = findButtonByText(saveDialog.getComponent(), "Cancel");
		assertNotNull(button);
		pressButton(button, false);
		waitForSwing();

		assertNull(cu.getComment(CodeUnit.POST_COMMENT));
		assertTrue(commentsDialog.isVisible());

		close(commentsDialog);
	}

	@Test
	public void testRemove() throws Exception {
		openX86ProgramInTool();
		Address addr = addr(0xf0000250);
		CodeUnit cu = program.getListing().getCodeUnitAt(addr);
		setAt(addr, CodeUnit.PLATE_COMMENT, PLATE, "OK");
		assertEquals(PLATE, cu.getComment(CodeUnit.PLATE_COMMENT));
		removeAt(addr, CodeUnit.PLATE_COMMENT);
		assertNull(cu.getComment(CodeUnit.PLATE_COMMENT));
		undo(program);
		assertEquals(PLATE, cu.getComment(CodeUnit.PLATE_COMMENT));
		redo(program);
		assertNull(cu.getComment(CodeUnit.PLATE_COMMENT));
	}

	@Test
	public void testHistory() throws Exception {
		openX86ProgramInTool();
		Address addr = addr(0x0100bbbb);

		setAt(addr, CodeUnit.EOL_COMMENT, EOL, "OK");
		setAt(addr, CodeUnit.EOL_COMMENT, EOL_U, "OK");

		CommentHistory[] history =
			program.getListing().getCommentHistory(addr, CodeUnit.EOL_COMMENT);
		assertEquals(2, history.length);

		for (int i = 0; i < history.length; i++) {
			assertEquals(SystemUtilities.getUserName(), history[i].getUserName());
			assertEquals(addr, history[i].getAddress());
			switch (i) {
				case 0:
					assertEquals(EOL_U, history[i].getComments());
					break;
				case 1:
					assertEquals(EOL, history[i].getComments());
					break;
			}
		}
	}

	/*******************************************************/

	@Test
	public void testReallyBigComment() throws Exception {
		openX86ProgramInTool();

		StringBuilder buffer = new StringBuilder();
		for (int i = 0; i < 1000; i++) {
			buffer.append("This is a big comment - line " + 1);
			buffer.append("\n");
		}

		String comment = buffer.toString();
		Address addr = addr(0x01006000);
		CodeUnit cu = program.getListing().getCodeUnitAt(addr);
		setAt(addr, CodeUnit.PRE_COMMENT, comment, "OK");
		assertEquals(comment, cu.getComment(CodeUnit.PRE_COMMENT));
	}

	/*******************************************************/

	@Test
	public void testNavigationFromSymbol() throws Exception {
		openX86ProgramInTool();

		// instigate dynamic data label at 1008094
		addReference(0x1001000, 0x1008094, RefType.DATA);

		Address srcAddr = addr(0x01006990);
		CodeUnit cu = program.getListing().getCodeUnitAt(srcAddr);

		String comment = "This is a comment DAT_01008094 with a label in it.";
		setAt(srcAddr, CodeUnit.PRE_COMMENT, comment, "OK");
		assertEquals(comment, cu.getComment(CodeUnit.PRE_COMMENT));

		browser.goToField(srcAddr, PreCommentFieldFactory.FIELD_NAME, 0, 23);
		click(browser, 2);

		Address destAddr = addr(0x01008094);
		assertEquals(destAddr, browser.getCurrentLocation().getAddress());
	}

	@Test
	public void testNavigationFromAddress() throws Exception {
		openX86ProgramInTool();
		Address srcAddr = addr(0x01006990);
		CodeUnit cu = program.getListing().getCodeUnitAt(srcAddr);

		String comment = "This is a comment 01008094 with an address in it.";
		setAt(srcAddr, CodeUnit.PRE_COMMENT, comment, "OK");
		assertEquals(comment, cu.getComment(CodeUnit.PRE_COMMENT));

		browser.goToField(srcAddr, PreCommentFieldFactory.FIELD_NAME, 0, 23);
		click(browser, 2);

		Address destAddr = addr(0x01008094);
		assertEquals(destAddr, browser.getCurrentLocation().getAddress());
	}

	@Test
	public void testNavigationSymbolAnnotation() throws Exception {
		openX86ProgramInTool();

		// instigate dynamic data label at 1008094
		addReference(0x1001000, 0x1008094, RefType.DATA);

		Address srcAddr = addr(0x01006990);

		String comment = "This is a comment {@sym DAT_01008094} with an annotation in it.";
		setAt(srcAddr, CodeUnit.PRE_COMMENT, comment, "OK");

		browser.goToField(srcAddr, PreCommentFieldFactory.FIELD_NAME, 0, 23);
		click(browser, 2);

		Address destAddr = addr(0x01008094);
		assertEquals(destAddr, browser.getCurrentLocation().getAddress());
	}

	@Test
	public void testNavigationSymbolAnnotation_WithNamespace() throws Exception {
		openX86ProgramInTool();

		Address srcAddr = addr(0x01006990);

		String comment = "This is a comment {@sym Deadpool::Bob} with an annotation in it.";
		setAt(srcAddr, CodeUnit.PRE_COMMENT, comment, "OK");

		browser.goToField(srcAddr, PreCommentFieldFactory.FIELD_NAME, 0, 20);
		click(browser, 2);

		Address destAddr = addr(0x01006100);
		assertEquals(destAddr, browser.getCurrentLocation().getAddress());
	}

	@Test
	public void testNavigationProgramAnnotation() throws Exception {
		openX86ProgramInTool();

		Address srcAddr = addr(0x01006990);

		String comment = "This is a symbol {@program Test@Deadpool::Bob} annotation.";
		setAt(srcAddr, CodeUnit.PRE_COMMENT, comment, "OK");

		browser.goToField(srcAddr, PreCommentFieldFactory.FIELD_NAME, 0, 23);
		click(browser, 2);

		Address destAddr = addr(0x01006100);
		assertEquals(destAddr, browser.getCurrentLocation().getAddress());
	}

	@Test
	public void testNavigationFromWildcard() throws Exception {
		openX86ProgramInTool();

		// instigate dynamic data labels
		addReference(0x1001000, 0x1008094, RefType.DATA);
		addReference(0x1001010, 0x1008194, RefType.DATA);
		addReference(0x1001020, 0x1008294, RefType.DATA);
		addReference(0x1001030, 0x1008394, RefType.DATA);

		Address srcAddr = addr(0x01006990);
		CodeUnit cu = program.getListing().getCodeUnitAt(srcAddr);

		String comment = "This is a comment DAT_* with a wildcard in it.";
		setAt(srcAddr, CodeUnit.PRE_COMMENT, comment, "OK");
		assertEquals(comment, cu.getComment(CodeUnit.PRE_COMMENT));

		browser.goToField(srcAddr, PreCommentFieldFactory.FIELD_NAME, 0, 19);
		click(browser, 2);

		GhidraProgramTableModel<?> model = waitForModel();

		assertEquals(4, model.getRowCount());

		GTable table = getTable();
		clickTableCell(table, 3, 0, 2);
		waitForSwing();

		Address destAddr = addr(0x01008394);
		assertEquals(destAddr, browser.getCurrentLocation().getAddress());

		getProviders()[0].closeComponent();

		assertEquals(destAddr, browser.getCurrentLocation().getAddress());
	}

	@Test
	public void testNavigationIn8051() throws Exception {
		resetFormatOptions(browser);

		open8051Program();

		AddressFactory af = program.getAddressFactory();
		AddressSpace codeSpace = af.getAddressSpace("CODE");
		AddressSpace extmemSpace = af.getAddressSpace("EXTMEM");

		Address addr = extmemSpace.getAddress(0);
		setAt(addr, CodeUnit.PLATE_COMMENT, "Around the world in 80 days.", "OK");

		browser.goToField(addr, PlateFieldFactory.FIELD_NAME, 1, 22);
		click(browser, 2);

		assertEquals(extmemSpace.getAddress(0x80), browser.getCurrentLocation().getAddress());
	}

	@Test
	public void testNoConvertingTabCharacters() throws Exception {
		openX86ProgramInTool();
		Address addr = addr(0x01006420);
		CodeUnit cu = program.getListing().getCodeUnitAt(addr);
		String tabComment = "abcd\tdefg\n\t1\t2\t3\t4";
		setAt(addr, CodeUnit.PLATE_COMMENT, tabComment, "OK");

		// space comment is exactly the same; i.e. make sure that no tab conversion happens
		String spaceComment = "abcd\tdefg\n\t1\t2\t3\t4";
		assertEquals(spaceComment, cu.getComment(CodeUnit.PLATE_COMMENT));
	}

	/*******************************************************/

	/**
	 * Test that when using the GoTo service the edit comments action
	 * is enabled.
	 *
	 * @since Tracker Id 354
	 */
	@Test
	public void testGoToEditCommentEnablement() throws Exception {
		openX86ProgramInTool();

		// create function at 0x1008040
		Address functionAddress = addr(0x1008040);
		addFunction("TestFunc", 0x1008040, 0x20);

		Address startAddress = addr(0x01006420);
		GoToService service = tool.getService(GoToService.class);

		// make sure we are starting on a known address
		service.goTo(startAddress);

		// in order to catch the bug for which this test was written we need
		// to call the goToQuery() method of the GoToService because that
		// method call results in a generic ProgramLocation event being
		// generated, whereas the goTo() methods will use a more specific
		// location, like an AddressFieldLocation
		Address nextAddress = startAddress.next();
		service.goToQuery(startAddress, new QueryData(nextAddress.toString(), false), null, null);

		// this call would fail before the fix was in place
		assertTrue("The edit comments action is not enabled after using " + "the GoToService.",
			editAction.isEnabledForContext(browser.getProvider().getActionContext(null)) &&
				editAction.isEnabled());

		// now go to a function location and make sure the action is disabled
		assertTrue("Unable to use the code browser to go to a function " + "signature location.",
			browser.goToField(functionAddress, FunctionSignatureFieldFactory.FIELD_NAME, 0, 0));

		assertTrue(
			"The edit comments action is not enabled when the current " +
				"program location is on a comment editable location.",
			editAction.isEnabledForContext(browser.getProvider().getActionContext(null)) &&
				editAction.isEnabled());

		assertTrue("Unable to use the code browser to go to a function " + "signature location.",
			browser.goToField(functionAddress, VariableCommentFieldFactory.FIELD_NAME, 0, 0));

		assertTrue(
			"The edit comments action is enabled over a variable " +
				"location when editing these comments is covered by a different " + "action.",
			!editAction.isEnabledForContext(browser.getProvider().getActionContext(null)));
	}

	private void setAt(Address addr, int commentType, String comment, String nameOfButtonToClick)
			throws Exception {

		assertTrue(browser.goToField(addr, AddressFieldFactory.FIELD_NAME, 0, 0));

		performAction(editAction, browser.getProvider(), false);
		waitForSwing();

		CommentsDialog dialog = waitForDialogComponent(CommentsDialog.class);
		assertNotNull(dialog);
		assertEquals("Set Comment(s) at Address " + addr.toString(), dialog.getTitle());

		runSwing(() -> dialog.setCommentType(commentType));
		waitForSwing();

		JTabbedPane tab = findComponent(dialog.getComponent(), JTabbedPane.class);
		assertNotNull(tab);
		JScrollPane scroll = (JScrollPane) tab.getSelectedComponent();
		JTextArea commentTextArea = (JTextArea) scroll.getViewport().getView();
		assertNotNull(commentTextArea);

		runSwing(() -> commentTextArea.setText(comment));
		waitForSwing();

		JButton button = findButtonByText(dialog.getComponent(), nameOfButtonToClick);
		assertNotNull(button);
		pressButton(button, false);
		waitForSwing();
	}

	private void removeAt(Address addr, int commentType) throws Exception {
		sendProgramLocation(addr, commentType);
		performAction(deleteAction, browser.getProvider(), false);
		waitForSwing();
	}

	private Address addr(long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	private ProgramLocation sendProgramLocation(Address addr, int type) {
		CodeUnit cu = program.getListing().getCodeUnitAt(addr);
		String[] comment = cu.getCommentAsArray(type);

		ProgramLocation loc = type == CodeUnit.EOL_COMMENT
				? new EolCommentFieldLocation(program, addr, null, comment, 0, 0, 0)
				: new CommentFieldLocation(program, addr, null, comment, type, 0, 0);

		tool.firePluginEvent(
			new ProgramLocationPluginEvent(testName.getMethodName(), loc, program));

		return loc;
	}

	private void openX86ProgramInTool() throws Exception {

		program = createDefaultProgram("Test", ProgramBuilder._X86, this);
		Memory memory = program.getMemory();
		int transactionID = program.startTransaction("Test");
		try {
			memory.createInitializedBlock("test1", addr(0x1006000), 0x1000, (byte) 0,
				TaskMonitorAdapter.DUMMY_MONITOR, false);
			memory.createInitializedBlock("test2", addr(0x1008000), 0x1000, (byte) 0,
				TaskMonitorAdapter.DUMMY_MONITOR, false);
			memory.createInitializedBlock("test3", addr(0x100b000), 0x1000, (byte) 0,
				TaskMonitorAdapter.DUMMY_MONITOR, false);
			memory.createInitializedBlock("test4", addr(0xf0000000), 0x2000, (byte) 0,
				TaskMonitorAdapter.DUMMY_MONITOR, false);

			SymbolTable st = program.getSymbolTable();
			Namespace ns = st.createNameSpace(null, "Deadpool", SourceType.USER_DEFINED);
			st.createLabel(addr(0x01006100), "Bob", ns, SourceType.USER_DEFINED);

		}
		finally {
			program.endTransaction(transactionID, true);
		}
		// write the file to the project to test external navigation for comment annotation
		env.getProject().getProjectData().getRootFolder().createFile("Test", program,
			TaskMonitor.DUMMY);
		env.showTool(program);
	}

	private void open8051Program() throws Exception {

		program = createDefaultProgram("Test", ProgramBuilder._8051, this);
		Memory memory = program.getMemory();

		AddressFactory af = program.getAddressFactory();
		AddressSpace codeSpace = af.getAddressSpace("CODE");
		AddressSpace extmemSpace = af.getAddressSpace("EXTMEM");

		int transactionID = program.startTransaction("Test");
		try {
			memory.createInitializedBlock("EEPROM", extmemSpace.getAddress(0), 0x100, (byte) 0,
				TaskMonitorAdapter.DUMMY_MONITOR, false);
			memory.createInitializedBlock("CODE", codeSpace.getAddress(0), 0x100, (byte) 0,
				TaskMonitorAdapter.DUMMY_MONITOR, false);
		}
		finally {
			program.endTransaction(transactionID, true);
		}

		env.showTool(program);
		waitForSwing();
	}

	private Reference addReference(long fromOffset, long toOffset, RefType refType) {
		int transactionID = program.startTransaction("Add Reference");
		try {
			return program.getReferenceManager().addMemoryReference(addr(fromOffset),
				addr(toOffset), refType, SourceType.USER_DEFINED, 0);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
	}

	private Function addFunction(String name, long functionEntry, int size) throws Exception {
		int transactionID = program.startTransaction("Add Function");
		try {
			Function function =
				program.getFunctionManager().createFunction(name, addr(functionEntry),
					new AddressSet(addr(functionEntry), addr(functionEntry + size - 1)),
					SourceType.USER_DEFINED);
			ReturnParameterImpl returnParam =
				new ReturnParameterImpl(IntegerDataType.dataType, program);
			ParameterImpl param1 = new ParameterImpl("p1", ByteDataType.dataType, program);
			param1.setComment("First Param");
			ParameterImpl param2 = new ParameterImpl("p2", IntegerDataType.dataType, program);
			param2.setComment("Second Param");
			function.updateFunction(
				program.getCompilerSpec().getDefaultCallingConvention().getName(), returnParam,
				FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.USER_DEFINED,
				param1, param2);
			return function;
		}
		finally {
			program.endTransaction(transactionID, true);
		}
	}

	private void configureTool(PluginTool pluginTool) throws Exception {
		pluginTool.addPlugin(CodeBrowserPlugin.class.getName());
		pluginTool.addPlugin(NextPrevAddressPlugin.class.getName());
		pluginTool.addPlugin(GoToAddressLabelPlugin.class.getName());
		pluginTool.addPlugin(CommentsPlugin.class.getName());

	}

	private GhidraProgramTableModel<?> waitForModel() throws Exception {
		int i = 0;
		while (i++ < 50) {
			TableComponentProvider<?>[] providers = getProviders();
			if (providers.length > 0) {
				GThreadedTablePanel<?> panel =
					(GThreadedTablePanel<?>) TestUtils.getInstanceField("threadedPanel",
						providers[0]);
				GTable table = panel.getTable();
				while (panel.isBusy()) {
					Thread.sleep(50);
				}
				return (GhidraProgramTableModel<?>) table.getModel();
			}
			Thread.sleep(50);
		}
		throw new Exception("Unable to get threaded table model");
	}

	private TableComponentProvider<?>[] getProviders() {
		TableServicePlugin tableServicePlugin = getPlugin(tool, TableServicePlugin.class);
		return tableServicePlugin.getManagedComponents();
	}

	private GTable getTable() {
		TableComponentProvider<?>[] providers = getProviders();
		assertEquals(1, providers.length);
		GThreadedTablePanel<?> panel =
			(GThreadedTablePanel<?>) TestUtils.getInstanceField("threadedPanel", providers[0]);
		return panel.getTable();
	}

	private void resetFormatOptions(CodeBrowserPlugin codeBrowserPlugin) {
		Options fieldOptions = codeBrowserPlugin.getFormatManager().getFieldOptions();
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
		waitForSwing();
		codeBrowserPlugin.updateNow();
	}
}
