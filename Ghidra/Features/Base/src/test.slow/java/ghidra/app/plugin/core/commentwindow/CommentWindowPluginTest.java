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
package ghidra.app.plugin.core.commentwindow;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.awt.Container;
import java.awt.Dimension;

import org.junit.*;

import docking.ComponentProvider;
import docking.widgets.table.GTable;
import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.test.*;

public class CommentWindowPluginTest extends AbstractGhidraHeadedIntegrationTest {
	private TestEnv env;
	private PluginTool tool;
	private AddressFactory addrFactory;
	private Program program;
	private CommentWindowPlugin plugin;
	private CodeBrowserPlugin browser;
	private GTable commentTable;
	private CommentWindowProvider provider;

	public CommentWindowPluginTest() {
		super();
	}

	@SuppressWarnings("unused")
	private Address addr(String address) {
		return addrFactory.getAddress(address);
	}

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		tool.addPlugin(CommentWindowPlugin.class.getName());
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		plugin = env.getPlugin(CommentWindowPlugin.class);
		browser = env.getPlugin(CodeBrowserPlugin.class);

		env.showTool();
		env.getTool().getToolFrame().setSize(new Dimension(1024, 768));
		waitForPostedSwingRunnables();
		provider = plugin.getProvider();
		loadProgram("notepad");

	}

	@After
	public void tearDown() {
		env.dispose();
	}

	private void loadProgram(String programName) throws Exception {

		ClassicSampleX86ProgramBuilder builder = new ClassicSampleX86ProgramBuilder();
		program = builder.getProgram();

		builder.createComment("01006420", "test EOL comment", CodeUnit.EOL_COMMENT);
		builder.createComment("01008004", "test Pre comment", CodeUnit.PRE_COMMENT);
		builder.createComment("0100b2b", "test Post comment", CodeUnit.POST_COMMENT);
		builder.createComment("010018a0", "test Plate comment", CodeUnit.PLATE_COMMENT);
		builder.createComment("010018cf", "test Repeatable comment", CodeUnit.REPEATABLE_COMMENT);

		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());
		builder.dispose();
		waitForPostedSwingRunnables();

		addrFactory = program.getAddressFactory();

		runSwing(() -> tool.showComponentProvider(provider, true));
		waitForPostedSwingRunnables();
		ComponentProvider commentWindowProvider = tool.getComponentProvider("Comment Window");
		Container container = commentWindowProvider.getComponent().getParent();
		assertNotNull(container);

		commentTable = (GTable) findComponentByName(container, "CommentTable");
		assertNotNull(commentTable);

		ThreadedTableModel<?, ?> tableModel = (ThreadedTableModel<?, ?>) commentTable.getModel();
		waitForTableModel(tableModel);
	}

	private void closeProgram() {
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.closeProgram(program, true);
	}

	@Test
	public void testNavigation() throws Exception {
		int numRows = commentTable.getRowCount();
		for (int i = 0; i < numRows; i++) {
			clickTableCell(commentTable, i, CommentTableModel.LOCATION_COL, 2);
			waitForPostedSwingRunnables();
			Address addr = browser.getCurrentAddress();
			Object tableAddr = addr.getAddress(
				commentTable.getValueAt(i, CommentTableModel.LOCATION_COL).toString());
			assertEquals(addr, tableAddr);
		}
	}

	@Test
	public void testCommentRemovedAndRestored() throws Exception {

		assertRowCount(5);

		clearComment(addr(0x010018cf));

		assertRowCount(4);

		undo(program);

		assertRowCount(5);
	}

	@Test
	public void testCommentAddedAndRestored() {

		int numComments = commentTable.getRowCount();

		assertEquals(5, numComments);

		addComment(addr("0x01001000"), CodeUnit.EOL_COMMENT, "Added EOL Comment");

		assertRowCount(6);

		undo(program);
		waitForTable();

		assertRowCount(5);
	}

	@Test
	public void testCommentChangedAndRestored() {

		int numComments = commentTable.getRowCount();

		assertEquals(5, numComments);

		// get the row we are testing
		int rowIndex = getTableRowIndex(addr("0x01006420"));
		Assert.assertNotEquals(-1, rowIndex);

		// First test to see if the comment we expect is in the table
		assertEquals("test EOL comment", getTableComment(rowIndex));

		// Then set the comment to a different value
		setComment(addr("0x01006420"), CodeUnit.EOL_COMMENT, "Changed EOL Comment");

		// Test to see if the changed comment is in the table
		assertEquals("Changed EOL Comment", getTableComment(rowIndex));

		// Undo and see if the original comment is back in the table			
		undo(program);
		waitForTable();

		assertEquals("test EOL comment", getTableComment(rowIndex));

	}

	@Test
	public void testProgramClose() throws Exception {

		closeProgram();

		waitForTable();

		assertEquals(commentTable.getRowCount(), 0);
		loadProgram("notepad");
	}

	private void addComment(Address addr, int commentType, String comment) {
		int id = program.startTransaction(testName.getMethodName());
		try {
			program.getListing().setComment(addr, commentType, comment);
		}
		finally {
			program.endTransaction(id, true);
		}
		waitForTable();
	}

	private void clearComment(Address addr) {
		int id = program.startTransaction(testName.getMethodName());
		try {
			program.getListing().clearComments(addr, addr);
		}
		finally {
			program.endTransaction(id, true);
		}

		waitForTable();
	}

	private void waitForTable() {
		ThreadedTableModel<?, ?> tableModel = (ThreadedTableModel<?, ?>) commentTable.getModel();
		waitForTableModel(tableModel);
	}

	private void assertRowCount(int n) {
		// unusual to not use an assert, but there seemed to be some timing issue with waitForTable()
		waitForCondition(() -> commentTable.getRowCount() == n);
	}

	private String getTableComment(int rowIndex) {
		return commentTable.getValueAt(rowIndex, CommentTableModel.COMMENT_COL).toString();
	}

	private void setComment(Address addr, int commentType, String comment) {
		int id = program.startTransaction(testName.getMethodName());
		try {
			program.getListing().setComment(addr, commentType, comment);
		}
		finally {
			program.endTransaction(id, true);
		}
		waitForTable();
	}

	private Address addr(long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	int getTableRowIndex(Address address) {

		int rowCount = commentTable.getRowCount();
		for (int i = 0; i < rowCount; i++) {

			Address addr = browser.getCurrentAddress();
			Object rowAddress = null;
			try {
				rowAddress = addr.getAddress(
					commentTable.getValueAt(i, CommentTableModel.LOCATION_COL).toString());
			}
			catch (AddressFormatException e) {
				e.printStackTrace();
			}

			if (address != null && address.equals(rowAddress)) {
				return i;
			}
		}
		return -1;

	}
}
