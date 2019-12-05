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
package help.screenshot;

import static org.junit.Assert.*;

import java.io.IOException;

import javax.swing.JFrame;

import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.widgets.tree.GTreeNode;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.main.datatree.FindCheckoutsDialog;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.test.FrontEndTestEnv;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * This screen shot generator houses code that needs to connect to a running server
 */
public class VersionControlSlowScreenShots extends GhidraScreenShotGenerator {

	private FrontEndTestEnv frontEnd;

	@Override
	@Before
	public void setUp() throws Exception {

		// super.setUp();   don't do this; use our tool instead

		frontEnd = new FrontEndTestEnv(true);
	}

	@Override
	@After
	public void tearDown() throws Exception {

		// super.tearDown();  don't do this; use our tool instead
		if (frontEnd != null) {
			frontEnd.dispose();
		}
		showResults();
	}

	@Override
	public void loadProgram() {
		// don't need to load a program
	}

	@Override
	protected String getHelpTopicName() {
		// this is needed, since our filename does not match the help topic
		return "VersionControl";
	}

	@Test
	public void testCheckedOut() throws Exception {

		frontEnd.createMultipleCheckins();

		Program p1 = frontEnd.buildProgram(this);
		DomainFolder rootFolder = frontEnd.getRootFolder();

		// Program A created by the FrontEndTestEnv
		rootFolder.createFile("Program_B", p1, TaskMonitor.DUMMY);

		FrontEndTool t = frontEnd.getFrontEndTool();
		JFrame frame = t.getToolFrame();

		captureWindow(frame, 400, 550);
	}

	@Test
	public void testFindMyCheckouts() throws Exception {

		frontEnd.createMultipleCheckins();

		DomainFolder rootFolder = frontEnd.getRootFolder();
		DomainFolder folder = rootFolder.createFolder("myFolder_1");
		folder = folder.createFolder("myFolder_2");
		Program p = frontEnd.buildProgram(this);
		folder.createFile("My_Program", p, TaskMonitor.DUMMY);
		p.release(this);

		GTreeNode node = frontEnd.waitForFolderNode("myFolder_1");
		assertNotNull(node);
		node = node.getChild("myFolder_2");
		assertNotNull(node);
		node = node.getChild("My_Program");
		assertNotNull(node);
		frontEnd.addToVersionControl(node, true);

		GTreeNode rootNode = frontEnd.getRootNode();
		frontEnd.selectNodes(rootNode);
		DockingActionIf action = frontEnd.getAction("Find Checkouts");
		frontEnd.performFrontEndAction(action);

		FindCheckoutsDialog dialog = waitForDialogComponent(FindCheckoutsDialog.class);
		assertNotNull(dialog);

		captureDialog(dialog);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private ActionContext createContext(GTreeNode... nodes) {
		return frontEnd.getDomainFileActionContext(nodes);
	}

	protected void createHistoryEntry(Program p, String symbolName)
			throws InvalidInputException, IOException, CancelledException {
		int transactionID = p.startTransaction("test");
		try {
			SymbolTable symTable = p.getSymbolTable();
			symTable.createLabel(p.getMinAddress().getNewAddress(0x010001000), symbolName,
				SourceType.USER_DEFINED);
		}
		finally {
			p.endTransaction(transactionID, true);
			p.save(null, TaskMonitor.DUMMY);
		}
	}

	protected void showHistory(final GTreeNode node) {
		final DockingActionIf historyAction = frontEnd.getAction("Show History");
		runSwing(() -> historyAction.actionPerformed(createContext(node)));
	}
}
