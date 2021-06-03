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
package ghidra.app.plugin.core.datamgr;

import static org.junit.Assert.*;

import java.io.*;

import javax.swing.JButton;
import javax.swing.SwingUtilities;
import javax.swing.event.TreeModelEvent;
import javax.swing.event.TreeModelListener;

import org.junit.*;

import docking.action.DockingActionIf;
import docking.widgets.filechooser.GhidraFileChooser;
import generic.test.TestUtils;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.datamgr.tree.ArchiveRootNode;
import ghidra.app.plugin.core.datamgr.tree.DataTypeArchiveGTree;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;

public abstract class AbstractCreateArchiveTest extends AbstractGhidraHeadedIntegrationTest {

	protected ArchiveRootNode archiveRootNode;
	protected TestEnv env;
	protected DataTypeManagerPlugin plugin;
	protected ProgramDB program;
	protected DataTypesProvider provider;
	protected PluginTool tool;
	protected DataTypeArchiveGTree tree;
	protected TreeModelModCounter treeModelModListener;

	protected ProgramDB buildProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("notepad", ProgramBuilder._TOY, this);

		builder.createMemory(".text", "0x1001000", 0x6600);
		builder.createMemory(".data", "0x1008000", 0x600);
		builder.createMemory(".data", "0x1008600", 0x1344);
		builder.createMemory(".rsrc", "0x100a000", 0x5400);
		builder.addCategory(new CategoryPath("/MISC"));
		CategoryPath path = new CategoryPath("/Category1");
		builder.addCategory(path);
		path = new CategoryPath(path, "Category2");
		builder.addCategory(path);
		path = new CategoryPath(path, "Category5");
		builder.addCategory(path);
		StructureDataType dt = new StructureDataType("DLL_Table", 0);
		dt.add(new WordDataType());
		builder.addDataType(dt);
		return builder.getProgram();
	}

	protected boolean chooserIsPendingUpdate(GhidraFileChooser chooser) {
		return (Boolean) TestUtils.invokeInstanceMethod("pendingUpdate", chooser);
	}

	protected void createCategory(Category category, String newCategoryName) {
		DataTypeManager dataTypeManager = category.getDataTypeManager();
		int id = dataTypeManager.startTransaction("new category");
		try {
			category.createCategory(newCategoryName);
		}
		catch (InvalidNameException e) {
			Assert.fail("Unexpected invalid name exception");
			e.printStackTrace();
		}
		finally {
			dataTypeManager.endTransaction(id, true);
		}
		waitForTree();
	}

	protected void createNewArchive(String archiveName, boolean deleteExisting) throws Exception {
		File archiveFile = new File(getTestDirectoryPath(), archiveName);
		if (deleteExisting && archiveFile.exists()) {
			Msg.trace(this, "\t" + testName.getMethodName() + ": found existing file - deleting: " +
				archiveFile.getAbsolutePath());
			boolean didDelete = archiveFile.delete();
			Msg.trace(this,
				"\t\t" + testName.getMethodName() + ": did it get deleted?: " + didDelete);

			if (!didDelete) {
				// try one more time
				waitForPostedSwingRunnables();
				sleep(1000);
				waitForPostedSwingRunnables();
				didDelete = archiveFile.delete();
				Msg.trace(this, "\t\t" + testName.getMethodName() +
					"after sleeping: did it get deleted?: " + didDelete);
				if (!didDelete) {
					Assert.fail(
						"Unable to create an archive, as the file already exists: " + archiveName);
				}
			}
		}

		DockingActionIf action = getAction(plugin, "New File Data Type Archive");
		DataTypeTestUtils.performAction(action, tree, false);

		GhidraFileChooser chooser = waitForDialogComponent(GhidraFileChooser.class);
		assertNotNull("File chooser was never shown", chooser);
		archiveFile.deleteOnExit();
		selectFileInChooser(chooser, archiveFile);
		waitForUpdateOnChooser(chooser);

		// hit "Create Archive" button
		Msg.trace(this, testName.getMethodName() + ": calling create archive...");
		JButton createArchiveButton = findButtonByText(chooser, "Create Archive");
		pressButton(createArchiveButton);
		Msg.trace(this, testName.getMethodName() + ":\tpressed the button on the swing thread");
		waitForPostedSwingRunnables();
		Msg.trace(this,
			"\t" + testName.getMethodName() + ":\tdone waiting for thread - created archive");

		chooser = getDialogComponent(GhidraFileChooser.class);
		assertNull("Chooser did not get closed", chooser);
		waitForTree();
	}

	protected synchronized int getTreeModelInsertedNodeCount() {
		return treeModelModListener.insertedCount;
	}

	protected void selectFileInChooser(final GhidraFileChooser fileChooser, final File file)
			throws Exception {
		waitForUpdateOnDirectory(fileChooser);

		SwingUtilities.invokeAndWait(new Runnable() {
			@Override
			public void run() {
				Msg.trace(this,
					"\t\t\t" + testName.getMethodName() + "set file in chooser: " + file.getName());
				fileChooser.setSelectedFile(file);
			}
		});
		waitForUpdateOnChooser(fileChooser);
	}

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		setErrorGUIEnabled(false);
		tool.addPlugin(CodeBrowserPlugin.class.getName());

		tool.addPlugin(DataTypeManagerPlugin.class.getName());
		plugin = env.getPlugin(DataTypeManagerPlugin.class);

		program = buildProgram();
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());

		env.showTool();

		provider = plugin.getProvider();
		tree = provider.getGTree();
		treeModelModListener = new TreeModelModCounter();
		tree.addGTModelListener(treeModelModListener);
		archiveRootNode = (ArchiveRootNode) tree.getViewRoot();

		tool.showComponentProvider(provider, true);
	}

	/*
	 * @see TestCase#tearDown()
	 */
	@After
	public void tearDown() throws Exception {

		SwingUtilities.invokeLater(() -> {
			ProgramManager pm = tool.getService(ProgramManager.class);
			pm.closeProgram();
		});
		waitForPostedSwingRunnables();

		// this handles the save changes dialog and potential analysis dialogs
		closeAllWindowsAndFrames();
		env.release(program);
		env.dispose();
	}

	protected void waitForTree() {
		waitForTree(tree);
	}

	protected void waitForUpdateOnDirectory(GhidraFileChooser chooser) throws Exception {
		// make sure swing has handled any pending changes
		waitForPostedSwingRunnables();

		// artificially high wait period that won't be reached most of the time
		int timeoutMillis = 5000;
		int totalTime = 0;
		while (chooserIsPendingUpdate(chooser) && (totalTime < timeoutMillis)) {
			Thread.sleep(50);
			totalTime += 50;
		}

		if (totalTime >= timeoutMillis) {
			Assert.fail("Timed-out waiting for directory to load");
		}

		// make sure swing has handled any pending changes
		waitForPostedSwingRunnables();
	}

	protected File writeTempFile(String filename) throws IOException {

		File file = new File(getTestDirectoryPath(), filename);
		file.deleteOnExit();

		BufferedWriter writer = new BufferedWriter(new FileWriter(file));
		writer.write("test file");
		writer.flush();
		writer.close();

		return file;
	}

	protected class TreeModelModCounter implements TreeModelListener {
		protected int insertedCount;

		@Override
		public void treeNodesChanged(TreeModelEvent e) {
			// don't care
		}

		@Override
		public void treeNodesInserted(TreeModelEvent e) {
			++insertedCount;
		}

		@Override
		public void treeNodesRemoved(TreeModelEvent e) {
			// don't care
		}

		@Override
		public void treeStructureChanged(TreeModelEvent e) {
			// don't care
		}
	}

}
