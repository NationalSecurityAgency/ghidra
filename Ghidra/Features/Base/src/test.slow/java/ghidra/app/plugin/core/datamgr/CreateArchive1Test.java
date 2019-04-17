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

import java.io.File;
import java.util.List;

import javax.swing.JButton;

import org.junit.Assert;
import org.junit.Test;

import docking.action.DockingActionIf;
import docking.widgets.OptionDialog;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.datamgr.archive.Archive;
import ghidra.app.plugin.core.datamgr.archive.FileArchive;
import ghidra.app.plugin.core.datamgr.tree.ArchiveNode;
import ghidra.framework.GenericRunInfo;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.util.Msg;

public class CreateArchive1Test extends AbstractCreateArchiveTest {

	@Test
	public void testCreateArchive() throws Exception {
		createNewArchive("MyArchive.gdt", true);

		// new node should be added to the tree; name is "Archive"
		ArchiveNode archiveNode = (ArchiveNode) archiveRootNode.getChild("MyArchive");
		assertNotNull(archiveNode);

		// verify that the archive is checked out
		assertTrue(((FileArchive) archiveNode.getArchive()).hasWriteLock());

	}

	@Test
	public void testCreateAndPopulate() throws Exception {
		// create new archive
		// make a change
		// save
		// close the archive
		// reopen the archive
		// check that the changes are there.
		String string = "MyArchive";
		createNewArchive(string + FileDataTypeManager.SUFFIX, true);

		ArchiveNode archiveNode = (ArchiveNode) archiveRootNode.getChild("MyArchive");
		createCategory(archiveNode.getCategory(), "bob");
		waitForTree();

		tree.setSelectedNode(archiveNode);
		waitForTree();

		createCategory(archiveNode.getCategory(), "joe");
		waitForTree();

		DockingActionIf action = getAction(plugin, "Save");
		DataTypeTestUtils.performAction(action, tree);
		waitForTree();

		action = getAction(plugin, "Close Archive");
		DataTypeTestUtils.performAction(action, tree);
		waitForTree();

		archiveNode =
			DataTypeTestUtils.openArchive(getTestDirectoryPath(), "MyArchive.gdt", false, plugin);
		assertNotNull(archiveNode.getChild("bob"));
		assertNotNull(archiveNode.getChild("joe"));

		File f = new File(getTestDirectoryPath(), "MyArchive.gdt.bak");
		f.deleteOnExit();
	}

	@Test
	public void testCreateArchiveNameCollision1() throws Exception {
		// create archive
		// attempt to create over a file that exists
		// answer yes to overwrite dialog
		// verify that the archive was saved by opening it again and checking it has the right stuff.

		// create file to cause a name collision
		File file = writeTempFile("MyArchive.gdt");

		int insertedCount = getTreeModelInsertedNodeCount();
		Msg.trace(this, testName.getMethodName() + ":NODE COUNT: " + insertedCount);

		createNewArchive("MyArchive.gdt", false);

		// find the option dialog
		OptionDialog optDialog = waitForDialogComponent(OptionDialog.class);

		JButton button = findButtonByText(optDialog.getComponent(), "Yes");
		Msg.trace(this, "\t" + testName.getMethodName() + ":preparing to answer yes to overwrite");
		pressButton(button);
		waitForTree();

		ArchiveNode archiveNode = (ArchiveNode) archiveRootNode.getChild("MyArchive");
		assertNotNull(archiveNode);

	}

	@Test
	public void testDeleteArchive() throws Exception {
		createNewArchive("MyArchive.gdt", true);

		// there may be an overwrite dialog shown after calling create new archive
		waitForSwing();
		OptionDialog optDialog = getDialogComponent(OptionDialog.class);
		if (optDialog != null) {
			Msg.trace(this,
				"\t" + testName.getMethodName() + ": found option dialog: " + optDialog.getTitle());
			JButton button = findButtonByText(optDialog.getComponent(), "Yes");
			pressButton(button);
		}

		waitForTree();
		String archiveName = "MyArchive";
		ArchiveNode archiveNode = (ArchiveNode) archiveRootNode.getChild(archiveName);

		// debug
		if (archiveNode == null) {
			List<GTreeNode> children = archiveRootNode.getChildren();
			System.err.println("did not find new node - children: ");
			for (GTreeNode treeNode : children) {
				System.err.println("\tchild: " + treeNode.getName());
			}
			sleep(5000);
			children = archiveRootNode.getChildren();
			System.err.println("did not find new node - children: ");
			for (GTreeNode treeNode : children) {
				System.err.println("\tchild: " + treeNode.getName());
			}

		}

		assertNotNull(
			"Did not find node (timing error? - see output for available nodes): " + archiveName,
			archiveNode);
		tree.setSelectedNode(archiveNode);

		DockingActionIf action = getAction(plugin, "Delete Archive");
		DataTypeTestUtils.performAction(action, tree, false);

		optDialog = waitForDialogComponent(OptionDialog.class);
		assertNotNull(optDialog);
		JButton button = findButtonByText(optDialog.getComponent(), "Yes");
		pressButton(button);
		waitForTree();

		assertNull(archiveRootNode.getChild(archiveName));

		waitForPostedSwingRunnables();

		// make sure it is deleted on disk as well
		try {
			archiveNode = DataTypeTestUtils.openArchive(GenericRunInfo.getProjectsDirPath(),
				"MyArchive.gdt", false, plugin);
			Archive archive = archiveNode.getArchive();
			Assert.fail("Should not have been able to open this archive " + archive.getName());
		}
		catch (Exception e) {
			// should fail since the existing file was not an archive
		}

	}

	@Test
	public void testCreateArchiveNameCollision2() throws Exception {

		// create archive
		// attempt to save over a file that exists
		// answer no to overwrite dialog
		// verify that the archive did not get saved to that name.

		// create file to cause a name collision
		File file = writeTempFile("MyArchive.gdt");

		createNewArchive("MyArchive.gdt", false);

		// find the option dialog
		OptionDialog optDialog = waitForDialogComponent(OptionDialog.class);

		JButton button = findButtonByText(optDialog.getComponent(), "No");
		pressButton(button);
		waitForPostedSwingRunnables();
		waitForTree();

		ArchiveNode archiveNode = (ArchiveNode) archiveRootNode.getChild("MyArchive");

		// debug
		if (archiveNode == null) {
			Msg.trace(this, "Did not find a newly created node!!!!");
			// ...try waiting some more, to see if we beat the update
			waitForTree();
			archiveNode = (ArchiveNode) archiveRootNode.getChild("MyArchive");
			Msg.trace(this, "\tand after waiting some more did we?: " + archiveNode);
		}

		assertNull(archiveNode);
	}

}
