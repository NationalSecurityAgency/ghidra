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
package ghidra.framework.main.datatree;

import static org.junit.Assert.*;

import java.util.function.BooleanSupplier;

import org.junit.*;

import ghidra.framework.client.ClientUtil;
import ghidra.framework.data.FolderLinkContentHandler;
import ghidra.framework.data.LinkHandler;
import ghidra.framework.data.LinkHandler.LinkStatus;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.database.DataTypeArchiveDB;
import ghidra.program.database.ProgramLinkContentHandler;
import ghidra.program.model.listing.Program;
import ghidra.server.remote.ServerTestUtil;
import ghidra.test.*;
import ghidra.util.Swing;
import ghidra.util.exception.DuplicateFileException;
import ghidra.util.task.TaskMonitor;

public class ProjectLinkFileStatusTest extends AbstractGhidraHeadedIntegrationTest {

	private FrontEndTestEnv env;

	private DomainFolder abcFolder;
	private DomainFolder xyzFolder;
	private DomainFile programFile;

	@Before
	public void setUp() throws Exception {

		env = new FrontEndTestEnv();

		/**
			/abc/               (folder)
			 	abc -> /xyz/abc (circular folder allowed as internal)
			 	foo             (program file)
			/xyz/     
			 	abc -> /abc     (folder link)
			 		abc -> /xyz/abc (circular folder allowed as internal)
			 		foo
			 	foo -> /abc/foo (program link)
			/e -> f (circular folder link path)
			/f -> g (circular folder link path)
			/g -> e (circular folder link path)
		**/

		DomainFolder rootFolder = env.getRootFolder();

		abcFolder = rootFolder.createFolder("abc");
		xyzFolder = rootFolder.createFolder("xyz");
		DomainFile abcLinkFile = abcFolder.copyToAsLink(xyzFolder, false);
		abcLinkFile.copyToAsLink(abcFolder, false);

		Program p = ToyProgramBuilder.buildSimpleProgram("foo", this);
		programFile = abcFolder.createFile("foo", p, TaskMonitor.DUMMY);
		p.release(this);

		programFile.copyToAsLink(xyzFolder, false);

		// Circular folder-link path without real folder
		rootFolder.createLinkFile(rootFolder.getProjectData(), "/f", true, "e",
			FolderLinkContentHandler.INSTANCE);
		rootFolder.createLinkFile(rootFolder.getProjectData(), "/g", true, "f",
			FolderLinkContentHandler.INSTANCE);
		rootFolder.createLinkFile(rootFolder.getProjectData(), "/e", true, "g",
			FolderLinkContentHandler.INSTANCE);

		rootFolder.createLinkFile(rootFolder.getProjectData(),
			"/home/tsharr2/Examples/linktest/usr/lib64/../lib64", true, "nested2lib64",
			FolderLinkContentHandler.INSTANCE);

		env.waitForTree();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
		ClientUtil.clearRepositoryAdapter("localhost", ServerTestUtil.GHIDRA_TEST_SERVER_PORT);
	}

	@Test
	public void testNonFileLink() throws Exception {
		DomainFileNode fileNode = env.waitForFileNode("/abc/foo");
		assertEquals(LinkStatus.NON_LINK,
			LinkHandler.getLinkFileStatus(fileNode.getDomainFile(), null));
	}

	@Test
	public void testExternalFileLink() throws Exception {

		//
		// Create external program file-link /abc/A to remote repository
		//
		DomainFile linkFile = abcFolder.createLinkFile("ghidra://localhost/Test/A", "A",
			ProgramLinkContentHandler.INSTANCE);

		env.waitForTree(); // give time for ChangeManager to update

		//
		// Verify /abc/A external program file-link exists with correct status and display name
		//
		DomainFileNode nodeA = waitForFileNode("/abc/A");
		assertFalse(nodeA.isFolderLink());
		assertEquals(linkFile, nodeA.getDomainFile());
		assertEquals(LinkStatus.EXTERNAL, LinkHandler.getLinkFileStatus(linkFile, null));
		String displayName = runSwing(() -> nodeA.getDisplayText());
		assertTrue("Unexpected node display name: " + displayName,
			displayName.contains("localhost[Test]:/A"));

		//
		// Create external program file-link /abc/B to local project
		//
		linkFile = abcFolder.createLinkFile("ghidra:/x/y/Test?/B", "B",
			ProgramLinkContentHandler.INSTANCE);

		env.waitForTree(); // give time for ChangeManager to update

		//
		// Verify /abc/B external program file-link exists with correct status and display name
		//
		DomainFileNode nodeB = waitForFileNode("/abc/B");
		assertFalse(nodeB.isFolderLink());
		assertEquals(linkFile, nodeB.getDomainFile());
		assertEquals(LinkStatus.EXTERNAL, LinkHandler.getLinkFileStatus(linkFile, null));
		displayName = runSwing(() -> nodeB.getDisplayText());
		assertTrue("Unexpected node display name: " + displayName, displayName.contains("Test:/B"));

		//
		// Remove /abc/foo file
		//
		DomainFile fooFile = abcFolder.getFile("foo");
		assertNotNull(fooFile);
		fooFile.delete();

		//
		// Replace deleted file with external program file-link to local project
		// which sets-up indirect link path from /xyz/foo -> /abc/foo -> local project file
		//
		linkFile = abcFolder.createLinkFile("ghidra:/x/y/Test?/foo", "foo",
			ProgramLinkContentHandler.INSTANCE);

		waitForSwing();  // give a chance for ChangeManager to be notified

		env.waitForTree(); // give time for ChangeManager to update

		//
		// Verify /abc/foo external program file-link exists with correct status and display name
		//
		DomainFileNode fooNode = waitForFileNode("/abc/foo");
		assertFalse(fooNode.isFolderLink());
		assertEquals(linkFile, fooNode.getDomainFile());
		assertEquals(LinkStatus.EXTERNAL, LinkHandler.getLinkFileStatus(linkFile, null));
		displayName = runSwing(() -> fooNode.getDisplayText());
		if (!displayName.contains("Test:/foo")) {
			int junk = 0;
		}
		assertTrue("Unexpected node display name: " + displayName,
			displayName.contains("Test:/foo"));

		//
		// Check pre-existing file-link /xyz/foo reflects external status
		//
		DomainFileNode fooLinkNode = waitForFileNode("/xyz/foo");
		assertEquals(LinkStatus.EXTERNAL,
			LinkHandler.getLinkFileStatus(fooLinkNode.getDomainFile(), null));
	}

	@Test
	public void testExternalFolderLink() throws Exception {

		// NOTE: Only refer to root repo folder with remote URL to avoid unwanted connection attempt

		//
		// Create external folder-link /abc/A to remote repository
		//
		DomainFile linkFile = abcFolder.createLinkFile("ghidra://localhost/Test/", "A",
			FolderLinkContentHandler.INSTANCE);

		env.waitForTree(); // give time for ChangeManager to update

		//
		// Verify /abc/A external folder-link exists with correct status and display name
		//
		DomainFileNode nodeA = waitForFileNode("/abc/A");
		assertTrue(nodeA.isFolderLink());
		assertEquals(linkFile, nodeA.getDomainFile());
		assertEquals(LinkStatus.EXTERNAL, LinkHandler.getLinkFileStatus(linkFile, null));
		String displayName = runSwing(() -> nodeA.getDisplayText());
		assertTrue("Unexpected node display name: " + displayName,
			displayName.contains("localhost[Test]:/"));

		//
		// Create external folder-link /abc/B to local project
		//
		linkFile =
			abcFolder.createLinkFile("ghidra:/x/y/Test?/B", "B", FolderLinkContentHandler.INSTANCE);

		env.waitForTree(); // give time for ChangeManager to update

		//
		// Verify /abc/B external folder-link exists with correct status and display name
		//
		DomainFileNode nodeB = waitForFileNode("/abc/B");
		assertTrue(nodeB.isFolderLink());
		assertEquals(linkFile, nodeB.getDomainFile());
		assertEquals(LinkStatus.EXTERNAL, LinkHandler.getLinkFileStatus(linkFile, null));
		displayName = runSwing(() -> nodeB.getDisplayText());
		assertTrue("Unexpected node display name: " + displayName, displayName.contains("Test:/B"));

		//
		// Remove /abc folder and its children
		//
		DomainFolder rootFolder = abcFolder.getParent();
		abcFolder.getFile("abc").delete();
		abcFolder.getFile("foo").delete();
		abcFolder.getFile("A").delete();
		abcFolder.getFile("B").delete();
		abcFolder.delete();

		//
		// Remove /xyz/foo file to avoid remote access attempt to ghidra://localhost/Test/foo
		// after /abc is replaced in the next step
		//
		DomainFile fooFile = xyzFolder.getFile("foo");
		assertNotNull(fooFile);
		fooFile.delete();

		//
		// Replace deleted folder with external folder-link to local project
		// which sets-up indirect link path from /xyz/abc -> /abc -> local project root folder
		//
		linkFile = rootFolder.createLinkFile("ghidra://localhost/Test/", "abc",
			FolderLinkContentHandler.INSTANCE);

		env.waitForTree(); // give time for ChangeManager to update

		//
		// Verify /abc external folder-link exists with correct status and display name
		//
		DomainFileNode abcLinkNode = waitForFileNode("/abc");
		assertTrue(abcLinkNode.isFolderLink());
		assertEquals(linkFile, abcLinkNode.getDomainFile());
		assertEquals(LinkStatus.EXTERNAL, LinkHandler.getLinkFileStatus(linkFile, null));
		displayName = runSwing(() -> abcLinkNode.getDisplayText());
		assertTrue("Unexpected node display name: " + displayName,
			displayName.contains("localhost[Test]:/"));

		//
		// Check pre-existing folder-link /xyz/abc reflects external status
		//
		DomainFileNode abcLinkNode2 = waitForFileNode("/xyz/abc");
		assertEquals(LinkStatus.EXTERNAL,
			LinkHandler.getLinkFileStatus(abcLinkNode2.getDomainFile(), null));
	}

	@Test
	public void testCircularFolderLink1() throws Exception {

		//
		// Verify broken folder-link status for /e which has circular reference
		//
		DomainFileNode eLinkNode = waitForFileNode("/e");
		assertTrue(eLinkNode.isFolderLink());
		String displayName = runSwing(() -> eLinkNode.getDisplayText());
		assertTrue("Unexpected node display name: " + displayName, displayName.endsWith(" f"));
		assertEquals(LinkStatus.BROKEN,
			LinkHandler.getLinkFileStatus(eLinkNode.getDomainFile(), null));
		String tooltip = eLinkNode.getToolTip().replace("&nbsp;", " ");
		assertTrue(tooltip.contains("circular"));

		//
		// Verify broken folder-link status for /g which has circular reference
		//
		DomainFileNode gLinkNode = waitForFileNode("/g");
		assertTrue(gLinkNode.isFolderLink());
		displayName = runSwing(() -> gLinkNode.getDisplayText());
		assertTrue("Unexpected node display name: " + displayName, displayName.endsWith(" e"));
		assertEquals(LinkStatus.BROKEN,
			LinkHandler.getLinkFileStatus(gLinkNode.getDomainFile(), null));
		tooltip = gLinkNode.getToolTip().replace("&nbsp;", " ");
		assertTrue(tooltip.contains("circular"));

		//
		// Verify broken folder-link status for /f which has circular reference
		//
		DomainFileNode fLinkNode = waitForFileNode("/f");
		assertTrue(fLinkNode.isFolderLink());
		displayName = runSwing(() -> fLinkNode.getDisplayText());
		assertTrue("Unexpected node display name: " + displayName, displayName.endsWith(" g"));
		assertEquals(LinkStatus.BROKEN,
			LinkHandler.getLinkFileStatus(fLinkNode.getDomainFile(), null));
		tooltip = fLinkNode.getToolTip().replace("&nbsp;", " ");
		assertTrue(tooltip.contains("circular"));

		//
		// Rename folder /e to /ABC causing folder-links to have broken path
		//
		Swing.runNow(() -> eLinkNode.setName("ABC"));

		env.waitForTree(); // give time for ChangeManager to update

		// Verify /e node not found
		assertNull(env.getRootNode().getChild("e"));

		//
		// Verify broken folder-link status for /ABC (final folder /e not found)
		//
		DomainFileNode abcLinkNode = waitForFileNode("/ABC");
		assertTrue(abcLinkNode.isFolderLink());
		displayName = runSwing(() -> abcLinkNode.getDisplayText());
		assertTrue("Unexpected node display name: " + displayName, displayName.endsWith(" f"));
		assertEquals(LinkStatus.BROKEN,
			LinkHandler.getLinkFileStatus(abcLinkNode.getDomainFile(), null));
		tooltip = abcLinkNode.getToolTip().replace("&nbsp;", " ");
		assertTrue(tooltip.contains("folder not found: /e"));

		//
		// Verify broken folder-link status for /g (final folder /e not found)
		//
		waitForFileNode("/g");
		assertTrue(gLinkNode.isFolderLink());
		displayName = runSwing(() -> gLinkNode.getDisplayText());
		assertTrue("Unexpected node display name: " + displayName, displayName.endsWith(" e"));
		assertEquals(LinkStatus.BROKEN,
			LinkHandler.getLinkFileStatus(gLinkNode.getDomainFile(), null));
		tooltip = gLinkNode.getToolTip().replace("&nbsp;", " ");
		assertTrue(tooltip.contains("folder not found: /e"));

		//
		// Verify broken folder-link status for /f (final folder /e not found)
		//
		waitForFileNode("/f");
		assertTrue(fLinkNode.isFolderLink());
		displayName = runSwing(() -> fLinkNode.getDisplayText());
		assertTrue("Unexpected node display name: " + displayName, displayName.endsWith(" g"));
		assertEquals(LinkStatus.BROKEN,
			LinkHandler.getLinkFileStatus(fLinkNode.getDomainFile(), null));
		tooltip = fLinkNode.getToolTip().replace("&nbsp;", " ");
		assertTrue(tooltip.contains("folder not found: /e"));

		//
		// Create folder /e
		//
		DomainFolder rootFolder = env.getRootFolder();
		rootFolder.createFolder("e");

		env.waitForTree(); // give time for ChangeManager to update

		//
		// Verify good folder-link status for /ABC
		//
		waitForFileNode("/ABC");
		assertTrue(abcLinkNode.isFolderLink());
		displayName = runSwing(() -> abcLinkNode.getDisplayText());
		assertTrue("Unexpected node display name: " + displayName, displayName.endsWith(" f"));
		assertEquals(LinkStatus.INTERNAL,
			LinkHandler.getLinkFileStatus(abcLinkNode.getDomainFile(), null));
		tooltip = gLinkNode.getToolTip().replace("&nbsp;", " ");
		assertFalse(tooltip.contains("folder not found"));
		assertFalse(tooltip.contains("circular"));

		//
		// Verify good folder-link status for /g
		//
		waitForFileNode("/g");
		assertTrue(gLinkNode.isFolderLink());
		displayName = runSwing(() -> gLinkNode.getDisplayText());
		assertTrue("Unexpected node display name: " + displayName, displayName.endsWith(" e"));
		assertEquals(LinkStatus.INTERNAL,
			LinkHandler.getLinkFileStatus(gLinkNode.getDomainFile(), null));
		tooltip = gLinkNode.getToolTip().replace("&nbsp;", " ");
		assertFalse(tooltip.contains("folder not found"));
		assertFalse(tooltip.contains("circular"));

		//
		// Verify good folder-link status for /f
		//
		waitForFileNode("/f");
		assertTrue(fLinkNode.isFolderLink());
		displayName = runSwing(() -> fLinkNode.getDisplayText());
		assertTrue("Unexpected node display name: " + displayName, displayName.endsWith(" g"));
		assertEquals(LinkStatus.INTERNAL,
			LinkHandler.getLinkFileStatus(fLinkNode.getDomainFile(), null));
		tooltip = fLinkNode.getToolTip().replace("&nbsp;", " ");
		assertFalse(tooltip.contains("folder not found"));
		assertFalse(tooltip.contains("circular"));
	}

	@Test
	public void testCircularFolderLink2() throws Exception {

		//
		// Verify good folder-link internal status for /abc/abc which has allowed circular reference
		//
		DomainFileNode abcAbcLinkNode = waitForFileNode("/abc/abc");
		assertTrue(abcAbcLinkNode.isFolderLink());
		String displayName = runSwing(() -> abcAbcLinkNode.getDisplayText());
		assertTrue("Unexpected node display name: " + displayName,
			displayName.endsWith(" /xyz/abc"));
		assertEquals(LinkStatus.INTERNAL,
			LinkHandler.getLinkFileStatus(abcAbcLinkNode.getDomainFile(), null));

		//
		// Verify good folder-link internal status for /xyz/abc which has allowed circular reference
		//
		DomainFileNode xyzAbcLinkNode = waitForFileNode("/xyz/abc");
		assertTrue(xyzAbcLinkNode.isFolderLink());
		displayName = runSwing(() -> xyzAbcLinkNode.getDisplayText());
		assertTrue("Unexpected node display name: " + displayName, displayName.endsWith(" /abc"));
		assertEquals(LinkStatus.INTERNAL,
			LinkHandler.getLinkFileStatus(xyzAbcLinkNode.getDomainFile(), null));

		//
		// Verify good folder-link internal status for /xyz/abc/abc which has allowed circular reference
		//
		DomainFileNode abcLinkedNode = waitForFileNode("/xyz/abc/abc");
		assertTrue(abcLinkedNode.isFolderLink());
		displayName = runSwing(() -> abcLinkedNode.getDisplayText());
		assertTrue("Unexpected node display name: " + displayName,
			displayName.endsWith(" /xyz/abc"));
		assertEquals(LinkStatus.INTERNAL,
			LinkHandler.getLinkFileStatus(abcLinkedNode.getDomainFile(), null));

		//
		// Rename folder /abc to /ABC causing folder-link /xyz/abc to become broken
		//
		abcFolder = abcFolder.setName("ABC");

		env.waitForTree(); // give time for ChangeManager to update

		// Verify /abc node not found
		assertNull(env.getRootNode().getChild("abc"));

		//
		// Verify broken folder-link status for /ABC/abc which has circular reference
		//
		DomainFileNode ABCAbcLinkNode = waitForFileNode("/ABC/abc");
		assertTrue(ABCAbcLinkNode.isFolderLink());
		displayName = runSwing(() -> ABCAbcLinkNode.getDisplayText());
		assertTrue("Unexpected node display name: " + displayName,
			displayName.endsWith(" /xyz/abc"));
		assertEquals(LinkStatus.BROKEN,
			LinkHandler.getLinkFileStatus(ABCAbcLinkNode.getDomainFile(), null));
		String tooltip = ABCAbcLinkNode.getToolTip().replace("&nbsp;", " ");
		assertTrue(tooltip.contains("folder not found: /abc"));

		env.waitForTree(); // give time for ChangeManager to update

		//
		// Verify that folder-link /xyz/abc is broken due to missing /abc
		//
		DomainFileNode n = waitForFileNode("/xyz/abc"); // wait for refresh
		assertTrue(n == xyzAbcLinkNode);
		assertTrue(xyzAbcLinkNode.isFolderLink());
		assertEquals(LinkStatus.BROKEN,
			LinkHandler.getLinkFileStatus(xyzAbcLinkNode.getDomainFile(), null));
		tooltip = xyzAbcLinkNode.getToolTip().replace("&nbsp;", " ");
		assertTrue("Unexpected tooltip: " + tooltip, tooltip.contains("folder not found: /abc"));

		//
		// Attempt conflicting folder-link creation
		//
		DomainFile linkFile = abcFolder.getParent()
				.createLinkFile("ghidra://localhost/Test/ABC", "ABC",
					FolderLinkContentHandler.INSTANCE);
		assertEquals("ABC.1", linkFile.getName());  // link forced to have unqiue name

		//
		// Try to force folder vs folder-link name conflict
		// While it won't be allowed it could occur in-the-wild due to shared project content
		// (case not tested here)
		//

		try {
			linkFile.setName("ABC");  // trigger folder name conflict for folder-link
			fail("Expected DuplicateFileException");
		}
		catch (DuplicateFileException e) {
			// expected for link file
		}

		try {
			abcFolder.setName("ABC.1");
			fail("Expected DuplicateFileException");
		}
		catch (DuplicateFileException e) {
			// expected for link file
		}

	}

	@Test
	public void testBrokenFileLink() throws Exception {

		//
		// Verify good internal file-link status for /xyz/foo -> /abc/foo
		//
		DomainFileNode linkNode = waitForFileNode("/xyz/foo");
		assertEquals(LinkStatus.INTERNAL,
			LinkHandler.getLinkFileStatus(linkNode.getDomainFile(), null));

		//
		// Copy program file /abc/foo as relative file-link /abc/foo.1 and verify good internal file-link status
		//
		DomainFile relativeProgramLink = programFile.copyToAsLink(abcFolder, true);
		assertEquals("/abc/foo.1", relativeProgramLink.getPathname());
		assertEquals(LinkStatus.INTERNAL, LinkHandler.getLinkFileStatus(relativeProgramLink, null));

		//
		// Delete program file /abc/foo and verify that file-link /abc/foo.1 becomes broken
		//
		programFile.delete();
		assertEquals(LinkStatus.BROKEN, LinkHandler.getLinkFileStatus(relativeProgramLink, null));

		env.waitForTree(); // give time for ChangeManager to update

		//
		// Verify broken /xyz/foo file link status due to deleted file /abc/foo
		//
		linkNode = waitForFileNode("/xyz/foo");
		assertEquals(LinkStatus.BROKEN,
			LinkHandler.getLinkFileStatus(linkNode.getDomainFile(), null));
		String tooltip = linkNode.getToolTip().replace("&nbsp;", " ");
		assertTrue(tooltip.contains("file not found: /abc/foo"));

		//
		// Create DataTypeArchive project file /abc/foo
		//
		DataTypeArchiveDB dtm = new DataTypeArchiveDB(abcFolder, "foo", this);
		dtm.save(null, TaskMonitor.DUMMY);
		dtm.release(this);

		env.waitForTree(); // give time for ChangeManager to update

		//
		// Verify that Program file-link is now broken due to incompatible content for /abc/foo
		//
		linkNode = waitForFileNode("/xyz/foo");
		assertEquals(LinkStatus.BROKEN,
			LinkHandler.getLinkFileStatus(linkNode.getDomainFile(), null));
		env.waitForSwing();
		tooltip = linkNode.getToolTip().replace("&nbsp;", " ");
		assertTrue("Unexpected tooltip: " + tooltip,
			tooltip.contains("incompatible content-type: /abc/foo"));

	}

	private DomainFileNode waitForFileNode(String path) {
		DomainFileNode fileNode = env.waitForFileNode(path);
		waitForRefresh(fileNode);
		return fileNode;
	}

	private void waitForRefresh(DomainFileNode fileNode) {
		waitFor(new BooleanSupplier() {
			@Override
			public boolean getAsBoolean() {
				return !fileNode.hasPendingRefresh();
			}
		});
	}

}
