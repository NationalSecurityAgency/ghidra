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

import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.data.LinkHandler;
import ghidra.framework.data.LinkHandler.LinkStatus;
import ghidra.framework.model.*;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Program;
import ghidra.server.remote.ServerTestUtil;
import ghidra.test.*;
import ghidra.util.task.TaskMonitor;

public class ProjectCopyPasteTest extends AbstractGhidraHeadedIntegrationTest {

	private FrontEndTestEnv env;

	private DomainFolder abcFolder;
	private DomainFile programFile;

	@Before
	public void setUp() throws Exception {

		env = new FrontEndTestEnv();

		/**
			/abc     (folder)
			 	foo  (program file)
			/xyz     (empty folder)
		**/

		DomainFolder rootFolder = env.getRootFolder();

		abcFolder = rootFolder.createFolder("abc");
		rootFolder.createFolder("xyz");

		Program p = ToyProgramBuilder.buildSimpleProgram("foo", this);
		programFile = abcFolder.createFile("foo", p, TaskMonitor.DUMMY);
		p.release(this);

		env.waitForTree();
	}

	@After
	public void tearDown() throws Exception {

		env.dispose();

		ClientUtil.clearRepositoryAdapter("localhost", ServerTestUtil.GHIDRA_TEST_SERVER_PORT);
	}

	@Test
	public void testCopyPasteFile() throws Exception {

		// Select /abc/foo file and Copy

		DomainFileNode fooFile = env.waitForFileNode("/abc/foo");

		final ActionContext copyActionContext = env.getDomainFileActionContext(fooFile);

		DockingActionIf copyAction = getAction(env.getFrontEndTool(), "Copy");
		assertNotNull("Copy action not found", copyAction);

		assertTrue(copyAction.isAddToPopup(copyActionContext));
		assertTrue(copyAction.isEnabledForContext(copyActionContext));
		runSwing(() -> copyAction.actionPerformed(copyActionContext));

		// Select /xyz folder and perform Paste

		DomainFolderNode xyzNode = env.waitForFolderNode("/xyz");

		final ActionContext pasteActionContext = env.getDomainFileActionContext(xyzNode);

		DockingActionIf pasteAction = getAction(env.getFrontEndTool(), "Paste");
		assertNotNull("Paste action not found", pasteAction);

		assertTrue(pasteAction.isAddToPopup(pasteActionContext));
		assertTrue(pasteAction.isEnabledForContext(pasteActionContext));
		runSwing(() -> pasteAction.actionPerformed(pasteActionContext));

		DomainFileNode fooCopyNode = env.waitForFileNode("/xyz/foo");
		DomainFile file = fooCopyNode.getDomainFile();
		assertTrue(file.exists());
		assertFalse(file.isLink());

		assertEquals(LinkStatus.NON_LINK, LinkHandler.getLinkFileStatus(file, null));
	}

	@Test
	public void testCopyPastInternalAbsoluteFileLink() throws Exception {
		testCopyPastInternalFileLink("Paste Link");
	}

	@Test
	public void testCopyPastInternalRelativeFileLink() throws Exception {
		testCopyPastInternalFileLink("Paste Relative-Link");
	}

	private void testCopyPastInternalFileLink(String pastActionName) throws Exception {

		/**
			/abc
			 	foo  (copied)
			/xyz     (pasted into)
			    foo ->     (direct link)
			    foo.1 ->   (link to direct link)
		**/

		boolean isRelative = pastActionName.contains("Relative");

		DockingActionIf copyAction = getAction(env.getFrontEndTool(), "Copy");
		assertNotNull("Copy action not found", copyAction);

		// Select /abc/foo file and perform Copy

		DomainFileNode fooNode = env.waitForFileNode("/abc/foo");
		final ActionContext copyActionContext = env.getDomainFileActionContext(fooNode);

		assertTrue(copyAction.isAddToPopup(copyActionContext));
		assertTrue(copyAction.isEnabledForContext(copyActionContext));
		runSwing(() -> copyAction.actionPerformed(copyActionContext));

		DockingActionIf pasteLinkAction = getAction(env.getFrontEndTool(), pastActionName);
		assertNotNull(pastActionName + " action not found", pasteLinkAction);

		// Select /xyz folder and perform Paste as Link

		DomainFolderNode xyzNode = env.waitForFolderNode("/xyz");
		final ActionContext pasteLinkActionContext = env.getDomainFileActionContext(xyzNode);

		assertTrue(pasteLinkAction.isAddToPopup(pasteLinkActionContext));
		assertTrue(pasteLinkAction.isEnabledForContext(pasteLinkActionContext));
		runSwing(() -> pasteLinkAction.actionPerformed(pasteLinkActionContext));

		DomainFileNode fooLinkNode = env.waitForFileNode("/xyz/foo");
		DomainFile file = fooLinkNode.getDomainFile();
		assertTrue(file.exists());
		assertTrue(file.isLink());
		LinkFileInfo linkInfo = file.getLinkInfo();
		assertFalse(linkInfo.isFolderLink());
		assertFalse(linkInfo.isExternalLink());
		assertEquals(isRelative ? "../abc/foo" : "/abc/foo", linkInfo.getLinkPath());
		assertNull(linkInfo.getLinkedFolder());

		ProjectData projectData = env.getFrontEndTool().getProject().getProjectData();

		DomainFile fooLinkFile = projectData.getFile("/xyz/foo");
		assertNotNull(fooLinkFile);
		assertTrue(fooLinkFile.exists());

		assertEquals(LinkStatus.INTERNAL, LinkHandler.getLinkFileStatus(fooLinkFile, null));

		DomainObject dobj = fooLinkFile.getDomainObject(this, false, false, TaskMonitor.DUMMY);
		try {
			assertTrue(dobj instanceof ProgramDB);
			assertTrue(dobj.canSave());
			assertTrue(dobj.isChangeable());
			assertEquals(programFile, dobj.getDomainFile());
		}
		finally {
			if (dobj != null) {
				dobj.release(this);
			}
		}

		// Select /xyz/foo file and perform Copy

		final ActionContext copy2ActionContext = env.getDomainFileActionContext(fooLinkNode);

		assertTrue(copyAction.isAddToPopup(copy2ActionContext));
		assertTrue(copyAction.isEnabledForContext(copy2ActionContext));
		runSwing(() -> copyAction.actionPerformed(copy2ActionContext));

		// Select /xyz folder and perform Paste as Link

		assertTrue(pasteLinkAction.isAddToPopup(pasteLinkActionContext));
		assertTrue(pasteLinkAction.isEnabledForContext(pasteLinkActionContext));
		runSwing(() -> pasteLinkAction.actionPerformed(pasteLinkActionContext));

		fooLinkNode = env.waitForFileNode("/xyz/foo.1");
		file = fooLinkNode.getDomainFile();
		assertTrue(file.exists());
		assertTrue(file.isLink());
		linkInfo = file.getLinkInfo();
		assertFalse(linkInfo.isFolderLink());
		assertFalse(linkInfo.isExternalLink());
		assertEquals(isRelative ? "foo" : "/xyz/foo", linkInfo.getLinkPath());
		assertNull(linkInfo.getLinkedFolder());

		fooLinkFile = projectData.getFile("/xyz/foo.1");
		assertNotNull(fooLinkFile);
		assertTrue(fooLinkFile.exists());

		assertEquals(LinkStatus.INTERNAL, LinkHandler.getLinkFileStatus(fooLinkFile, null));

		dobj = fooLinkFile.getDomainObject(this, false, false, TaskMonitor.DUMMY);
		try {
			assertTrue(dobj instanceof ProgramDB);
			assertTrue(dobj.canSave());
			assertTrue(dobj.isChangeable());
			assertEquals(programFile, dobj.getDomainFile());
		}
		finally {
			if (dobj != null) {
				dobj.release(this);
			}
		}
	}

	@Test
	public void testCopyPastFolder() throws Exception {

		// Select /abc file from viewed project and Copy

		DomainFolderNode abcFolderNode = env.waitForFolderNode("/abc");

		final ActionContext copyActionContext = env.getDomainFileActionContext(abcFolderNode);

		DockingActionIf copyAction = getAction(env.getFrontEndTool(), "Copy");
		assertNotNull("Copy action not found", copyAction);

		assertTrue(copyAction.isAddToPopup(copyActionContext));
		assertTrue(copyAction.isEnabledForContext(copyActionContext));
		runSwing(() -> copyAction.actionPerformed(copyActionContext));

		// Select /xyz folder and perform Paste

		DomainFolderNode xyzNode = env.waitForFolderNode("/xyz");

		final ActionContext pasteActionContext = env.getDomainFileActionContext(xyzNode);

		DockingActionIf pasteAction = getAction(env.getFrontEndTool(), "Paste");
		assertNotNull("Paste action not found", pasteAction);

		assertTrue(pasteAction.isAddToPopup(pasteActionContext));
		assertTrue(pasteAction.isEnabledForContext(pasteActionContext));
		runSwing(() -> pasteAction.actionPerformed(pasteActionContext));

		DomainFolderNode abcCopyNode = env.waitForFolderNode("/xyz/abc");
		DomainFolder folder = abcCopyNode.getDomainFolder();
		assertTrue(!folder.isEmpty());

		DomainFile file = folder.getFile("foo");
		assertNotNull(file);
		assertTrue(file.exists());

	}

	@Test
	public void testCopyPastInternalAbsoluteFolderLink() throws Exception {
		testCopyPastInternalFolderLink("Paste Link");
	}

	@Test
	public void testCopyPastInternalRelativeFolderLink() throws Exception {
		testCopyPastInternalFolderLink("Paste Relative-Link");
	}

	private void testCopyPastInternalFolderLink(String pastActionName) throws Exception {

		/**
			/abc     (copied)
			 	foo
			/xyz     (pasted into)
			    abc ->     (direct link)
			    abc.1 ->   (link to direct link)
		**/

		boolean isRelative = pastActionName.contains("Relative");

		DockingActionIf copyAction = getAction(env.getFrontEndTool(), "Copy");
		assertNotNull("Copy action not found", copyAction);

		// Select /abc folder and perform Copy

		DomainFolderNode abcNode = env.waitForFolderNode("/abc");
		final ActionContext copyActionContext = env.getDomainFileActionContext(abcNode);

		assertTrue(copyAction.isAddToPopup(copyActionContext));
		assertTrue(copyAction.isEnabledForContext(copyActionContext));
		runSwing(() -> copyAction.actionPerformed(copyActionContext));

		// Select /xyz folder and perform Paste as Link /xyz/abc

		DockingActionIf pasteLinkAction = getAction(env.getFrontEndTool(), pastActionName);
		assertNotNull(pastActionName + " action not found", pasteLinkAction);

		DomainFolderNode xyzNode = env.waitForFolderNode("/xyz");
		final ActionContext pasteLinkActionContext = env.getDomainFileActionContext(xyzNode);

		assertTrue(pasteLinkAction.isAddToPopup(pasteLinkActionContext));
		assertTrue(pasteLinkAction.isEnabledForContext(pasteLinkActionContext));
		runSwing(() -> pasteLinkAction.actionPerformed(pasteLinkActionContext));

		final DomainFileNode xyzAbcLinkNode = env.waitForFileNode("/xyz/abc");
		final DomainFile xyzAbcLinkFile = xyzAbcLinkNode.getDomainFile();
		assertTrue(xyzAbcLinkFile.exists());
		assertTrue(xyzAbcLinkFile.isLink());
		LinkFileInfo xyzAbcLinkInfo = xyzAbcLinkFile.getLinkInfo();
		assertTrue(xyzAbcLinkInfo.isFolderLink());
		assertFalse(xyzAbcLinkInfo.isExternalLink());
		assertEquals(isRelative ? "../abc" : "/abc", xyzAbcLinkInfo.getLinkPath());

		assertEquals(LinkStatus.INTERNAL, LinkHandler.getLinkFileStatus(xyzAbcLinkFile, null));

		final LinkedDomainFolder xyzAbcLinkedFolder = xyzAbcLinkInfo.getLinkedFolder();
		assertNotNull(xyzAbcLinkedFolder);
		assertTrue(xyzAbcLinkedFolder.isLinked());
		assertEquals(abcFolder, xyzAbcLinkedFolder.getRealFolder());

		ProjectData projectData = env.getFrontEndTool().getProject().getProjectData();

		DomainFile fooFile = projectData.getFile("/xyz/abc/foo");
		assertNotNull(fooFile);
		assertTrue(fooFile.exists());

		DomainObject dobj = fooFile.getDomainObject(this, false, false, TaskMonitor.DUMMY);
		try {
			assertTrue(dobj instanceof ProgramDB);
			assertTrue(dobj.canSave());
			assertTrue(dobj.isChangeable());
			assertEquals(programFile, dobj.getDomainFile());
		}
		finally {
			if (dobj != null) {
				dobj.release(this);
			}
		}

		// Select /xyz/abc linked-folder and perform Copy

		final ActionContext copy2ActionContext = env.getDomainFileActionContext(xyzAbcLinkNode);

		assertTrue(copyAction.isAddToPopup(copy2ActionContext));
		assertTrue(copyAction.isEnabledForContext(copy2ActionContext));
		runSwing(() -> copyAction.actionPerformed(copy2ActionContext));

		// Select /xyz and perform Paste as Link /xyz/abc.1

		assertTrue(pasteLinkAction.isAddToPopup(pasteLinkActionContext));
		assertTrue(pasteLinkAction.isEnabledForContext(pasteLinkActionContext));
		runSwing(() -> pasteLinkAction.actionPerformed(pasteLinkActionContext));

		final DomainFileNode xyzAbc1CopyNode = env.waitForFileNode("/xyz/abc.1");
		DomainFile xyzAbc1LinkFile = xyzAbc1CopyNode.getDomainFile();
		assertTrue(xyzAbc1LinkFile.exists());
		assertTrue(xyzAbc1LinkFile.isLink());
		LinkFileInfo xyzAbc1LinkInfo = xyzAbc1LinkFile.getLinkInfo();
		assertTrue(xyzAbc1LinkInfo.isFolderLink());
		assertFalse(xyzAbc1LinkInfo.isExternalLink());
		assertEquals(isRelative ? "abc" : "/xyz/abc", xyzAbc1LinkInfo.getLinkPath());

		assertEquals(LinkStatus.INTERNAL, LinkHandler.getLinkFileStatus(xyzAbc1LinkFile, null));

		final LinkedDomainFolder xyzAbc1LinkedFolder = xyzAbc1LinkInfo.getLinkedFolder();
		assertNotNull(xyzAbc1LinkedFolder);
		assertTrue(xyzAbc1LinkedFolder.isLinked());

		assertEquals(xyzAbcLinkedFolder.getRealFolder(), xyzAbc1LinkedFolder.getRealFolder());

		fooFile = projectData.getFile("/xyz/abc.1/foo");
		assertNotNull(fooFile);
		assertTrue(fooFile.exists());

		dobj = fooFile.getDomainObject(this, false, false, TaskMonitor.DUMMY);
		try {
			assertTrue(dobj instanceof ProgramDB);
			assertTrue(dobj.canSave());
			assertTrue(dobj.isChangeable());
			assertEquals(programFile, dobj.getDomainFile());
		}
		finally {
			if (dobj != null) {
				dobj.release(this);
			}
		}

	}

}
