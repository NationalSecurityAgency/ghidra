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

import java.io.File;
import java.io.IOException;
import java.net.URL;

import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.data.FolderLinkContentHandler;
import ghidra.framework.data.LinkHandler;
import ghidra.framework.data.LinkHandler.LinkStatus;
import ghidra.framework.model.*;
import ghidra.framework.protocol.ghidra.*;
import ghidra.framework.protocol.ghidra.GhidraURLQuery.LinkFileControl;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.ProgramLinkContentHandler;
import ghidra.server.remote.ServerTestUtil;
import ghidra.test.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

public class ProjectCopyPasteFromRepositoryTest extends AbstractGhidraHeadedIntegrationTest {

	private String testDirPath;
	private File serverRoot;
	private URL viewURL;

	private FrontEndTestEnv env;

	@Before
	public void setUp() throws Exception {
		testDirPath = getTestDirectoryPath();

		env = new FrontEndTestEnv();

		startServer();
	}

	@After
	public void tearDown() throws Exception {

		env.dispose();

		killServer();

		ClientUtil.clearRepositoryAdapter("localhost", ServerTestUtil.GHIDRA_TEST_SERVER_PORT);
	}

	private void killServer() {

		if (serverRoot == null) {
			return;
		}

		ServerTestUtil.disposeServer();

		FileUtilities.deleteDir(serverRoot);
	}

	private void startServer() throws Exception {

		// Authorized user "test" is predefined within TestServer.zip
		ServerTestUtil.setLocalUser("test");

		// Create server instance
		serverRoot = new File(testDirPath, "TestServer");

		ServerTestUtil.createPopulatedTestServer(serverRoot.getAbsolutePath());

		ServerTestUtil.startServer(serverRoot.getAbsolutePath(),
			ServerTestUtil.GHIDRA_TEST_SERVER_PORT, -1, false, false, false);

		viewURL = GhidraURL.makeURL("localhost", ServerTestUtil.GHIDRA_TEST_SERVER_PORT, "Test");

		addLinkedServerContent();
	}

	private void addRepoView() throws IOException {

		Project project = env.getFrontEndTool().getProject();
		ProjectData projectData = project.addProjectView(viewURL, true);
		assertNotNull(projectData);
		assertEquals(viewURL, projectData.getProjectLocator().getURL());

		// validate the view was added to project
		ProjectLocator[] projViews = project.getProjectViews();
		assertEquals(1, projViews.length);
	}

	private void addLinkedServerContent() throws Exception {

		/**
		 * Initial server files:
		 *   /foo
		 *   /notepad
		 *   /f1/bash
		 */

		GhidraURLQuery.queryRepositoryUrl(viewURL, false, new GhidraURLResultHandlerAdapter() {
			@Override
			public void processResult(DomainFolder serverRootFolder, URL url, TaskMonitor monitor)
					throws IOException, CancelledException {

				//
				// Add folder link:  /f1Link -> f1
				//
				DomainFile linkFile =
					serverRootFolder.createLinkFile(serverRootFolder.getProjectData(), "/f1", true,
						"f1Link", FolderLinkContentHandler.INSTANCE);
				assertNotNull(linkFile);
				assertTrue(linkFile.isLink() && linkFile.getLinkInfo().isFolderLink());
				assertEquals("f1", linkFile.getLinkInfo().getLinkPath());
				linkFile.addToVersionControl("Add Folder Link", false, monitor);

				//
				// Add file link: /bashLink -> f1/bash
				//
				linkFile = serverRootFolder.createLinkFile(serverRootFolder.getProjectData(),
					"/f1/bash", true, "bashLink", ProgramLinkContentHandler.INSTANCE);
				assertNotNull(linkFile);
				assertTrue(linkFile.isLink() && !linkFile.getLinkInfo().isFolderLink());
				assertEquals("f1/bash", linkFile.getLinkInfo().getLinkPath());
				linkFile.addToVersionControl("Add File Link", false, monitor);
			}
		}, LinkFileControl.NO_FOLLOW, TaskMonitor.DUMMY);

	}

	@Test
	public void testCopyPasteExternalFile() throws Exception {

		env.getRootFolder().createFolder("xyz");

		addRepoView();

		env.waitForTree();

		//
		// Select foo file from viewed repository and Copy
		//
		DataTreeHelper viewTreeHelper = env.getReadOnlyProjectTreeHelper(viewURL.toExternalForm());
		assertNotNull("repo data tree view not found", viewTreeHelper);

		DomainFileNode fooFile = viewTreeHelper.waitForFileNode("/foo");

		final ActionContext copyActionContext = viewTreeHelper.getDomainFileActionContext(fooFile);

		DockingActionIf copyAction = getAction(env.getFrontEndTool(), "Copy");
		assertNotNull("Copy action not found", copyAction);

		assertTrue(copyAction.isAddToPopup(copyActionContext));
		assertTrue(copyAction.isEnabledForContext(copyActionContext));
		runSwing(() -> copyAction.actionPerformed(copyActionContext));

		//
		// Select xyz folder and perform Paste
		//
		DomainFolderNode xyzNode = env.waitForFolderNode("/xyz");

		final ActionContext pasteActionContext = env.getDomainFileActionContext(xyzNode);

		DockingActionIf pasteAction = getAction(env.getFrontEndTool(), "Paste");
		assertNotNull("Paste action not found", pasteAction);

		assertTrue(pasteAction.isAddToPopup(pasteActionContext));
		assertTrue(pasteAction.isEnabledForContext(pasteActionContext));
		runSwing(() -> pasteAction.actionPerformed(pasteActionContext));

		//
		// Verify paste of external file from repository to active project
		//
		DomainFileNode fooCopyNode = env.waitForFileNode("/xyz/foo");
		DomainFile file = fooCopyNode.getDomainFile();
		assertTrue(file.exists());
		assertFalse(file.isLink());

		assertEquals(LinkStatus.NON_LINK, LinkHandler.getLinkFileStatus(file, null));
	}

	@Test
	public void testCopyPasteExternalLinkFile() throws Exception {

		env.getRootFolder().createFolder("xyz");

		addRepoView();

		env.waitForTree();

		//
		// Select bashLink link-file from viewed repository and Copy
		//
		DataTreeHelper viewTreeHelper = env.getReadOnlyProjectTreeHelper(viewURL.toExternalForm());
		assertNotNull("repo data tree view not found", viewTreeHelper);

		DomainFileNode bashLinkFile = viewTreeHelper.waitForFileNode("/bashLink");

		final ActionContext copyActionContext =
			viewTreeHelper.getDomainFileActionContext(bashLinkFile);

		DockingActionIf copyAction = getAction(env.getFrontEndTool(), "Copy");
		assertNotNull("Copy action not found", copyAction);

		assertTrue(copyAction.isAddToPopup(copyActionContext));
		assertTrue(copyAction.isEnabledForContext(copyActionContext));
		runSwing(() -> copyAction.actionPerformed(copyActionContext));

		//
		// Select xyz folder and perform Paste
		//
		DomainFolderNode xyzNode = env.waitForFolderNode("/xyz");

		final ActionContext pasteActionContext = env.getDomainFileActionContext(xyzNode);

		DockingActionIf pasteAction = getAction(env.getFrontEndTool(), "Paste");
		assertNotNull("Paste action not found", pasteAction);

		assertTrue(pasteAction.isAddToPopup(pasteActionContext));
		assertTrue(pasteAction.isEnabledForContext(pasteActionContext));
		runSwing(() -> pasteAction.actionPerformed(pasteActionContext));

		//
		// Verify paste of external link-file from repository to active project
		//
		DomainFileNode bashLinkCopyNode = env.waitForFileNode("/xyz/bashLink");
		DomainFile file = bashLinkCopyNode.getDomainFile();
		assertTrue(file.exists());
		assertTrue(file.isLink());

		assertEquals(LinkStatus.EXTERNAL, LinkHandler.getLinkFileStatus(file, null));
		assertFalse(file.getLinkInfo().isFolderLink());

		//
		// Verify external URL to the link referenced file is applied with normal copy
		//
		assertEquals(viewURL + "/f1/bash", file.getLinkInfo().getLinkPath());
	}

	@Test
	public void testCopyPasteExternalFileAsLink() throws Exception {

		env.getRootFolder().createFolder("abc");

		addRepoView();

		env.waitForTree();

		//
		// Select /foo file from viewed project and Copy
		//
		DataTreeHelper viewTreeHelper = env.getReadOnlyProjectTreeHelper(viewURL.toExternalForm());
		assertNotNull("repo data tree view not found", viewTreeHelper);

		DomainFileNode fooFile = viewTreeHelper.waitForFileNode("/foo");

		final ActionContext copyActionContext = viewTreeHelper.getDomainFileActionContext(fooFile);

		URL sharedFileURL = GhidraURL.makeURL("localhost", ServerTestUtil.GHIDRA_TEST_SERVER_PORT,
			"Test", "/foo", null);

		DockingActionIf copyAction = getAction(env.getFrontEndTool(), "Copy");
		assertNotNull("Copy action not found", copyAction);

		assertTrue(copyAction.isAddToPopup(copyActionContext));
		assertTrue(copyAction.isEnabledForContext(copyActionContext));
		runSwing(() -> copyAction.actionPerformed(copyActionContext));

		//
		// Select /abc folder and perform Paste Link
		//
		DomainFolderNode abcNode = env.waitForFolderNode("/abc");

		final ActionContext pasteLinkActionContext = env.getDomainFileActionContext(abcNode);

		DockingActionIf pasteLinkAction = getAction(env.getFrontEndTool(), "Paste Link");
		assertNotNull("Paste Link action not found", pasteLinkAction);

		assertTrue(pasteLinkAction.isAddToPopup(pasteLinkActionContext));
		assertTrue(pasteLinkAction.isEnabledForContext(pasteLinkActionContext));
		runSwing(() -> pasteLinkAction.actionPerformed(pasteLinkActionContext));

		//
		// Verify external file paste as link
		//
		DomainFileNode fooCopyNode = env.waitForFileNode("/abc/foo");
		DomainFile file = fooCopyNode.getDomainFile();
		assertTrue(file.exists());
		assertTrue(file.isLink());
		LinkFileInfo linkInfo = file.getLinkInfo();
		assertFalse(linkInfo.isFolderLink());
		assertTrue(linkInfo.isExternalLink());

		assertEquals(LinkStatus.EXTERNAL, LinkHandler.getLinkFileStatus(file, null));

		assertEquals(sharedFileURL.toExternalForm(), linkInfo.getLinkPath());

		assertEquals(sharedFileURL, fooFile.getDomainFile().getSharedProjectURL(null));

		//
		// Verify link open follows into repository to open domain object database
		//
		DomainObject dobj = null;
		try {
			dobj = file.getDomainObject(this, false, false, TaskMonitor.DUMMY);
			assertTrue(dobj instanceof ProgramDB);
			assertFalse(dobj.canSave());
			assertTrue(dobj.isChangeable());
		}
		finally {
			if (dobj != null) {
				dobj.release(this);
			}
		}
	}

	@Test
	public void testCopyPasteExternalLinkFileAsLink() throws Exception {

		env.getRootFolder().createFolder("abc");

		addRepoView();

		env.waitForTree();

		//
		// Select /bashLink file from viewed project and Copy
		//
		DataTreeHelper viewTreeHelper = env.getReadOnlyProjectTreeHelper(viewURL.toExternalForm());
		assertNotNull("repo data tree view not found", viewTreeHelper);

		DomainFileNode bashLinkFile = viewTreeHelper.waitForFileNode("/bashLink");

		final ActionContext copyActionContext =
			viewTreeHelper.getDomainFileActionContext(bashLinkFile);

		URL sharedFileURL = GhidraURL.makeURL("localhost", ServerTestUtil.GHIDRA_TEST_SERVER_PORT,
			"Test", "/bashLink", null);

		DockingActionIf copyAction = getAction(env.getFrontEndTool(), "Copy");
		assertNotNull("Copy action not found", copyAction);

		assertTrue(copyAction.isAddToPopup(copyActionContext));
		assertTrue(copyAction.isEnabledForContext(copyActionContext));
		runSwing(() -> copyAction.actionPerformed(copyActionContext));

		//
		// Select /abc folder and perform Paste Link
		//
		DomainFolderNode abcNode = env.waitForFolderNode("/abc");

		final ActionContext pasteLinkActionContext = env.getDomainFileActionContext(abcNode);

		DockingActionIf pasteLinkAction = getAction(env.getFrontEndTool(), "Paste Link");
		assertNotNull("Paste Link action not found", pasteLinkAction);

		assertTrue(pasteLinkAction.isAddToPopup(pasteLinkActionContext));
		assertTrue(pasteLinkAction.isEnabledForContext(pasteLinkActionContext));
		runSwing(() -> pasteLinkAction.actionPerformed(pasteLinkActionContext));

		//
		// Verify external link-file paste as link
		//
		DomainFileNode bashLinkCopyNode = env.waitForFileNode("/abc/bashLink");
		DomainFile file = bashLinkCopyNode.getDomainFile();
		assertTrue(file.exists());
		assertTrue(file.isLink());
		LinkFileInfo linkInfo = file.getLinkInfo();
		assertFalse(linkInfo.isFolderLink());
		assertTrue(linkInfo.isExternalLink());

		assertEquals(LinkStatus.EXTERNAL, LinkHandler.getLinkFileStatus(file, null));

		assertEquals(sharedFileURL.toExternalForm(), linkInfo.getLinkPath());

		assertEquals(sharedFileURL, bashLinkFile.getDomainFile().getSharedProjectURL(null));

		//
		// Verify link open follows double-hop into repository to open domain object database
		//
		DomainObject dobj = null;
		try {
			dobj = file.getDomainObject(this, false, false, TaskMonitor.DUMMY);
			assertTrue(dobj instanceof ProgramDB);
			assertFalse(dobj.canSave());
			assertTrue(dobj.isChangeable());
		}
		finally {
			if (dobj != null) {
				dobj.release(this);
			}
		}
	}

	@Test
	public void testCopyPastExternalFolder() throws Exception {

		env.getRootFolder().createFolder("xyz");

		addRepoView();

		env.waitForTree();

		//
		// Select /f1 folder from viewed project and Copy
		//
		DataTreeHelper viewTreeHelper = env.getReadOnlyProjectTreeHelper(viewURL.toExternalForm());
		assertNotNull("repo data tree view not found", viewTreeHelper);

		DomainFolderNode f1Folder = viewTreeHelper.waitForFolderNode("/f1");

		final ActionContext copyActionContext = viewTreeHelper.getDomainFileActionContext(f1Folder);

		DockingActionIf copyAction = getAction(env.getFrontEndTool(), "Copy");
		assertNotNull("Copy action not found", copyAction);

		assertTrue(copyAction.isAddToPopup(copyActionContext));
		assertTrue(copyAction.isEnabledForContext(copyActionContext));
		runSwing(() -> copyAction.actionPerformed(copyActionContext));

		//
		// Select xyz folder and perform Paste
		//
		DomainFolderNode xyzNode = env.waitForFolderNode("/xyz");

		final ActionContext pasteActionContext = env.getDomainFileActionContext(xyzNode);

		DockingActionIf pasteAction = getAction(env.getFrontEndTool(), "Paste");
		assertNotNull("Paste action not found", pasteAction);

		assertTrue(pasteAction.isAddToPopup(pasteActionContext));
		assertTrue(pasteAction.isEnabledForContext(pasteActionContext));
		runSwing(() -> pasteAction.actionPerformed(pasteActionContext));

		//
		// Verify external folder paste (full folder copy) with its content file
		//
		DomainFolderNode f1CopyNode = env.waitForFolderNode("/xyz/f1");
		DomainFolder folder = f1CopyNode.getDomainFolder();
		assertTrue(!folder.isEmpty());

		DomainFile file = folder.getFile("bash");
		assertNotNull(file);
		assertTrue(file.exists());

		assertEquals(LinkStatus.NON_LINK, LinkHandler.getLinkFileStatus(file, null));
	}

	@Test
	public void testCopyPastExternalFolderAsLink() throws Exception {

		env.getRootFolder().createFolder("abc");

		addRepoView();

		env.waitForTree();

		//
		// Select f1 folder from viewed project and Copy
		//
		DataTreeHelper viewTreeHelper = env.getReadOnlyProjectTreeHelper(viewURL.toExternalForm());
		assertNotNull("repo data tree view not found", viewTreeHelper);

		DomainFolderNode f1Folder = viewTreeHelper.waitForFolderNode("/f1");

		final ActionContext copyActionContext = viewTreeHelper.getDomainFileActionContext(f1Folder);

		URL sharedFolderURL = GhidraURL.makeURL("localhost", ServerTestUtil.GHIDRA_TEST_SERVER_PORT,
			"Test", "/f1/", null);

		DockingActionIf copyAction = getAction(env.getFrontEndTool(), "Copy");
		assertNotNull("Copy action not found", copyAction);

		assertTrue(copyAction.isAddToPopup(copyActionContext));
		assertTrue(copyAction.isEnabledForContext(copyActionContext));
		runSwing(() -> copyAction.actionPerformed(copyActionContext));

		//
		// Select abc folder and perform Paste Link
		//
		DomainFolderNode abcNode = env.waitForFolderNode("/abc");

		final ActionContext pasteLinkActionContext = env.getDomainFileActionContext(abcNode);

		DockingActionIf pasteLinkAction = getAction(env.getFrontEndTool(), "Paste Link");
		assertNotNull("Paste Link action not found", pasteLinkAction);

		assertTrue(pasteLinkAction.isAddToPopup(pasteLinkActionContext));
		assertTrue(pasteLinkAction.isEnabledForContext(pasteLinkActionContext));
		runSwing(() -> pasteLinkAction.actionPerformed(pasteLinkActionContext));

		//
		// Verify external folder paste as link
		//
		DomainFileNode abcCopyNode = env.waitForFileNode("/abc/f1");
		DomainFile file = abcCopyNode.getDomainFile();
		assertTrue(file.exists());
		assertTrue(file.isLink());
		LinkFileInfo linkInfo = file.getLinkInfo();
		assertTrue(linkInfo.isFolderLink());
		assertTrue(linkInfo.isExternalLink());

		assertEquals(LinkStatus.EXTERNAL, LinkHandler.getLinkFileStatus(file, null));

		//
		// Folder link-paths intentionally omit the trailing / so they can adapt to use
		// of folder or another folder-link-file at the referenced location
		//
		String urlPath = sharedFolderURL.toExternalForm(); // will end with '/'
		urlPath = urlPath.substring(0, urlPath.length() - 1); // strip trailing '/'

		assertEquals(urlPath, linkInfo.getLinkPath());

		LinkedDomainFolder linkedFolder = linkInfo.getLinkedFolder();
		assertNotNull(linkedFolder);
		assertTrue(linkedFolder.isLinked());
		assertEquals(f1Folder.getDomainFolder(), linkedFolder.getRealFolder());

		ProjectData projectData = env.getFrontEndTool().getProject().getProjectData();

		//
		// Verify stored folder and its indirect folder content access via ProjectData
		//
		DomainFolder remoteFolder = projectData.getFolder("/abc/f1");
		assertNull(remoteFolder); // must use filter to allow externals
		remoteFolder = projectData.getFolder("/abc/f1", DomainFolderFilter.ALL_FOLDERS_FILTER);
		assertEquals(linkedFolder, remoteFolder);
		assertEquals(sharedFolderURL, remoteFolder.getSharedProjectURL());

		DomainFile remoteFile = projectData.getFile("/abc/f1/bash");
		assertNull(remoteFile); // must use filter to allow externals
		remoteFile = projectData.getFile("/abc/f1/bash", DomainFileFilter.ALL_FILES_FILTER);
		assertNotNull(remoteFile);
		assertTrue(remoteFile.exists());
		URL sharedFileURL = GhidraURL.makeURL("localhost", ServerTestUtil.GHIDRA_TEST_SERVER_PORT,
			"Test", "/f1", "bash", null);
		assertEquals(sharedFileURL, remoteFile.getSharedProjectURL(null));

		//
		// Verify ability to open linked-folder content
		//
		DomainObject dobj = null;
		try {
			dobj = remoteFile.getDomainObject(this, false, false, TaskMonitor.DUMMY);
			assertTrue(dobj instanceof ProgramDB);
			assertFalse(dobj.canSave());
			assertTrue(dobj.isChangeable());
		}
		finally {
			if (dobj != null) {
				dobj.release(this);
			}
		}
	}

	@Test
	public void testCopyPastExternalFolderLinkAsLink() throws Exception {

		env.getRootFolder().createFolder("abc");

		addRepoView();

		env.waitForTree();

		//
		// Select f1Link folder-link from viewed project and Copy
		//
		DataTreeHelper viewTreeHelper = env.getReadOnlyProjectTreeHelper(viewURL.toExternalForm());
		assertNotNull("repo data tree view not found", viewTreeHelper);

		DomainFileNode f1LinkFile = viewTreeHelper.waitForFileNode("/f1Link");

		final ActionContext copyActionContext =
			viewTreeHelper.getDomainFileActionContext(f1LinkFile);

		URL sharedFolderURL = GhidraURL.makeURL("localhost", ServerTestUtil.GHIDRA_TEST_SERVER_PORT,
			"Test", "/f1Link", null);

		DockingActionIf copyAction = getAction(env.getFrontEndTool(), "Copy");
		assertNotNull("Copy action not found", copyAction);

		assertTrue(copyAction.isAddToPopup(copyActionContext));
		assertTrue(copyAction.isEnabledForContext(copyActionContext));
		runSwing(() -> copyAction.actionPerformed(copyActionContext));

		//
		// Select abc folder and perform Paste Link
		//
		DomainFolderNode abcNode = env.waitForFolderNode("/abc");

		final ActionContext pasteLinkActionContext = env.getDomainFileActionContext(abcNode);

		DockingActionIf pasteLinkAction = getAction(env.getFrontEndTool(), "Paste Link");
		assertNotNull("Paste Link action not found", pasteLinkAction);

		assertTrue(pasteLinkAction.isAddToPopup(pasteLinkActionContext));
		assertTrue(pasteLinkAction.isEnabledForContext(pasteLinkActionContext));
		runSwing(() -> pasteLinkAction.actionPerformed(pasteLinkActionContext));

		DomainFileNode f1LinkCopyNode = env.waitForFileNode("/abc/f1Link");
		DomainFile file = f1LinkCopyNode.getDomainFile();
		assertTrue(file.exists());
		assertTrue(file.isLink());
		LinkFileInfo linkInfo = file.getLinkInfo();
		assertTrue(linkInfo.isFolderLink());
		assertTrue(linkInfo.isExternalLink());

		assertEquals(LinkStatus.EXTERNAL, LinkHandler.getLinkFileStatus(file, null));

		//
		// Folder link-paths intentionally omit the trailing / so they can adapt to use
		// of folder or another folder-link-file at the referenced location
		//
		String urlPath = sharedFolderURL.toExternalForm();

		assertEquals(urlPath, linkInfo.getLinkPath());

		LinkedDomainFolder linkedFolder = linkInfo.getLinkedFolder();
		assertNotNull(linkedFolder);
		assertTrue(linkedFolder.isLinked());

		assertEquals("/f1Link", linkedFolder.getLinkedPathname());

		assertNotNull("Linked folder content not found", linkedFolder.getFile("bash"));

		//
		// Verify stored folder and its double-hop indirect folder content access via ProjectData
		//
		ProjectData projectData = env.getFrontEndTool().getProject().getProjectData();
		DomainFile remoteFile =
			projectData.getFile("/abc/f1Link/bash", DomainFileFilter.ALL_FILES_FILTER);
		assertNotNull(remoteFile);
		assertTrue(remoteFile.exists());
		URL sharedFileURL = GhidraURL.makeURL("localhost", ServerTestUtil.GHIDRA_TEST_SERVER_PORT,
			"Test", "/f1Link", "bash", null);
		assertEquals(sharedFileURL, remoteFile.getSharedProjectURL(null));

		//
		// Verify ability to open double-hop linked-folder content
		//
		DomainObject dobj = null;
		try {
			dobj = remoteFile.getDomainObject(this, false, false, TaskMonitor.DUMMY);
			assertTrue(dobj instanceof ProgramDB);
			assertFalse(dobj.canSave());
			assertTrue(dobj.isChangeable());
		}
		finally {
			if (dobj != null) {
				dobj.release(this);
			}
		}
	}

}
