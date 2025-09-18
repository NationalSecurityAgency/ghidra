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

import ghidra.framework.data.FolderLinkContentHandler;
import ghidra.framework.data.LinkHandler.LinkStatus;
import ghidra.framework.main.datatable.DomainFileInfo;
import ghidra.framework.main.datatable.DomainFileType;
import ghidra.framework.model.*;
import ghidra.program.database.ProgramLinkContentHandler;
import ghidra.program.model.listing.Program;
import ghidra.test.*;
import ghidra.util.task.TaskMonitor;

public class ProjectLinkFileStatusTableTest extends AbstractGhidraHeadedIntegrationTest {

	private FrontEndTestEnv env;
	private FrontEndDataTableHelper tableHelper;

	private DomainFolder rootFolder;
	private DomainFolder abcFolder;
	private DomainFolder xyzFolder;

	@Before
	public void setUp() throws Exception {
		env = new FrontEndTestEnv();

		/**
			/abc/               (folder)
			 	abc -> /xyz/abc (circular)
			 	bar             (program file)
			/xyz/				(folder)
			 	abc -> /abc     (folder link)
			 		abc ->      (circular)
			 		bar			(program within linked-folder should not appear in table)
		**/

		rootFolder = env.getRootFolder();

		abcFolder = rootFolder.createFolder("abc");
		xyzFolder = rootFolder.createFolder("xyz");
		DomainFile abcLinkFile = abcFolder.copyToAsLink(xyzFolder, false);
		abcLinkFile.copyToAsLink(abcFolder, false);

		Program p = ToyProgramBuilder.buildSimpleProgram("bar", this);
		abcFolder.createFile("bar", p, TaskMonitor.DUMMY);
		p.release(this);

		tableHelper = new FrontEndDataTableHelper(env.getFrontEndTool());
		tableHelper.showTablePanel();
		tableHelper.waitForTable();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testFileWithinLinkedFolder() throws Exception {

		//
		// Check program file
		//

		DomainFileInfo fileInfo = tableHelper.getDomainFileInfoByPath("/abc/bar");
		assertNotNull(fileInfo);

		DomainFile df = fileInfo.getDomainFile();
		LinkFileInfo linkInfo = df.getLinkInfo();
		assertNull(linkInfo);

		DomainFileType domainFileType = fileInfo.getDomainFileType();
		assertEquals("Program", domainFileType.getDisplayString());
		assertTrue("Unexpected tooltip: " + fileInfo.getToolTip(),
			fileInfo.getToolTip().startsWith("Last Modified"));

		//
		// Verify program file reflected within linked-folder is not shown in table
		//

		fileInfo = tableHelper.getDomainFileInfoByPath("/xyz/bar");
		assertNull(fileInfo);

	}

	@Test
	public void testFileLink() throws Exception {

		//
		// Create program link without referenced program in place
		//

		xyzFolder.createLinkFile(rootFolder.getProjectData(), "/foo", false, "foo",
			ProgramLinkContentHandler.INSTANCE);

		tableHelper.waitForTable();

		//
		// Check initial state of broken program link
		//

		DomainFileInfo fileInfo = tableHelper.getDomainFileInfoByPath("/xyz/foo");
		assertNotNull(fileInfo);

		DomainFile df = fileInfo.getDomainFile();
		LinkFileInfo linkInfo = df.getLinkInfo();
		assertNotNull(linkInfo);

		LinkStatus linkStatus = linkInfo.getLinkStatus(null);
		assertEquals(LinkStatus.BROKEN, linkStatus);

		DomainFileType domainFileType = fileInfo.getDomainFileType();
		assertEquals("ProgramLink", domainFileType.getDisplayString());
		assertTrue("Unexpected tooltip: " + fileInfo.getToolTip(),
			fileInfo.getToolTip().startsWith("Broken ProgramLink - file not found"));

		//
		// Add program file which should repair broken program link
		//

		Program p = ToyProgramBuilder.buildSimpleProgram("foo", this);
		DomainFile programFile = rootFolder.createFile("foo", p, TaskMonitor.DUMMY);
		p.release(this);

		tableHelper.waitForTable();

		//
		// Check for new program file
		//

		fileInfo = tableHelper.getDomainFileInfoByPath("/foo");
		assertNotNull(fileInfo);

		df = fileInfo.getDomainFile();
		linkInfo = df.getLinkInfo();
		assertNull(linkInfo);

		domainFileType = fileInfo.getDomainFileType();
		assertEquals("Program", domainFileType.getDisplayString());
		assertTrue("Unexpected tooltip: " + fileInfo.getToolTip(),
			fileInfo.getToolTip().startsWith("Last Modified")); // no error

		//
		// Check for repaired program link
		//

		fileInfo = tableHelper.getDomainFileInfoByPath("/xyz/foo");
		assertNotNull(fileInfo);

		df = fileInfo.getDomainFile();
		linkInfo = df.getLinkInfo();
		assertNotNull(linkInfo);

		linkStatus = linkInfo.getLinkStatus(null);
		assertEquals(LinkStatus.INTERNAL, linkStatus);

		domainFileType = fileInfo.getDomainFileType();
		assertEquals("ProgramLink", domainFileType.getDisplayString());
		assertTrue("Unexpected tooltip: " + fileInfo.getToolTip(),
			fileInfo.getToolTip().startsWith("Last Modified")); // no error

	}

	@Test
	public void testFolderLink() throws Exception {

		// Create folder link without referenced folder in place
		xyzFolder.createLinkFile(rootFolder.getProjectData(), "/aaa", false, "aaa",
			FolderLinkContentHandler.INSTANCE);

		tableHelper.waitForTable();

		//
		// Check initial state of broken folder link
		//

		DomainFileInfo fileInfo = tableHelper.getDomainFileInfoByPath("/xyz/aaa");
		assertNotNull(fileInfo);

		DomainFile df = fileInfo.getDomainFile();
		LinkFileInfo linkInfo = df.getLinkInfo();
		assertNotNull(linkInfo);

		LinkStatus linkStatus = linkInfo.getLinkStatus(null);
		assertEquals(LinkStatus.BROKEN, linkStatus);

		DomainFileType domainFileType = fileInfo.getDomainFileType();
		assertEquals("FolderLink", domainFileType.getDisplayString());
		assertTrue("Unexpected tooltip: " + fileInfo.getToolTip(),
			fileInfo.getToolTip().startsWith("Broken FolderLink - folder not found"));

		//
		// Add folder file which should repair broken folder link
		//

		rootFolder.createFolder("aaa");

		tableHelper.waitForTable();

		//
		// Check for repaired folder link
		//

		fileInfo = tableHelper.getDomainFileInfoByPath("/xyz/aaa");
		assertNotNull(fileInfo);

		df = fileInfo.getDomainFile();
		linkInfo = df.getLinkInfo();
		assertNotNull(linkInfo);

		linkStatus = linkInfo.getLinkStatus(null);
		assertEquals(LinkStatus.INTERNAL, linkStatus);

		domainFileType = fileInfo.getDomainFileType();
		assertEquals("FolderLink", domainFileType.getDisplayString());
		assertTrue("Unexpected tooltip: " + fileInfo.getToolTip(),
			fileInfo.getToolTip().startsWith("Last Modified")); // no error

	}

}
