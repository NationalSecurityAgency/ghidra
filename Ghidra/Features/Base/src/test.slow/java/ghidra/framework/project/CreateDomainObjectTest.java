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
package ghidra.framework.project;

import static org.junit.Assert.*;

import org.junit.*;

import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;
import ghidra.test.*;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * test for creating a new empty tool with the new front end
 */
public class CreateDomainObjectTest extends AbstractGhidraHeadedIntegrationTest {

	private final static String PROJECT_NAME1 = "DomainObjTests";
	private final static String PROJECT_NAME2 = "DomainObjTests2";

	private Project project;
	private String testDir;

	/**
	* Constructor
	* @param arg0
	*/
	public CreateDomainObjectTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		testDir = getTestDirectoryPath();
		ProjectTestUtils.deleteProject(testDir, PROJECT_NAME1);
		ProjectTestUtils.deleteProject(testDir, PROJECT_NAME2);
		project = ProjectTestUtils.getProject(testDir, PROJECT_NAME1);
	}

	@After
	public void tearDown() throws Exception {
		if (project != null) {
			project.close();
		}
		ProjectTestUtils.deleteProject(testDir, PROJECT_NAME1);
		ProjectTestUtils.deleteProject(testDir, PROJECT_NAME2);

	}

	/**
	 * Test domain object.
	 * @throws Exception
	 */
	@Test
	public void testDomainObject() throws Exception {

		// test 1 create a program and add it to a project
		Program program1 = createProgram(project, "Prog1", this);
		PluginTool consumer2 = new DummyTool();
		Program program2 = null;
		try {
			// test 2 - get the object from the project and make sure it is the
			// same instance.
			program2 = getProgram(project, "Prog1", consumer2);
			if (program1 != program2) {
				Assert.fail("Not same instance");
			}
		}
		finally {
			program1.release(this);
			if (program2 != null) {
				program2.release(consumer2);
			}
		}

		// test 3 - close the project and make sure the object is still there
		// when the project is reopened.
		project.close();
		project = ProjectTestUtils.getProject(testDir, PROJECT_NAME1);
		Program program3 = getProgram(project, "Prog1", this);
		if (program3 == null) {
			Assert.fail("Can't get program");
			return;
		}
		program3.release(this);

		// test 4 - rename program
		renameProgram(program3, "Prog2");
		project.close();
		project = ProjectTestUtils.getProject(testDir, PROJECT_NAME1);
		program3 = getProgram(project, "Prog2", this);
		if (program3 == null) {
			Assert.fail("Rename failed");
			return;
		}
		program3.release(this);

		// test 5 - get domainFile from other project view and make sure it is read-only
		project.close();
		Project project2 = ProjectTestUtils.getProject(testDir, PROJECT_NAME2);
		try {
			project2.addProjectView(GhidraURL.makeURL(testDir, PROJECT_NAME1));
		}
		catch (Exception e) {
			Assert.fail("View Not found");
		}
		program3 = getViewedObject(project2, "Prog2", this);
		if (program3 == null) {
			Assert.fail("getViewedObject failed");
			return;
		}
		project2.close();
		program3.release(this);

		// test 6 - test deleteObject file
		project = ProjectTestUtils.getProject(testDir, PROJECT_NAME1);
		deleteObject(project, "Prog2");
		project.close();
		project = ProjectTestUtils.getProject(testDir, PROJECT_NAME1);
		Program prog = getProgram(project, "Prog2", this);
		if (prog != null) {
			Assert.fail("deleteObject failed");
		}

		// test 7 = test create folder
		createFolder(project, "Data");
		project.close();
		project = ProjectTestUtils.getProject(testDir, PROJECT_NAME1);
		DomainFolder folder = getFolder(project, "Data");
		if (folder == null) {
			Assert.fail("Cannot create folder");
		}

		// test 8 - test cannot create folder in root
		// this is currently ok
		///		createFolderAtRoot(project, "John");

		// test 9 - test delete folder
		deleteFolder(project, "Data");
		project.close();
		project = ProjectTestUtils.getProject(testDir, PROJECT_NAME1);
		folder = getFolder(project, "Data");
		if (folder != null) {
			Assert.fail("Cannot delete folder");
		}

		// test 10 - rename folder
		createFolder(project, "Data");
		renameFolder(project, "Data", "Data2");
		project.close();
		project = ProjectTestUtils.getProject(testDir, PROJECT_NAME1);
		folder = getFolder(project, "Data2");
		if (folder == null) {
			Assert.fail("Cannot create folder");
		}

		// test 11 - test readOnly flag
		createProgramReadOnly(project, "Prog1");
		testReadOnly(project, "Prog1");
		project.close();
		project = ProjectTestUtils.getProject(testDir, PROJECT_NAME1);
		testReadOnly(project, "Prog1");
		project.close();
		// test 12 - delete project
		ProjectTestUtils.deleteProject(testDir, PROJECT_NAME1);
		ProjectTestUtils.deleteProject(testDir, PROJECT_NAME2);

		// test 13 - copy files and folders
		project.close();
		project = ProjectTestUtils.getProject(testDir, PROJECT_NAME1);
		buildTree(project, "A");
		copyTree(project, "A", "B");
		testTree(project, "B", "A");
		moveTree(project, "A", "C");
		testTree(project, "C", "A");
		if (getFolder(project, "A") != null) {
			Assert.fail("A still exists after moving it to C");
		}
		project.close();
		ProjectTestUtils.deleteProject(testDir, PROJECT_NAME1);
	}

	private static void renameProgram(Program p, String newName) throws Exception {
		DomainFile dfile = p.getDomainFile();
		dfile.setName(newName);
	}

	private static Program createProgram(Project proj, String progName, Object consumer)
			throws Exception {

		Program p = createDefaultProgram(progName, ProgramBuilder._TOY, consumer);
		DomainFolder df = proj.getProjectData().getRootFolder();
		df.createFile(progName, p, null);
		return p;
	}

	private static void createProgramReadOnly(Project proj, String progName) throws Exception {

		PluginTool t = new DummyTool();
		Program p = createDefaultProgram(progName, ProgramBuilder._TOY, t);

		try {
			DomainFolder df = proj.getProjectData().getRootFolder();
			DomainFile dfile = df.createFile(progName, p, null);
			dfile.setReadOnly(true);
		}
		finally {
			p.release(t);
		}
	}

	private static Program getProgram(Project proj, String progName, Object consumer)
			throws Exception {
		DomainFolder df = proj.getProjectData().getRootFolder();

		DomainFile dfile = df.getFile(progName);
		if (dfile == null) {
			return null;
		}
		return (Program) dfile.getDomainObject(consumer, false, false, null);
	}

	private static void testReadOnly(Project proj, String progName) throws Exception {
		DomainFolder df = proj.getProjectData().getRootFolder();
		DomainFile dfile = df.getFile(progName);
		if (!dfile.isReadOnly()) {
			Assert.fail("test readOnly failed");
		}
	}

	private static void deleteObject(Project proj, String progName) throws Exception {
		DomainFolder df = proj.getProjectData().getRootFolder();
		DomainFile file = df.getFile(progName);
		file.delete();
	}

	private static Program getViewedObject(Project proj, String progName, Object consumer)
			throws Exception {
		ProjectData[] pd = proj.getViewedProjectData();

		DomainFolder mydf = pd[0].getRootFolder();
		DomainFile dfile = mydf.getFile(progName);
		if (dfile.canSave()) {
			Assert.fail("Get Viewed Object is savable");
		}
		return (Program) dfile.getDomainObject(consumer, false, false, null);
	}

	private static void createFolder(Project proj, String folderName) throws Exception {
		DomainFolder df = proj.getProjectData().getRootFolder();
		df.createFolder(folderName);
	}

	private static DomainFolder getFolder(Project proj, String folderName) throws Exception {
		DomainFolder df = proj.getProjectData().getRootFolder();
		return df.getFolder(folderName);
	}

	private static void renameFolder(Project proj, String oldName, String newName)
			throws Exception {
		DomainFolder df = proj.getProjectData().getRootFolder();
		DomainFolder folder = df.getFolder(oldName);
		folder = folder.setName(newName);
		assertEquals(newName, folder.getName());
	}

	private static void deleteFolder(Project proj, String folderName) throws Exception {
		DomainFolder df = proj.getProjectData().getRootFolder();
		df = df.getFolder(folderName);
		df.delete();
	}

	private static void buildTree(Project proj, String folderName) throws Exception {
		DomainFolder df = proj.getProjectData().getRootFolder();

		DomainFolder f = df.createFolder(folderName);
		DomainFolder f2 = f.createFolder("X");
		DomainFolder f3 = f.createFolder("Y");
		DomainFolder f4 = f.createFolder("Z");

		PluginTool t = new DummyTool("Tool1");

		Program p1 = null;
		Program p2 = null;
		Program p3 = null;
		Program p4 = null;
		Program p5 = null;
		try {

			p1 = createDefaultProgram("Test", ProgramBuilder._TOY, t);
			p2 = createDefaultProgram("Test", ProgramBuilder._TOY, t);
			p3 = createDefaultProgram("Test", ProgramBuilder._TOY, t);
			p4 = createDefaultProgram("Test", ProgramBuilder._TOY, t);
			p5 = createDefaultProgram("Test", ProgramBuilder._TOY, t);

			f.createFile("AAA", p1, null);
			f.createFile("BBB", p2, null);
			f2.createFile("CCC", p3, null);
			f3.createFile("DDD", p4, null);
			f4.createFile("EEE", p5, null);
		}
		finally {
			if (p1 != null) {
				p1.release(t);
			}
			if (p2 != null) {
				p2.release(t);
			}
			if (p3 != null) {
				p3.release(t);
			}
			if (p4 != null) {
				p4.release(t);
			}
			if (p5 != null) {
				p5.release(t);
			}
		}
	}

	private static void testTree(Project proj, String fname1, String fname2) throws Exception {
		DomainFolder df = proj.getProjectData().getRootFolder();

		DomainFolder f = df.getFolder(fname1);
		f = f.getFolder(fname2);
		DomainFolder f2 = f.getFolder("X");
		DomainFolder f3 = f.getFolder("Y");
		DomainFolder f4 = f.getFolder("Z");

		PluginTool t = new DummyTool("Tool1");

		if ((f.getFile("AAA") == null) || (f.getFile("BBB") == null) ||
			(f2.getFile("CCC") == null) || (f3.getFile("DDD") == null) ||
			(f4.getFile("EEE") == null)) {
			Assert.fail("test tree " + fname1 + " failed, can't get file");
		}
		DomainFile file = f4.getFile("EEE");
		DomainObject obj = file.getDomainObject(t, false, false, null);
		if (obj == null) {
			Assert.fail("Testing tree, domainObj == null");
		}
		else {
			obj.release(t);
		}
	}

	private static void copyTree(Project proj, String from, String to) throws Exception {
		DomainFolder df = proj.getProjectData().getRootFolder();

		DomainFolder f = df.createFolder(to);
		DomainFolder f2 = df.getFolder(from);
		f2.copyTo(f, TaskMonitorAdapter.DUMMY_MONITOR);
	}

	private static void moveTree(Project proj, String from, String to) throws Exception {
		DomainFolder df = proj.getProjectData().getRootFolder();

		DomainFolder f = df.createFolder(to);
		DomainFolder f2 = df.getFolder(from);
		f2.moveTo(f);
	}

}
