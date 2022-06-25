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
package ghidra.program.database;

import static org.junit.Assert.*;

import java.io.File;
import java.util.Random;
import java.util.Set;

import org.junit.*;

import generic.test.AbstractGTest;
import ghidra.framework.data.ProjectFileManager;
import ghidra.framework.model.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramUserData;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.project.test.TestProjectManager;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.ProjectTestUtils;
import ghidra.util.Msg;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

public class ProgramUserDataTest extends AbstractGhidraHeadedIntegrationTest {

	private String TEMP = AbstractGTest.getTestDirectoryPath();
	private static Random RAND = new Random();

	private ProjectLocator projectLocator;
	private Project project;
	private File userDir;
	private File dataDir;
	private DomainFile df;
	private AddressSpace space;

	@Before
	public void setUp() throws Exception {
		ProjectTestUtils.deleteProject(TEMP, "Test");
		projectLocator = new ProjectLocator(TEMP, "Test");
		project = TestProjectManager.get().createProject(projectLocator, null, true);
		dataDir =
			new File(projectLocator.getProjectDir(), ProjectFileManager.INDEXED_DATA_FOLDER_NAME);
		userDir = new File(projectLocator.getProjectDir(), ProjectFileManager.USER_FOLDER_NAME);

		ProgramBuilder builder = new ProgramBuilder("Test", ProgramBuilder._TOY);
		df = project.getProjectData()
				.getRootFolder()
				.createFile("test", builder.getProgram(),
					TaskMonitor.DUMMY);
		builder.dispose();

		Program program = null;
		try {
			program =
				(Program) df.getDomainObject(this, false, false, TaskMonitor.DUMMY);
		}
		catch (VersionException e) {
			assertTrue(e.isUpgradable());
			program =
				(Program) df.getDomainObject(this, true, false, TaskMonitor.DUMMY);
			program.save("upgrade", TaskMonitor.DUMMY);
		}
		finally {
			program.release(this);
		}
	}

	@After
	public void tearDown() {
		if (project != null) {
			project.close();
		}
		ProjectTestUtils.deleteProject(TEMP, "Test");
	}

	private void change(Program p) {
		int txId = p.startTransaction("change");
		try {
			p.setExecutablePath(Integer.toString(RAND.nextInt()));
		}
		finally {
			p.endTransaction(txId, true);
		}
	}

	private void change(ProgramUserData userData, String propertyName, Address addr, Object value) {
		int txId = userData.startTransaction();
		try {
			if (value instanceof String) {
				StringPropertyMap map =
					userData.getStringProperty(testName.getMethodName(), propertyName, true);
				map.add(addr, (String) value);
			}
			else {
				fail("Unsupported property class: " + value.getClass().getName());
			}
		}
		finally {
			userData.endTransaction(txId);
		}
	}

	private int getLatestDbVersion(File dbDir) {
		int ver = -1;
		for (String f : dbDir.list()) {
			if (f.startsWith("db.") && f.endsWith(".gbf")) {
				String str = f.substring(3, f.length() - 4);
				int val = Integer.parseInt(str);
				if (val > ver) {
					ver = val;
				}
			}
		}
		return ver;
	}

	@Test
	public void testSaveAs() throws Exception {

		// User data should not exist following import/upgrade
		assertTrue("User data directory not found", userDir.isDirectory());

		File userDataSubDir = new File(userDir, "00");
		assertFalse("User data directory should be empty", userDataSubDir.isDirectory());

		DomainFile df2;

		Program program = (Program) df.getDomainObject(this, false, false, TaskMonitor.DUMMY);
		space = program.getAddressFactory().getDefaultAddressSpace();
		assertFalse(program.isChanged());
		assertTrue(program.canSave());

		// Modify program content - no user data should be saved
		change(program);
		assertTrue(program.isChanged());
		program.save("save", TaskMonitor.DUMMY);
		assertFalse(program.isChanged());
		assertFalse("User data directory should be empty", userDataSubDir.isDirectory());

		// Modify user data content
		ProgramUserData userData = program.getProgramUserData();
		change(userData, "STRING", space.getAddress(0), "Str0");
		change(userData, "STRING", space.getAddress(10), "Str10");
		assertFalse(program.isChanged());

		String newName = df.getName() + ".1";
		df2 = df.getParent().createFile(newName, program, TaskMonitor.DUMMY);

		program.release(this);

		program = (Program) df2.getDomainObject(this, false, false, TaskMonitor.DUMMY);
		assertFalse(program.isChanged());

		// Verify user data content
		userData = program.getProgramUserData();
		StringPropertyMap map =
			userData.getStringProperty(testName.getMethodName(), "STRING", false);
		assertEquals("Str0", map.getString(space.getAddress(0)));
		assertEquals("Str10", map.getString(space.getAddress(10)));
		assertNull(map.getString(space.getAddress(20)));
		assertFalse(program.isChanged());

		program.release(this);
	}

	@Test
	public void testLazySaveAndDelete() throws Exception {

		// NOTE: test has been written to work with IndexedLocalFileSystem storage schema

		// User data should not exist following import/upgrade
		assertTrue("User data directory not found", userDir.isDirectory());

		File userDataSubDir = new File(userDir, "00");
		assertFalse("User data directory should be empty", userDataSubDir.isDirectory());

		File dbDir = new File(dataDir, "00/~00000000.db");
		int ver;

		Program program = (Program) df.getDomainObject(this, false, false, TaskMonitor.DUMMY);
		space = program.getAddressFactory().getDefaultAddressSpace();
		assertFalse(program.isChanged());
		assertTrue(program.canSave());

		// Modify program content - no user data should be saved
		change(program);
		assertTrue(program.isChanged());
		program.save("save", TaskMonitor.DUMMY);
		assertFalse(program.isChanged());
		assertFalse("User data directory should be empty", userDataSubDir.isDirectory());

		ver = getLatestDbVersion(dbDir);

		// Modify user data content
		ProgramUserData userData = program.getProgramUserData();
		change(userData, "STRING", space.getAddress(0), "Str0");
		change(userData, "STRING", space.getAddress(10), "Str10");
		assertFalse(program.isChanged());

		program.release(this);

		assertEquals("User data files missing", 2, userDataSubDir.list().length);
		assertEquals("Program database should not have been updated", ver,
			getLatestDbVersion(dbDir));

		program = (Program) df.getDomainObject(this, false, false, TaskMonitor.DUMMY);
		assertFalse(program.isChanged());

		// Verify user data content
		userData = program.getProgramUserData();
		StringPropertyMap map =
			userData.getStringProperty(testName.getMethodName(), "STRING", false);
		assertEquals("Str0", map.getString(space.getAddress(0)));
		assertEquals("Str10", map.getString(space.getAddress(10)));
		assertNull(map.getString(space.getAddress(20)));
		assertFalse(program.isChanged());

		// Modify user data content
		change(userData, "STRING", space.getAddress(10), "Str10a");
		change(userData, "STRING", space.getAddress(20), "Str20a");
		assertFalse(program.isChanged());

		program.release(this);

		program = (Program) df.getDomainObject(this, false, false, TaskMonitor.DUMMY);
		assertFalse(program.isChanged());

		// Verify user data content
		userData = program.getProgramUserData();
		map = userData.getStringProperty(testName.getMethodName(), "STRING", false);
		assertEquals("Str0", map.getString(space.getAddress(0)));
		assertEquals("Str10a", map.getString(space.getAddress(10)));
		assertEquals("Str20a", map.getString(space.getAddress(20)));
		assertFalse(program.isChanged());

		program.release(this);

		assertEquals("User data files missing", 2, userDataSubDir.list().length);
		df.delete();
		assertEquals("User data directory should be empty following delete", 0,
			userDataSubDir.list().length);

	}

	@Test
	public void testProjectOpenReconcile() throws Exception {

		// TODO: Multi-user repository connect case not tested

		Program program = (Program) df.getDomainObject(this, false, false, TaskMonitor.DUMMY);
		space = program.getAddressFactory().getDefaultAddressSpace();
		// Create user data content
		ProgramUserData userData = program.getProgramUserData();
		change(userData, "STRING", space.getAddress(0), "Str0");
		change(userData, "STRING", space.getAddress(10), "Str10");

		program.release(this);

		// Close and re-open (domain file remains intact)
		project.close();
		ProjectManager projectManager = TestProjectManager.get();
		project = projectManager.openProject(projectLocator, false, false);

		df = project.getProjectData().getFile("/test");

		program = (Program) df.getDomainObject(this, false, false, TaskMonitor.DUMMY);
		assertFalse(program.isChanged());

		// Verify user data content
		userData = program.getProgramUserData();
		StringPropertyMap map =
			userData.getStringProperty(testName.getMethodName(), "STRING", false);
		assertEquals("Str0", map.getString(space.getAddress(0)));
		assertEquals("Str10", map.getString(space.getAddress(10)));
		assertNull(map.getString(space.getAddress(20)));
		assertFalse(program.isChanged());

		program.release(this);

		// Close and re-open (domain file removed)
		project.close();
		FileUtilities.deleteDir(dataDir);
		dataDir.mkdir();
		assertEquals(0, dataDir.list().length);
		project = projectManager.openProject(projectLocator, false, false);

		// NOTE: Cleanup usually starts 5-minutes after project open - lets force it to happen now
		invokeInstanceMethod("reconcileUserDataFiles", project.getProjectData());

		// User data cleanup should occur
		File userDataSubDir = new File(userDir, "00");
		assertTrue("User data directory not found", userDataSubDir.isDirectory());

		String[] list = userDataSubDir.list();
		if (list.length != 0) {
			Msg.debug(this, "Files not deleted: ");
			for (String filename : list) {
				Msg.debug(this, "\tfile: " + filename);
			}

			fail("User data directory should be empty - see output for files found");
		}
	}

	@Test
	public void testSetGetStringProperty() throws Exception {
		Program program = (Program) df.getDomainObject(this, false, false, TaskMonitor.DUMMY);

		ProgramUserData userData = program.getProgramUserData();
		userData.setStringProperty("Foo", "Bar");
		assertEquals("Bar", userData.getStringProperty("Foo", null));
		program.release(this);

		program = (Program) df.getDomainObject(this, false, false, TaskMonitor.DUMMY);
		userData = program.getProgramUserData();
		assertEquals("Bar", userData.getStringProperty("Foo", null));
		program.release(this);
	}

	@Test
	public void testGetStringPropertyNames() throws Exception {
		Program program = (Program) df.getDomainObject(this, false, false, TaskMonitor.DUMMY);

		ProgramUserData userData = program.getProgramUserData();
		userData.setStringProperty("Alpha", "alpha");
		userData.setStringProperty("Beta", "beta");
		Set<String> stringPropertyNames = userData.getStringPropertyNames();
		assertEquals(2, stringPropertyNames.size());
		assertTrue(stringPropertyNames.contains("Alpha"));
		assertTrue(stringPropertyNames.contains("Beta"));

		program.release(this);
	}

	@Test
	public void testGetStringPropertyForNondefinedProperty() throws Exception {
		Program program = (Program) df.getDomainObject(this, false, false, TaskMonitor.DUMMY);

		ProgramUserData userData = program.getProgramUserData();
		assertEquals("xxx", userData.getStringProperty("ABC", "xxx"));
		assertEquals("zzz", userData.getStringProperty("ABC", "zzz"));

		program.release(this);
	}

	@Test
	public void testRemoveStringProperty() throws Exception {
		Program program = (Program) df.getDomainObject(this, false, false, TaskMonitor.DUMMY);

		ProgramUserData userData = program.getProgramUserData();
		userData.setStringProperty("foo", "bar");
		program.release(this);

		// reload and make sure the property is there

		program = (Program) df.getDomainObject(this, false, false, TaskMonitor.DUMMY);
		userData = program.getProgramUserData();
		assertEquals("bar", userData.getStringProperty("foo", null));
		assertEquals("bar", userData.removeStringProperty("foo"));
		program.release(this);

		// reload and make sure the property is gone

		program = (Program) df.getDomainObject(this, false, false, TaskMonitor.DUMMY);
		userData = program.getProgramUserData();
		assertNull(userData.getStringProperty("foo", null));

		program.release(this);

	}
}
