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
package ghidra.app.util.viewer.util;

import static org.junit.Assert.*;

import org.junit.*;

import ghidra.framework.model.*;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramUserData;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitor;

public class PersistentOpenCloseManagerTest extends AbstractGhidraHeadedIntegrationTest {
	private DomainFile df;
	private AddressSpace space;
	private Program program;
	private OpenCloseManager openCloseMgr;
	private TestEnv env;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		Project project = env.getProject();
		ProgramBuilder builder = new ProgramBuilder("Test", ProgramBuilder._TOY, this);
		ProjectData projectData = project.getProjectData();

		DomainFolder rootFolder = projectData.getRootFolder();
		program = builder.getProgram();
		df = rootFolder.createFile("test", program, TaskMonitor.DUMMY);

		space = program.getAddressFactory().getDefaultAddressSpace();
		ProgramUserData programUserData = program.getProgramUserData();
		openCloseMgr = new PersistentOpenCloseManager(programUserData, "test", "test");
	}

	@After
	public void tearDown() {
		env.dispose();
	}

	@Test
	public void testOpenByDefaultCloseAllOpenAll() throws Exception {
		assertTrue(openCloseMgr.isOpen(addr(0)));
		assertTrue(openCloseMgr.isOpen(addr(100)));
		assertTrue(openCloseMgr.isOpenByDefault());

		openCloseMgr.closeAll();

		assertFalse(openCloseMgr.isOpen(addr(0)));
		assertFalse(openCloseMgr.isOpen(addr(100)));
		assertFalse(openCloseMgr.isOpenByDefault());

		openCloseMgr.openAll();
		assertTrue(openCloseMgr.isOpen(addr(0)));
		assertTrue(openCloseMgr.isOpen(addr(100)));
		assertTrue(openCloseMgr.isOpenByDefault());
	}

	@Test
	public void testCloseAndOpenSpecificAddresses() throws Exception {
		assertTrue(openCloseMgr.isOpen(addr(0)));
		assertTrue(openCloseMgr.isOpen(addr(100)));

		openCloseMgr.close(addr(0));

		assertFalse(openCloseMgr.isOpen(addr(0)));
		assertTrue(openCloseMgr.isOpen(addr(100)));

		openCloseMgr.open(addr(0));

		assertTrue(openCloseMgr.isOpen(addr(0)));
		assertTrue(openCloseMgr.isOpen(addr(100)));
	}

	@Test
	public void testOpenAndCloseSpecificAddressesWithDefaultClosed() throws Exception {
		openCloseMgr.closeAll();

		assertFalse(openCloseMgr.isOpen(addr(0)));
		assertFalse(openCloseMgr.isOpen(addr(100)));

		openCloseMgr.open(addr(0));

		assertTrue(openCloseMgr.isOpen(addr(0)));
		assertFalse(openCloseMgr.isOpen(addr(100)));

		openCloseMgr.close(addr(0));

		assertFalse(openCloseMgr.isOpen(addr(0)));
		assertFalse(openCloseMgr.isOpen(addr(100)));
	}

	@Test
	public void testPersistence() throws Exception {
		openCloseMgr.closeAll();
		assertFalse(openCloseMgr.isOpen(addr(0)));
		assertFalse(openCloseMgr.isOpen(addr(100)));

		openCloseMgr.open(addr(0));
		assertTrue(openCloseMgr.isOpen(addr(0)));
		assertFalse(openCloseMgr.isOpen(addr(100)));

		program.release(this);
		program = (Program) df.getDomainObject(this, false, false, TaskMonitor.DUMMY);
		space = program.getAddressFactory().getDefaultAddressSpace();
		ProgramUserData programUserData = program.getProgramUserData();
		openCloseMgr = new PersistentOpenCloseManager(programUserData, "test", "test");

		assertTrue(openCloseMgr.isOpen(addr(0)));
		assertFalse(openCloseMgr.isOpen(addr(100)));
		assertFalse(openCloseMgr.isOpenByDefault());
	}

	private Address addr(long offset) {
		return space.getAddress(offset);
	}

}
