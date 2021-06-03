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
package ghidra.server;

import static org.junit.Assert.*;

import java.io.File;

import org.junit.*;

import ghidra.framework.remote.User;
import ghidra.server.remote.ServerTestUtil;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.exception.DuplicateFileException;
import ghidra.util.exception.UserAccessException;

public class RepositoryManagerTest extends AbstractGhidraHeadedIntegrationTest {

	private RepositoryManager mgr;
	private File root;

	public RepositoryManagerTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		File parent = createTempDirectory(getName());
		root = new File(parent, "Repositories");
		if (root.exists()) {
			deleteFiles(root);
			root.delete();
		}
		root.mkdir();
		writeUserList(root);
	}

	@After
	public void tearDown() throws Exception {
		if (mgr != null) {
			mgr.dispose();
		}
		deleteFiles(root);
		root.delete();
	}

	@Test
	public void testCreateRepositoryManager() throws Exception {

		mgr = new RepositoryManager(root, false, 0, false);
		assertNotNull(mgr);

		String[] userNames = mgr.getAllUsers("User_0");
		assertEquals(10, userNames.length);
	}

	@Test
	public void testCreateRepositoryManagerWithAnonymous() throws Exception {

		mgr = new RepositoryManager(root, false, 0, true);
		assertNotNull(mgr);

		String[] userNames = mgr.getAllUsers("User_0");
		assertEquals(10, userNames.length);

		userNames = mgr.getAllUsers(UserManager.ANONYMOUS_USERNAME);
		assertEquals(0, userNames.length);
	}

	@Test
	public void testCreateRepository() throws Exception {
		mgr = new RepositoryManager(root, false, 0, false);

		Repository rep = mgr.createRepository("User_0", "REPOSITORY_A");
		assertNotNull(rep);
	}

	@Test
	public void testCreateRepositoryAnonymous() throws Exception {
		mgr = new RepositoryManager(root, false, 0, true);

		Repository rep = mgr.createRepository("User_0", "REPOSITORY_A");
		assertNotNull(rep);

		try {
			mgr.createRepository(UserManager.ANONYMOUS_USERNAME, "REPOSITORY_B");
			Assert.fail("Expected UserAccessException");
		}
		catch (UserAccessException e) {
			// expected
		}
	}

	@Test
	public void testCreateDuplicateRepository() throws Exception {
		mgr = new RepositoryManager(root, false, 0, false);
		mgr.createRepository("User_0", "REPOSITORY_A");
		try {
			mgr.createRepository("User_5", "REPOSITORY_A");
			Assert.fail("Should have gotten DuplicateNameException!");
		}
		catch (DuplicateFileException e) {
		}
	}

	@Test
	public void testGetRepository() throws Exception {
		mgr = new RepositoryManager(root, false, 0, true);
		Repository rep1 = mgr.createRepository("User_0", "REPOSITORY_A");
		addUsers("User_0", true, rep1);

		Repository rep2 = mgr.createRepository("User_0", "REPOSITORY_B");
		addUsers("User_0", false, rep2);

		Repository rep3 = mgr.createRepository("User_9", "REPOSITORY_9A");
		addUsers("User_9", false, rep3);

		Repository rep4 = mgr.createRepository("User_9", "REPOSITORY_9B");
		addUsers("User_9", false, rep4);

		assertEquals(rep1, mgr.getRepository("User_1", "REPOSITORY_A"));
		assertEquals(rep1, mgr.getRepository(UserManager.ANONYMOUS_USERNAME, "REPOSITORY_A"));
		assertEquals(rep2, mgr.getRepository("User_2", "REPOSITORY_B"));
		try {
			mgr.getRepository(UserManager.ANONYMOUS_USERNAME, "REPOSITORY_B");
			Assert.fail("Expected UserAccessException");
		}
		catch (UserAccessException e) {
			// expected
		}
		assertEquals(rep3, mgr.getRepository("User_3", "REPOSITORY_9A"));
		assertEquals(rep4, mgr.getRepository("User_4", "REPOSITORY_9B"));
	}

	@Test
	public void testGetRepositoryBadUser() throws Exception {
		mgr = new RepositoryManager(root, false, 0, false);
		mgr.createRepository("User_0", "REPOSITORY_A");

		try {
			mgr.getRepository("unknownUser", "REPOSITORY_A");
			Assert.fail("Should not have been able to get repository!");
		}
		catch (UserAccessException e) {
		}

		try {
			mgr.getRepository(UserManager.ANONYMOUS_USERNAME, "REPOSITORY_A");
			Assert.fail("Should not have been able to get repository!");
		}
		catch (UserAccessException e) {
		}
	}

	private void addUsers(String currentUser, boolean allowAnonymousAccess, Repository rep)
			throws Exception {
		User[] users = new User[10];
		for (int i = 0; i < 10; i++) {
			String name = "User_" + i;
			int type = User.READ_ONLY;
			if (name.equals(currentUser)) {
				type = User.ADMIN;
			}
			users[i] = new User("User_" + i, type);
		}
		rep.setUserList(currentUser, users, allowAnonymousAccess);
	}

	private void writeUserList(File repositoryRoot) throws Exception {

		String[] userNames = new String[10];
		for (int i = 0; i < userNames.length; i++) {
			userNames[i] = "User_" + i;
		}

		ServerTestUtil.createUsers(repositoryRoot.getAbsolutePath(), userNames);
	}

	/**
	 * Recursive method to delete files in the given parent directory.
	 */
	private boolean deleteFiles(File parent) {

		File[] f = parent.listFiles();
		for (File element : f) {
			if (element.isDirectory()) {
				if (!deleteFiles(element)) {
					return false;
				}
				element.delete();
			}
			else if (!element.delete()) {
				return false;
			}
		}
		return true;
	}

}
