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

import ghidra.framework.client.ClientUtil;
import ghidra.framework.remote.User;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.NamingUtilities;
import ghidra.util.exception.UserAccessException;
import utilities.util.FileUtilities;

public class RepositoryTest extends AbstractGhidraHeadedIntegrationTest {

	private static final String REPOSITORY_NAME = "My_Repository";

	private File serverRoot;
	private RepositoryManager mgr;
	private Repository repository;
	private String userName;

	@Before
	public void setUp() throws Exception {

		userName = ClientUtil.getUserName();

		File parent = createTempDirectory(getClass().getSimpleName());

		// Create repository manager with no users
		serverRoot = new File(parent, "My_Server");
		FileUtilities.deleteDir(serverRoot);
		serverRoot.mkdir();

		mgr = new RepositoryManager(serverRoot, false, 0, false);
		mgr.getUserManager().addUser(userName);

		repository = mgr.createRepository(userName, REPOSITORY_NAME);
	}

	@Test
	public void testGetRepositoryName() throws Exception {
		assertEquals(REPOSITORY_NAME, repository.getName());
	}

	@Test
	public void testSetGetUserList() throws Exception {
		User[] users = new User[5];
		users[0] = new User("user-a", User.READ_ONLY);
		users[1] = new User("user-b", User.WRITE);
		users[2] = new User("user-c", User.ADMIN);
		users[3] = new User("user-d", User.READ_ONLY);
		users[4] = new User(userName, User.ADMIN);

		repository.setUserList(userName, users, false);

		User[] reportedUsers = repository.getUserList(userName);
		assertEquals(users.length, reportedUsers.length);

		for (int i = 0; i < users.length; i++) {
			assertEquals(users[i].getName(), reportedUsers[i].getName());
			assertEquals(users[i].getPermissionType(), reportedUsers[i].getPermissionType());
		}
	}

	@Test
	public void testSetListBadUser() throws Exception {

		User[] users = new User[5];
		users[0] = new User("user-a", User.READ_ONLY);
		users[1] = new User("user-b", User.WRITE);
		users[2] = new User("user-c", User.ADMIN);
		users[3] = new User("user-d", User.READ_ONLY);
		users[4] = new User(userName, User.WRITE);
		try {
			repository.setUserList(userName, users, false);
			Assert.fail("Should not have been able to change current user's access!");
		}
		catch (UserAccessException e) {
		}

		users[3] = new User("user-x", User.ADMIN);
		try {
			repository.setUserList(userName, users, false);
			Assert.fail("Should not have been able to set the user list!");
		}
		catch (UserAccessException e) {
		}

		users[4] = new User(userName, User.ADMIN);
		repository.setUserList(userName, users, false);

		User[] reportedUsers = repository.getUserList(userName);
		assertEquals(users.length, reportedUsers.length);
		for (int i = 0; i < users.length; i++) {
			assertEquals(users[i].getName(), reportedUsers[i].getName());
			assertEquals(users[i].getPermissionType(), reportedUsers[i].getPermissionType());
		}
	}

	@Test
	public void testExistingRepository() throws Exception {

		User[] users = new User[5];
		users[0] = new User("user-a", User.READ_ONLY);
		users[1] = new User("user-b", User.WRITE);
		users[2] = new User("user-c", User.ADMIN);
		users[3] = new User("user-d", User.READ_ONLY);
		users[4] = new User(userName, User.ADMIN);

		repository.setUserList(userName, users, false);

		File repRoot = new File(serverRoot, NamingUtilities.mangle(REPOSITORY_NAME));
		Repository rep = new Repository(mgr, null, repRoot, REPOSITORY_NAME);
		assertNotNull(rep);

		User[] reportedUsers = rep.getUserList(userName);
		assertEquals(users.length, reportedUsers.length);
		for (int i = 0; i < users.length; i++) {
			assertEquals(users[i].getName(), reportedUsers[i].getName());
			assertEquals(users[i].getPermissionType(), reportedUsers[i].getPermissionType());
		}

	}

}
