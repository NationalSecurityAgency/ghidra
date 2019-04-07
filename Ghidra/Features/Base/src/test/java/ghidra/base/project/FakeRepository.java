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
package ghidra.base.project;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import generic.test.TestUtils;
import ghidra.framework.model.DomainFile;
import ghidra.framework.remote.User;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.test.TestEnv;

/**
 * This class represents the idea of a shared Ghidra repository.  This class is meant to be
 * used in lieu creating a Ghidra Server and interacting with it via the network stack.   This 
 * class allows testers to create users and projects that will all share the same version 
 * control system.  Thus, this shared repository is intended to allow for easy testing 
 * of changes to {@link DomainFile}s under version control.
 * 
 * <P>If you do not need to test version controlled files or any other multi-user interaction, 
 * then do not use this class, but instead use {@link TestEnv}.
 * 
 * <P>Example usage:
 * <pre>
 * 		
 *		FakeRepositoryrepo = new FakeRepository();
 *
 *		project1 = repo.createProject("user1");
 *		project2 = repo.createProject("user2");
 *
 *		DomainFile df = project1.addDomainFile("notepad");
 *		project1.addToVersionControl(df, false); // file is now visible to all project2 as well
 * </pre>
 * 
 * @see FakeRepository
 */
public class FakeRepository {

	private Map<String, User> usersByName = new HashMap<>();
	private Map<User, FakeSharedProject> projectsByUser = new HashMap<>();

	private LocalFileSystem versionedFileSystem;

	public FakeRepository() {
		// validation must be enabled if both environments are utilized by a test
		LocalFileSystem.setValidationRequired();
	}

	/**
	 * Creates a user by the given name
	 * 
	 * @param name the username
	 * @return the new user
	 */
	public User createUser(String name) {
		User user = usersByName.get(name);
		if (user != null) {
			// likely a programming error
			throw new IllegalArgumentException("Attempted to create the same user more than once");
		}

		user = new User(name, User.WRITE);
		usersByName.put(name, user);
		return user;
	}

	/**
	 * Creates a new fake project for the given username
	 * 
	 * @param username the name of the user
	 * @return the new project
	 * @throws IOException if there are any issues creating the project 
	 */
	public FakeSharedProject createProject(String username) throws IOException {
		User user = createUser(username);
		return createProject(user);
	}

	/**
	 * Creates a new fake project for the given user
	 * 
	 * @param user the user
	 * @return the new project
	 * @throws IOException if there are any issues creating the project 
	 */
	public FakeSharedProject createProject(User user) throws IOException {

		FakeSharedProject existingProject = projectsByUser.get(user);
		if (existingProject != null) {
			// likely a programming error
			throw new IllegalArgumentException(
				"Attempted to create a second shared project for the same user");
		}

		FakeSharedProject project = new FakeSharedProject(this, user);
		projectsByUser.put(user, project);

		if (versionedFileSystem == null) {
			versionedFileSystem = project.getVersionedFileSystem();
			TestUtils.setInstanceField("isShared", versionedFileSystem, Boolean.TRUE);
		}
		return project;
	}

	/**
	 * Gets the shared filesystem
	 * 
	 * @return the shared filesystem
	 */
	public LocalFileSystem getSharedFileSystem() {
		return versionedFileSystem;
	}

	/**
	 * Triggers a refresh on all projects.  Use this method if you make a file system change
	 * and you wish each file system sharing this repo to update.
	 */
	public void refresh() {
		projectsByUser.values().stream().forEach(p -> p.refresh());
	}

	/**
	 * Disposes this repo and all of its projects
	 */
	public void dispose() {
		projectsByUser.values().forEach(p -> disposeProject(p));
	}

	private void disposeProject(FakeSharedProject p) {
		p.dispose();
	}

}
