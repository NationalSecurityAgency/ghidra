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
package ghidra.framework;

import java.io.File;

import utility.module.ModuleUtilities;

public class TestApplicationUtils {

	public static File getTestApplicationRootDirectory() {
		// returns the application root used for testing; called before Application.initialize()
		File repo = getCurrentRepoDirectory();
		return new File(repo, "Ghidra");
	}

	public static File getCurrentRepoDirectory() {
		// Assumption: the user is running tests from within a repo sub-project
		// 
		// At the time writing "user.dir" is the "Ghidra" directory.
		// Update: it seems things have changed (jUnit 4, maybe?)--this value is now 
		//         ghidra/Ghidra/Features/Base
		String userDir = System.getProperty("user.dir");
		File repo = ModuleUtilities.findRepo(new File(userDir));
		return repo;
	}

	/**
	 * Returns a directory that contains all repos for a given git clone. This
	 * directory name is unique to the active clone collection, which makes it
	 * useful for creating unique temporary directories to allow multiple
	 * simultaneous test runs.
	 * 
	 * @return the parent dir of the current repo
	 */
	public static File getRepoContainerDirectory() {
		File repo = getCurrentRepoDirectory();
		File repoContainer = repo.getParentFile();
		return repoContainer;
	}

	/**
	 * Creates a folder that is unique for the current repo. This allows clients
	 * to have multiple clones on their machine, running tests from each repo
	 * simultaneously.
	 * 
	 * @return a folder that is unique for the current repo.
	 */
	public static File getUniqueTempFolder() {
		//
		// Create a unique name based upon the repo from which we are running.
		//
		File reposContainer = TestApplicationUtils.getRepoContainerDirectory();

		File tmpDir = new File(System.getProperty("java.io.tmpdir"));
		String tempName = tmpDir.getName();

		//
		// The container name makes this name unique across multiple Eclipses; the system temp 
		// name makes this name unique across multiple runs from the same Eclipse
		//
		String name = reposContainer.getName() + tempName;
		return new File(tmpDir, name);
	}
}
