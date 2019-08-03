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
import java.util.List;

import org.apache.commons.lang3.StringUtils;

import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.AssertException;
import utilities.util.FileUtilities;
import utility.module.ModuleUtilities;

public class TestApplicationUtils {

	/**
	 * Returns the directory that contains the source code repository
	 * @return the directory that contains the source code repository
	 */
	private static File getCurrentRepoDirectory() {
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
	 * Returns a directory that contains all repos for a given git clone. This directory name 
	 * is unique to the active clone collection, which makes it useful for creating unique 
	 * temporary directories to allow multiple simultaneous test runs.
	 * 
	 * @return the parent dir of the current repo
	 */
	private static File getRepoContainerDirectory() {
		File repo = getCurrentRepoDirectory();
		if (repo == null) {
			return null;
		}
		File repoContainer = repo.getParentFile();
		return repoContainer;
	}

	/**
	 * Returns the directory containing the installation of this application.   The value returned
	 * here will either be an actual installation directory or the parent directory of a cloned
	 * repository.  This method will work in the various modes of operation, including:
	 * <ul>
	 * 	<li><u>Development Mode</u> - running from a repo clone, from inside of an IDE or the 
	 * command-line.   In this mode a sample directory structure is:
	 * <pre>
	 * 		/.../git_repos/ghidra_clone/ghidra/Ghidra/Features/Base/src/...
	 * 
	 * 		which means this method will return 'ghidra_clone'
	 * </pre>
	 *  </li>
	 *  <li><u>Batch Testing Mode</u> - running from a test server, but not from inside a 
	 *  complete build.  This mode uses jar files for the compiled source code, but is running 
	 *  from within the structure of a cloned repo.  In this mode a sample directory structure is:
	 * <pre>
	 * 		/.../git_repos/ghidra_clone/ghidra/Ghidra/Features/Base/src/...
	 * 
	 * 		which means this method will return 'ghidra_clone'
	 * </pre>
	 *  </li>
	 *  <li><u>Eclipse Release Development Mode</u> - running from a full application release.  
	 *  This mode uses jar files from the installation for dependencies.  The user test files 
	 *  are run from within an Eclipse that has been linked with the application installation.
	 *  In this mode a sample directory structure is:
	 * <pre>
	 * 		/.../Software/ghidra_10.0/Ghidra/Features/Base/lib/Base.jar
	 * 
	 * 		which means this method will return 'ghidra_10.0'
	 * </pre>
	 *  </li>
	 * </ul>
	 * 
	 * 
	 * @return the installation directory
	 */
	public static File getInstallationDirectory() {

		File repo = getCurrentRepoDirectory();
		if (repo != null) {
			// development mode: either user-level or test machine
			return repo;
		}

		// Assumption - in an installation the current user dir is /.../<Ghidra Install Dir>/Ghidra

		String currentDir = System.getProperty("user.dir");
		Msg.debug(null, "user.dir: " + currentDir);

		// Assume that core library files are bundled in a jar file.  Find the installation
		// directory by using the distributed jar file.
		File jarFile = SystemUtilities.getSourceLocationForClass(SystemUtilities.class);
		if (jarFile == null || !jarFile.getName().endsWith(".jar")) {
			throw new AssertException("Unable to determine the installation directory");
		}

		// Assumption - jar file location follows this form:
		// <Installation Dir>/App Name/Module Group/Module Name/lib/file.jar
		List<String> parts = FileUtilities.pathToParts(jarFile.getAbsolutePath());
		int last = parts.size() - 1;
		int installDir = last - 5; // 5 folders above the filename (see above)

		String path = StringUtils.join(parts.subList(0, installDir + 1), File.separator);
		return new File(path);
	}

	/**
	 * Creates a folder that is unique for the current installation. This allows clients to 
	 * have multiple clones (for development mode) or multiple installations (for release mode)
	 * on their machine, running tests from each repo simultaneously.
	 * 
	 * @return a folder that is unique for the current installation
	 */
	public static File getUniqueTempFolder() {

		//
		// Create a unique name based upon the repo from which we are running.
		//
		File reposContainer = getRepoContainerDirectory();
		if (reposContainer == null) {
			File installDir = getInstallationDirectory();
			reposContainer = installDir;
		}

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
