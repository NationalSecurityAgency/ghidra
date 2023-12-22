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
package ghidra.query.test;

import java.io.*;

import ghidra.features.bsim.query.BSimControlLaunchable;
import ghidra.util.MD5Utilities;
import utilities.util.FileUtilities;

/**
 * The TEST_DIRECTORY String should be changed to point to a directory that will
 * hold data for the server and for the tests.  To start, this directory should contain
 * a subdirectory "raw", and within this subdirectory should be the following 3 specific binary 
 * executables:
 *    libreadline.so.7.0
 *    libhistory.so.7.0
 *    bash
 *    
 *    all pulled from Ubuntu 18.04.5.
 */
public class BSimServerTestUtil {
	private static final String HOST_URL = "postgresql://localhost";
//	private static final String HOST_URL = "https://localhost:9200";
//	private static final String HOST_URL = "file:///tmp/bsimtest/db";
	private static final String TEST_DIRECTORY = "/tmp/bsimtest";
	public static final String REPO_NAME = "repo";
	public static final String LIBHISTORY_MD5 = "0a860a716d5bec97c64db652549b72fd";
	public static final String LIBREADLINE_MD5 = "71b5761b43b840eb88d053790deaf77c";
	public static final String BASH_MD5 = "557c0271e30cf474e0f46f93721fd1ba";
	public String repoName;
	public String bsimURLString = HOST_URL + '/' + REPO_NAME;
	public String testDir;
	public String ghidraDir;
	public String projectDir;
	public String rawDir;
	public String xmlDir;
	public String serverDir;
	public String serverTouchDir;
	public boolean isElasticSearch;
	public boolean isH2Database;

	public BSimServerTestUtil() {
		testDir = TEST_DIRECTORY;
		ghidraDir = TEST_DIRECTORY + "/ghidra";
		repoName = REPO_NAME;
		projectDir = testDir + "/project";
		rawDir = testDir + "/raw";
		xmlDir = testDir + "/xml";
		serverDir = testDir + "/db";
		serverTouchDir = testDir + "/servertouch";
		isElasticSearch = HOST_URL.startsWith("http") || HOST_URL.startsWith("elastic");
		isH2Database = HOST_URL.startsWith("file");
	}

	public void verifyDirectories() throws FileNotFoundException {
		File dir0 = new File(testDir);
		if (!dir0.exists()) {
			throw new FileNotFoundException("Could not find test directory");
		}
		File dir1 = new File(projectDir);
		if (!dir1.exists()) {
			if (!dir1.mkdir()) {
				throw new FileNotFoundException("Could not create project directory");
			}
		}
		File dir2 = new File(xmlDir);
		if (!dir2.exists()) {
			if (!dir2.mkdir()) {
				throw new FileNotFoundException("Could not create xml directory");
			}
		}
		File dir3 = new File(ghidraDir);
		if (!dir3.exists()) {
			if (!dir3.mkdir()) {
				throw new FileNotFoundException("Could not create ghidra directory");
			}
		}
	}

	public void verifyRaw() throws IOException {
		File rawDirectory = new File(rawDir);
		if (!rawDirectory.exists()) {
			throw new FileNotFoundException(rawDir);
		}
		if (!rawDirectory.isDirectory()) {
			throw new FileNotFoundException("/raw is not a directory");
		}
		String[] list = rawDirectory.list();
		boolean readlinePresent = false;
		boolean historyPresent = false;
		boolean bashPresent = false;
		for (String element : list) {
			File lib = new File(rawDirectory, element);
			if (element.equals("libreadline.so.7.0")) {
				String md5 = MD5Utilities.getMD5Hash(lib);
				if (md5.equals(LIBREADLINE_MD5)) {
					readlinePresent = true;
				}
				else {
					throw new FileNotFoundException("libreadline.so.7.0 md5 does not match");
				}
			}
			else if (element.equals("libhistory.so.7.0")) {
				String md5 = MD5Utilities.getMD5Hash(lib);
				if (md5.equals(LIBHISTORY_MD5)) {
					historyPresent = true;
				}
				else {
					throw new FileNotFoundException("libhistory.so.7.0 md5 does not match");
				}
			}
			else if (element.equals("bash")) {
				String md5 = MD5Utilities.getMD5Hash(lib);
				if (md5.equals(BASH_MD5)) {
					bashPresent = true;
				}
				else {
					throw new FileNotFoundException("bash md5 does not match");
				}
			}
		}
		if (!readlinePresent) {
			throw new FileNotFoundException("Missing libreadline.so.7.0");
		}
		if (!historyPresent) {
			throw new FileNotFoundException("Missing libhistory.so.7.0");
		}
		if (!bashPresent) {
			throw new FileNotFoundException("Missing bash");
		}
	}

	public void startServer() throws Exception {
		if (isElasticSearch || isH2Database) {
			return;				// Don't try to start elasticsearch server
		}
		File touch = new File(serverTouchDir);
		if (touch.exists()) {
			return;
		}
		File dir = new File(serverDir);
		if (dir.isDirectory()) {
			FileUtilities.deleteDir(dir);
		}
		String[] params = new String[2];

		params[0] = "start";
		params[1] = serverDir;
		dir.mkdir();			// Create the data directory

		new BSimControlLaunchable().run(params);

		byte[] touchBytes = new byte[2];
		touchBytes[0] = 'a';
		touchBytes[1] = 'b';
		FileUtilities.writeBytes(touch, touchBytes);
	}

	public void shutdownServer() throws Exception {
		if (isElasticSearch || isH2Database) {
			return;
		}
		File touch = new File(serverTouchDir);
		if (!touch.exists()) {
			return;
		}
		String[] params = new String[2];

		params[0] = "stop";
		params[1] = serverDir;
		new BSimControlLaunchable().run(params);
		touch.delete();						// Remove the touch file
		File dir = new File(serverDir);
		if (dir.isDirectory()) {
			FileUtilities.deleteDir(dir);	// Clean up database files
		}
	}
}
