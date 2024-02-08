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
package ghidra.formats.gfilesystem;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;

public class LocalGFileSystemTest {

	private File testTempDir;
	private FileSystemService fsService;
	private File workDir;
	private LocalFileSystem localFS;

	@Before
	public void setup() throws IOException {
		testTempDir = AbstractGenericTest.createTempDirectory("localfs_test");
		fsService = new FileSystemService(new File(testTempDir, "cache"));
		workDir = new File(testTempDir, "work");
		workDir.mkdirs();
		localFS = fsService.getLocalFS();
	}

	@Test
	public void testBasePathLookups() throws IOException {
		File subworkdir = new File(workDir, "sub/Sub2/SUB3");
		subworkdir.mkdirs();

		GFile sub = localFS.lookup(FSUtilities.normalizeNativePath(workDir.getPath() + "/sub"));
		assertNotNull(sub);

		GFile rootNull = localFS.lookup(null);
		assertNotNull(rootNull);

		GFile rootSlash = localFS.lookup("/");
		assertNotNull(rootSlash);

	}

	@Test
	public void testSubFSLookup() throws IOException {
		File subworkdir = new File(workDir, "sub/Sub2/SUB3");
		subworkdir.mkdirs();

		File f = File.createTempFile("testfile", null, subworkdir);

		try (LocalFileSystemSub subFS =
			new LocalFileSystemSub(workDir, localFS)) {
			GFile gfile = subFS.lookup("/sub/Sub2/SUB3/" + f.getName());
			assertNotNull(gfile);
			assertEquals(FSUtilities.normalizeNativePath(f.getPath()), gfile.getFSRL().getPath());
			assertEquals("/sub/Sub2/SUB3/" + f.getName(), gfile.getPath());

			GFile rootDir = subFS.lookup("/");
			assertNotNull(rootDir);
			assertEquals("/", rootDir.getPath());
			assertEquals(FSUtilities.normalizeNativePath(workDir.getPath()),
				rootDir.getFSRL().getPath());

			rootDir = subFS.lookup(null);
			assertNotNull(rootDir);
			assertEquals("/", rootDir.getPath());
			assertEquals(FSUtilities.normalizeNativePath(workDir.getPath()),
				rootDir.getFSRL().getPath());

			GFile baseDir = subFS.lookup("/sub");
			assertNotNull(baseDir);
		}
	}

}
