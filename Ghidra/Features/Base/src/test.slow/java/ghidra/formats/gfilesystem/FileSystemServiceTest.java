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
import ghidra.app.util.bin.ByteProvider;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

public class FileSystemServiceTest extends AbstractGhidraHeadedIntegrationTest {

	private File fssTestDir;
	private FileSystemService fsService;
	private TaskMonitor monitor = TaskMonitor.DUMMY;

	@Before
	public void setup() throws IOException {
		fssTestDir = AbstractGenericTest.createTempDirectory("filesystemservice_test");
		fsService = new FileSystemService(new File(fssTestDir, "cache"));
	}

	@Test
	public void testLocalFileNotUnnecessarilyCached() throws IOException, CancelledException {
		File localFile = new File(fssTestDir, "file.txt");
		FileUtilities.writeStringToFile(localFile, "this is a test");
		FSRL localFSRL = fsService.getLocalFSRL(localFile);
		try (ByteProvider byteProvider = fsService.getByteProvider(localFSRL, true, monitor)) {
			assertEquals(localFile, byteProvider.getFile());
		}
	}

	@Test
	public void testChangedLocalFile() throws IOException, CancelledException {
		// Verifies that a fully qualified FSRL with MD5 generates a IOException failure
		// when the original file was changed.
		File localFile = new File(fssTestDir, "file.txt");
		FileUtilities.writeStringToFile(localFile, "this is a test");
		FSRL localFSRL = fsService.getLocalFSRL(localFile);
		localFSRL = fsService.getFullyQualifiedFSRL(localFSRL, monitor);

		FileUtilities.writeStringToFile(localFile, "this is a test with additional bytes");
		try (ByteProvider byteProvider = fsService.getByteProvider(localFSRL, false, monitor)) {
			fail("Should not get here, got: " + byteProvider.getFSRL());
		}
		catch (IOException e) {
			assertTrue(e.getMessage().contains("hash has changed"));

		}
	}
}
