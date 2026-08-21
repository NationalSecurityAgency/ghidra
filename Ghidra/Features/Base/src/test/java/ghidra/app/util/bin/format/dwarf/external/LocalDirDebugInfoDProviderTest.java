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
package ghidra.app.util.bin.format.dwarf.external;

import static org.junit.Assert.*;

import java.io.*;
import java.time.Duration;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.util.bin.format.dwarf.external.DebugStreamProvider.StreamInfo;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

public class LocalDirDebugInfoDProviderTest extends AbstractGenericTest {
	private TaskMonitor monitor = TaskMonitor.DUMMY;
	private File tmpDir;

	@Before
	public void setUp() throws Exception {
		tmpDir = createTempDirectory("debuginfod_provider_test");
	}

	@Test
	public void testAgeOff() throws IOException {
		LocalDirDebugInfoDProvider provider = new LocalDirDebugInfoDProvider(tmpDir);
		provider.purgeAll();

		String buildId = "0000000000000000000000000000000000000000";

		File f = new File(tmpDir, buildId + "/debuginfo");

		FileUtilities.checkedMkdirs(f.getParentFile());
		FileUtilities.writeStringToFile(f, "test1");
		f.setLastModified(System.currentTimeMillis() - Duration.ofDays(1).toMillis()); // make it look recent

		provider.performCacheMaintIfNeeded();
		assertTrue(f.isFile()); // should still be there

		provider.purgeAll();

		FileUtilities.checkedMkdirs(f.getParentFile());
		FileUtilities.writeStringToFile(f, "test1");
		f.setLastModified(
			System.currentTimeMillis() - LocalDirDebugInfoDProvider.MAX_FILE_AGE_MS - 1000); // make it look old

		provider.performCacheMaintIfNeeded();
		assertFalse(f.isFile()); // should be gone
	}

	@Test
	public void testGet() throws IOException, CancelledException {
		LocalDirDebugInfoDProvider provider = new LocalDirDebugInfoDProvider(tmpDir);
		provider.purgeAll();

		String buildId = "0000000000000000000000000000000000000000";

		File f = new File(tmpDir, buildId + "/debuginfo");
		FileUtilities.checkedMkdirs(f.getParentFile());
		FileUtilities.writeStringToFile(f, "test1");

		File result = provider.getFile(ExternalDebugInfo.forBuildId(buildId), monitor);

		assertEquals("debuginfo", result.getName());
		assertEquals(5, result.length());
	}

	@Test
	public void testPut() throws IOException, CancelledException {
		LocalDirDebugInfoDProvider provider = new LocalDirDebugInfoDProvider(tmpDir);
		provider.purgeAll();

		String buildId = "0000000000000000000000000000000000000000";
		byte bytes[] = "test".getBytes();
		StreamInfo stream = new StreamInfo(new ByteArrayInputStream(bytes), bytes.length);
		File f = provider.putStream(ExternalDebugInfo.forBuildId(buildId), stream, monitor);

		assertEquals("debuginfo", f.getName());
		assertEquals(bytes.length, f.length());
	}

	@Test
	public void testPutNonBuildId() throws CancelledException {
		LocalDirDebugInfoDProvider provider = new LocalDirDebugInfoDProvider(tmpDir);
		provider.purgeAll();

		byte bytes[] = "test".getBytes();
		StreamInfo stream = new StreamInfo(new ByteArrayInputStream(bytes), bytes.length);
		try {
			File f = provider.putStream(ExternalDebugInfo.forDebugLink("test.debug", 0x11223344),
				stream, monitor);
			fail("Shouldn't get here: " + f);
		}
		catch (IOException e) {
			// successfully failed
		}
	}
}
