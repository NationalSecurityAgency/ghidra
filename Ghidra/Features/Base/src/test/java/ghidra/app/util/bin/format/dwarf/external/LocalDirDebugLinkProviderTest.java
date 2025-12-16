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

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

public class LocalDirDebugLinkProviderTest extends AbstractGenericTest {
	private TaskMonitor monitor = TaskMonitor.DUMMY;
	private File tmpDir;

	@Before
	public void setUp() throws Exception {
		tmpDir = createTempDirectory("debuglink_provider_test");
	}

	@Test
	public void testGet() throws IOException, CancelledException {
		File debugNestedDir = new File(tmpDir, "sub/sub2/sub3");
		File debugFile = new File(debugNestedDir, "debugfile.abc");
		FileUtilities.mkdirs(debugFile.getParentFile());
		Files.writeString(debugFile.toPath(), "test_debuglink"); 
		int crc = LocalDirDebugLinkProvider.calcCRC(debugFile);

		LocalDirDebugLinkProvider provider = new LocalDirDebugLinkProvider(tmpDir);
		File result =
			provider.getFile(ExternalDebugInfo.forDebugLink("debugfile.abc", crc), monitor);

		assertEquals("test_debuglink", Files.readString(result.toPath()));
	}
}
