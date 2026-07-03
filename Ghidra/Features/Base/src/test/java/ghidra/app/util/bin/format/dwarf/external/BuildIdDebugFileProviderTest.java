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

public class BuildIdDebugFileProviderTest extends AbstractGenericTest {
	private TaskMonitor monitor = TaskMonitor.DUMMY;
	private File tmpDir;

	@Before
	public void setUp() throws Exception {
		tmpDir = createTempDirectory("buildid_provider_test");
	}

	@Test
	public void testGet() throws IOException, CancelledException {
		BuildIdDebugFileProvider provider = new BuildIdDebugFileProvider(tmpDir);

		String buildId = "0000000000000000000000000000000000000000";

		File f = new File(tmpDir,
			"%s/%s.debug".formatted(buildId.substring(0, 2), buildId.substring(2)));
		FileUtilities.checkedMkdirs(f.getParentFile());
		FileUtilities.writeStringToFile(f, "test1");

		File result = provider.getFile(ExternalDebugInfo.forBuildId(buildId), monitor);

		assertEquals("test1", Files.readString(result.toPath()));
		assertEquals(5, result.length());
	}
}
