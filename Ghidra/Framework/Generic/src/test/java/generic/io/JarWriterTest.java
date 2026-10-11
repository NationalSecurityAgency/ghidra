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
package generic.io;

import static org.junit.Assert.*;

import java.io.*;
import java.nio.file.Files;
import java.util.jar.JarOutputStream;
import java.util.zip.ZipInputStream;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

public class JarWriterTest {

	@Rule
	public TemporaryFolder temporary = new TemporaryFolder();

	private void writeFile(File directory, String name, String contents) throws IOException {
		Files.writeString(new File(directory, name).toPath(), contents);
	}

	private int entryCount(byte[] archive) throws IOException {
		int count = 0;
		try (ZipInputStream input = new ZipInputStream(new ByteArrayInputStream(archive))) {
			while (input.getNextEntry() != null) {
				count++;
				input.readAllBytes();
			}
		}
		return count;
	}

	@Test
	public void testCanceledDirectoryReportsFailure() throws Exception {
		File directory = temporary.newFolder("files");
		writeFile(directory, "one.txt", "one");
		TaskMonitorAdapter monitor = new TaskMonitorAdapter(true);
		monitor.cancel();
		ByteArrayOutputStream bytes = new ByteArrayOutputStream();
		try (JarOutputStream output = new JarOutputStream(bytes)) {
			assertFalse(new JarWriter(output).outputRecursively(directory, "", monitor));
		}
		assertEquals(0, entryCount(bytes.toByteArray()));
	}

	@Test
	public void testCanceledEmptyDirectoryReportsFailure() throws Exception {
		File directory = temporary.newFolder("empty");
		TaskMonitorAdapter monitor = new TaskMonitorAdapter(true);
		monitor.cancel();
		try (JarOutputStream output = new JarOutputStream(new ByteArrayOutputStream())) {
			assertFalse(new JarWriter(output).outputRecursively(directory, "", monitor));
		}
	}

	private void assertCancellationDuringDirectory(boolean nested) throws Exception {
		File directory = temporary.newFolder("project");
		File files = nested ? new File(directory, "nested") : directory;
		if (nested) {
			assertTrue(files.mkdir());
		}
		writeFile(files, "one.txt", "one");
		writeFile(files, "two.txt", "two");
		TaskMonitorAdapter monitor = new TaskMonitorAdapter(true);
		ByteArrayOutputStream bytes = new ByteArrayOutputStream();
		try (JarOutputStream output = new JarOutputStream(bytes)) {
			JarWriter writer = new JarWriter(output) {
				@Override
				public boolean outputFile(File file, String path, TaskMonitor taskMonitor) {
					boolean written = super.outputFile(file, path, taskMonitor);
					taskMonitor.cancel(); // Actual first entry is written before cancellation.
					return written;
				}
			};
			assertFalse(writer.outputRecursively(directory, "", monitor));
		}
		assertTrue(monitor.isCancelled());
		assertEquals(1, entryCount(bytes.toByteArray()));
	}

	@Test
	public void testCancellationBetweenFilesReportsFailure() throws Exception {
		assertCancellationDuringDirectory(false);
	}

	@Test
	public void testNestedCancellationPropagatesFailure() throws Exception {
		assertCancellationDuringDirectory(true);
	}

	@Test
	public void testCompleteDirectoryWritesAllFiles() throws Exception {
		File directory = temporary.newFolder("complete");
		writeFile(directory, "one.txt", "one");
		writeFile(directory, "two.txt", "two");
		ByteArrayOutputStream bytes = new ByteArrayOutputStream();
		try (JarOutputStream output = new JarOutputStream(bytes)) {
			assertTrue(new JarWriter(output).outputRecursively(directory, "", TaskMonitor.DUMMY));
		}
		assertEquals(2, entryCount(bytes.toByteArray()));
	}

	@Test
	public void testExcludedFilesStillReportSuccess() throws Exception {
		File directory = temporary.newFolder("excluded");
		writeFile(directory, "one.txt", "one");
		writeFile(directory, "program.lock", "lock");
		ByteArrayOutputStream bytes = new ByteArrayOutputStream();
		try (JarOutputStream output = new JarOutputStream(bytes)) {
			JarWriter writer = new JarWriter(output, new String[] { ".lock" });
			assertTrue(writer.outputRecursively(directory, "", TaskMonitor.DUMMY));
		}
		assertEquals(1, entryCount(bytes.toByteArray()));
	}
}
