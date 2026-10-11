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
package utilities.util;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

import java.io.*;
import java.nio.file.Files;
import java.util.concurrent.TimeUnit;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import generic.jar.ResourceFile;
import ghidra.util.exception.IOCancelledException;
import ghidra.util.task.TaskMonitorAdapter;

public class FileCopyProgressTest {
	@Rule
	public TemporaryFolder temporaryFolder = new TemporaryFolder();

	@Test
	public void testFileCopyPreservesLargeMaximum() throws Exception {
		assertLargeMaximum(0, (long) Integer.MAX_VALUE + 17);
	}

	@Test
	public void testResourceToFilePreservesLargeMaximum() throws Exception {
		assertLargeMaximum(1, (1L << 32) + 17);
	}

	@Test
	public void testResourceToResourcePreservesLargeMaximum() throws Exception {
		assertLargeMaximum(2, (long) Integer.MAX_VALUE + 17);
	}

	@Test
	public void testFileToStreamPreservesLargeMaximum() throws Exception {
		assertLargeMaximum(3, (1L << 32) + 17);
	}

	@Test
	public void testSmallCopiesPreserveMaximumAndBytes() throws Exception {
		byte[] bytes = { 1, 2, 3, 4, 5 };
		File source = temporaryFolder.newFile();
		Files.write(source.toPath(), bytes);
		for (int kind = 0; kind < 4; kind++) {
			File destination = temporaryFolder.newFile();
			RecordingMonitor monitor = new RecordingMonitor(false);
			copy(kind, source, destination, monitor);
			assertEquals(bytes.length, monitor.maximum);
			assertArrayEquals(bytes, Files.readAllBytes(destination.toPath()));
			assertFalse(monitor.isCancelled());
		}
	}

	@Test
	public void testEmptyCopiesPreserveZeroMaximum() throws Exception {
		File source = temporaryFolder.newFile();
		for (int kind = 0; kind < 4; kind++) {
			File destination = temporaryFolder.newFile();
			RecordingMonitor monitor = new RecordingMonitor(false);
			copy(kind, source, destination, monitor);
			assertEquals(0, monitor.maximum);
			assertEquals(0, destination.length());
		}
	}

	private void assertLargeMaximum(int kind, long size) throws Exception {
		assumeTrue("Sparse file qualification requires Linux", System.getProperty("os.name").equals("Linux"));
		File source = temporaryFolder.newFile();
		try (RandomAccessFile sparse = new RandomAccessFile(source, "rw")) {
			sparse.setLength(size);
		}
		assertEquals(size, source.length());
		// Linux CI checks the real allocated blocks, not just logical size.
		if (System.getProperty("os.name").equals("Linux")) {
			Process allocation = new ProcessBuilder("du", "-k", source.getAbsolutePath()).start();
			try {
				assertTrue("Sparse allocation check timed out", allocation.waitFor(10, TimeUnit.SECONDS));
				String output = new String(allocation.getInputStream().readAllBytes());
				assertEquals(0, allocation.exitValue());
				assertTrue("Sparse source must use at most 128 KiB", Long.parseLong(output.split("\\s+")[0]) <= 128);
			}
			finally {
				allocation.destroyForcibly();
			}
		}
		File destination = temporaryFolder.newFile();
		RecordingMonitor monitor = new RecordingMonitor(true);
		try {
			copy(kind, source, destination, monitor);
			fail("Copy must stop on actual cancellation");
		}
		catch (IOCancelledException expected) {
			// Baseline writes one 32 KiB block before observing cancellation.
		}
		assertTrue("Actual monitor cancellation must be enabled", monitor.isCancelled());
		assertTrue(destination.length() <= FileUtilities.IO_BUFFER_SIZE);
		assertEquals("Use the source's full long size for progress", size, monitor.maximum);
	}

	private void copy(int kind, File source, File destination, RecordingMonitor monitor)
			throws IOException {
		switch (kind) {
			case 0 -> FileUtilities.copyFile(source, destination, false, monitor);
			case 1 -> FileUtilities.copyFile(new ResourceFile(source), destination, false, monitor);
			case 2 -> FileUtilities.copyFile(new ResourceFile(source), new ResourceFile(destination), monitor);
			case 3 -> {
				try (OutputStream out = new FileOutputStream(destination)) {
					FileUtilities.copyFileToStream(source, out, monitor);
				}
			}
			default -> throw new AssertionError(kind);
		}
	}

	private static class RecordingMonitor extends TaskMonitorAdapter {
		private final boolean cancelOnInitialize;
		private long maximum = -1;

		RecordingMonitor(boolean cancelOnInitialize) {
			super(true);
			this.cancelOnInitialize = cancelOnInitialize;
		}

		@Override
		public void initialize(long maximum) {
			super.initialize(maximum);
			this.maximum = maximum;
			if (cancelOnInitialize) {
				cancel();
				assertTrue("Cancellation must be active before copying", isCancelled());
			}
		}
	}
}
