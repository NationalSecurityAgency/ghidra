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
package ghidra.framework.store.db;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;

import org.junit.*;

import db.buffers.*;
import generic.test.AbstractGenericTest;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.framework.store.local.LocalFolderItem;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import mockit.*;
import utilities.util.FileUtilities;

public class VersionFailureRecoveryTest extends AbstractGenericTest {

	private File testDir = new File(getTestDirectoryPath(), "VersionFailureRecoveryTest");
	private File testFile = new File(getTestDirectoryPath(), "TestBufferFile.tmp");

	private LocalFileSystem versionedFileSystem;

	@Before
	public void setUp() throws Exception {

		testFile.delete();

		FileUtilities.deleteDir(testDir);
		testDir.mkdir();

		versionedFileSystem =
			LocalFileSystem.getLocalFileSystem(testDir.getAbsolutePath(), true, true, false, false);
	}

	@After
	public void tearDown() throws Exception {
		testFile.delete();
		versionedFileSystem.dispose();
		FileUtilities.deleteDir(testDir);
	}

	/**
	 * This test is intended to verify that an IOException thrown during the streaming creation
	 * of a new versioned file will properly cleanup and not leave an invalid database item
	 */
	@Test
	public void testAddToVersionControlFailure() {

		new FakeBadBufferFile(); // setup for mocking

		LocalBufferFile fakeBadBufferFile = null;
		try {
			fakeBadBufferFile = new LocalBufferFile(testFile, BufferMgr.DEFAULT_BUFFER_SIZE);
			versionedFileSystem.createDatabase("/", "test", "xFILEIDx", fakeBadBufferFile,
				"comment", "PROGRAM", false, TaskMonitor.DUMMY, "test-user");
			fail("Expected IOException");
		}
		catch (InvalidNameException e) {
			fail("unexpected");
		}
		catch (CancelledException e) {
			fail("unexpected");
		}
		catch (IOException e) {
			assertEquals("forced block read failure", e.getMessage());
		}
		finally {
			if (fakeBadBufferFile != null) {
				fakeBadBufferFile.delete();
			}
		}

		try {
			LocalFolderItem item = versionedFileSystem.getItem("/", "test");
			assertNull("Did not expect item to exist in filesystem", item);
		}
		catch (IOException e) {
			failWithException("Unexpected IOException", e);
		}

	}

	private class FakeBadBufferFile extends MockUp<LocalBufferFile> {

		@Mock
		public int getIndexCount() {
			return 10;
		}

		@Mock
		public InputBlockStream getInputBlockStream(Invocation invocation) {

			LocalBufferFile bufferFile = invocation.getInvokedInstance();

			return new InputBlockStream() {

				@Override
				public boolean includesHeaderBlock() {
					return true;
				}

				@Override
				public void close() throws IOException {
					// ignore
				}

				@Override
				public int getBlockSize() {
					return bufferFile.getBufferSize();
				}

				@Override
				public BufferFileBlock readBlock() throws IOException {
					throw new IOException("forced block read failure");
				}

				@Override
				public int getBlockCount() {
					return bufferFile.getIndexCount();
				}
			};
		}

	}
}
