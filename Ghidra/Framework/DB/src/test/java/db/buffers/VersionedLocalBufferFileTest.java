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
package db.buffers;

import static org.junit.Assert.*;

import java.io.*;
import java.util.Arrays;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.util.task.TaskMonitorAdapter;
import utilities.util.FileUtilities;

public class VersionedLocalBufferFileTest extends AbstractGenericTest {

	private static final int BUFFER_SIZE = 1024;
	private static final int PRIVATE = -1;
	private static final int VERSIONED = 1;

	private File testDir = new File(getTestDirectoryPath(), "LocalManagedBufferFileTest");

	private PrivateTestFileMgr privateTestFileMgr;
	private VersionedTestFileMgr versionedTestFileMgr;

	public VersionedLocalBufferFileTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		FileUtilities.deleteDir(testDir);
		testDir.mkdir();

		privateTestFileMgr = new PrivateTestFileMgr(1);
		versionedTestFileMgr = new VersionedTestFileMgr();

	}

	@After
	public void tearDown() throws Exception {
		FileUtilities.deleteDir(testDir);

	}

	private class PrivateTestFileMgr implements BufferFileManager {

		private final int instanceNum;
		private int currentVersion = 0;

		PrivateTestFileMgr(int instanceNum) {
			this.instanceNum = instanceNum;
		}

		@Override
		public File getBufferFile(int version) {
			return new File(testDir, "private" + instanceNum + "." + version + ".bf");
		}

		@Override
		public File getChangeDataFile(int version) {
			return new File(testDir, "appChangeData" + instanceNum + "." + ".bf");
		}

		@Override
		public File getChangeMapFile() {
			return new File(testDir, "private" + instanceNum + "." + ".map");
		}

		@Override
		public int getCurrentVersion() {
			return currentVersion;
		}

		@Override
		public File getVersionFile(int version) {
			return null;
		}

		@Override
		public void updateEnded(long checkinId) {
			if (checkinId != -1) {
				throw new IllegalArgumentException("Expected -1 checkinId for private file update");
			}
		}

		@Override
		public void versionCreated(int version, String comment, long checkinId) {
			if (version != (currentVersion + 1)) {
				throw new IllegalArgumentException("Unexpected version specified: " + version);
			}
			currentVersion = version;
		}

	}

	private class VersionedTestFileMgr implements BufferFileManager {

		private int currentVersion = 0;

		@Override
		public File getBufferFile(int version) {
			return new File(testDir, "versioned" + version + ".bf");
		}

		@Override
		public File getChangeDataFile(int version) {
			return new File(testDir, "appChangeData" + version + ".bf");
		}

		@Override
		public File getChangeMapFile() {
			return null;
		}

		@Override
		public int getCurrentVersion() {
			return currentVersion;
		}

		@Override
		public File getVersionFile(int version) {
			return new File(testDir, "versionData" + version + ".bf");
		}

		@Override
		public void updateEnded(long checkinId) {
			if (checkinId != 1) {
				throw new IllegalArgumentException(
						"Expected +1 checkinId for versioned file update");
			}
		}

		@Override
		public void versionCreated(int version, String comment, long checkinId) {
			if (version != (currentVersion + 1)) {
				throw new IllegalArgumentException("Unexpected version specified: " + version);
			}
			currentVersion = version;
		}

	}

	/**
	 * Test add-to-version control scenario: versioned file is created using private file.
	 * Test results in the creation of private file and version-1 containing:
	 * 		Parms: TestParm1=0x321, TestParm2=0x543
	 * 		Buffers: 0[10]=0xf0.., 1[11]=0xf1.., 2[-1]=empty
	 * @throws Exception
	 */
	@Test
	public void testVersionedFileCreateAndCopy() throws Exception {
		LocalManagedBufferFile vbf = null;
		LocalManagedBufferFile pbf = null;
		try {

			// Create Version-1
			vbf = new LocalManagedBufferFile(BUFFER_SIZE, versionedTestFileMgr, VERSIONED);
			assertEquals(BUFFER_SIZE, vbf.getBufferSize());

			assertEquals("Free list should be empty", 0, vbf.getFreeIndexes().length);
			assertEquals(0, vbf.getIndexCount());

			int[] freeList = doWriteReadTest(vbf);

			int indexCnt = vbf.getIndexCount();// causes corresponding buffer ID's to become -1
			vbf.setFreeIndexes(freeList);
			long vfileID = vbf.getFileId();
			assertTrue(vfileID != 0);
			vbf.setParameter("TestParm1", 0x321);
			vbf.setParameter("TestParm2", 0x543);

			vbf.close();
			vbf = null;

			assertEquals(1, versionedTestFileMgr.getCurrentVersion());
			assertTrue(versionedTestFileMgr.getBufferFile(1).exists());
			assertTrue(!versionedTestFileMgr.getVersionFile(1).exists());
			assertTrue(!versionedTestFileMgr.getChangeDataFile(1).exists());

			// Reopen versioned buffer file for reading
			vbf = new LocalManagedBufferFile(versionedTestFileMgr, false, -1, VERSIONED);
			assertEquals(indexCnt, vbf.getIndexCount());
			assertTrue(Arrays.equals(freeList, vbf.getFreeIndexes()));
			assertEquals(vfileID, vbf.getFileId());
			assertEquals(0x321, vbf.getParameter("TestParm1"));
			assertEquals(0x543, vbf.getParameter("TestParm2"));

			doReadTest2(vbf);

			// Simulate private checkout
			pbf = new LocalManagedBufferFile(vbf.getBufferSize(), privateTestFileMgr, PRIVATE);
			LocalBufferFile.copyFile(vbf, pbf, null, TaskMonitorAdapter.DUMMY_MONITOR);

			assertEquals(indexCnt, pbf.getIndexCount());
			assertTrue(Arrays.equals(freeList, pbf.getFreeIndexes()));
			long pfileID = pbf.getFileId();
			assertTrue(pfileID != 0);
			assertTrue(pfileID != vfileID);
			assertEquals(0x321, pbf.getParameter("TestParm1"));
			assertEquals(0x543, pbf.getParameter("TestParm2"));

			doReadTest2(pbf);

			pbf.close();
			pbf = null;

			vbf.close();
			vbf = null;

			assertEquals(1, privateTestFileMgr.getCurrentVersion());
			assertTrue(privateTestFileMgr.getBufferFile(1).exists());
			assertTrue(!privateTestFileMgr.getChangeDataFile(1).exists());

		}
		finally {
			if (vbf != null) {
				try {
					vbf.close();
				}
				catch (IOException e) {
					// ignore
				}
			}
			if (pbf != null) {
				try {
					pbf.close();
				}
				catch (IOException e) {
					// ignore
				}
			}
		}
	}

	private void writeAppChangeFile(LocalManagedBufferFile bf) throws IOException {

		LocalBufferFile changeFile = (LocalBufferFile) bf.getSaveChangeDataFile();
		try {
			assertNotNull(changeFile);

			byte[] data = new byte[BUFFER_SIZE];
			DataBuffer buf = new DataBuffer(data);

			Arrays.fill(data, (byte) 0x55);
			buf.setId(0);
			changeFile.put(buf, 0);

			File file = changeFile.getFile();
			changeFile.close();
			changeFile = null;

			assertTrue(file.exists());
		}
		finally {
			if (changeFile != null) {
				try {
					changeFile.close();
				}
				catch (IOException e) {
					// ignore
				}
			}
		}

	}

	/**
	 * Test checked-out file modify scenario: version-1 file is created and derived private file is modified.
	 * Test results in the creation of private file and version-1.  Version-1 file contains:
	 * 		Parms: TestParm1=0x321, TestParm2=0x543
	 * 		Buffers: 0[10]=0xf0.., 1[11]=0xf1.., 2[-1]=empty
	 * Private file is based upon version-1 and modified to contain:
	 * 		Parms: TestParm1=0x322, TestParm2=0x544
	 * 		Buffers: 0[10]=0xf0.., 1[11]=0xf1.., 2[-1]=empty, 3[-1]=empty, 4[14]=0xf4..
	 * @throws Exception
	 */
	@Test
	public void testPrivateModify() throws Exception {

		testVersionedFileCreateAndCopy();

		LocalManagedBufferFile pbf = null;
		LocalManagedBufferFile saveFile = null;
		try {

			// Open private file for version update
			pbf = new LocalManagedBufferFile(privateTestFileMgr, true, -1, PRIVATE);

			saveFile = (LocalManagedBufferFile) pbf.getSaveFile();
			assertNotNull(saveFile);

			long pfileID = pbf.getFileId();
			assertTrue(pfileID != 0);

			// Write application level change file
			writeAppChangeFile(pbf);

			// Modify save file
			byte[] data = new byte[BUFFER_SIZE];
			DataBuffer buf = new DataBuffer(data);

			Arrays.fill(data, (byte) 0xf3);
			buf.setId(13);
			saveFile.put(buf, 3);

			Arrays.fill(data, (byte) 0xf4);
			buf.setId(14);
			saveFile.put(buf, 4);

			// Set free ID list for output file
			int[] newFreeList = new int[] { 2, 3 };
			saveFile.setFreeIndexes(newFreeList);

			// Copy/Set file parameters
			saveFile.setParameter("TestParm1", 0x322);
			saveFile.setParameter("TestParm2", 0x544);

			pbf.saveCompleted(true);

			pbf.close();
			pbf = null;

			saveFile.close();
			saveFile = null;

			assertEquals(2, privateTestFileMgr.getCurrentVersion());
			assertTrue(privateTestFileMgr.getBufferFile(2).exists());
			assertTrue(privateTestFileMgr.getChangeDataFile(2).exists());

		}
		finally {
			if (saveFile != null) {
				try {
					pbf.saveCompleted(false);
					saveFile.close();
				}
				catch (IOException e) {
					// ignore
				}
			}
			if (pbf != null) {
				try {
					pbf.close();
				}
				catch (IOException e) {
					// ignore
				}
			}
		}
	}

	/**
	 * Test quick checkin scenario: versioned file is updated using private changes.
	 * Test results in the creation of a private file and version-2 containing:
	 * 		Parms: TestParm1=0x322, TestParm2=0x544
	 * 		Buffers: 0[10]=0xf0.., 1[11]=0xf1.., 2[-1]=empty, 3[-1]=empty, 4[14]=0xf4..
	 * Version-1 file contains:
	 * 		Parms: TestParm1=0x321, TestParm2=0x543
	 * 		Buffers: 0[10]=0xf0.., 1[11]=0xf1.., 2[-1]=empty
	 * @throws Exception
	 */
	@Test
	public void testVersionQuickUpdate() throws Exception {

		testPrivateModify();

		LocalManagedBufferFile vbf = null;
		LocalManagedBufferFile pbf = null;
		VersionFile vf = null;
		try {

			// Open Versioned file for update
			vbf = new LocalManagedBufferFile(versionedTestFileMgr, true, 1, VERSIONED);

			// Open private file for checkin source
			pbf = new LocalManagedBufferFile(privateTestFileMgr, false, -1, PRIVATE);

			// Create version-2 using quick update
			pbf.createNewVersion(vbf, null, TaskMonitorAdapter.DUMMY_MONITOR);

			vbf.close();
			vbf = null;

			assertTrue(versionedTestFileMgr.getBufferFile(2).exists());
			assertTrue(versionedTestFileMgr.getVersionFile(1).exists());
			assertTrue(versionedTestFileMgr.getChangeDataFile(1).exists());

			// Clear private change files - simulate continued checkout
			privateTestFileMgr.getChangeDataFile(-1).delete();
			privateTestFileMgr.getChangeMapFile().delete();

			// Reopen versioned buffer file for reading
			vbf = new LocalManagedBufferFile(versionedTestFileMgr, false, -1, VERSIONED);
			assertEquals(2, vbf.getVersion());

			long fileId = vbf.getFileId();
			assertTrue(fileId != 0);

			vf = new VersionFile(versionedTestFileMgr.getVersionFile(1));
			assertEquals(fileId, vf.getTargetFileID());

// TODO: Check version file data ?

			vf.close();
			vf = null;

			checkSameContent(vbf, pbf);

			vbf.close();
			vbf = null;

			pbf.close();
			pbf = null;

		}
		finally {
			if (vf != null) {
				try {
					vf.close();
				}
				catch (IOException e) {
					// ignore
				}
			}
			if (vbf != null) {
				try {
					vbf.close();
				}
				catch (IOException e) {
					// ignore
				}
			}
			if (pbf != null) {
				try {
					pbf.close();
				}
				catch (IOException e) {
					// ignore
				}
			}
		}
	}

	/**
	 * Test opening an older version of a versioned file.
	 * Version-1 is opened and checked.
	 * @throws Exception
	 */
	@Test
	public void testOldVersionOpen() throws Exception {

		testVersionQuickUpdate();

		LocalManagedBufferFile vbf = null;
		try {

			// Open/reconstruct old Versioned file
			vbf = new LocalManagedBufferFile(versionedTestFileMgr, 1, -1);

			assertEquals(3, vbf.getIndexCount());
			assertTrue(Arrays.equals(new int[] { 2 }, vbf.getFreeIndexes()));

			assertEquals(0x321, vbf.getParameter("TestParm1"));
			assertEquals(0x543, vbf.getParameter("TestParm2"));

			doReadTest2(vbf);

			vbf.close();
			vbf = null;

		}
		finally {
			if (vbf != null) {
				try {
					vbf.close();
				}
				catch (IOException e) {
					// ignore
				}
			}
		}
	}

	/**
	 * Modifies version-2 and produces version-3 which contains:
	 * 		Parms: TestParm1=0x329, TestParm2=0x549, TestParm2=0x679
	 * 		Buffers: 0[-1]=empty, 1[11]=0xf1.., 2[12]=0xf2.., 3[13]=0xf3.., 4[14]=empty, 5[15]=0xf5.., 6[-1]=empty, 7[17]=0xf7.., 8[18]=0xf8.., 9[19]=0xf9..
	 * @throws IOException
	 */
	private void createVersion3() throws IOException {

		LocalManagedBufferFile vbf = null;
		LocalManagedBufferFile saveFile = null;
		try {

			// Open private file for version update
			vbf = new LocalManagedBufferFile(versionedTestFileMgr, true, -1, VERSIONED);

			saveFile = (LocalManagedBufferFile) vbf.getSaveFile();
			assertNotNull(saveFile);

			long pfileID = vbf.getFileId();
			assertTrue(pfileID != 0);

			// Write application level change file
			writeAppChangeFile(vbf);

			// Modify save file
			byte[] data = new byte[BUFFER_SIZE];
			DataBuffer buf = new DataBuffer(data);

			Arrays.fill(data, (byte) 0xf2);// modified empty buffer
			buf.setId(12);
			saveFile.put(buf, 2);

			Arrays.fill(data, (byte) 0xf3);// new buffer
			buf.setId(13);
			saveFile.put(buf, 3);

			Arrays.fill(data, (byte) 0xf4);// new buffer - added to free list below
			buf.setId(14);
			saveFile.put(buf, 4);

			Arrays.fill(data, (byte) 0xf5);// new buffer
			buf.setId(13);
			saveFile.put(buf, 5);

			Arrays.fill(data, (byte) 0xf6);// new buffer - added to free list below
			buf.setId(16);
			saveFile.put(buf, 6);

			Arrays.fill(data, (byte) 0xf7);// new buffer
			buf.setId(17);
			saveFile.put(buf, 7);

			Arrays.fill(data, (byte) 0xf8);// new buffer - added to free list below
			buf.setId(18);
			saveFile.put(buf, 8);

			Arrays.fill(data, (byte) 0xf9);// new buffer
			buf.setId(19);
			saveFile.put(buf, 9);

			// Set free ID list for output file
			int[] newFreeList = new int[] { 0, 4, 6 };
			saveFile.setFreeIndexes(newFreeList);

			// Copy/Set file parameters
			saveFile.setParameter("TestParm1", 0x329);
			saveFile.setParameter("TestParm2", 0x549);
			saveFile.setParameter("TestParm3", 0x679);

			vbf.saveCompleted(true);

			vbf.close();
			vbf = null;

			saveFile.close();
			saveFile = null;

			assertEquals(2, privateTestFileMgr.getCurrentVersion());
			assertTrue(privateTestFileMgr.getBufferFile(2).exists());
			assertTrue(privateTestFileMgr.getChangeDataFile(2).exists());

		}
		finally {
			if (saveFile != null) {
				try {
					vbf.saveCompleted(false);
					saveFile.close();
				}
				catch (IOException e) {
					// ignore
				}
			}
			if (vbf != null) {
				try {
					vbf.close();
				}
				catch (IOException e) {
					// ignore
				}
			}
		}
	}

	/**
	 * Test local update following a merge checkin scenario.  A new private file is created based upon version-1.
	 * This private file is modified resulting in a file which is same size as version-2.  This new private file
	 * prior to update contains:
	 * 		Parms: TestParm1=0x320, TestParm2=0x540
	 * 		Buffers: 0[10]=0xf0.., 1[21]=0xff.., 2[-1]=empty, 3[13]=0xf3.., 4[14]=empty
	 * Following update the private file should match version-2 which contains:
	 * 		Parms: TestParm1=0x322, TestParm2=0x544
	 * 		Buffers: 0[10]=0xf0.., 1[11]=0xf1.., 2[-1]=empty, 3[-1]=empty, 4[14]=0xf4..
	 * @throws Exception
	 */
	@Test
	public void testVersionLocalUpdate() throws Exception {

		testVersionQuickUpdate();

		LocalManagedBufferFile vbf = null;
		LocalManagedBufferFile pbf = null;
		LocalManagedBufferFile saveFile = null;
		try {

			// Simulate checkout of version-1 (new private instance)
			privateTestFileMgr = new PrivateTestFileMgr(2);
			vbf = new LocalManagedBufferFile(versionedTestFileMgr, 1, -1);
			pbf = new LocalManagedBufferFile(vbf.getBufferSize(), privateTestFileMgr, PRIVATE);
			LocalBufferFile.copyFile(vbf, pbf, null, TaskMonitorAdapter.DUMMY_MONITOR);

			vbf.close();
			vbf = null;

			pbf.close();
			pbf = null;

			//
			// Modify private checkout file (with different changes than version-2 contains)
			// Same-size case: private file is same size as version-2
			//

			// Open private file for version update
			pbf = new LocalManagedBufferFile(privateTestFileMgr, true, -1, PRIVATE);

			saveFile = (LocalManagedBufferFile) pbf.getSaveFile();
			assertNotNull(saveFile);

			// Write application level change file
			writeAppChangeFile(pbf);

			// Modify save file
			byte[] data = new byte[BUFFER_SIZE];
			DataBuffer buf = new DataBuffer(data);

			Arrays.fill(data, (byte) 0xff);// modified buffer
			buf.setId(21);
			saveFile.put(buf, 1);

			Arrays.fill(data, (byte) 0xf3);// new buffer
			buf.setId(13);
			saveFile.put(buf, 3);

			Arrays.fill(data, (byte) 0xf4);// new buffer - added to free list below
			buf.setId(14);
			saveFile.put(buf, 4);

			// Set free ID list for output file
			int[] newFreeList = new int[] { 2, 4 };
			saveFile.setFreeIndexes(newFreeList);

			// Copy/Set file parameters
			saveFile.setParameter("TestParm1", 0x320);
			saveFile.setParameter("TestParm2", 0x540);

			pbf.saveCompleted(true);

			pbf.close();
			pbf = null;

			saveFile.close();
			saveFile = null;

			//
			// Perform update of private file to replicate version-2
			//

			// Open version-2
			vbf = new LocalManagedBufferFile(versionedTestFileMgr, false, -1, VERSIONED);

			// Reopen private file
			pbf = new LocalManagedBufferFile(privateTestFileMgr, true, -1, -1);

			// Perform quick update of private file to replicate version-2 file - should wipe-out all private changes
			pbf.updateFrom(vbf, 1, TaskMonitorAdapter.DUMMY_MONITOR);

			pbf.close();
			pbf = null;

			// Reopen to pickup update modifications
			pbf = new LocalManagedBufferFile(privateTestFileMgr, true, -1, -1);

			checkSameContent(vbf, pbf);

			vbf.close();
			vbf = null;

			pbf.close();
			pbf = null;

		}
		finally {
			if (saveFile != null) {
				try {
					saveFile.close();
				}
				catch (IOException e) {
					// ignore
				}
			}
			if (vbf != null) {
				try {
					vbf.close();
				}
				catch (IOException e) {
					// ignore
				}
			}
			if (pbf != null) {
				try {
					pbf.close();
				}
				catch (IOException e) {
					// ignore
				}
			}
		}

		assertTrue("File handles may have failed to close properly",
			FileUtilities.deleteDir(testDir));
	}

	/**
	 * Test local update following a merge checkin scenario.  A new private file is created based upon version-1.
	 * This private file is modified resulting in a file which is longer than version-2.  This new private file
	 * prior to update contains:
	 * 		Parms: TestParm1=0x320, TestParm2=0x540, TestParm2=0x670
	 * 		Buffers: 0[-1]=empty, 1[11]=0xf1.., 2[12]=0xf2.., 3[13]=0xf3.., 4[14]=empty, 5[15]=0xf5.., 6[-1]=empty
	 * Following update the private file should match version-2 which contains:
	 * 		Parms: TestParm1=0x322, TestParm2=0x544
	 * 		Buffers: 0[10]=0xf0.., 1[11]=0xf1.., 2[-1]=empty, 3[-1]=empty, 4[14]=0xf4..
	 * @throws Exception
	 */
	@Test
	public void testVersionLocalTruncationUpdate() throws Exception {

		testVersionQuickUpdate();

		LocalManagedBufferFile vbf = null;
		LocalManagedBufferFile pbf = null;
		LocalManagedBufferFile saveFile = null;
		try {

			// Simulate checkout of version-1 (new private instance)
			privateTestFileMgr = new PrivateTestFileMgr(2);
			vbf = new LocalManagedBufferFile(versionedTestFileMgr, 1, -1);
			pbf = new LocalManagedBufferFile(vbf.getBufferSize(), privateTestFileMgr, PRIVATE);
			LocalBufferFile.copyFile(vbf, pbf, null, TaskMonitorAdapter.DUMMY_MONITOR);

			vbf.close();
			vbf = null;

			pbf.close();
			pbf = null;

			//
			// Modify private checkout file (with different changes than version-2 contains)
			// Truncation case: private file is longer than version-2 and must get truncated
			//

			// Open private file for version update
			pbf = new LocalManagedBufferFile(privateTestFileMgr, true, -1, PRIVATE);

			saveFile = (LocalManagedBufferFile) pbf.getSaveFile();
			assertNotNull(saveFile);

			// Write application level change file
			writeAppChangeFile(pbf);

			// Modify save file
			byte[] data = new byte[BUFFER_SIZE];
			DataBuffer buf = new DataBuffer(data);

			Arrays.fill(data, (byte) 0xf2);// modified empty buffer
			buf.setId(12);
			saveFile.put(buf, 2);

			Arrays.fill(data, (byte) 0xf3);// new buffer
			buf.setId(13);
			saveFile.put(buf, 3);

			Arrays.fill(data, (byte) 0xf4);// new buffer - added to free list below
			buf.setId(14);
			saveFile.put(buf, 4);

			Arrays.fill(data, (byte) 0xf5);// new buffer
			buf.setId(13);
			saveFile.put(buf, 5);

			// Set free ID list for output file
			int[] newFreeList = new int[] { 0, 4, 6 };
			saveFile.setFreeIndexes(newFreeList);

			// Copy/Set file parameters
			saveFile.setParameter("TestParm1", 0x320);
			saveFile.setParameter("TestParm2", 0x540);
			saveFile.setParameter("TestParm3", 0x670);

			pbf.saveCompleted(true);

			pbf.close();
			pbf = null;

			saveFile.close();
			saveFile = null;

			//
			// Perform update of private file to replicate version-2
			//

			// Open version-2
			vbf = new LocalManagedBufferFile(versionedTestFileMgr, false, -1, VERSIONED);

			// Reopen private file
			pbf = new LocalManagedBufferFile(privateTestFileMgr, true, -1, -1);

			// Perform quick update of private file to replicate version-2 file - should wipe-out all private changes
			pbf.updateFrom(vbf, 1, TaskMonitorAdapter.DUMMY_MONITOR);

			pbf.close();
			pbf = null;

			// Reopen to pickup update modifications
			pbf = new LocalManagedBufferFile(privateTestFileMgr, true, -1, -1);

			checkSameContent(vbf, pbf);

			vbf.close();
			vbf = null;

			pbf.close();
			pbf = null;

		}
		finally {
			if (saveFile != null) {
				try {
					saveFile.close();
				}
				catch (IOException e) {
					// ignore
				}
			}
			if (vbf != null) {
				try {
					vbf.close();
				}
				catch (IOException e) {
					// ignore
				}
			}
			if (pbf != null) {
				try {
					pbf.close();
				}
				catch (IOException e) {
					// ignore
				}
			}
		}

		assertTrue("File handles may have failed to close properly",
			FileUtilities.deleteDir(testDir));
	}

	/**
	 * Test local update following a merge checkin scenario.  A new private file is created based upon version-1.
	 * This private file is modified resulting in a file which is shorter than version-2.  This new private file
	 * prior to update contains:
	 * 		Parms: TestParm1=0x320
	 * 		Buffers: 0[-1]=empty, 1[21]=0xff.., 2[12]=0xf2..
	 * Following update the private file should match version-2 which contains:
	 * 		Parms: TestParm1=0x322, TestParm2=0x544
	 * 		Buffers: 0[10]=0xf0.., 1[11]=0xf1.., 2[-1]=empty, 3[-1]=empty, 4[14]=0xf4..
	 * @throws Exception
	 */
	@Test
	public void testVersionLocalExpansionUpdate() throws Exception {

		testVersionQuickUpdate();

		LocalManagedBufferFile vbf = null;
		LocalManagedBufferFile pbf = null;
		LocalManagedBufferFile saveFile = null;
		try {

			// Simulate checkout of version-1 (new private instance)
			privateTestFileMgr = new PrivateTestFileMgr(2);
			vbf = new LocalManagedBufferFile(versionedTestFileMgr, 1, -1);
			pbf = new LocalManagedBufferFile(vbf.getBufferSize(), privateTestFileMgr, PRIVATE);
			LocalBufferFile.copyFile(vbf, pbf, null, TaskMonitorAdapter.DUMMY_MONITOR);

			vbf.close();
			vbf = null;

			pbf.close();
			pbf = null;

			//
			// Modify private checkout file (with different changes than version-2 contains)
			// Expansion case: private file is shorter than version-2 and must get expanded
			//

			// Open private file for version update
			pbf = new LocalManagedBufferFile(privateTestFileMgr, true, -1, PRIVATE);

			saveFile = (LocalManagedBufferFile) pbf.getSaveFile();
			assertNotNull(saveFile);

			// Write application level change file
			writeAppChangeFile(pbf);

			// Modify save file
			byte[] data = new byte[BUFFER_SIZE];
			DataBuffer buf = new DataBuffer(data);

			Arrays.fill(data, (byte) 0xff);// modified
			buf.setId(21);
			saveFile.put(buf, 1);

			Arrays.fill(data, (byte) 0xf2);// modified empty buffer
			buf.setId(12);
			saveFile.put(buf, 2);

			// Set free ID list for output file
			int[] newFreeList = new int[] { 0 };
			saveFile.setFreeIndexes(newFreeList);

			// Copy/Set file parameters
			saveFile.setParameter("TestParm1", 0x320);

			pbf.saveCompleted(true);

			pbf.close();
			pbf = null;

			saveFile.close();
			saveFile = null;

			//
			// Perform update of private file to replicate version-2
			//

			// Open version-2
			vbf = new LocalManagedBufferFile(versionedTestFileMgr, false, -1, VERSIONED);

			// Reopen private file
			pbf = new LocalManagedBufferFile(privateTestFileMgr, true, -1, -1);

			// Perform quick update of private file to replicate version-2 file - should wipe-out all private changes
			pbf.updateFrom(vbf, 1, TaskMonitorAdapter.DUMMY_MONITOR);

			pbf.close();
			pbf = null;

			// Reopen to pickup update modifications
			pbf = new LocalManagedBufferFile(privateTestFileMgr, true, -1, -1);

			checkSameContent(vbf, pbf);

			vbf.close();
			vbf = null;

			pbf.close();
			pbf = null;

		}
		finally {
			if (saveFile != null) {
				try {
					saveFile.close();
				}
				catch (IOException e) {
					// ignore
				}
			}
			if (vbf != null) {
				try {
					vbf.close();
				}
				catch (IOException e) {
					// ignore
				}
			}
			if (pbf != null) {
				try {
					pbf.close();
				}
				catch (IOException e) {
					// ignore
				}
			}
		}

		assertTrue("File handles may have failed to close properly",
			FileUtilities.deleteDir(testDir));
	}

	/**
	 * Test local update following a merge checkin scenario.  A new private file is created based upon version-1.
	 * This private file is modified resulting in a file which is shorter than a new version-3.  This new private file
	 * prior to update contains:
	 * 		Parms: TestParm1=0x320
	 * 		Buffers: 0[-1]=empty, 1[21]=0xff.., 2[12]=0xf2..
	 * Following update the private file should match version-3 which contains:
	 * 		Parms: TestParm1=0x329, TestParm2=0x549, TestParm2=0x679
	 * 		Buffers: 0[-1]=empty, 1[11]=0xf1.., 2[12]=0xf2.., 3[13]=0xf3.., 4[14]=empty, 5[15]=0xf5.., 6[-1]=empty, 7[17]=0xf7.., 8[18]=0xf8.., 9[19]=0xf9..
	 * @throws Exception
	 */
	@Test
	public void testVersionLocalExpansionUpdate2() throws Exception {

		testVersionQuickUpdate();

		LocalManagedBufferFile vbf = null;
		LocalManagedBufferFile pbf = null;
		LocalManagedBufferFile saveFile = null;
		try {

			// Simulate checkout of version-1 (new private instance)
			privateTestFileMgr = new PrivateTestFileMgr(2);
			vbf = new LocalManagedBufferFile(versionedTestFileMgr, 1, -1);
			pbf = new LocalManagedBufferFile(vbf.getBufferSize(), privateTestFileMgr, PRIVATE);
			LocalBufferFile.copyFile(vbf, pbf, null, TaskMonitorAdapter.DUMMY_MONITOR);

			vbf.close();
			vbf = null;

			pbf.close();
			pbf = null;

			//
			// Modify private checkout file (with different changes than version-2 contains)
			// Expansion case: private file is shorter than version-2 and must get expanded
			//

			// Open private file for version update
			pbf = new LocalManagedBufferFile(privateTestFileMgr, true, -1, PRIVATE);

			saveFile = (LocalManagedBufferFile) pbf.getSaveFile();
			assertNotNull(saveFile);

			// Write application level change file
			writeAppChangeFile(pbf);

			// Modify save file
			byte[] data = new byte[BUFFER_SIZE];
			DataBuffer buf = new DataBuffer(data);

			Arrays.fill(data, (byte) 0xff);// modified
			buf.setId(21);
			saveFile.put(buf, 1);

			Arrays.fill(data, (byte) 0xf2);// modified empty buffer
			buf.setId(12);
			saveFile.put(buf, 2);

			// Set free ID list for output file
			int[] newFreeList = new int[] { 0 };
			saveFile.setFreeIndexes(newFreeList);

			// Copy/Set file parameters
			saveFile.setParameter("TestParm1", 0x320);

			pbf.saveCompleted(true);

			pbf.close();
			pbf = null;

			saveFile.close();
			saveFile = null;

			createVersion3();

			//
			// Perform update of private file to replicate version-3
			//

			// Open version-3
			vbf = new LocalManagedBufferFile(versionedTestFileMgr, false, -1, VERSIONED);

			// Reopen private file
			pbf = new LocalManagedBufferFile(privateTestFileMgr, true, -1, -1);

			// Perform quick update of private file to replicate version-3 file - should wipe-out all private changes
			pbf.updateFrom(vbf, 1, TaskMonitorAdapter.DUMMY_MONITOR);

			pbf.close();
			pbf = null;

			// Reopen to pickup update modifications
			pbf = new LocalManagedBufferFile(privateTestFileMgr, true, -1, -1);

			checkSameContent(vbf, pbf);

			vbf.close();
			vbf = null;

			pbf.close();
			pbf = null;

		}
		finally {
			if (saveFile != null) {
				try {
					saveFile.close();
				}
				catch (IOException e) {
					// ignore
				}
			}
			if (vbf != null) {
				try {
					vbf.close();
				}
				catch (IOException e) {
					// ignore
				}
			}
			if (pbf != null) {
				try {
					pbf.close();
				}
				catch (IOException e) {
					// ignore
				}
			}
		}

		assertTrue("File handles may have failed to close properly",
			FileUtilities.deleteDir(testDir));
	}

	private void checkSameContent(LocalManagedBufferFile expectedBf,
			LocalManagedBufferFile inspectedBf) throws IOException {

		assertEquals(expectedBf.getIndexCount(), inspectedBf.getIndexCount());

		int[] vFreeList = inspectedBf.getFreeIndexes();
		int[] pFreeList = inspectedBf.getFreeIndexes();
		Arrays.sort(vFreeList);
		Arrays.sort(pFreeList);
		assertTrue("Free index lists differ", Arrays.equals(vFreeList, pFreeList));

		assertTrue("Parameter list mismatch",
			Arrays.equals(expectedBf.getParameterNames(), inspectedBf.getParameterNames()));
		for (String name : expectedBf.getParameterNames()) {
			assertEquals("Parameter values differ", expectedBf.getParameter(name),
				inspectedBf.getParameter(name));
		}

		DataBuffer pbuf = new DataBuffer();
		DataBuffer vbuf = new DataBuffer();
		int cnt = inspectedBf.getIndexCount();
		for (int i = 0; i < cnt; i++) {
			checkSameContent(i, expectedBf.get(vbuf, i), inspectedBf.get(pbuf, i));
		}
	}

	private void checkSameContent(int index, DataBuffer expectedBuf, DataBuffer inspectedBuf) {
		assertEquals("Buffer " + index + " empty flag", expectedBuf.isEmpty(),
			inspectedBuf.isEmpty());
		assertEquals("Buffer " + index + " has unexpected ID", expectedBuf.getId(),
			inspectedBuf.getId());
		if (!expectedBuf.isEmpty()) {
			assertTrue("Buffer " + index + " content differs",
				Arrays.equals(expectedBuf.data, inspectedBuf.data));
		}
	}

	private int[] doWriteReadTest(LocalManagedBufferFile bf) throws IOException {

		DataBuffer buf = new DataBuffer(BUFFER_SIZE - 1);

		try {
			bf.get(buf, 0);
			Assert.fail("Expected EOFException getting non-exting buffer");
		}
		catch (EOFException e) {
			// expected
		}

		try {
			bf.put(buf, 0);
			Assert.fail("Expected IllegalArgumentException putting small buffer");
		}
		catch (IllegalArgumentException e) {
			// expected
		}

		byte[] data = new byte[BUFFER_SIZE];
		buf = new DataBuffer(data);

		Arrays.fill(data, (byte) 0xf0);
		buf.setId(10);
		bf.put(buf, 0);

		Arrays.fill(data, (byte) 0xf1);
		buf.setId(11);
		bf.put(buf, 1);

		Arrays.fill(data, (byte) 0xf2);
		buf.setId(12);
		bf.put(buf, 2);

		doReadTest1(bf);

		buf.setId(12);
		buf.setEmpty(true);
		bf.put(buf, 2);

		doReadTest2(bf);

		// Return static free list
		return new int[] { 2 };
	}

	private void doReadTest1(LocalManagedBufferFile bf) throws IOException {

		DataBuffer buf = new DataBuffer();

		bf.get(buf, 0);
		assertEquals(10, buf.getId());
		assertTrue(!buf.isEmpty());
		checkData(buf.data, (byte) 0xf0);

		bf.get(buf, 2);
		assertEquals(12, buf.getId());
		assertTrue(!buf.isEmpty());
		checkData(buf.data, (byte) 0xf2);

		bf.get(buf, 1);
		assertEquals(11, buf.getId());
		assertTrue(!buf.isEmpty());
		checkData(buf.data, (byte) 0xf1);
	}

	private void doReadTest2(LocalManagedBufferFile bf) throws IOException {

		DataBuffer buf = new DataBuffer();

		bf.get(buf, 0);
		assertEquals(10, buf.getId());
		assertTrue(!buf.isEmpty());
		checkData(buf.data, (byte) 0xf0);

		bf.get(buf, 2);
		assertEquals(-1, buf.getId());
		assertTrue(buf.isEmpty());

		bf.get(buf, 1);
		assertEquals(11, buf.getId());
		assertTrue(!buf.isEmpty());
		checkData(buf.data, (byte) 0xf1);
	}

	private void checkData(byte[] data, byte b) {
		assertEquals(BUFFER_SIZE, data.length);

	}

}
