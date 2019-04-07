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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;

import org.junit.*;

import db.DBFileListener;
import db.Database;
import generic.test.AbstractGenericTest;
import ghidra.framework.store.db.PrivateDatabase;
import ghidra.util.task.TaskMonitorAdapter;
import utilities.util.FileUtilities;

/**
 *
 */
public class RecoveryFileTest extends AbstractGenericTest {

	private static int BUFFER_SIZE = LocalBufferFile.getRecommendedBufferSize(500);

	private static final File testDir = new File(AbstractGenericTest.getTestDirectoryPath(), "test");

	/**
	 * Constructor for RecoveryFileTest.
	 * @param arg0
	 */
	public RecoveryFileTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		FileUtilities.deleteDir(testDir);
		testDir.mkdir();
	}

	@After
	public void tearDown() throws Exception {
		FileUtilities.deleteDir(testDir);

	}

	/**
	 *
	 * File created:
	 *   bufferCnt buffers are filled with data, -bufferID stored at offset 0
	 *
	 * Recovery snapshot taken after each transaction.
	 * Transaction 1:
	 *   growCnt buffers are added with data, -bufferID stored at offset 0
	 * Transaction 2:
	 *   all odd numbered buffers between 1 and bufferCnt-1 are deleted/freed
	 *   +bufferID stored at offset 0 for buffers 0, 40, 80 ... <bufferCnt-1>
	 * Transaction 3:
	 *   +bufferID stored at offset 0 for buffers 20, 60, 100 ... <bufferCnt-1>
	 * Transaction 4:
	 *   +bufferID stored at offset 0 for buffers 10, 30, 50 ... <bufferCnt-1>
	 *
	 * @param bufferCnt
	 * @param growCnt
	 * @return
	 * @throws Exception
	 */
	private BufferMgr init(int bufferCnt, int growCnt) throws Exception {

		BufferMgr bufferMgr = null;
		boolean success = false;
		try {

			LocalBufferFile bf = PrivateDatabase.createDatabase(testDir, new DBFileListener() {
				@Override
				public void versionCreated(Database db, int version) {

				}
			}, BUFFER_SIZE);

			bufferMgr = new BufferMgr(BUFFER_SIZE, 16 * 1024, 4);

			// Add data buffers to original file
			for (int i = 0; i < bufferCnt; i++) {
				DataBuffer buf = bufferMgr.createBuffer();
				buf.putInt(0, -i); // store negative index value
				bufferMgr.releaseBuffer(buf);
			}

			bufferMgr.saveAs(bf, true, TaskMonitorAdapter.DUMMY_MONITOR);

			// Grow file if requested
			int modCnt = 0;
			int newBufferCnt = bufferCnt + growCnt;
			for (int i = bufferCnt; i < newBufferCnt; i++) {
				DataBuffer buf = bufferMgr.createBuffer();
				buf.putInt(0, -i); // store negative index value
				bufferMgr.releaseBuffer(buf);
				++modCnt;
			}
			bufferCnt = newBufferCnt;
			System.out.println("Added " + modCnt + " buffers");
			bufferMgr.checkpoint();

			bufferMgr.takeRecoverySnapshot(null, TaskMonitorAdapter.DUMMY_MONITOR);

			assertTrue(RecoveryMgr.canRecover(bf));

			// Remove every other buffer (build-up free list)
			modCnt = 0;
			for (int i = 1; i < bufferCnt; i += 2) {
				bufferMgr.deleteBuffer(i);
				++modCnt;
			}
			System.out.println("Deleted " + modCnt + " buffers");

			modCnt = 0;
			for (int i = 0; i < bufferCnt; i += 40) {
				DataBuffer buf = bufferMgr.getBuffer(i);
				buf.putInt(0, i); // store positive index value
				bufferMgr.releaseBuffer(buf);
				++modCnt;
			}
			System.out.println("Modified " + modCnt + " buffers");
			bufferMgr.checkpoint();

			bufferMgr.takeRecoverySnapshot(null, TaskMonitorAdapter.DUMMY_MONITOR);

			assertTrue(RecoveryMgr.canRecover(bf));

			modCnt = 0;
			for (int i = 20; i < bufferCnt; i += 40) {
				DataBuffer buf = bufferMgr.getBuffer(i);
				buf.putInt(0, i); // store positive index value
				bufferMgr.releaseBuffer(buf);
				++modCnt;
			}
			System.out.println("Modified " + modCnt + " buffers");
			bufferMgr.checkpoint();

			assertTrue(bufferMgr.takeRecoverySnapshot(null, TaskMonitorAdapter.DUMMY_MONITOR));

			assertTrue(RecoveryMgr.canRecover(bf));

			modCnt = 0;
			for (int i = 10; i < bufferCnt; i += 20) {
				DataBuffer buf = bufferMgr.getBuffer(i);
				buf.putInt(0, i); // store positive index value
				bufferMgr.releaseBuffer(buf);
				++modCnt;
			}
			System.out.println("Modified " + modCnt + " buffers");
			bufferMgr.checkpoint();

			assertTrue(bufferMgr.takeRecoverySnapshot(null, TaskMonitorAdapter.DUMMY_MONITOR));

			assertTrue(RecoveryMgr.canRecover(bf));

			success = true;
		}
		finally {
			if (!success && bufferMgr != null) {
				bufferMgr.dispose();
			}
		}

		return bufferMgr;
	}

	@Test
	public void testRecovery() throws Exception {

		BufferMgr bufferMgr = null;
		BufferMgr bufferMgr2 = null;
		try {

			// Make sure we stress the RecoveryFile storage
			int bufferCnt = BUFFER_SIZE * 10;

			bufferMgr = init(bufferCnt, BUFFER_SIZE);
			bufferCnt += BUFFER_SIZE;

			PrivateDatabase pdb = new PrivateDatabase(testDir);
			pdb.refresh();
			assertTrue(pdb.canRecover());

			// Leave first file open so that recovery files are not removed
			// Open a new instance to verify recovery

			LocalBufferFile bf2 = pdb.openBufferFileForUpdate();

			assertTrue(RecoveryMgr.canRecover(bf2));

			bufferMgr2 = new BufferMgr(bf2);

			assertTrue(bufferMgr2.recover(TaskMonitorAdapter.DUMMY_MONITOR));

			assertTrue(bufferMgr2.canSave());

			assertEquals(bufferCnt,
				bufferMgr2.getAllocatedBufferCount() + bufferMgr2.getFreeBufferCount());

			for (int i = 1; i < bufferCnt; i += 2) {
				try {
					bufferMgr2.getBuffer(i);
					Assert.fail("Expected deleted buffer: " + i);
				}
				catch (IOException e) {
					// Ignore
				}
			}

			for (int i = 0; i < bufferCnt; i += 10) {
				DataBuffer buf = bufferMgr2.getBuffer(i);
				assertEquals(buf.getInt(0), i);
				bufferMgr2.releaseBuffer(buf);
			}

		}
		finally {
			if (bufferMgr != null) {
				bufferMgr.dispose();
			}
			if (bufferMgr2 != null) {
				bufferMgr2.dispose();
			}
		}

	}

	@Test
	public void testRecoveryWithSave() throws Exception {

		BufferMgr bufferMgr = null;
		BufferMgr bufferMgr2 = null;
		BufferMgr bufferMgr3 = null;
		try {

			// Make sure we stress the RecoveryFile storage
			int bufferCnt = BUFFER_SIZE * 10;

			bufferMgr = init(bufferCnt, BUFFER_SIZE);
			bufferCnt += BUFFER_SIZE;

			PrivateDatabase pdb = new PrivateDatabase(testDir);
			pdb.refresh();
			assertTrue(pdb.canRecover());

			// Leave first file open so that recovery files are not removed
			// Open a new instance to verify recovery

			LocalBufferFile bf2 = pdb.openBufferFileForUpdate();

			assertTrue(RecoveryMgr.canRecover(bf2));

			bufferMgr2 = new BufferMgr(bf2);

			assertTrue(bufferMgr2.recover(TaskMonitorAdapter.DUMMY_MONITOR));

			assertTrue(bufferMgr2.canSave());

			bufferMgr2.save(null, null, TaskMonitorAdapter.DUMMY_MONITOR);

			// Open saved file and check content

			LocalBufferFile bf3 = pdb.openBufferFile();

			bufferMgr3 = new BufferMgr(bf3);

			assertEquals(bufferCnt,
				bufferMgr3.getAllocatedBufferCount() + bufferMgr3.getFreeBufferCount());

			for (int i = 1; i < bufferCnt; i += 2) {
				try {
					bufferMgr3.getBuffer(i);
					Assert.fail("Expected deleted buffer: " + i);
				}
				catch (IOException e) {
					// Ignore
				}
			}

			for (int i = 0; i < bufferCnt; i += 10) {
				DataBuffer buf = bufferMgr3.getBuffer(i);
				assertEquals(buf.getInt(0), i);
				bufferMgr3.releaseBuffer(buf);
			}

		}
		finally {
			if (bufferMgr != null) {
				bufferMgr.dispose();
			}
			if (bufferMgr2 != null) {
				bufferMgr2.dispose();
			}
			if (bufferMgr3 != null) {
				bufferMgr3.dispose();
			}
		}

	}

	@Test
	public void testRecoveryAfterUndo() throws Exception {

		BufferMgr bufferMgr = null;
		BufferMgr bufferMgr2 = null;
		try {
			// Make sure we stress the RecoveryFile storage
			int bufferCnt = BUFFER_SIZE * 10;

			bufferMgr = init(bufferCnt, BUFFER_SIZE);
			bufferCnt += BUFFER_SIZE;

			bufferMgr.undo(true);

			assertTrue(bufferMgr.takeRecoverySnapshot(null, TaskMonitorAdapter.DUMMY_MONITOR));

			PrivateDatabase pdb = new PrivateDatabase(testDir);
			pdb.refresh();
			assertTrue(pdb.canRecover());

			// Leave first file open so that recovery files are not removed
			// Open a new instance to verify recovery

			LocalBufferFile bf2 = pdb.openBufferFileForUpdate();

			assertTrue(RecoveryMgr.canRecover(bf2));

			bufferMgr2 = new BufferMgr(bf2);

			assertTrue(bufferMgr2.recover(TaskMonitorAdapter.DUMMY_MONITOR));

			assertTrue(bufferMgr2.canSave());

			assertEquals(bufferCnt,
				bufferMgr2.getAllocatedBufferCount() + bufferMgr2.getFreeBufferCount());

			for (int i = 1; i < bufferCnt; i += 2) {
				try {
					bufferMgr2.getBuffer(i);
					Assert.fail("Expected deleted buffer: " + i);
				}
				catch (IOException e) {
					// Ignore
				}
			}

			for (int i = 0; i < bufferCnt; i += 20) {
				DataBuffer buf = bufferMgr2.getBuffer(i);
				assertEquals(buf.getInt(0), i);
				bufferMgr2.releaseBuffer(buf);
			}

			for (int i = 10; i < bufferCnt; i += 20) {
				DataBuffer buf = bufferMgr2.getBuffer(i);
				assertEquals(buf.getInt(0), -i);
				bufferMgr2.releaseBuffer(buf);
			}

		}
		finally {
			if (bufferMgr != null) {
				bufferMgr.dispose();
			}
			if (bufferMgr2 != null) {
				bufferMgr2.dispose();
			}
		}
	}

	@Test
	public void testRecoveryAfterMultiUndo() throws Exception {

		BufferMgr bufferMgr = null;
		BufferMgr bufferMgr2 = null;
		try {
			// Make sure we stress the RecoveryFile storage
			int bufferCnt = BUFFER_SIZE * 10;

			bufferMgr = init(bufferCnt, BUFFER_SIZE);

			bufferMgr.undo(true);
			bufferMgr.undo(true);
			bufferMgr.undo(true);
			bufferMgr.undo(true);

			assertTrue(bufferMgr.takeRecoverySnapshot(null, TaskMonitorAdapter.DUMMY_MONITOR));

			PrivateDatabase pdb = new PrivateDatabase(testDir);
			pdb.refresh();
			assertTrue(pdb.canRecover());

			// Leave first file open so that recovery files are not removed
			// Open a new instance to verify recovery

			LocalBufferFile bf2 = pdb.openBufferFileForUpdate();

			assertTrue(RecoveryMgr.canRecover(bf2));

			bufferMgr2 = new BufferMgr(bf2);

			assertTrue(bufferMgr2.recover(TaskMonitorAdapter.DUMMY_MONITOR));

			assertTrue(bufferMgr2.canSave());

			assertEquals(bufferCnt,
				bufferMgr2.getAllocatedBufferCount() + bufferMgr2.getFreeBufferCount());

			for (int i = 0; i < bufferCnt; i++) {
				DataBuffer buf = bufferMgr2.getBuffer(i);
				assertEquals(buf.getInt(0), -i);
				bufferMgr2.releaseBuffer(buf);
			}

		}
		finally {
			if (bufferMgr != null) {
				bufferMgr.dispose();
			}
			if (bufferMgr2 != null) {
				bufferMgr2.dispose();
			}
		}
	}
}
