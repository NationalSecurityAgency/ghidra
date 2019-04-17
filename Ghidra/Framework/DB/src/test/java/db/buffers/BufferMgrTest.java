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
import java.util.Arrays;
import java.util.Random;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.util.Msg;
import utilities.util.FileUtilities;

public class BufferMgrTest extends AbstractGenericTest {

	private static int BUFFER_SIZE = 256;
	private static int CACHE_SIZE = 4096;

	private BufferMgr mgr;

	private File testDir;

	private Random random = new Random();

	private int bufferSize;

	// Fill data
	private byte[] fillPattern1;
	private byte[] fillPattern2;

	private short shortData;
	private long longData;
	private byte[] bytes;

	// Performance test data
	int totalReadCount;
	int totalUpdateCount;

	@Before
	public void setUp() throws Exception {

		// Initialize fill data
		shortData = (short) random.nextInt();
		bytes = new byte[128];
		random.nextBytes(bytes);

		testDir = createTempDirectory(getClass().getSimpleName());
	}

	@After
	public void tearDown() throws Exception {

		if (mgr != null) {
			mgr.dispose();
			mgr = null;
		}
		FileUtilities.deleteDir(testDir);
	}

	private void fillDataBuf(DataBuffer buf) {
		int offset = buf.putShort(0, shortData);
		offset = buf.putInt(offset, buf.getId());
		offset = buf.putLong(offset, longData);
		buf.put(offset, bytes);
	}

	private boolean validDataBuf(DataBuffer buf) {
		int offset = 0;
		if (shortData != buf.getShort(offset)) {
			System.out.println("Bad short value at buffer offset " + offset);
			return false;
		}
		offset += 2;
		if (buf.getId() != buf.getInt(offset)) {
			System.out.println("Bad integer value at buffer offset " + offset);
			return false;
		}
		offset += 4;
		if (longData != buf.getLong(offset)) {
			System.out.println("Bad long value at buffer offset " + offset);
			return false;
		}
		offset += 8;
		if (!Arrays.equals(bytes, buf.get(offset, bytes.length))) {
			System.out.println("Bad byte data at buffer offset " + offset);
			return false;
		}
		return true;
	}

	private void initNewFile() throws IOException {

		mgr = new BufferMgr(BUFFER_SIZE, CACHE_SIZE, 10);

		bufferSize = mgr.getBufferSize();

		// Generate random fill patterns
		fillPattern1 = new byte[bufferSize];
		random.nextBytes(fillPattern1);
		fillPattern2 = new byte[bufferSize];
		random.nextBytes(fillPattern2);
	}

	@Test
	public void testCreateBuffer() throws IOException {

		initNewFile();

		assertTrue(!mgr.isChanged());

		DataBuffer buf = mgr.createBuffer();
		assertEquals(1, mgr.getLockCount());
		int id = buf.getId();
		buf.put(0, fillPattern1);
		mgr.releaseBuffer(buf);

		assertTrue(mgr.isChanged());

		buf = mgr.getBuffer(id);
		assertEquals(1, mgr.getLockCount());
		byte[] data = buf.get(0, buf.length());

		// Try to get locked buffer
		Msg.error(this, ">>>>>>>>>>>>>>>> Expected Exception");
		try {
			mgr.getBuffer(id);
			Assert.fail();
		}
		catch (IOException e) {
			// Expected due to locked buffer
		}
		Msg.error(this, "<<<<<<<<<<<<<<<< End Expected Exception");

		mgr.releaseBuffer(buf);
		assertEquals(0, mgr.getLockCount());

		assertTrue(Arrays.equals(fillPattern1, data));

		// Release buffer a second time

		try {
			mgr.releaseBuffer(buf);
			Assert.fail();
		}
		catch (Exception e) {
			// expected
		}
		assertEquals(0, mgr.getLockCount());

		// Get non-existent buffer
		try {
			buf = mgr.getBuffer(++id);
			Assert.fail();
		}
		catch (IOException e) {
			// expected
		}
		assertEquals(0, mgr.getLockCount());
	}

	@Test
	public void testUpdateBuffer() throws IOException {

		initNewFile();

		assertTrue(!mgr.isChanged());

		DataBuffer buf = mgr.createBuffer();
		assertEquals(1, mgr.getLockCount());
		int id = buf.getId();
		buf.put(0, fillPattern1);
		mgr.releaseBuffer(buf);
		assertEquals(0, mgr.getLockCount());

		assertTrue(mgr.isChanged());

		buf = mgr.getBuffer(id);
		assertEquals(1, mgr.getLockCount());
		fillDataBuf(buf);
		mgr.releaseBuffer(buf);
		assertEquals(0, mgr.getLockCount());

		buf = mgr.getBuffer(id);
		assertEquals(1, mgr.getLockCount());
		assertTrue(validDataBuf(buf));
		mgr.releaseBuffer(buf);
		assertEquals(0, mgr.getLockCount());
	}

	@Test
	public void testDeleteBuffer() throws IOException {

		initNewFile();

		DataBuffer buf = mgr.createBuffer();
		assertEquals(1, mgr.getLockCount());
		int id = buf.getId();
		buf.put(0, fillPattern1);
		mgr.releaseBuffer(buf);
		assertEquals(0, mgr.getLockCount());

		buf = mgr.getBuffer(id);
		assertEquals(1, mgr.getLockCount());
		mgr.releaseBuffer(buf);
		assertEquals(0, mgr.getLockCount());

		mgr.deleteBuffer(id);
		assertEquals(0, mgr.getLockCount());
		try {
			buf = mgr.getBuffer(id);
			Assert.fail("Deleted buffer still exists");
		}
		catch (IOException e) {
			// Exception should occur
		}
		assertEquals(0, mgr.getLockCount());
	}

	@Test
	public void testUndo() throws IOException {

		initNewFile();

		assertTrue(!mgr.isChanged());

		// Create buffer (Starts CP1)
		DataBuffer buf = mgr.createBuffer();
		int id = buf.getId();
		fillDataBuf(buf);
		mgr.releaseBuffer(buf);

		assertTrue(mgr.isChanged());

		// Undo create (Restore CP0)
		assertTrue(mgr.undo(true));
		assertTrue(!mgr.hasUndoCheckpoints());
		assertTrue(mgr.hasRedoCheckpoints());

		assertTrue(!mgr.isChanged());

		// Verify that buffer does not exist
		try {
			buf = mgr.getBuffer(id);
			Assert.fail();
		}
		catch (IOException e) {
			// Expected - buffer does not exist
		}

		// Create buffer again and immediately delete (Starts CP1a)
		buf = mgr.createBuffer();
		id = buf.getId();
		fillDataBuf(buf);
		mgr.releaseBuffer(buf);
		mgr.deleteBuffer(id);
		assertTrue(!mgr.hasRedoCheckpoints());

		// *** Checkpoint (Ends CP1)
		mgr.checkpoint();
		assertTrue(mgr.hasUndoCheckpoints());
		assertTrue(!mgr.hasRedoCheckpoints());

		assertTrue(mgr.isChanged());

		// Undo modification (Restore CP0)
		assertTrue(mgr.undo(true));
		assertTrue(!mgr.hasUndoCheckpoints());
		assertTrue(mgr.hasRedoCheckpoints());

		assertTrue(!mgr.isChanged());

		// Create buffer again - reallocation (Starts CP1b)
		buf = mgr.createBuffer();
		assertEquals(id, buf.getId());
		fillDataBuf(buf);
		mgr.releaseBuffer(buf);
		assertTrue(!mgr.hasRedoCheckpoints());

		// Create second buffer, validate id and delete
		buf = mgr.createBuffer();
		assertEquals(id + 1, buf.getId());
		mgr.releaseBuffer(buf);
		mgr.deleteBuffer(id + 1);

		// *** Checkpoint (Ends CP1b)
		mgr.checkpoint();
		assertTrue(mgr.hasUndoCheckpoints());
		assertTrue(!mgr.hasRedoCheckpoints());

		// Modify buffer (Starts CP2a)
		buf = mgr.getBuffer(id);
		buf.put(0, fillPattern1);
		mgr.releaseBuffer(buf);

		// Undo modification (Restore CP1b)
		assertTrue(mgr.undo(true));
		assertTrue(mgr.hasUndoCheckpoints());
		assertTrue(mgr.hasRedoCheckpoints());

		// Verify that buffer is restored
		buf = mgr.getBuffer(id);
		assertTrue(validDataBuf(buf));
		mgr.releaseBuffer(buf);

		// Delete buffer (Starts CP2b)
		mgr.deleteBuffer(id);
		assertTrue(!mgr.hasRedoCheckpoints());

		// Undo delete (Restore CP1b)
		assertTrue(mgr.undo(true));
		assertTrue(mgr.hasUndoCheckpoints());
		assertTrue(mgr.hasRedoCheckpoints());

		// Verify that buffer is restored
		buf = mgr.getBuffer(id);
		assertTrue(validDataBuf(buf));
		mgr.releaseBuffer(buf);

		// Undo create (Restore CP0)
		assertTrue(mgr.undo(true));
		assertTrue(!mgr.hasUndoCheckpoints());
		assertTrue(mgr.hasRedoCheckpoints());

		// Verify that buffer does not exist
		try {
			buf = mgr.getBuffer(id);
			Assert.fail();
		}
		catch (IOException e) {
			// Expected - buffer does not exist
		}

		// No more undos
		assertTrue(!mgr.undo(true));
	}

	@Test
	public void testUndoAll() throws IOException {

		initNewFile();

		assertTrue(!mgr.isChanged());

		// Exceed undo stack size with new buffers
		for (int i = 0; i < 15; i++) {

			// Create buffer (Starts CP1)
			DataBuffer buf = mgr.createBuffer();
			fillDataBuf(buf);
			mgr.releaseBuffer(buf);

			mgr.checkpoint();

			assertTrue(mgr.isChanged());

		}

		// Undo all possible buffer adds
		int count = 0;
		while (mgr.hasUndoCheckpoints()) {
			assertTrue(mgr.undo(true));
			++count;
		}
		assertEquals(10, count);

		// Should still be changes which are not undoable
		assertTrue(mgr.isChanged());

		// No more undos
		assertTrue(!mgr.undo(true));
	}

	@Test
	public void testRollback() throws IOException {

		initNewFile();

		// Create buffer (Starts CP1)
		DataBuffer buf = mgr.createBuffer();
		int id = buf.getId();
		fillDataBuf(buf);
		mgr.releaseBuffer(buf);

		// Undo create (Restore CP0)
		assertTrue(mgr.undo(false));
		assertTrue(!mgr.hasUndoCheckpoints());
		assertTrue(!mgr.hasRedoCheckpoints());

		// Verify that buffer does not exist
		try {
			buf = mgr.getBuffer(id);
			Assert.fail();
		}
		catch (IOException e) {
			// Expected - buffer does not exist
		}

		// Create buffer again and immediately delete (Starts CP1a)
		buf = mgr.createBuffer();
		id = buf.getId();
		fillDataBuf(buf);
		mgr.releaseBuffer(buf);
		mgr.deleteBuffer(id);
		assertTrue(!mgr.hasRedoCheckpoints());

		// *** Checkpoint (Ends CP1)
		mgr.checkpoint();
		assertTrue(mgr.hasUndoCheckpoints());
		assertTrue(!mgr.hasRedoCheckpoints());

		// Undo modification (Restore CP0)
		assertTrue(mgr.undo(false));
		assertTrue(!mgr.hasUndoCheckpoints());
		assertTrue(!mgr.hasRedoCheckpoints());

		// Create buffer again - reallocation (Starts CP1b)
		buf = mgr.createBuffer();
		assertEquals(id, buf.getId());
		fillDataBuf(buf);
		mgr.releaseBuffer(buf);
		assertTrue(!mgr.hasRedoCheckpoints());

		// Create second buffer, validate id and delete
		buf = mgr.createBuffer();
		assertEquals(id + 1, buf.getId());
		mgr.releaseBuffer(buf);
		mgr.deleteBuffer(id + 1);

		// *** Checkpoint (Ends CP1b)
		mgr.checkpoint();
		assertTrue(mgr.hasUndoCheckpoints());
		assertTrue(!mgr.hasRedoCheckpoints());

		// Modify buffer (Starts CP2a)
		buf = mgr.getBuffer(id);
		buf.put(0, fillPattern1);
		mgr.releaseBuffer(buf);

		// Undo modification (Restore CP1b)
		assertTrue(mgr.undo(false));
		assertTrue(mgr.hasUndoCheckpoints());
		assertTrue(!mgr.hasRedoCheckpoints());

		// Verify that buffer is restored
		buf = mgr.getBuffer(id);
		assertTrue(validDataBuf(buf));
		mgr.releaseBuffer(buf);

		// Delete buffer (Starts CP2b)
		mgr.deleteBuffer(id);
		assertTrue(!mgr.hasRedoCheckpoints());

		// Undo delete (Restore CP1b)
		assertTrue(mgr.undo(false));
		assertTrue(mgr.hasUndoCheckpoints());
		assertTrue(!mgr.hasRedoCheckpoints());

		// Verify that buffer is restored
		buf = mgr.getBuffer(id);
		assertTrue(validDataBuf(buf));
		mgr.releaseBuffer(buf);

		// Undo create (Restore CP0)
		assertTrue(mgr.undo(false));
		assertTrue(!mgr.hasUndoCheckpoints());
		assertTrue(!mgr.hasRedoCheckpoints());

		// Verify that buffer does not exist
		try {
			buf = mgr.getBuffer(id);
			Assert.fail();
		}
		catch (IOException e) {
			// Expected - buffer does not exist
		}

		// No more undos
		assertTrue(!mgr.undo(true));
	}

	@Test
	public void testRedo() throws IOException {

		initNewFile();

		assertTrue(!mgr.isChanged());

		assertTrue(mgr.atCheckpoint());
		assertEquals(0, mgr.getAllocatedBufferCount());

		// Create buffer and immediately delete (Starts CP1)
		DataBuffer buf = mgr.createBuffer();
		int id = buf.getId();
		mgr.releaseBuffer(buf);
		mgr.deleteBuffer(id);
		assertTrue(!mgr.atCheckpoint());
		assertEquals(0, mgr.getAllocatedBufferCount());

		// Checkpoint (Ends CP1)
		mgr.checkpoint();
		assertTrue(mgr.hasUndoCheckpoints());
		assertTrue(!mgr.hasRedoCheckpoints());
		assertTrue(mgr.atCheckpoint());

		// Re-create buffer and verify proper reallocation of buffer (CP2)
		buf = mgr.createBuffer();
		assertEquals(id, buf.getId());
		fillDataBuf(buf);
		mgr.releaseBuffer(buf);
		assertTrue(!mgr.atCheckpoint());
		assertEquals(1, mgr.getAllocatedBufferCount());

		// Checkpoint (Ends CP2)
		mgr.checkpoint();
		assertTrue(mgr.hasUndoCheckpoints());
		assertTrue(!mgr.hasRedoCheckpoints());
		assertTrue(mgr.atCheckpoint());

		// Modify buffer (Starts CP3)
		buf = mgr.getBuffer(id);
		buf.put(0, fillPattern1);
		mgr.releaseBuffer(buf);
		assertTrue(!mgr.atCheckpoint());

		// Checkpoint (Ends CP3)
		mgr.checkpoint();
		assertTrue(mgr.hasUndoCheckpoints());
		assertTrue(!mgr.hasRedoCheckpoints());
		assertTrue(mgr.atCheckpoint());

		// Delete buffer (Starts CP4)
		mgr.deleteBuffer(id);
		assertTrue(!mgr.atCheckpoint());
		assertEquals(0, mgr.getAllocatedBufferCount());

		// Undo delete (Restore CP3)
		assertTrue(mgr.undo(true));
		assertTrue(mgr.hasUndoCheckpoints());
		assertTrue(mgr.hasRedoCheckpoints());
		assertTrue(mgr.atCheckpoint());
		assertEquals(1, mgr.getAllocatedBufferCount());

		// Verify that buffer is restored
		buf = mgr.getBuffer(id);
		byte[] data = buf.get(0, fillPattern1.length);
		assertTrue(Arrays.equals(data, fillPattern1));
		mgr.releaseBuffer(buf);
		assertTrue(mgr.atCheckpoint());

		// Undo modification (Restore CP2)
		assertTrue(mgr.undo(true));
		assertTrue(mgr.hasUndoCheckpoints());
		assertTrue(mgr.hasRedoCheckpoints());
		assertTrue(mgr.atCheckpoint());

		// Verify that buffer is restored
		buf = mgr.getBuffer(id);
		assertTrue(validDataBuf(buf));
		mgr.releaseBuffer(buf);
		assertTrue(mgr.atCheckpoint());

		// Undo reallocation (Restore CP1)
		assertTrue(mgr.undo(true));
		assertTrue(mgr.hasUndoCheckpoints());
		assertTrue(mgr.hasRedoCheckpoints());
		assertTrue(mgr.atCheckpoint());
		assertEquals(0, mgr.getAllocatedBufferCount());

		// Verify that buffer does not exist
		try {
			buf = mgr.getBuffer(id);
			Assert.fail();
		}
		catch (IOException e) {
			// Expected - buffer does not exist
		}
		assertTrue(mgr.atCheckpoint());

		// Undo initial creation (Restore CP0)
		assertTrue(mgr.undo(true));
		assertTrue(!mgr.hasUndoCheckpoints());
		assertTrue(mgr.hasRedoCheckpoints());
		assertTrue(mgr.atCheckpoint());
		assertEquals(0, mgr.getAllocatedBufferCount());

		assertTrue(!mgr.isChanged());

		// Verify that buffer does not exist
		try {
			buf = mgr.getBuffer(id);
			Assert.fail();
		}
		catch (IOException e) {
			// Expected - buffer does not exist
		}
		assertTrue(mgr.atCheckpoint());

		// Redo initial create w/ delete (Restore CP1)
		assertTrue(mgr.redo());
		assertTrue(mgr.hasUndoCheckpoints());
		assertTrue(mgr.hasRedoCheckpoints());
		assertTrue(mgr.atCheckpoint());
		assertEquals(0, mgr.getAllocatedBufferCount());

		assertTrue(mgr.isChanged());

		// Verify that buffer does not exist
		try {
			buf = mgr.getBuffer(id);
			Assert.fail();
		}
		catch (IOException e) {
			// Expected - buffer does not exist
		}
		assertTrue(mgr.atCheckpoint());

		// Redo reallocation (Restore CP2)
		assertTrue(mgr.redo());
		assertTrue(mgr.hasUndoCheckpoints());
		assertTrue(mgr.hasRedoCheckpoints());
		assertTrue(mgr.atCheckpoint());
		assertEquals(1, mgr.getAllocatedBufferCount());

		// Verify that buffer is restored
		buf = mgr.getBuffer(id);
		assertTrue(validDataBuf(buf));
		mgr.releaseBuffer(buf);
		assertTrue(mgr.atCheckpoint());

		// Redo modification (Restore CP3)
		assertTrue(mgr.redo());
		assertTrue(mgr.hasUndoCheckpoints());
		assertTrue(mgr.hasRedoCheckpoints());
		assertTrue(mgr.atCheckpoint());

		// Verify that modified buffer is restored
		buf = mgr.getBuffer(id);
		data = buf.get(0, fillPattern1.length);
		assertTrue(Arrays.equals(data, fillPattern1));
		mgr.releaseBuffer(buf);
		assertTrue(mgr.atCheckpoint());

		// Redo delete (Restore CP4)
		assertTrue(mgr.redo());
		assertTrue(mgr.hasUndoCheckpoints());
		assertTrue(!mgr.hasRedoCheckpoints());
		assertTrue(mgr.atCheckpoint());
		assertEquals(0, mgr.getAllocatedBufferCount());

		// Verify that buffer does not exist
		try {
			buf = mgr.getBuffer(id);
			Assert.fail();
		}
		catch (IOException e) {
			// Expected - buffer does not exist
		}
		assertTrue(mgr.atCheckpoint());

		// No more Redos
		assertTrue(!mgr.redo());

		// Verify proper reallocation of buffers
		buf = mgr.createBuffer();
		assertEquals(id, buf.getId());
		mgr.releaseBuffer(buf);
		buf = mgr.createBuffer();
		assertEquals(id + 1, buf.getId());
		mgr.releaseBuffer(buf);

	}

	@Test
	public void testSaveAs() throws Exception {

		initNewFile();

		assertTrue(!mgr.isChanged());

		DataBuffer buf = mgr.createBuffer();
		int id = buf.getId();
		buf.put(0, fillPattern1);
		mgr.releaseBuffer(buf);

		assertTrue(mgr.isChanged());

		File f = new File(testDir, "test.bf");
		LocalBufferFile bf = new LocalBufferFile(f, bufferSize);

		mgr.saveAs(bf, true, null);

		assertTrue(!mgr.isChanged());

		mgr.dispose();

		bf = new LocalBufferFile(f, true);
		mgr = new BufferMgr(bf);

		buf = mgr.getBuffer(id);
		assertTrue(Arrays.equals(fillPattern1, buf.get(0, fillPattern1.length)));
		mgr.releaseBuffer(buf);

	}

	@Test
	public void testSave() throws Exception {

		initNewFile();

		assertTrue(!mgr.isChanged());

		// Initial file build - 50 buffers
		for (int i = 0; i < 50; i++) {
			DataBuffer buf = mgr.createBuffer();
			assertEquals(i, buf.getId());
			buf.put(0, fillPattern1);
			mgr.releaseBuffer(buf);
		}

		assertTrue(mgr.isChanged());

		try {
			// Save not allowed initially
			mgr.save(null, null, null);
			Assert.fail();
		}
		catch (IOException e) {
			// expected
		}

		// 1st Save (saveAs)
		BufferFileManager fileMgr = new DummyBufferFileMgr(testDir, "test", false, false);

		File bfile = fileMgr.getBufferFile(1);
		assertTrue(!bfile.exists());

		LocalManagedBufferFile bf = new LocalManagedBufferFile(bufferSize, fileMgr, -1);
		assertEquals(1, bf.getVersion());
		assertEquals(0, fileMgr.getCurrentVersion());

		mgr.saveAs(bf, true, null);
		assertTrue(!mgr.isChanged());
		assertEquals(1, fileMgr.getCurrentVersion());
		assertTrue(bfile.exists());

		// Add 5 new buffers
		for (int i = 0; i < 5; i++) {
			DataBuffer buf = mgr.createBuffer();
			assertEquals(50 + i, buf.getId());
			buf.put(0, fillPattern1);
			mgr.releaseBuffer(buf);
		}

		// Modify 10 buffers
		for (int i = 5; i < 15; i++) {
			DataBuffer buf = mgr.getBuffer(i);
			buf.put(0, fillPattern2);
			mgr.releaseBuffer(buf);
		}

		// Delete 10 buffers (5 of these had been modified)
		for (int i = 10; i < 20; i++) {
			mgr.deleteBuffer(i);
		}

		assertTrue(mgr.isChanged());

		// 2nd Save (save)
		bfile = fileMgr.getBufferFile(2);
		assertTrue(!bfile.exists());

		mgr.save(null, null, null);
		assertTrue(!mgr.isChanged());
		assertEquals(2, fileMgr.getCurrentVersion());
		assertTrue(bfile.exists());

		// Delete 10 buffers
		for (int i = 20; i < 30; i++) {
			mgr.deleteBuffer(i);
		}

		assertTrue(mgr.isChanged());

		// 3rd Save (save)
		bfile = fileMgr.getBufferFile(3);
		assertTrue(!bfile.exists());

		mgr.save(null, null, null);
		assertTrue(!mgr.isChanged());
		assertEquals(3, fileMgr.getCurrentVersion());
		assertTrue(bfile.exists());

		// Add 20 buffers (reused buffers)
		for (int i = 19; i >= 0; --i) {
			DataBuffer buf = mgr.createBuffer();
			buf.put(0, fillPattern2);
			mgr.releaseBuffer(buf);
		}

		// Add 10 new buffers
		for (int i = 0; i < 10; i++) {
			DataBuffer buf = mgr.createBuffer();
			assertEquals(55 + i, buf.getId());
			buf.put(0, fillPattern1);
			mgr.releaseBuffer(buf);
		}

		assertTrue(mgr.isChanged());

		// 4th Save (save)
		bfile = fileMgr.getBufferFile(4);
		assertTrue(!bfile.exists());

		mgr.save(null, null, null);
		assertTrue(!mgr.isChanged());
		assertEquals(4, fileMgr.getCurrentVersion());
		assertTrue(bfile.exists());

		mgr.dispose();

		assertTrue(bfile.exists());

		// Re-open and verify data
		bf = new LocalManagedBufferFile(fileMgr, true, -1, -1);
		assertTrue(bfile.exists());
		mgr = new BufferMgr(bf);

		assertTrue(!mgr.isChanged());

		for (int i = 0; i < 5; i++) {
			DataBuffer buf = mgr.getBuffer(i);
			assertTrue(Arrays.equals(fillPattern1, buf.get(0, fillPattern1.length)));
			mgr.releaseBuffer(buf);
		}

		for (int i = 5; i < 30; i++) {
			DataBuffer buf = mgr.getBuffer(i);
			assertTrue(Arrays.equals(fillPattern2, buf.get(0, fillPattern2.length)));
			mgr.releaseBuffer(buf);
		}

		for (int i = 30; i < 65; i++) {
			DataBuffer buf = mgr.getBuffer(i);
			assertTrue(Arrays.equals(fillPattern1, buf.get(0, fillPattern1.length)));
			mgr.releaseBuffer(buf);
		}

		assertTrue(!mgr.isChanged());

		try {
			mgr.getBuffer(66);
			Assert.fail();
		}
		catch (IOException e) {
			// expected
		}
	}

}
