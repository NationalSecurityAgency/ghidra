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

import java.io.File;
import java.io.IOException;
import java.util.Date;
import java.util.NoSuchElementException;

import db.DBChangeSet;
import db.DBHandle;
import ghidra.util.Msg;
import ghidra.util.datastruct.IntSet;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

class RecoveryMgr {

	private static final String SNAPSHOT1_FILE = "snapshotA.grf";
	private static final String SNAPSHOT2_FILE = "snapshotB.grf";
	private static final String SNAPSHOT1_CHANGESET_FILE = "changeA.grf";
	private static final String SNAPSHOT2_CHANGESET_FILE = "changeB.grf";

	private static final String CHANGE_SET_REQUIRED_PARM = "";

	private File[] snapshotFiles;
	private File[] changeFiles;
	private int snapshotIndex = -1;
	private RecoveryFile activeFile;
	private IntSet oldIndexSet;
	private boolean newSnapshot;
	private long lastSnapshotTime;

	private boolean recovered = false;
	private boolean recoveryHasChangeSet = false;

	private BufferMgr bufferMgr;

	private int[] buffersSaved = new int[] { 0, 0 };
	private int[] buffersIgnored = new int[] { 0, 0 };
	private int[] buffersRemoved = new int[] { 0, 0 };

	/**
	 * Constructor used to perform recovery.
	 * Once constructed snapshots may be performed.
	 * @param bufferMgr
	 * @param monitor
	 */
	RecoveryMgr(BufferMgr bufferMgr, TaskMonitor monitor) throws IOException, CancelledException {

		this.bufferMgr = bufferMgr;
		BufferFile bf = bufferMgr.getSourceFile();
		if (!(bf instanceof LocalBufferFile)) {
			throw new RuntimeException("Invalid use of recovery manager");
		}
		LocalBufferFile lbf = (LocalBufferFile) bf;
		snapshotFiles = getSnapshotFiles(lbf);
		changeFiles = getChangeFiles(lbf);

		RecoveryFile recoveryFile = getRecoveryFile(lbf, snapshotFiles);
		if (recoveryFile != null) {
			try {
				lastSnapshotTime = recoveryFile.getFile().lastModified();
				snapshotIndex = recoveryFile.getFile().equals(snapshotFiles[0]) ? 0 : 1;
				try {
					recoveryHasChangeSet =
						(recoveryFile.getParameter(CHANGE_SET_REQUIRED_PARM) != 0);
				}
				catch (NoSuchElementException e) {
				}
				if (!recoveryHasChangeSet || changeFiles[snapshotIndex].exists()) {
					Msg.info(this, "Applying buffer file recovery data: " + lbf.getFile());
					bufferMgr.recover(recoveryFile, snapshotIndex, monitor);
					recovered = true;
				}
			}
			finally {
				try {
					recoveryFile.close();
				}
				catch (IOException e) {
				}
			}
		}
		if (snapshotIndex != 0) {
			snapshotFiles[0].delete();
			changeFiles[0].delete();
		}
		if (snapshotIndex != 1) {
			snapshotFiles[1].delete();
			changeFiles[1].delete();
		}
	}

	/**
	 * Constructor for snapshot use only.
	 * @param bufferMgr
	 */
	RecoveryMgr(BufferMgr bufferMgr) {

		this.bufferMgr = bufferMgr;
		BufferFile bf = bufferMgr.getSourceFile();
		if (!(bf instanceof LocalBufferFile)) {
			throw new RuntimeException("Invalid use of recovery manager");
		}
		LocalBufferFile lbf = (LocalBufferFile) bf;
		snapshotFiles = getSnapshotFiles(lbf);
		changeFiles = getChangeFiles(lbf);

		snapshotFiles[0].delete();
		snapshotFiles[1].delete();
		changeFiles[0].delete();
		changeFiles[1].delete();
	}

	void dispose() {
		if (activeFile != null) {
			endSnapshot(false);
			activeFile = null;
		}
		snapshotFiles[0].delete();
		changeFiles[0].delete();
		snapshotFiles[1].delete();
		changeFiles[1].delete();

		snapshotFiles[0] = null;
		snapshotFiles[1] = null;
		changeFiles[0] = null;
		changeFiles[1] = null;
	}

	boolean recovered() {
		return recovered;
	}

	/**
	 * Returns the recovery change data file for reading or null if one is not available.
	 * The caller must dispose of the returned file before peforming generating any new
	 * recovery snapshots.
	 * @throws IOException
	 */
	LocalBufferFile getRecoveryChangeSetFile() throws IOException {
		if (recovered && recoveryHasChangeSet) {
			return new LocalBufferFile(changeFiles[snapshotIndex], true);
		}
		return null;
	}

	void clear() {
		if (activeFile != null) {
			throw new AssertException("Snapshot already in progress");
		}
		snapshotFiles[0].delete();
		snapshotFiles[1].delete();
		changeFiles[0].delete();
		changeFiles[1].delete();
	}

	static boolean canRecover(LocalBufferFile bf) {
		RecoveryFile rf = null;
		try {
			File[] snapshotFiles = getSnapshotFiles(bf);
			rf = getRecoveryFile(bf, snapshotFiles);
			if (rf != null) {
				boolean canRecover = true;
				try {
					if (rf.getParameter(CHANGE_SET_REQUIRED_PARM) != 0) {
						File[] changeFiles = getChangeFiles(bf);
						int snapshotIndex = rf.getFile().equals(snapshotFiles[0]) ? 0 : 1;
						canRecover = changeFiles[snapshotIndex].exists();
					}
				}
				catch (NoSuchElementException e) {
				}
				return canRecover;
			}
		}
		catch (IOException e) {
		}
		finally {
			if (rf != null) {
				try {
					rf.close();
				}
				catch (IOException e) {
				}
			}
		}
		return false;
	}

	private static RecoveryFile getRecoveryFile(LocalBufferFile srcBf, File[] snapshotFiles) {
		RecoveryFile[] recoveryFiles = new RecoveryFile[2];
		long[] modTimes = new long[2];
		for (int i = 0; i < recoveryFiles.length; i++) {
			if (snapshotFiles[i].exists()) {
				try {
					RecoveryFile rf = new RecoveryFile(srcBf, snapshotFiles[i]);
					if (rf.isValid()) {
						recoveryFiles[i] = rf;
						modTimes[i] = rf.getTimestamp();
					}
					else {
						rf.close();
					}
				}
				catch (IOException e) {
				}
			}
		}

		if (recoveryFiles[0] != null) {
			if (recoveryFiles[1] != null) {
				RecoveryFile closeRf = null;
				try {
					if (modTimes[1] == modTimes[0]) {
						Msg.warn(RecoveryMgr.class,
							"Recover files have same timestamp: " + modTimes[0]);
						closeRf = recoveryFiles[1];
						try {
							recoveryFiles[0].close();
						}
						catch (IOException e) {
						}
						return null; // can not use either file!
					}
					else if (modTimes[1] > modTimes[0]) {
						closeRf = recoveryFiles[0];
						return recoveryFiles[1];
					}
					closeRf = recoveryFiles[1];
					return recoveryFiles[0];
				}
				finally {
					if (closeRf != null) {
						try {
							closeRf.close();
						}
						catch (IOException e) {
						}
					}
				}
			}
			return recoveryFiles[0];
		}
		return recoveryFiles[1];
	}

	private static File[] getSnapshotFiles(LocalBufferFile bf) {
		File dir = bf.getFile().getParentFile();
		return new File[] { new File(dir, SNAPSHOT1_FILE), new File(dir, SNAPSHOT2_FILE) };
	}

	private static File[] getChangeFiles(LocalBufferFile bf) {
		File dir = bf.getFile().getParentFile();
		return new File[] { new File(dir, SNAPSHOT1_CHANGESET_FILE),
			new File(dir, SNAPSHOT2_CHANGESET_FILE) };
	}

	/**
	 * Open a recovery file for an updated snapshot
	 * @param indexCnt the total number of allocated indexes within the corresponding source buffer file.
	 * @param freeIndexes a list of indexes which are currently free/empty.
	 * @param changeSet an optional database-backed change set which reflects changes
	 * made since the last version.
	 * @param monitor
	 * @throws IOException
	 * @throws CancelledException
	 */
	void startSnapshot(int indexCnt, int[] freeIndexes, DBChangeSet changeSet, TaskMonitor monitor)
			throws CancelledException, IOException {
		if (activeFile != null) {
			throw new AssertException("Snapshot already in progress");
		}
		recovered = false;
		++snapshotIndex;
		if (snapshotIndex == 2) {
			snapshotIndex = 0;
		}

		// Prevent duplicate snapshot times
		long t = (new Date()).getTime();
		if ((t - lastSnapshotTime) < 1) {
			try {
				Thread.sleep(2);
			}
			catch (InterruptedException e) {
			}
			t = (new Date()).getTime();
		}

		boolean success = false;
		try {
			newSnapshot = !snapshotFiles[snapshotIndex].exists();
			try {
				activeFile = new RecoveryFile((LocalBufferFile) bufferMgr.getSourceFile(),
					snapshotFiles[snapshotIndex], newSnapshot);
			}
			catch (IOException e) {
				if (newSnapshot) {
					throw e;
				}
				// Assume an invalid file - remove bad snapshot and create a new file
				snapshotFiles[snapshotIndex].delete();
				newSnapshot = true;
				activeFile = new RecoveryFile((LocalBufferFile) bufferMgr.getSourceFile(),
					snapshotFiles[snapshotIndex], newSnapshot);
			}
			activeFile.setIndexCount(indexCnt);
			activeFile.setFreeIndexList(freeIndexes);
			oldIndexSet = new IntSet(activeFile.getBufferIndexes());
			if (changeSet != null) {
				activeFile.setParameter(CHANGE_SET_REQUIRED_PARM, 1);
				changeFiles[snapshotIndex].delete();
				DBHandle csh = new DBHandle();
				try {
					changeSet.write(csh, true);
					csh.saveAs(changeFiles[snapshotIndex], true, monitor);
				}
				finally {
					csh.close();
				}
			}
			else {
				activeFile.setParameter(CHANGE_SET_REQUIRED_PARM, 0);
			}
			success = true;
		}
		finally {
			if (!success && activeFile != null) {
				activeFile.close();
				activeFile = null;
				snapshotFiles[snapshotIndex].delete();
				changeFiles[snapshotIndex].delete();
			}
		}
		buffersSaved[snapshotIndex] = 0;
		buffersIgnored[snapshotIndex] = 0;
		buffersRemoved[snapshotIndex] = 0;
	}

	/**
	 * Returns true if snapshot is in progress
	 */
	boolean isSnapshotInProgress() {
		return activeFile != null;
	}

	/**
	 * End the recovery snapshot and close the underlying file.
	 * @param commit if true the snapshot is finalized and stored, otherwise
	 * the snapshot is deleted.
	 */
	void endSnapshot(boolean commit) {
		if (activeFile == null) {
			throw new AssertException("Snapshot not in progress");
		}
		try {
			if (commit) {
				// Elliminate buffers if they were not put into the snapshot.
				//  This is the result of an undo which may have reverted a buffer to
				// its original unmodified state.
				int[] indexes = oldIndexSet.getValues();
				for (int i = 0; i < indexes.length; i++) {
					activeFile.removeBuffer(indexes[i]);
				}
				buffersRemoved[snapshotIndex] = indexes.length;
				File file = activeFile.getFile();
				activeFile.close();
				lastSnapshotTime = file.lastModified();
				Msg.info(this,
					(new Date()) + " Recovery snapshot created: " + snapshotFiles[snapshotIndex]);
			}
			else {
				activeFile.close();
			}
		}
		catch (IOException e) {
			commit = false;
		}

		activeFile = null;
		if (!commit) {
			snapshotFiles[snapshotIndex].delete();
			--snapshotIndex;
			if (snapshotIndex < 0) {
				snapshotIndex = 1;
			}
		}
	}

//	void clearParameters() throws IOException {
//		if (activeFile == null) {
//			throw new AssertException("Snapshot not in progress");
//		}
//		activeFile.clearUserParameters();
//	}
//
//	void setParameter(String name, int value) throws IOException {
//		if (activeFile == null) {
//			throw new AssertException("Snapshot not in progress");
//		}
//		activeFile.setUserParameter(name, value);
//	}

	/**
	 * Write a modified buffer corresponding to the specified BufferNode
	 * to the current open snapshot file.  The following BufferNode fields
	 * are utilized which should not be modified concurrent with this
	 * method invocation: 'id' and  'snapshotTaken'.
	 * @param buf
	 * @param node
	 * @throws IOException
	 */
	void putBuffer(DataBuffer buffer, BufferNode node) throws IOException {
		if (activeFile == null) {
			throw new AssertException("Snapshot not in progress");
		}
		if (newSnapshot || !node.snapshotTaken[snapshotIndex]) {
			activeFile.putBuffer(buffer);
			node.snapshotTaken[snapshotIndex] = true;
			++buffersSaved[snapshotIndex];
		}
		else {
			++buffersIgnored[snapshotIndex];
		}
		oldIndexSet.remove(node.id);
	}

	void printStats() {
		Msg.info(this, "RecoveryMgr stats:");
		for (int i = 0; i < 2; i++) {
			String lastSnapshot = snapshotIndex == i ? "*" : " ";
			Msg.info(this, "  " + lastSnapshot + snapshotFiles[i]);
			Msg.info(this, "     buffers saved: " + buffersSaved[i]);
			Msg.info(this, "     buffers unchanged: " + buffersIgnored[i]);
			Msg.info(this, "     buffers removed: " + buffersRemoved[i]);
		}
	}

}
