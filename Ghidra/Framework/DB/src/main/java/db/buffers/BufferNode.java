/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

/**
 * <code>BufferNode</code> is a DataBuffer wrapper which facilitates
 * linking node into various lists and status tracking.  
 * Linked lists supported, include:
 * <ul>
 * <li>Buffer cache</li>
 * <li>Buffer versions</li>
 * <li>Checkpoint list</li>
 * </ul>
 */
class BufferNode {

	/**
	 * Chain of buffers currently in memory cache
	 */
	BufferNode nextCached;
	BufferNode prevCached;
	
	/**
	 * Chain of buffers having the same buffer ID which 
	 * have been modified.  Each version corresponds to a
	 * different checkpoint.
	 */
	BufferNode nextVersion;
	BufferNode prevVersion;
	
	/**
	 * Chain of buffers corresponding to a single checkpoint.
	 */
	BufferNode nextInCheckpoint;
	BufferNode prevInCheckpoint;
	
	final int id;	
	int checkpoint;

	/**
	 * DataBuffer object reference.  Holds memory reference to buffer object.
	 */	
	DataBuffer buffer = null;

	/**
	 * DataBuffer index within disk cache.
	 * A value of -1 indicates that buffer has not yet been written to disk cache.
	 */	
	int diskCacheIndex = -1;
	
	/**
	 * The <code>locked</code> flag is set true when the associated buffer has been
	 * given out for update.  When the buffer is released, <code>locked</code> is set
	 * false.
	 */
	boolean locked = false;
	
	/**
	 * The <code>empty</code> flag is set true when a buffer has been deleted and is
	 * available for re-use.  If false, the buffer has been allocated.
	 */
	boolean empty = false;
	
	/**
	 * The <code>modified</code> flag is set true the first time it is modified
	 * relative to the source file.  Once a save occurs to a buffer file, this can
	 * be set false.  This flag remains false for original source buffers which
	 * are not modified.
	 */
	boolean modified = false;  // modification relative to original source file
	
	/**
	 * The <code>isDirty</code> flag indicates that the associated buffer has been
	 * modified since the last time it was written to the disk cache storage.
	 * Once re-written to the disk cache, this flag is set to false.
	 */
	boolean isDirty = false;  // modification relative to cache file copy
	
	/**
	 * The <code>snapshotTaken</code> flags are used by the RecoveryMgr to track if a 
	 * modified node has been written to the recovery file.
	 */
	boolean[] snapshotTaken = new boolean[] {false, false};
	
	/**
	 * Construct a buffer node.
	 */
	BufferNode(int id, int checkpoint) {
		this.id = id;
		this.checkpoint = checkpoint;
	}
	
	/**
	 * Clear snapshotTaken flags so that node will be properly retained by the next recovery snapshot
	 * if necessary.
	 */
	void clearSnapshotTaken() {
		snapshotTaken[0] = false;
		snapshotTaken[1] = false;
	}
	
	/**
	 * Unlink this node from the Cache list
	 */
	void removeFromCache() {
		prevCached.nextCached = nextCached;
		nextCached.prevCached = prevCached;
		nextCached = null;
		prevCached = null;	
	}
	
	/**
	 * Link this node to the top of the Cache list.
	 * @param cacheHead
	 */
	void addToCache(BufferNode cacheHead) {
		prevCached = cacheHead;
		nextCached = cacheHead.nextCached;
		cacheHead.nextCached.prevCached = this;
		cacheHead.nextCached = this;
	}
	
	/**
	 * Unlink this node from the Checkpoint list
	 */
	void removeFromCheckpoint() {
		prevInCheckpoint.nextInCheckpoint = nextInCheckpoint;
		nextInCheckpoint.prevInCheckpoint = prevInCheckpoint;
		nextInCheckpoint = null;
		prevInCheckpoint = null;	
	}
	
	/**
	 * Link this node to the top of the Checkpoint list.
	 * @param checkpointHead
	 */
	void addToCheckpoint(BufferNode checkpointHead) {
		prevInCheckpoint = checkpointHead;
		nextInCheckpoint = checkpointHead.nextInCheckpoint;
		checkpointHead.nextInCheckpoint.prevInCheckpoint = this;
		checkpointHead.nextInCheckpoint = this;	
	}
	
	/**
	 * Unlink this node from the version list.
	 */
	void removeFromVersion() {
		prevVersion.nextVersion = nextVersion;
		nextVersion.prevVersion = prevVersion;
		nextVersion = null;
		prevVersion = null;	
	}
	
	/**
	 * Link this node to the top of the version list.
	 * @param versionHead
	 */
	void addToVersion(BufferNode versionHead) {
		prevVersion = versionHead;
		nextVersion = versionHead.nextVersion;
		versionHead.nextVersion.prevVersion = this;
		versionHead.nextVersion = this;
	}
}
