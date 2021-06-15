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

import java.io.*;
import java.util.*;

import db.DBChangeSet;
import db.DBHandle;
import db.buffers.LocalBufferFile.BufferFileFilter;
import ghidra.framework.ShutdownHookRegistry;
import ghidra.framework.ShutdownPriority;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.datastruct.ObjectArray;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * <code>BufferMgr</code> provides low-level buffer management and caching.
 * Checkpointing and buffer versioning is supported along with an undo/redo
 * capability.
 */
public class BufferMgr {

	public static final String ALWAYS_PRECACHE_PROPERTY = "db.always.precache";

	private static boolean alwaysPreCache =
		SystemUtilities.getBooleanProperty(ALWAYS_PRECACHE_PROPERTY, false);

	public static final int DEFAULT_BUFFER_SIZE = 16 * 1024;
	public static final int DEFAULT_CHECKPOINT_COUNT = 10;
	public static final int DEFAULT_CACHE_SIZE = 4 * 1024 * 1024;
	private static final int MINIMUM_CACHE_SIZE = 64 * 1024;

	private static final String CACHE_FILE_PREFIX = "ghidra";
	private static final String CACHE_FILE_EXT = ".cache";

	// Dummy node id's for Head and Tail nodes
	private static final int HEAD = -1;
	private static final int TAIL = -2;

	private static HashSet<BufferMgr> openInstances;

	private int maxCheckpoints; // minimum = 2
	private int maxCacheSize; // in memory buffer count (minimum 64KB equivalent)

	private int currentCheckpoint = -1;

	private boolean corruptedState = false;

	private BufferFile sourceFile;
	private LocalBufferFile cacheFile;

	private RecoveryMgr recoveryMgr;
	private Object snapshotLock = new Object(); // Used to prevent BufferNode modifications during snapshot
	private boolean modifiedSinceSnapshot = false;
	private boolean hasNonUndoableChanges = false;

	private int bufferSize;

	/**
	 * The cached buffer list provides a linked list of all
	 * buffer nodes which have an in-memory buffer.  Oldest
	 * cached nodes are at the bottom (cacheTail.prevCached).
	 */
	private BufferNode cacheHead;
	private BufferNode cacheTail;
	private int cacheSize = 0;
	private int buffersOnHand = 0;
	private int lockCount = 0;

	/**
	 * Available memory cache buffers
	 */
	private Stack<DataBuffer> freeBuffers = new Stack<>();

	// Cache statistics data
	private long cacheHits = 0; // buffer requests satisified by memory cache
	private long cacheMisses = 0; // buffer requests not satisified by memory cache
	private int lowWaterMark = -1; // lowest buffer cache point

	/**
	 * Collection of checkpoint heads for undo
	 */
	private ArrayList<BufferNode> checkpointHeads = new ArrayList<>();

	/**
	 * Collection of checkpoint heads for redo
	 */
	private ArrayList<BufferNode> redoCheckpointHeads = new ArrayList<>();

	/**
	 * Current checkpoint head.  If null a new checkpoint must be
	 * established on the first buffer modification.
	 */
	private BufferNode currentCheckpointHead;

	/**
	 * Baseline checkpoint head.  This is holds the oldest version of
	 * each buffer supported by undo.
	 */
	private BufferNode baselineCheckpointHead;

	/**
	 * Index provider for database buffer file.
	 */
	private IndexProvider indexProvider;

	/**
	 * Index provider for cache file.
	 */
	private IndexProvider cacheIndexProvider;

	/**
	 * The buffer table contains stacks for each buffer id.
	 * The table contains the head buffer node.  When new buffer
	 * versions are created, they are pushed onto the stack - e.g.,
	 * inserted between the head and the next node.
	 */
	private ObjectArray bufferTable;

	private static final int INITIAL_BUFFER_TABLE_SIZE = 1024;

	/**
	 * An optional pre-cache of all buffers can be performed within a separate 
	 * thread if enabled.
	 */
	private enum PreCacheStatus {
		INIT, RUNNING, INTERUPTED, STOPPED
	}

	private PreCacheStatus preCacheStatus = PreCacheStatus.INIT;
	private Thread preCacheThread; // only used once for original sourceFile (TODO: use currently not supported)
	private Object preCacheLock = new Object();

	/**
	 * Construct a new buffer manager with no underlying source file using the
	 * default buffer size, cache size and maximum undo count.
	 * @throws IOException if a cache file access error occurs
	 */
	public BufferMgr() throws IOException {
		this(null, DEFAULT_BUFFER_SIZE, DEFAULT_CACHE_SIZE, DEFAULT_CHECKPOINT_COUNT);
	}

	/**
	 * Construct a new buffer manager with no underlying source file.
	 * @param requestedBufferSize requested buffer size.  Actual buffer size may
	 * vary.
	 * @param approxCacheSize approximate size of cache in Bytes.
	 * @param maxUndos maximum number of checkpoints retained for undo (Minimum=1).
	 * @throws IOException if a cache file access error occurs
	 */
	public BufferMgr(int requestedBufferSize, long approxCacheSize, int maxUndos)
			throws IOException {
		this(null, requestedBufferSize, approxCacheSize, maxUndos);
	}

	/**
	 * Construct a buffer manager for a given source file using default
	 * cache size and maximum undo count.
	 * @param sourceFile buffer file
	 * @throws IOException if source or cache file access error occurs
	 */
	public BufferMgr(BufferFile sourceFile) throws IOException {
		this(sourceFile, DEFAULT_BUFFER_SIZE, DEFAULT_CACHE_SIZE, DEFAULT_CHECKPOINT_COUNT);
	}

	/**
	 * Construct a buffer manager for a given source file using default
	 * cache size and maximum undo count.
	 * @param sourceFile buffer file
	 * @param approxCacheSize approximate size of cache in Bytes.
	 * @param maxUndos maximum number of checkpoints retained for undo (Minimum=1).
	 * @throws IOException if source or cache file access error occurs
	 */
	public BufferMgr(BufferFile sourceFile, long approxCacheSize, int maxUndos) throws IOException {
		this(sourceFile, 0, approxCacheSize, maxUndos);
	}

	/**
	 * Construct a buffer manager for a given source file.
	 * @param sourceFile buffer source file
	 * @param requestedBufferSize requested buffer size.  Actual buffer size may
	 * vary (ignored if source is not null).
	 * @param approxCacheSize approximate size of cache in Bytes.
	 * @param maxUndos maximum number of checkpoints retained for undo (Minimum=1).
	 * @throws IOException if source or cache file access error occurs
	 */
	private BufferMgr(BufferFile sourceFile, int requestedBufferSize, long approxCacheSize,
			int maxUndos) throws FileNotFoundException, IOException {
		bufferSize = requestedBufferSize;
		if (sourceFile != null) {
			this.sourceFile = sourceFile;
			int cnt = sourceFile.getIndexCount();
			indexProvider = new IndexProvider(cnt, sourceFile.getFreeIndexes());
			bufferTable = new ObjectArray(cnt + INITIAL_BUFFER_TABLE_SIZE);
			bufferSize = sourceFile.getBufferSize();
		}
		else {
			indexProvider = new IndexProvider();
			bufferTable = new ObjectArray(INITIAL_BUFFER_TABLE_SIZE);
			bufferSize = LocalBufferFile.getRecommendedBufferSize(bufferSize);
		}

		// Set maximum
		maxCheckpoints = maxUndos < 1 ? DEFAULT_CHECKPOINT_COUNT : (maxUndos + 1);

		// Compute cache size
		approxCacheSize =
			approxCacheSize < MINIMUM_CACHE_SIZE ? MINIMUM_CACHE_SIZE : approxCacheSize;
		maxCacheSize = (int) (approxCacheSize / bufferSize);

		// Setup memory cache list
		cacheHead = new BufferNode(HEAD, -1);
		cacheTail = new BufferNode(TAIL, -1);
		cacheHead.nextCached = cacheTail;
		cacheTail.prevCached = cacheHead;

		// Create disk cache file
		cacheFile = new LocalBufferFile(bufferSize, CACHE_FILE_PREFIX, CACHE_FILE_EXT);

		cacheIndexProvider = new IndexProvider();

		// Setup baseline - checkpoint 0
		startCheckpoint();
		baselineCheckpointHead = currentCheckpointHead;
		currentCheckpointHead = null;

		// Copy file parameters into cache file
		if (sourceFile != null) {
			String[] parmNames = sourceFile.getParameterNames();
			for (int i = 0; i < parmNames.length; i++) {
				String name = parmNames[i];
				cacheFile.setParameter(name, sourceFile.getParameter(name));
			}
		}

		addInstance(this);

		if (alwaysPreCache) {
			startPreCacheIfNeeded();
		}
	}

	/**
	 * Enable and start source buffer file pre-cache if appropriate.
	 * This may be forced for all use cases by setting the System property 
	 * db.always.precache=true
	 * WARNING! EXPERIMENTAL !!!
	 */
	public void enablePreCache() {
		synchronized (preCacheLock) {
			if (preCacheStatus == PreCacheStatus.INIT) {
				startPreCacheIfNeeded();
			}
		}
	}

	/**
	 * Add new BufferMgr instance and ensure that all non-disposed
	 * BufferMgr instances are properly disposed when the VM shuts-down.
	 * @param bufMgr new instance
	 */
	private static synchronized void addInstance(BufferMgr bufMgr) {

		if (openInstances == null) {

			openInstances = new HashSet<>();

			Runnable cleanupTask = () -> {
				Object[] instanceList;
				synchronized (BufferMgr.class) {
					instanceList = openInstances.toArray();
				}
				for (int i = 0; i < instanceList.length; i++) {
					BufferMgr bufferMgr = (BufferMgr) instanceList[i];
					try {
						bufferMgr.dispose();
					}
					catch (Throwable t) {
						// Ignore errors
					}
				}
			};
			ShutdownHookRegistry.addShutdownHook(cleanupTask,
				ShutdownPriority.DISPOSE_FILE_HANDLES);
		}
		openInstances.add(bufMgr);
	}

	/**
	 * Set the corrupt state flag for this buffer manager.  This will cause any snapshot
	 * attempt to fail and cause most public access methods to throw an IOException.
	 * The caller should log this action and the reason for it.
	 */
	public void setCorruptedState() {
		corruptedState = true;
	}

	/**
	 * Determine if BufferMgr has become corrupted (IOException has occurred).
	 * @return true if this BufferMgr is corrupt.
	 */
	public boolean isCorrupted() {
		return corruptedState;
	}

	/**
	 * Remove a BufferMgr instance after it has been disposed.
	 * @param bufMgr disposed instance
	 */
	private static synchronized void removeInstance(BufferMgr bufMgr) {
		openInstances.remove(bufMgr);
	}

	/**
	 * Get the current number of locked buffers.
	 * @return int
	 */
	public synchronized int getLockCount() {
		return lockCount;
	}

	/**
	 * @return the size of each buffer in bytes.
	 */
	public int getBufferSize() {
		return bufferSize;
	}

	/**
	 * @return returns the source file
	 */
	public BufferFile getSourceFile() {
		return sourceFile;
	}

	/**
	 * Dispose of buffer manager when finalized.
	 */
	@Override
	protected void finalize() throws Throwable {
		dispose(true);
		super.finalize();
	}

	/**
	 * Get file parameter
	 * @param name parameter name/key
	 * @return parameter value
	 * @throws NoSuchElementException if parameter not found
	 */
	int getParameter(String name) throws NoSuchElementException {
		return cacheFile.getParameter(name);
	}

	/**
	 * Set file parameter
	 * @param name parameter name/key
	 * @param value parameter value
	 */
	void setParameter(String name, int value) {
		cacheFile.setParameter(name, value);
	}

	/**
	 * Dispose of all buffer manager resources including any source
	 * buffer file.  Any existing recovery data will be discarded.
	 * This method should be called when this buffer manager instance
	 * is no longer needed.
	 */
	public void dispose() {
		dispose(false);
	}

	/**
	 * Dispose of all buffer manager resources including any source
	 * buffer file.
	 * This method should be called when this buffer manager instance
	 * is no longer needed.
	 * @param keepRecoveryData true if existing snapshot recovery files 
	 * should not be deleted.
	 */
	public void dispose(boolean keepRecoveryData) {

		synchronized (snapshotLock) {

			stopPreCache();

			synchronized (this) {

				if (recoveryMgr != null) {
					if (!keepRecoveryData) {
						recoveryMgr.dispose();
					}
					recoveryMgr = null;
				}
				if (sourceFile != null) {
					sourceFile.dispose();
					sourceFile = null;
				}
				if (cacheFile != null) {
					cacheFile.delete();
					cacheFile = null;
				}

				// Dispose all buffer nodes - speeds up garbage collection
				if (checkpointHeads != null) {
					Iterator<BufferNode> iter = checkpointHeads.iterator();
					while (iter.hasNext()) {
						BufferNode node = iter.next();
						while (node != null) {
							BufferNode next = node.nextInCheckpoint;
							node.buffer = null;
							node.nextCached = null;
							node.prevCached = null;
							node.nextInCheckpoint = null;
							node.prevInCheckpoint = null;
							node.nextVersion = null;
							node.prevVersion = null;
							node = next;
						}
					}
					checkpointHeads = null;
				}
				if (redoCheckpointHeads != null) {
					Iterator<BufferNode> iter = redoCheckpointHeads.iterator();
					while (iter.hasNext()) {
						BufferNode node = iter.next();
						while (node != null) {
							BufferNode next = node.nextInCheckpoint;
							node.buffer = null;
							node.nextCached = null;
							node.prevCached = null;
							node.nextInCheckpoint = null;
							node.prevInCheckpoint = null;
							node.nextVersion = null;
							node.prevVersion = null;
							node = next;
						}
					}
					redoCheckpointHeads = null;
				}
				bufferTable = null;
				currentCheckpointHead = null;
				baselineCheckpointHead = null;
				hasNonUndoableChanges = false;

				removeInstance(this);
			}
		}
	}

	/**
	 * If maximum number of checkpoints is exceeded, pack oldest
	 * checkpoint into baseline.
	 */
	private void packCheckpoints() {
		if (checkpointHeads.size() <= maxCheckpoints) {
			return;
		}

		BufferNode cpHead = checkpointHeads.get(1); // oldest checkpoint (excluding baseline)
		BufferNode cpNode = cpHead.nextInCheckpoint;
		while (cpNode.id != TAIL) {
			BufferNode baseline = cpNode.nextVersion;
			BufferNode cpNext = cpNode.nextInCheckpoint;
			if (baseline.id != TAIL) {
				// Discard old baseline buffer node - free disk cache index
				disposeNode(baseline, true);
			}

			// Node becomes new baseline buffer version
			cpNode.checkpoint = 0;
			cpNode.addToCheckpoint(baselineCheckpointHead);

			cpNode = cpNext;
		}

		// Discard checkpoint list
		checkpointHeads.remove(1);

		hasNonUndoableChanges = true;
	}

	/**
	 * Dispose a checkpoint buffer node.
	 * Node is removed from all applicable lists and the disk
	 * cache index added to free index list.
	 * @param node buffer node to dispose
	 */
	private void disposeNode(BufferNode node, boolean isVersioned) {
		node.removeFromCheckpoint();
		if (isVersioned) {
			node.removeFromVersion();
		}
		if (node.buffer != null) {
			freeBuffers.push(node.buffer);
			removeFromCache(node);
		}
		if (node.diskCacheIndex >= 0) {
			cacheIndexProvider.freeIndex(node.diskCacheIndex);
			node.diskCacheIndex = -1;
		}
	}

	/**
	 * Dispose all nodes in list.
	 * @param head list head
	 */
	private void disposeNodeList(BufferNode head) {
		BufferNode node = head.nextInCheckpoint;
		while (node.id != TAIL) {
			BufferNode nextNode = node.nextInCheckpoint;
			disposeNode(node, false);
			node = nextNode;
		}
	}

	/**
	 * Dispose all redo checkpoint lists.
	 */
	private void disposeRedoCheckpoints() {
		int cnt = redoCheckpointHeads.size();
		if (cnt == 0) {
			return;
		}
		for (int i = 0; i < cnt; i++) {
			disposeNodeList(redoCheckpointHeads.get(i));
		}
		redoCheckpointHeads.clear();
	}

	/**
	 * Set the maximum number of undoable checkpoints maintained by buffer manager.
	 * Existing redo checkpoints are cleared and the stack of undo checkpoints
	 * will be reduced if maxUndos is less than the current setting.
	 * @param maxUndos maximum number of undo checkpoints.  A negative
	 * value restores the default value.
	 */
	public void setMaxUndos(int maxUndos) {
		synchronized (snapshotLock) {
			synchronized (this) {
				maxCheckpoints = maxUndos < 0 ? DEFAULT_CHECKPOINT_COUNT : (maxUndos + 1);
				while (checkpointHeads.size() > maxCheckpoints) {
					packCheckpoints();
				}
				disposeRedoCheckpoints();
			}
		}
	}

	/**
	 * Clear all checkpoints and re-baseline buffers
	 */
	public void clearCheckpoints() {
		synchronized (snapshotLock) {
			synchronized (this) {
				int oldMaxCheckpoints = maxCheckpoints;
				checkpoint();
				setMaxUndos(0);
				setMaxUndos(oldMaxCheckpoints);
			}
		}
	}

	/**
	 * Get the maximum number of checkpoints retained.
	 * @return int
	 */
	public int getMaxUndos() {
		return maxCheckpoints;
	}

	/**
	 * Get a reusable buffer object from cache.
	 * The oldest buffer node is removed from memory cache.
	 * @return buffer object.
	 * @throws IOException if a cache file access error occurs
	 */
	private DataBuffer getCacheBuffer() throws IOException {

		// Create new buffer if cache not fully allocated
		if (cacheSize < maxCacheSize) {
			++cacheSize;
			lowWaterMark = cacheSize;
			return new DataBuffer(cacheFile.getBufferSize());
		}

		// Use buffer from free stack if available
		if (!freeBuffers.isEmpty()) {
			--buffersOnHand;
			if (buffersOnHand < lowWaterMark) {
				lowWaterMark = buffersOnHand;
			}
			return freeBuffers.pop();
		}

		// Get oldest buffer node in cache
		BufferNode oldNode = cacheTail.prevCached;
		if (oldNode.id == HEAD) {
			// cache limit has been exceeded
			throw new IOException("Out of cache buffer space");
		}

		// Unload buffer from memory cache
		DataBuffer buf = oldNode.buffer;
		unloadCachedNode(oldNode);
		removeFromCache(oldNode);

		return buf;
	}

	/**
	 * Remove a buffer node from memory cache.
	 * @param node buffer node
	 */
	private void removeFromCache(BufferNode node) {
		if (node.buffer != null) {
			node.removeFromCache();
			node.buffer = null;

			--buffersOnHand;
			if (buffersOnHand < lowWaterMark) {
				lowWaterMark = buffersOnHand;
			}
		}
	}

	/**
	 * Return the specified node to cache with the associated buffer object.
	 * @param node node to be cached
	 * @param buf buffer object
	 */
	private void returnToCache(BufferNode node, DataBuffer buf) {
// ?? Should not happen
		if (node.buffer != null || buf == null) {
			throw new AssertException();
		}

		node.buffer = buf; // TODO: Set buffer ID
		node.addToCache(cacheHead);
		++buffersOnHand;
	}

	/**
	 * Return a reusable buffer to the cache.
	 * @param buf buffer to be returned.
	 */
	private void returnFreeBuffer(DataBuffer buf) {

		++buffersOnHand;
		freeBuffers.push(buf);
	}

	/**
	 * Stop the pre-cache thread if currently active
	 */
	private void stopPreCache() {
		synchronized (preCacheLock) {
			if (preCacheThread == null) {
				return;
			}
			if (preCacheStatus == PreCacheStatus.RUNNING) {
				preCacheThread.interrupt();
				preCacheStatus = PreCacheStatus.INTERUPTED;
			}
			try {
				// wait for pre-cache thread to finish
				preCacheLock.wait();
			}
			catch (InterruptedException e) {
				// ignore
			}
		}
	}

	/**
	 * Start pre-cache of source file if appropriate.
	 * This targets remote buffer file adapters only. 
	 */
	private void startPreCacheIfNeeded() {
		if (preCacheThread != null) {
			throw new IllegalStateException("pre-cache thread already active");
		}
		if (!(sourceFile instanceof BufferFileAdapter)) {
			return; // only pre-cache remote buffer files which utilize a BufferFileAdapter
		}
		BufferFileAdapter sourceAdapter = (BufferFileAdapter) sourceFile;
		if (!sourceAdapter.isRemote()) {
			return; // only pre-cache remote buffer files
		}
		synchronized (preCacheLock) {
			preCacheThread = new Thread(() -> {
				try {
					preCacheSourceFile();
				}
				catch (InterruptedIOException e) {
					// ignore
				}
				catch (IOException e) {
					Msg.error(BufferMgr.this, "pre-cache failure: " + e.getMessage(), e);
				}
				finally {
					synchronized (preCacheLock) {
						preCacheStatus = PreCacheStatus.STOPPED;
						preCacheThread = null;
						preCacheLock.notifyAll();
					}
				}
			});
			preCacheThread.setName("Pre-Cache");
			preCacheThread.setPriority(Thread.MIN_PRIORITY);
			preCacheThread.start();
			preCacheStatus = PreCacheStatus.RUNNING;
		}
	}

	/**
	 * Pre-cache source file into cache file.  This is intended to be run in a 
	 * dedicated thread when the source file is remote.
	 */
	private void preCacheSourceFile() throws IOException {
		if (!(sourceFile instanceof BufferFileAdapter)) {
			throw new UnsupportedOperationException("unsupported use of preCacheSourceFile");
		}
		Msg.trace(BufferMgr.this, "Pre-cache started...");
		int cacheCount = 0;
		BufferFileAdapter sourceAdapter = (BufferFileAdapter) sourceFile;
		try (InputBlockStream inputBlockStream = sourceAdapter.getInputBlockStream()) {
			BufferFileBlock block;
			while (!Thread.interrupted() && (block = inputBlockStream.readBlock()) != null) {
				DataBuffer buf = LocalBufferFile.getDataBuffer(block);
				if (buf != null && !buf.isEmpty() && preCacheBuffer(buf)) { // skip head block and empty blocks
					++cacheCount;
				}
			}
			Msg.trace(BufferMgr.this, "Pre-cache added " + cacheCount + " of " +
				sourceFile.getIndexCount() + " buffers to cache");
		}
	}

	/**
	 * Pre-cache an non-requested buffer from the sourceFile
	 * @param buf source file data buffer
	 * @throws IOException if cache file access error occurs
	 * @return true if block added to cache, false if already cached
	 */
	private synchronized boolean preCacheBuffer(DataBuffer buf) throws IOException {

		int id = buf.getId();

		BufferNode node = getCachedBufferNode(id);
		if (node != null) {
			return false; // buffer already cached
		}

		// Create new buffer node at checkpoint 0 (baseline)
		node = createNewBufferNode(id, baselineCheckpointHead, null);
		node.buffer = buf;

		// Unload node to cache file and discard node buffer
		// which does not belong to memory cache
		unloadCachedNode(node);
		node.buffer = null;

		return true;
	}

	/**
	 * Get the buffer node at the current checkpoint level.
	 * Creates node from source if necessary.
	 * @param id buffer id.
	 * @param load if true, buffer will be loaded into memory cache.
	 * @return buffer node or null if node not found
	 * @throws IOException if source or cache file access error occurs
	 */
	private BufferNode getBufferNode(int id, boolean load) throws IOException {

		BufferNode node = getCachedBufferNode(id);
		if (node == null) {

			// First time buffer has been requested - get from source file
			if (sourceFile == null) {
				throw new IOException("Invalid buffer");
			}
// ?? error handling
			DataBuffer buf = getCacheBuffer();
			try {
				sourceFile.get(buf, id); // use source buffer id as index
			}
			catch (IOException e) {
				returnFreeBuffer(buf);
				throw e;
			}

			// Create new buffer node at checkpoint 0 (baseline)
			node = createNewBufferNode(id, baselineCheckpointHead, null);

			// Add node to cache
			returnToCache(node, buf);

			return node;
		}
		else if (node.locked) {
			throw new IOException("Locked buffer");
		}

		// if requested, load from disk cache file and add node to memory cache list
		if (load) {
			loadCachedNode(node);
		}

		return node;
	}

	/**
	 * Create a new buffer node associated with the specified checkpoint list.
	 * If versionHead is null, a new buffer table entry and version list will be created.
	 * @param id buffer id
	 * @param checkpointHead head of checkpoint list
	 * @param versionHead head of buffer version list, may be null
	 * @return new buffer node
	 */
	private BufferNode createNewBufferNode(int id, BufferNode checkpointHead,
			BufferNode versionHead) {

		// Create new buffer node at checkpoint
		BufferNode node = new BufferNode(id, checkpointHead.checkpoint);

		// Add source node to checkpoint list
		node.addToCheckpoint(checkpointHead);

		// Create new buffer list for id and add to buffer table
		if (versionHead == null) {
			createNewBufferList(id, node);
		}
		else {
			node.addToVersion(versionHead);
		}

		return node;
	}

	/**
	 * Create a new buffer version list and add the specified node.
	 * @param id buffer id
	 * @param node the first buffer version to add into list
	 * @return buffer version head.
	 */
	private BufferNode createNewBufferList(int id, BufferNode node) {

		BufferNode head = new BufferNode(HEAD, -1);
		BufferNode tail = new BufferNode(TAIL, -1);
		head.nextVersion = node;
		node.prevVersion = head;
		node.nextVersion = tail;
		tail.prevVersion = node;
		bufferTable.put(id, head);

		return head;
	}

	/**
	 * Get the buffer node at the current checkpoint level.
	 * @param id buffer id.
	 * @return buffer node or null if node not found
	 */
	private BufferNode getCachedBufferNode(int id) throws IOException {
		if (bufferTable == null) {
			throw new ClosedException();
		}
		BufferNode bufListHead = (BufferNode) bufferTable.get(id);
		BufferNode node = null;
		if (bufListHead != null) {
			node = bufListHead.nextVersion;
		}
		return node;
	}

	/**
	 * Load buffer from disk cache into memory cache.
	 * @param node buffer node to be unloaded from memory cache.
	 * @throws IOException if a cache file access error occurs
	 */
	private void loadCachedNode(BufferNode node) throws IOException {
		// if requested, load from disk cache file and add node to memory cache list
		if (node.buffer == null) {
			if (node.locked || node.empty) {
				throw new IOException("Invalid or locked buffer");
			}
			returnToCache(node, cacheFile.get(getCacheBuffer(), node.diskCacheIndex));
			++cacheMisses;
		}
		else {
			if (node.prevCached.id != HEAD) {
				// Move to top of cache
				node.removeFromCache();
				node.addToCache(cacheHead);
			}
			++cacheHits;
		}
	}

	/**
	 * Unload buffer from memory cache to disk cache if needed.
	 * @param node buffer node to be unloaded from memory cache.
	 * @throws IOException if a cache file access error occurs
	 */
	private void unloadCachedNode(BufferNode node) throws IOException {

// ?? Should not happen
		if (node.buffer == null) {
			throw new AssertException();
		}

		// Ensure that old node is retained in disk cache
		if (node.diskCacheIndex < 0) {
			node.diskCacheIndex = cacheIndexProvider.allocateIndex();
			cacheFile.put(node.buffer, node.diskCacheIndex);
		}
		else if (node.isDirty) {
			// Overwrite if node is dirty
			cacheFile.put(node.buffer, node.diskCacheIndex);
		}
		node.isDirty = false;
	}

	/**
	 * Get the specified buffer.
	 * When done working with the buffer, the method releaseBuffer
	 * must be used to return it to the buffer manager.  Buffers
	 * should not be held for long periods.
	 * @param id buffer id
	 * @return buffer object, or null if buffer not found
	 * @throws IOException if source or cache file access error occurs
	 */
	public synchronized DataBuffer getBuffer(int id) throws IOException {

		if (corruptedState) {
			throw new IOException("Corrupted BufferMgr state");
		}

		BufferNode node = getBufferNode(id, true); // loads buffer into memory cache
		DataBuffer buf = node.buffer;
		if (node.empty || buf.isEmpty()) {
			throw new IOException("Invalid buffer: " + id);
		}

		// Buffers requested forUpdate are removed from cache
		if (node.checkpoint != currentCheckpoint || currentCheckpointHead == null) {
			unloadCachedNode(node);
		}
		removeFromCache(node);

		node.locked = true;
		++lockCount;

		return buf;
	}

	/**
	 * Get a new or recycled buffer.
	 * New buffer is always returned with update enabled.
	 * When done working with the buffer, the method releaseBuffer
	 * must be used to return it to the buffer manager.  Buffers
	 * should not be held for long periods.
	 * @return buffer object, or null if buffer not found
	 * @throws IOException if a cache file access error occurs
	 */
	public DataBuffer createBuffer() throws IOException {
		synchronized (snapshotLock) {
			synchronized (this) {

				if (corruptedState) {
					throw new IOException("Corrupted BufferMgr state");
				}

				int id = indexProvider.allocateIndex();
				DataBuffer buf = null;
				BufferNode node = getCachedBufferNode(id);
				if (node != null) {
					buf = node.buffer;
					node.locked = true;
					removeFromCache(node);
				}

				buf = buf != null ? buf : getCacheBuffer();
				buf.setId(id);
				buf.setDirty(true);
				buf.setEmpty(false);

				++lockCount;
				return buf;
			}
		}
	}

	/**
	 * Release buffer back to buffer manager.
	 * After invoking this method, the buffer object should not
	 * be used and all references should be dropped.
	 * @param buf data buffer
	 * @throws IOException if IO error occurs
	 */
	public void releaseBuffer(DataBuffer buf) throws IOException {

		try {
			if (buf.isDirty()) {
				releaseDirtyBuffer(buf);
			}
			else {
				releaseCleanBuffer(buf);
			}
		}
		catch (Exception e) {
			handleCorruptionException(e, "BufferMgr buffer release failed");
		}
	}

	/**
	 * Handle exception which indicates a potential corruption of the BufferMgr state
	 * @param exception exception
	 * @param errorText associated error text
	 * @throws IOException exception thrown if instance of IOException
	 */
	private void handleCorruptionException(Exception exception, String errorText)
			throws IOException {
		Msg.error(this, errorText, exception);
		corruptedState = true;
		if (exception instanceof IOException) {
			throw (IOException) exception;
		}
		if (!(exception instanceof RuntimeException)) {
			exception = new RuntimeException(errorText, exception);
		}
		throw (RuntimeException) exception;
	}

	private void releaseCleanBuffer(DataBuffer buf) throws IOException {
		synchronized (this) {
			int id = buf.getId();
			BufferNode node = getCachedBufferNode(id);

			if (node == null || !node.locked) {// verify buffer lock
				throw new AssertException();
			}

			// reintroduce unlocked buffer node into cache
			node.locked = false;
			--lockCount;
			returnToCache(node, buf);
		}
	}

	private void releaseDirtyBuffer(DataBuffer buf) throws IOException, AssertionError {
		synchronized (snapshotLock) {
			synchronized (this) {

				int id = buf.getId();
				BufferNode node = getCachedBufferNode(id);

				if (node != null && !node.locked) {
					throw new AssertException();
				}

				modifiedSinceSnapshot = true;

				// Establish current checkpoint if necessary
				if (currentCheckpointHead == null) {
					startCheckpoint();
				}

				// Create new buffer node if necessary
				if (node == null) {
					node = createNewBufferNode(id, currentCheckpointHead, null);
				}

				// Handle update of existing buffer node
				else {

					// Buffer should not be in memory cache
					if (node.buffer != null) {
						throw new AssertionError("Invalid buffer state");
					}

					// Create new buffer version if needed
					if (currentCheckpoint != node.checkpoint) {
						BufferNode head = node.prevVersion;
						if (head.id != HEAD) {
							throw new AssertException("Head expected");
						}
						node.locked = false; // unlock old node
						node = createNewBufferNode(id, currentCheckpointHead, head);
					}
				}
				buf.setDirty(false);
				node.isDirty = true;
				node.modified = true;
				node.empty = buf.isEmpty();

				// Add deleted buffer ID to free stack - node remains empty unless re-created
				if (node.empty) {
					indexProvider.freeIndex(id);
				}

				// reintroduce unlocked buffer node into cache
				node.locked = false;
				--lockCount;
				returnToCache(node, buf);
			}
		}
	}

	/**
	 * Delete buffer.
	 * DataBuffer is added to the free list for reuse.
	 * @param id buffer id
	 * @throws IOException if source or cache file access error occurs
	 */
	public void deleteBuffer(int id) throws IOException {
		synchronized (snapshotLock) {
			synchronized (this) {
				if (corruptedState) {
					throw new IOException("Corrupted BufferMgr state");
				}
				try {
					DataBuffer buf = getBuffer(id);
					buf.setEmpty(true);
					buf.setDirty(true);
					releaseBuffer(buf);
				}
				catch (Exception e) {
					handleCorruptionException(e, "BufferMgr buffer delete failed");
				}
			}
		}
	}

	/**
	 * @return true if no buffers have been updated since last checkpoint.
	 */
	public boolean atCheckpoint() {
		return currentCheckpointHead == null;
	}

	/**
	 * Completes a transaction by closing the current checkpoint.  All
	 * modified buffers since the previous invocation of this method
	 * will be contained within "transaction".
	 * The redo stack will be cleared.
	 * @return true if checkpoint successful, or false if buffers are read-only
	 */
	public boolean checkpoint() {
		synchronized (snapshotLock) {
			synchronized (this) {
				if (currentCheckpointHead == null) {
					// Nothing has been stored at current checkpoint
					return false;
				}

				if (lockCount != 0) {
					throw new AssertException(
						"Can't checkpoint with locked buffers (" + lockCount + " locks found)");
				}

				currentCheckpointHead = null;
				return true;
			}
		}
	}

	/**
	 * @return true if unsaved "buffer" changes exist.
	 * If no changes have been made, or all changes have been
	 * "undone", false will be returned.  Parameter changes
	 * are no considered.
	 */
	public synchronized boolean isChanged() {
		return currentCheckpoint != 0 || currentCheckpointHead != null || hasNonUndoableChanges;
	}

	/**
	 * Create a new checkpoint node list.
	 * The redo stack will be cleared.
	 */
	private void startCheckpoint() {

		// Clear Redo checkpoints
		disposeRedoCheckpoints();

		// Create new checkpoint
		++currentCheckpoint;
		BufferNode head = new BufferNode(HEAD, currentCheckpoint);
		BufferNode tail = new BufferNode(TAIL, currentCheckpoint);
		head.nextInCheckpoint = tail;
		tail.prevInCheckpoint = head;
		checkpointHeads.add(head);

		// Set as current checkpoint
		currentCheckpointHead = head;

		// pack old checkpoint if necessary
		packCheckpoints();
	}

	/**
	 * Indicates whether checkpoint versions are available for undo.
	 * @return true if undo is available
	 */
	public boolean hasUndoCheckpoints() {
		return checkpointHeads.size() > 1;
	}

	/**
	 * Indicates whether checkpoint versions are available for redo.
	 * @return true if redo is available
	 */
	public boolean hasRedoCheckpoints() {
		return redoCheckpointHeads.size() != 0;
	}

	/**
	 * @return number of undo-able transactions
	 */
	public int getAvailableUndoCount() {
		return checkpointHeads.size() - 1;
	}

	/**
	 * @return the number of redo-able transactions
	 */
	public int getAvailableRedoCount() {
		return redoCheckpointHeads.size();
	}

	/**
	 * Backup to previous checkpoint.  Method should not be invoked
	 * when one or more buffers are locked.
	 * @param redoable true if currrent checkpoint should be moved to redo stack
	 * @return true if successful else false
	 * @throws IOException if IO error occurs
	 */
	public boolean undo(boolean redoable) throws IOException {
		synchronized (snapshotLock) {
			synchronized (this) {

				if (lockCount != 0) {
					throw new AssertException(
						"Can't undo with locked buffers (" + lockCount + " locks found)");
				}

				int ix = checkpointHeads.size() - 1;
				if (ix < 1) {
					return false;
				}

				modifiedSinceSnapshot = true;

				// Remove current checkpoint
				BufferNode cpHead = checkpointHeads.remove(ix);

				// Process all nodes within the checkpoint list
				BufferNode node = cpHead.nextInCheckpoint;
				int srcIndexCnt = sourceFile != null ? sourceFile.getIndexCount() : 0;
				int revisedIndexCnt = indexProvider.getIndexCount();
				while (node.id != TAIL) {

					BufferNode oldVer = node.nextVersion;
					node.removeFromVersion();

					if (oldVer.prevVersion.id != HEAD) {
						throw new AssertException(); // ?? should never happen
					}

					if (oldVer.id == TAIL) {
						// Node was unknown prior to this checkpoint
						bufferTable.remove(node.id);
						if (sourceFile == null || node.id >= srcIndexCnt) {
							// Buffer was created within checkpoint - compute file truncation index
							revisedIndexCnt = Math.min(node.id, revisedIndexCnt);
						}
						else if (!node.empty) {
							// Buffer was changed from original source - free it
							indexProvider.freeIndex(node.id);
						}
					}
					else {
						if (node.empty) {
							// Node was removed within checkpoint - reallocate if appropriate
							// Double check previous checkpoint - make sure it is not empty
							if (!oldVer.empty) {
								if (!indexProvider.allocateIndex(node.id)) {
									throw new AssertException();
								}
							}
						}
						else if (oldVer.empty) {
							// Node was re-allocated within this checkpoint
							indexProvider.freeIndex(node.id);
						}
						oldVer.clearSnapshotTaken();
					}
					node = node.nextInCheckpoint;
				}
				indexProvider.truncate(revisedIndexCnt);

				if (redoable) {
					// Move checkpoint to redo list
					redoCheckpointHeads.add(cpHead);
				}
				else {
					// Elliminate checkpoint contents and redo stack
					// if not redoable
					disposeNodeList(cpHead);
					disposeRedoCheckpoints();
				}

				// Set current checkpoint
				cpHead = checkpointHeads.get(ix - 1);
				currentCheckpoint = cpHead.checkpoint;
				currentCheckpointHead = null;

				return true;
			}
		}
	}

	/**
	 * Redo next checkpoint. Method should not be invoked
	 * when one or more buffers are locked.
	 * @return true if successful else false
	 */
	public boolean redo() {
		synchronized (snapshotLock) {
			synchronized (this) {

				if (lockCount != 0) {
					throw new AssertException(
						"Can't redo with locked buffers (" + lockCount + " locks found)");
				}

				int ix = redoCheckpointHeads.size() - 1;
				if (ix < 0) {
					return false;
				}

				modifiedSinceSnapshot = true;

				// Restore checkpoint from redo stack
				// Process all nodes within the checkpoint list
				BufferNode cpHead = redoCheckpointHeads.remove(ix);
				BufferNode node = cpHead.nextInCheckpoint;
				while (node.id != TAIL) {

					// Get node
					BufferNode head = (BufferNode) bufferTable.get(node.id);
					if (head == null) {

						// Node was allocated within this checkpoint - reallocate it
						if (!indexProvider.allocateIndex(node.id)) {
							throw new AssertException();
						}
						if (node.empty) {
							indexProvider.freeIndex(node.id);
						}

						node.clearSnapshotTaken();

						// Create new buffer version list and add buffer version
						head = createNewBufferList(node.id, node);
					}
					else {
						// Node was modified within this checkpoint - insert version
						BufferNode curVer = head.nextVersion;
						if (node.empty) {
							// Node was removed within checkpoint - free it if appropriate
							// Double check previous checkpoint - make sure it is not empty
							if (!curVer.empty) {
								indexProvider.freeIndex(node.id);
							}
						}
						else if (curVer.empty) {
							// Node was re-allocated within checkpoint - reallocate it
							if (!indexProvider.allocateIndex(node.id)) {
								throw new AssertException();
							}
						}
						node.clearSnapshotTaken();
						node.addToVersion(head);
					}

					node = node.nextInCheckpoint;
				}

				// Move checkpoint to undo list
				checkpointHeads.add(cpHead);

				// Set current checkpoint
				currentCheckpoint = cpHead.checkpoint;
				currentCheckpointHead = null;

				return true;
			}
		}
	}

	/**
	 * @return true if save operation can be performed.
	 * @throws IOException if IO error occurs
	 */
	public boolean canSave() throws IOException {
		if (corruptedState) {
			return false;
		}
		if (sourceFile instanceof ManagedBufferFile) {
			return ((ManagedBufferFile) sourceFile).canSave();
		}
		return false;
	}

	/**
	 * @return true if buffers have been modified since opening or since
	 * last snapshot.
	 */
	public synchronized boolean modifiedSinceSnapshot() {
		return modifiedSinceSnapshot;
	}

	/**
	 * Generate recovery snapshot of unsaved data.
	 * @param changeSet an optional database-backed change set which reflects changes
	 * made since the last version.
	 * @param monitor task monitor
	 * @return true if snapshot successful, false if
	 * @throws IOException if IO error occurs
	 * @throws CancelledException if task monitor is cancelled
	 */
	public boolean takeRecoverySnapshot(DBChangeSet changeSet, TaskMonitor monitor)
			throws IOException, CancelledException {

		if (corruptedState) {
			throw new IOException("Corrupted BufferMgr state");
		}

		if (!(sourceFile instanceof LocalBufferFile)) {
			throw new RuntimeException("Invalid use of recovery manager");
		}

		synchronized (snapshotLock) {
			if (!canSave()) {
				// Can only handle update of existing file so we know where to put recovery files
				throw new RuntimeException(
					"Recovery snapshot only permitted for update of existing file");
			}
			if (currentCheckpointHead != null) {
				return false; // in middle of transaction
			}
			if (recoveryMgr == null) {
				recoveryMgr = new RecoveryMgr(this);
			}
			boolean success = false;
			try {
				recoveryMgr.startSnapshot(indexProvider.getIndexCount(),
					indexProvider.getFreeIndexes(), changeSet, monitor);

				//			// Save off parameter settings
				//			recoveryMgr.clearParameters();
				//			String[] names = cacheFile.getParameterNames();
				//			for (int i = 0; i < names.length; i++) {
				//				recoveryMgr.setParameter(names[i], cacheFile.getParameter(names[i]));
				//			}

				// Save off modified buffers
				int srcIndexCnt = sourceFile.getIndexCount();
				int indexCnt = indexProvider.getIndexCount();
				monitor.initialize(indexCnt);

				// Allocate working buffer
				DataBuffer buf = new DataBuffer(cacheFile.getBufferSize());

				for (int id = 0; id < indexCnt; id++) {

					monitor.checkCanceled();
					monitor.setProgress(id);

					// Check for cached buffer
					BufferNode node = null;
					boolean writeBuffer = false;

					/*
					 * Must be very careful since we would like to allow concurrent buffer
					 * 'gets' while the snapshot is in progress.  Since we must avoid locking
					 * the buffer nodes to prevent exceptions, we must copy the buffer before
					 * it is possibly reclaimed and reused by another buffer node.  Other
					 * fields concerning the snapshot mechanism within the node should remain
					 * unchanged in a read-only situation.  Buffer modifications are locked-out
					 */
					synchronized (this) {

						node = getCachedBufferNode(id);
						if (node != null) {

							if (id < srcIndexCnt && node.checkpoint == 0 && !node.modified) {
								// Buffer has not changed
								continue;
							}

							if (!node.empty) {
								if (node.buffer == null) {
									// copy buffer from disk cache
									cacheFile.get(buf, node.diskCacheIndex);
								}
								else {
									// copy buffer from cached memory buffer
									buf.copy(0, node.buffer, 0, node.buffer.length());
								}
								buf.setId(id);
								writeBuffer = true;
							}
						}
					}

					// Keep modified buffer
					if (writeBuffer) {
						recoveryMgr.putBuffer(buf, node);
					}
				}
				modifiedSinceSnapshot = false;
				success = true;
			}
			finally {
				if (recoveryMgr.isSnapshotInProgress()) {
					recoveryMgr.endSnapshot(success);
				}
				//			recoveryMgr.printStats();
			}
			return success;
		}
	}

	/**
	 * Returns the recovery changeSet data file for reading or null if one is not available.
	 * The caller must dispose of the returned file before peforming generating any new
	 * recovery snapshots.
	 * @return recovery change set buffer file
	 * @throws IOException if IO error occurs
	 */
	public LocalBufferFile getRecoveryChangeSetFile() throws IOException {
		if (recoveryMgr != null) {
			return recoveryMgr.getRecoveryChangeSetFile();
		}
		return null;
	}

	/**
	 * Immediately following instantiation of this BufferMgr, discard any pre-existing
	 * recovery snapshots.
	 */
	public void clearRecoveryFiles() {
		synchronized (snapshotLock) {
			synchronized (this) {
				if (!(sourceFile instanceof LocalBufferFile) || bufferTable == null ||
					isChanged() || recoveryMgr != null || lockCount != 0) {
					return;
				}
				new RecoveryMgr(this); // causes snapshot files to be deleted
			}
		}
	}

	/**
	 * Immediately following instatiation of this BufferMgr, attempt a unsaved data recovery.
	 * If successful, the method getRecoveryChangeSetFile should be invoked to obtain/open the
	 * changeSet data file which must be used by the application to recover the changeSet.
	 * If recovery is cancelled, this buffer manager must be disposed.
	 * since the underlying state will be corrupt.
	 * @param monitor task monitor
	 * @return true if recovery successful else false
	 * @throws IOException if IO error occurs
	 * @throws CancelledException if task monitor is cancelled
	 */
	public boolean recover(TaskMonitor monitor) throws IOException, CancelledException {
		synchronized (snapshotLock) {
			synchronized (this) {

				// Can only recover local buffer files which have not yet been modified
				if (!(sourceFile instanceof LocalBufferFile) || bufferTable == null ||
					isChanged() || recoveryMgr != null || lockCount != 0 || corruptedState) {
					return false;
				}

				recoveryMgr = new RecoveryMgr(this, monitor);

				return recoveryMgr.recovered();
			}
		}
	}

	/**
	 * Recover data from recovery file
	 * @param recoveryFile recovery file
	 * @param recoveryIndex recovery index (0 or 1) which corresponds to
	 * recoveryFile.
	 * @param monitor task monitor
	 * @throws IOException if IO error occurs
	 * @throws CancelledException if task monitor is cancelled
	 */
	synchronized void recover(RecoveryFile recoveryFile, int recoveryIndex, TaskMonitor monitor)
			throws IOException, CancelledException {

		if (corruptedState) {
			throw new IOException("Corrupted BufferMgr state");
		}

		boolean success = false;
		try {

			startCheckpoint();

			int[] bufferIndexes = recoveryFile.getBufferIndexes();
			monitor.initialize(bufferIndexes.length);

			// Ensure that all indexes are allocated
			int origIndexCount = indexProvider.getIndexCount();
			int recoveryIndexCount = recoveryFile.getIndexCount();
			if (recoveryIndexCount > origIndexCount) {
				// Allocate and free all indexes added to end of file
				int maxIndex = recoveryIndexCount - 1;
				indexProvider.allocateIndex(maxIndex);
				indexProvider.freeIndex(maxIndex);
			}

			// Recover free buffer list
			int[] freeIndexes = recoveryFile.getFreeIndexList();
			for (int i = 0; i < freeIndexes.length; i++) {
				monitor.checkCanceled();
				if (freeIndexes[i] >= origIndexCount) {
					// Newly allocated free buffer
					BufferNode node =
						createNewBufferNode(freeIndexes[i], currentCheckpointHead, null);
					node.isDirty = true;
					node.modified = true;
					node.empty = true;
				}
				else if (!indexProvider.isFree(freeIndexes[i])) {
					deleteBuffer(freeIndexes[i]);
				}
			}

//			// Recover parameters
//			cacheFile.clearParameters();
//			String[] parmNames = recoveryFile.getUserParameterNames();
//			for (int i = 0; i < parmNames.length; i++) {
//				cacheFile.setParameter(parmNames[i], recoveryFile.getUserParameter(parmNames[i]));
//			}

			// Recover modified buffers
			Arrays.sort(bufferIndexes);
			for (int i = 0; i < bufferIndexes.length; i++) {

				monitor.checkCanceled();
				monitor.setProgress(i + 1);

				// Get recovery buffer
				int index = bufferIndexes[i];
				indexProvider.allocateIndex(index);

				BufferNode node = createNewBufferNode(index, currentCheckpointHead, null);
				DataBuffer buf = getCacheBuffer();
				buf.setId(index);
				buf.setDirty(true);
				buf.setEmpty(false);

				recoveryFile.getBuffer(buf, index);

				node.isDirty = true;
				node.modified = true;
				node.empty = false;
				node.snapshotTaken[recoveryIndex] = true; // buffer already stored in recovery file

				// Add node to cache
				returnToCache(node, buf);
			}
			checkpoint();
			success = true;
		}
		finally {
			if (!success) {
				Msg.error(this, "Buffer file recover failed using: " + recoveryFile.getFile());
			}
			corruptedState = !success;
		}

	}

	/**
	 * Determine if unsaved changes can be recovered for the current BufferFile
	 * associated with the specified bfMgr.
	 * @param bfMgr buffer file manager
	 * @return true if a recover is possible
	 */
	public static boolean canRecover(BufferFileManager bfMgr) {
		int ver = bfMgr.getCurrentVersion();
		if (ver < 1) {
			return false;
		}
		LocalBufferFile bf = null;
		try {
			bf = new LocalBufferFile(bfMgr.getBufferFile(ver), true);
			return RecoveryMgr.canRecover(bf);
		}
		catch (IOException e) {
			// handled below
		}
		finally {
			if (bf != null) {
				try {
					bf.close();
				}
				catch (IOException e) {
					// we tried
				}
			}
		}
		return false;
	}

	/**
	 * Save the current set of buffers to a new version of the source buffer file.
	 * If the buffer manager was not instantiated with a source file an
	 * IllegalStateException will be thrown.
	 * @param comment if version history is maintained, this comment will be
	 * associated with the new version.
	 * @param changeSet an optional database-backed change set which reflects changes
	 * made since the last version.
	 * @param monitor a cancellable task monitor.  This method will establish the
	 * maximum progress count.
	 * @throws CancelledException if the task monitor cancelled the operation.
	 * @throws IOException if source, cache or destination file access error occurs
	 */
	public void save(String comment, DBChangeSet changeSet, TaskMonitor monitor)
			throws IOException, CancelledException {

		synchronized (snapshotLock) {
			synchronized (this) {
				if (!(sourceFile instanceof ManagedBufferFile)) {
					throw new IOException("Save not allowed");
				}

				if (corruptedState) {
					throw new IOException("Corrupted BufferMgr state");
				}

				if (lockCount != 0) {
					throw new IOException("Attempted save while buffers are locked");
				}

				if (monitor == null) {
					monitor = TaskMonitor.DUMMY;
				}

				boolean oldCancelState = monitor.isCancelEnabled();

				ManagedBufferFile outFile = null;
				monitor.setMessage("Waiting for pre-save to complete...");
				if (sourceFile instanceof LocalManagedBufferFile) {
					// Use monitor for local saves
					outFile = ((LocalManagedBufferFile) sourceFile).getSaveFile(monitor);
				}
				else {
					// Monitor not supported for remote saves
					monitor.setCancelEnabled(false);
					outFile = ((ManagedBufferFile) sourceFile).getSaveFile();
					monitor.setCancelEnabled(oldCancelState & !monitor.isCancelled());
				}
				if (outFile == null) {
					throw new IOException("Save not allowed");
				}

				boolean success = false;
				try {

					if (comment != null) {
						outFile.setVersionComment(comment);
					}

					doSave(outFile, monitor);
					monitor.setCancelEnabled(false);

					if (changeSet != null) {
						BufferFile changeFile =
							((ManagedBufferFile) sourceFile).getSaveChangeDataFile();
						if (changeFile != null) {
							monitor.setMessage("Saving change data...");
							DBHandle cfh = new DBHandle(outFile.getBufferSize());
							changeSet.write(cfh, false);
							cfh.saveAs(changeFile, true, null);
							cfh.close();
						}
					}
					monitor.setMessage("Completing file save...");
					success = true;
				}
				finally {
					((ManagedBufferFile) sourceFile).saveCompleted(success);
					monitor.setCancelEnabled(oldCancelState & !monitor.isCancelled());
				}

				setSourceFile(outFile);
			}
		}
	}

	/**
	 * Save the current set of buffers to a new buffer file.
	 * @param outFile an empty buffer file open for writing
	 * @param associateWithNewFile if true the outFile will be associated with this BufferMgr as the
	 * current source file, if false no change will be made to this BufferMgr's state and the outFile
	 * will be written and set as read-only.  The caller is responsible for disposing the outFile if
	 * this parameter is false.
	 * @param monitor a cancelable task monitor.  This method will establish the
	 * maximum progress count.
	 * @throws CancelledException if the task monitor canceled the operation.
	 * @throws IOException if source, cache or destination file access error occurs
	 */
	public void saveAs(BufferFile outFile, boolean associateWithNewFile, TaskMonitor monitor)
			throws IOException, CancelledException {
		synchronized (snapshotLock) {
			synchronized (this) {

				if (corruptedState) {
					throw new IOException("Corrupted BufferMgr state");
				}

				if (outFile.getIndexCount() != 0) {
					throw new IllegalArgumentException("Empty buffer file must be provided");
				}

				if (lockCount != 0) {
					throw new IOException("Attempted saveAs while buffers are locked");
				}

				if (monitor == null) {
					monitor = TaskMonitor.DUMMY;
				}

				int indexCnt = indexProvider.getIndexCount();
				monitor.initialize(indexCnt);

				boolean success = false;
				try {
					doSave(outFile, monitor);
					monitor.setCancelEnabled(false);
					monitor.setMessage("Completing file save...");
					outFile.setReadOnly();
					success = true;
				}
				finally {
					if (!success) {
						outFile.delete();
					}
					monitor.setCancelEnabled(true);
				}
				if (associateWithNewFile) {
					setSourceFile(outFile);
				}
			}
		}
	}

	/**
	 * Write all changes to the specified outFile
	 * @param outFile output buffer file
	 * @param monitor task monitor
	 * @throws IOException if IO error occurs
	 * @throws CancelledException thrown if task cancelled
	 */
	private void doSave(BufferFile outFile, TaskMonitor monitor)
			throws IOException, CancelledException {
		int indexCnt = indexProvider.getIndexCount();
		int preSaveCnt = outFile.getIndexCount();

		if (monitor == null) {
			monitor = TaskMonitor.DUMMY;
		}
		monitor.initialize(indexCnt);
		monitor.setMessage("Saving file...");

		// Determine number of buffers to be written (required for remote stream transfer)
		// Count non-empty buffers which have been created or modified
		// Empty buffers will be flushed when outFile is closed
		int bufCount = 0;
		for (int id = 0; id < indexCnt; id++) {
			monitor.checkCanceled();
			BufferNode node = getCachedBufferNode(id);
			if (node != null) {
				// check nod which resides in cache
				if (!node.empty && (id >= preSaveCnt || node.checkpoint != 0 || node.modified)) {
					++bufCount;
				}
			}
			else if (id >= preSaveCnt && !indexProvider.isFree(id)) {
				// node not in cache, must be copied if not empty
				// will cause buffer to be cached for use during output below
				DataBuffer buf = getBuffer(id); // will add to cache for use during output below
				if (buf != null) {
					++bufCount;
					releaseBuffer(buf);
				}
			}
		}

		// write/update all non-empty buffers
		try (OutputBlockStream out = LocalBufferFile.getOutputBlockStream(outFile, bufCount)) {
			for (int id = 0; id < indexCnt; id++) {
				monitor.checkCanceled();
				monitor.setProgress(id);

				// get buffer node from cache
				// if not contained within cache it does not need to be stored
				BufferNode node = getCachedBufferNode(id);
				if (node != null) {
					if (!node.empty &&
						(id >= preSaveCnt || node.checkpoint != 0 || node.modified)) {
						loadCachedNode(node);
						BufferFileBlock block =
							LocalBufferFile.getBufferFileBlock(node.buffer, bufferSize);
						out.writeBlock(block);
					}
				}
			}
		}

		// Set free ID list for output file
		// It is important that this is done after the streaming is complete
		// so that the changeMap and free buffers are updated properly.
		outFile.setFreeIndexes(indexProvider.getFreeIndexes());

		// Copy file parameters from cache file
		String[] parmNames = cacheFile.getParameterNames();
		for (int i = 0; i < parmNames.length; i++) {
			String name = parmNames[i];
			outFile.setParameter(name, cacheFile.getParameter(name));
		}
	}

	private void setSourceFile(BufferFile newFile) {

		// Close buffer file
		if (sourceFile != null) {
			sourceFile.dispose();
			sourceFile = null;
		}

		// Switch buffer manager to use new buffer file
		int tempMaxCheckpoints = this.maxCheckpoints;
		setMaxUndos(0); // pack all versions into baseline checkpoint
		currentCheckpointHead = null; // force checkpoint on next update
		setMaxUndos(tempMaxCheckpoints); // restore max checkpoint count

		// Set all baseline nodes as unmodified
		BufferNode node = baselineCheckpointHead.nextInCheckpoint;
		while (node.id != TAIL) {
			node.modified = false;
			node.checkpoint = 0;
			node = node.nextInCheckpoint;
		}
		currentCheckpoint = 0;
		hasNonUndoableChanges = false;
		sourceFile = newFile;

		if (recoveryMgr != null) {
			recoveryMgr.clear();
		}
	}

	public long getCacheHits() {
		return cacheHits;
	}

	public long getCacheMisses() {
		return cacheMisses;
	}

	public int getLowBufferCount() {
		return lowWaterMark;
	}

	public void resetCacheStatistics() {
		cacheHits = 0;
		cacheMisses = 0;
		lowWaterMark = cacheSize;
	}

	public String getStatusInfo() {
		StringBuffer buf = new StringBuffer();
		if (corruptedState) {
			buf.append("BufferMgr is Corrupt!\n");
		}
		buf.append("Checkpoints: ");
		buf.append(currentCheckpoint);
		if (sourceFile != null) {
			buf.append("\n Source file: ");
			buf.append(sourceFile.toString());
		}
		buf.append("\n Cache file: ");
		buf.append(cacheFile.toString());
		buf.append("\n Buffer size: ");
		buf.append(bufferSize);
		buf.append("\n Cache size: ");
		buf.append(cacheSize);
		buf.append("\n Cache hits: ");
		buf.append(cacheHits);
		buf.append("\n Cache misses: ");
		buf.append(cacheMisses);
		buf.append("\n Locked buffers: ");
		buf.append(lockCount);
		buf.append("\n Low water buffer count: ");
		buf.append(lowWaterMark);
		buf.append("\n");
		return buf.toString();
	}

	public int getAllocatedBufferCount() {
		return indexProvider.getIndexCount() - indexProvider.getFreeIndexCount();
	}

	public int getFreeBufferCount() {
		return indexProvider.getFreeIndexCount();
	}

	public static void cleanupOldCacheFiles() {
		File tmpDir = new File(System.getProperty("java.io.tmpdir"));
		File[] cacheFiles =
			tmpDir.listFiles(new BufferFileFilter(CACHE_FILE_PREFIX, CACHE_FILE_EXT));
		if (cacheFiles == null) {
			return;
		}
		for (int i = 0; i < cacheFiles.length; i++) {
			cacheFiles[i].delete();
		}
	}
}
