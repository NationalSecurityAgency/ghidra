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
import java.util.*;

import ghidra.util.datastruct.IntIntHashtable;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.NoValueException;

/**
 * <code>VersionFile</code> records buffer changes and parameters necessary to reconstruct an
 * older version of a LocalBufferFile.
 */
class RecoveryFile {

	private static final int MAGIC_NUMBER = 0x38DE7654;

	private static final int VALID = 1;
	private static final int INVALID = 0;

	// Version file parameter keys
	private static final String RECOVERY_PARM_PREFIX = "~RF.";
	private static final String MAGIC_NUMBER_PARM = RECOVERY_PARM_PREFIX + "VersionFile";
	private static final String SRC_FILE_ID_HI_PARM = RECOVERY_PARM_PREFIX + "SrcIdHi";
	private static final String SRC_FILE_ID_LOW_PARM = RECOVERY_PARM_PREFIX + "SrcIdLow";
	private static final String IS_VALID_PARM = RECOVERY_PARM_PREFIX + "OrigBufCnt";
	private static final String TIMESTAMP_HI_PARM = RECOVERY_PARM_PREFIX + "TimestampHi";
	private static final String TIMESTAMP_LOW_PARM = RECOVERY_PARM_PREFIX + "TimestampLow";
	private static final String MAP_BUFFER_INDEX_PARM = RECOVERY_PARM_PREFIX + "MapIndex";
	private static final String FREE_LIST_BUFFER_INDEX_PARM =
		RECOVERY_PARM_PREFIX + "FreeListIndex";
	private static final String FREE_LIST_SIZE_PARM = RECOVERY_PARM_PREFIX + "FreeListSize";
	private static final String INDEX_COUNT_PARM = RECOVERY_PARM_PREFIX + "BufferCount";

	// Exception messages
	private static final String BAD_FREE_LIST = "Recovery file is corrupt - bad free list";
	private static final String BAD_BUFFER_MAP = "Recovery file is corrupt - bad buffer map";

	// Used by both the Buffer Map and Free Index List
	private static final int NEXT_BUFFER_INDEX_OFFSET = 0;
	private static final int FIRST_ENTRY_OFFSET = 4;

	private boolean readOnly;

	private boolean valid = false;
	private long timestamp;
	private boolean modified = false;
	private LocalBufferFile recoveryFile;
	private long srcFileId;
	private int indexCnt;
	private IndexProvider vfIndexProvider;
	private int freeListIndex = -1;
	private int mapIndex = -1;

	private int[] freeIndexes; // sorted to facilitate binary search

	// maps buffer IDs to version file buffer indexes
	private IntIntHashtable bufferIndexMap = new IntIntHashtable();

	/**
	 * Construct a new recovery file for update/output.
	 * @param srcBf the original source buffer file to which this file applies.
	 * @param rfile version buffer file to be updated/created
	 * @param create true to create the file
	 * @throws IOException if the file already exists or an IO error occurs
	 */
	RecoveryFile(LocalBufferFile srcBf, File rfile, boolean create) throws IOException {

		readOnly = false;

		if (create) {
			indexCnt = srcBf.getIndexCount();

			recoveryFile = new LocalBufferFile(rfile, srcBf.getBufferSize());

			// Save magic number for version file
			recoveryFile.setParameter(MAGIC_NUMBER_PARM, MAGIC_NUMBER);

			// Mark as invalid
			recoveryFile.setParameter(IS_VALID_PARM, INVALID);

			// Save original and source file ID as user parameter values
			srcFileId = srcBf.getFileId();
			recoveryFile.setParameter(SRC_FILE_ID_HI_PARM, (int) (srcFileId >>> 32));
			recoveryFile.setParameter(SRC_FILE_ID_LOW_PARM, (int) (srcFileId & 0xffffffffL));

			vfIndexProvider = new IndexProvider();

			modified = true;
		}
		else {
			recoveryFile = new LocalBufferFile(rfile, false);

			valid = (recoveryFile.getParameter(IS_VALID_PARM) == VALID);
			if (!valid) {
				throw new IOException("Can not update invalid recovery file");
			}

			parseFile();

			if (srcFileId != srcBf.getFileId()) {
				throw new IOException("Recovery file not associated with source file");
			}

			vfIndexProvider =
				new IndexProvider(recoveryFile.getIndexCount(), recoveryFile.getFreeIndexes());
		}

	}

	/**
	 * Construct a read-only recovery file
	 * @param srcBf the original source buffer file to which this file applies.
	 * @param rfile version buffer file to be updated/created
	 * @throws IOException if the file already exists or an IO error occurs
	 */
	RecoveryFile(LocalBufferFile srcBf, File rfile) throws IOException {
		recoveryFile = new LocalBufferFile(rfile, true);
		readOnly = true;
		parseFile();
		valid =
			(recoveryFile.getParameter(IS_VALID_PARM) == VALID && srcFileId == srcBf.getFileId());
	}

	private void setModified() {
		if (valid) {
			recoveryFile.setParameter(IS_VALID_PARM, INVALID);
			valid = false;
			modified = true;
		}
	}

	File getFile() {
		return recoveryFile.getFile();
	}

	boolean isValid() {
		return valid;
	}

	long getTimestamp() {
		return timestamp;
	}

	void close() throws IOException {

		if (recoveryFile == null) {
			return;
		}

		if (!readOnly && modified && !recoveryFile.isReadOnly()) {
			saveBufferMap();
			saveFreeIndexList();
			recoveryFile.setParameter(INDEX_COUNT_PARM, indexCnt);
			recoveryFile.setFreeIndexes(vfIndexProvider.getFreeIndexes());

			long t = (new Date()).getTime();
			recoveryFile.setParameter(TIMESTAMP_HI_PARM, (int) (t >>> 32));
			recoveryFile.setParameter(TIMESTAMP_LOW_PARM, (int) (t & 0xffffffffL));

			recoveryFile.setParameter(IS_VALID_PARM, VALID); // mark as valid
		}
		recoveryFile.close();
		recoveryFile = null;
	}

	private void parseFile() throws IOException {

		try {
			if (MAGIC_NUMBER != recoveryFile.getParameter(MAGIC_NUMBER_PARM)) {
				throw new IOException("Invalid recovery file");
			}

			try {
				timestamp = ((long) recoveryFile.getParameter(TIMESTAMP_HI_PARM) << 32) |
					(recoveryFile.getParameter(TIMESTAMP_LOW_PARM) & 0xffffffffL);
			}
			catch (NoSuchElementException e) {
				// Not as good - better than nothing
				timestamp = recoveryFile.getFile().lastModified();
			}

			srcFileId = ((long) recoveryFile.getParameter(SRC_FILE_ID_HI_PARM) << 32) |
				(recoveryFile.getParameter(SRC_FILE_ID_LOW_PARM) & 0xffffffffL);

			indexCnt = recoveryFile.getParameter(INDEX_COUNT_PARM);

			readBufferMap();

			readFreeIndexList();

		}
		catch (NoSuchElementException e) {
			throw new IOException("Corrupt recovery file");
		}

	}

	private void saveBufferMap() throws IOException {

		DataBuffer buf = new DataBuffer(recoveryFile.getBufferSize());

		if (mapIndex < 0) {
			mapIndex = vfIndexProvider.allocateIndex();
			buf.setId(mapIndex);
			buf.putInt(NEXT_BUFFER_INDEX_OFFSET, -1);
			recoveryFile.setParameter(MAP_BUFFER_INDEX_PARM, mapIndex);
		}
		else {
			recoveryFile.get(buf, mapIndex);
		}

		int maxOffset = (recoveryFile.getBufferSize() - 8) & ~0x07;
		int offset = FIRST_ENTRY_OFFSET;

		// Save new map entries
		int thisIndex = mapIndex;
		int[] realIndexes = bufferIndexMap.getKeys();
		for (int i = 0; i <= realIndexes.length; i++) {

			if (offset > maxOffset) {

				boolean newBuf = false;
				int nextIndex = buf.getInt(NEXT_BUFFER_INDEX_OFFSET);
				if (nextIndex < 0) {
					nextIndex = vfIndexProvider.allocateIndex();
					newBuf = true;
				}

				buf.putInt(NEXT_BUFFER_INDEX_OFFSET, nextIndex);
				recoveryFile.put(buf, thisIndex);

				thisIndex = nextIndex;
				if (newBuf) {
					buf.setId(thisIndex);
					buf.putInt(NEXT_BUFFER_INDEX_OFFSET, -1);
				}
				else {
					recoveryFile.get(buf, thisIndex);
				}

				offset = FIRST_ENTRY_OFFSET;
			}

			// Save map entry as single integer
			if (i == realIndexes.length) {
				buf.putInt(offset, -1);
			}
			else {
				try {
					offset = buf.putInt(offset, realIndexes[i]);
					offset = buf.putInt(offset, bufferIndexMap.get(realIndexes[i]));
				}
				catch (NoValueException e) {
					throw new AssertException();
				}
			}
		}

		// Make sure last buffer is saved
		recoveryFile.put(buf, thisIndex);
	}

	private void readBufferMap() throws NoSuchElementException, IOException {

		mapIndex = recoveryFile.getParameter(MAP_BUFFER_INDEX_PARM);

		int maxOffset = (recoveryFile.getBufferSize() - 8) & ~0x07;

		int thisIndex = mapIndex;
		DataBuffer mapBuffer = new DataBuffer();
		recoveryFile.get(mapBuffer, thisIndex);
		if (mapBuffer.isEmpty()) {
			throw new IOException(BAD_BUFFER_MAP);
		}

		int nextMapEntryOffset = FIRST_ENTRY_OFFSET;

		while (true) {
			if (nextMapEntryOffset > maxOffset) {
				// Get next map buffer
				thisIndex = mapBuffer.getInt(NEXT_BUFFER_INDEX_OFFSET);
				recoveryFile.get(mapBuffer, thisIndex);
				if (mapBuffer.isEmpty()) {
					throw new IOException(BAD_BUFFER_MAP);
				}
				nextMapEntryOffset = FIRST_ENTRY_OFFSET;
			}

			// Read map entry - end of list signified by -1
			int realIndex = mapBuffer.getInt(nextMapEntryOffset);
			if (realIndex < 0) {
				return;
			}
			nextMapEntryOffset += 4;
			int recoveryIndex = mapBuffer.getInt(nextMapEntryOffset);
			nextMapEntryOffset += 4;
			bufferIndexMap.put(realIndex, recoveryIndex);
		}
	}

	private void saveFreeIndexList() throws IOException {

		DataBuffer buf = new DataBuffer(recoveryFile.getBufferSize());
		if (freeListIndex < 0) {
			freeListIndex = vfIndexProvider.allocateIndex();
			buf.setId(freeListIndex);
			buf.putInt(NEXT_BUFFER_INDEX_OFFSET, -1);
			recoveryFile.setParameter(FREE_LIST_BUFFER_INDEX_PARM, freeListIndex);
		}
		else {
			recoveryFile.get(buf, freeListIndex);
		}
		recoveryFile.setParameter(FREE_LIST_SIZE_PARM, freeIndexes.length);

		int maxOffset = (recoveryFile.getBufferSize() - 4) & ~0x03;
		int offset = FIRST_ENTRY_OFFSET;

		// Save freeIndexes entries
		int thisIndex = freeListIndex;
		for (int i = 0; i <= freeIndexes.length; i++) {

			if (offset > maxOffset) {

				boolean newBuf = false;
				int nextIndex = buf.getInt(NEXT_BUFFER_INDEX_OFFSET);
				if (nextIndex < 0) {
					nextIndex = vfIndexProvider.allocateIndex();
					newBuf = true;
				}

				buf.putInt(NEXT_BUFFER_INDEX_OFFSET, nextIndex);
				recoveryFile.put(buf, thisIndex);

				thisIndex = nextIndex;
				if (newBuf) {
					buf.setId(thisIndex);
					buf.putInt(NEXT_BUFFER_INDEX_OFFSET, -1);
				}
				else {
					recoveryFile.get(buf, thisIndex);
				}

				offset = FIRST_ENTRY_OFFSET;
			}

			// Save list entry as single integer
			int val = (i == freeIndexes.length ? -1 : freeIndexes[i]);
			offset = buf.putInt(offset, val);
		}

		// Make sure last buffer is saved
		recoveryFile.put(buf, thisIndex);
	}

	private void readFreeIndexList() throws NoSuchElementException, IOException {

		freeListIndex = recoveryFile.getParameter(FREE_LIST_BUFFER_INDEX_PARM);

		int size = recoveryFile.getParameter(FREE_LIST_SIZE_PARM);
		freeIndexes = new int[size];

		int maxOffset = (recoveryFile.getBufferSize() - 4) & ~0x03;

		int thisIndex = freeListIndex;
		DataBuffer listBuffer = new DataBuffer();
		recoveryFile.get(listBuffer, thisIndex);
		if (listBuffer.isEmpty()) {
			throw new IOException(BAD_FREE_LIST);
		}
		int offset = FIRST_ENTRY_OFFSET;
		int entryIx = 0;

		while (true) {
			if (offset > maxOffset) {
				// Get next list buffer
				thisIndex = listBuffer.getInt(NEXT_BUFFER_INDEX_OFFSET);
				recoveryFile.get(listBuffer, thisIndex);
				if (listBuffer.isEmpty()) {
					throw new IOException(BAD_FREE_LIST);
				}
				offset = FIRST_ENTRY_OFFSET;
			}

			// Read entry - end of list signified by -1
			int origIndex = listBuffer.getInt(offset);
			if (origIndex < 0) {
				break;
			}
			if (entryIx == size) {
				throw new IOException(BAD_FREE_LIST);
			}
			offset += 4;
			freeIndexes[entryIx++] = origIndex;
		}
		if (entryIx != size) {
			throw new IOException(BAD_FREE_LIST);
		}
		Arrays.sort(freeIndexes);
	}

	/**
	 * Set the current index count for the file
	 * @param newIndexCount the count
	 */
	void setIndexCount(int newIndexCount) {
		setModified();
		for (int index = indexCnt; index < newIndexCount; index++) {
			removeBuffer(index);
		}
		indexCnt = newIndexCount;
	}

	/**
	 * Returns the index count for the file
	 * @return the count
	 */
	int getIndexCount() {
		return indexCnt;
	}

	/**
	 * Set the free index list
	 * @param freeIndexes the indexes
	 */
	void setFreeIndexList(int[] freeIndexes) {
		setModified();
		this.freeIndexes = freeIndexes.clone();
		Arrays.sort(this.freeIndexes);
		for (int index : freeIndexes) {
			removeBuffer(index);
		}
	}

	/**
	 * Returns the list of free indexes associated with the original buffer file.
	 * @return the indexes
	 */
	int[] getFreeIndexList() {
		return freeIndexes;
	}

	/**
	 * Store buffer which has been modified in the target.
	 * @param buf modified buffer
	 * @throws IOException if an IO error occurs
	 */
	void putBuffer(DataBuffer buf) throws IOException {
		if (recoveryFile == null) {
			throw new IOException("Version file is closed");
		}
		if (readOnly) {
			throw new IOException("Version file is read-only");
		}
		setModified();
		int vfIndex;
		int id = buf.getId();
		try {
			vfIndex = bufferIndexMap.get(id);
		}
		catch (NoValueException e) {
			vfIndex = vfIndexProvider.allocateIndex();
			bufferIndexMap.put(id, vfIndex);
		}
		recoveryFile.put(buf, vfIndex);
	}

	/**
	 * Remove a buffer previously stored to the snapshot
	 * by removing it from the map.  It is OK to invoke
	 * this method for an index whose buffer was never
	 * put into this file.
	 * @param id buffer ID
	 */
	void removeBuffer(int id) {
		setModified();
		try {
			int vfIndex = bufferIndexMap.remove(id);
			vfIndexProvider.freeIndex(vfIndex);
		}
		catch (NoValueException e) {
			// ignore?
		}
	}

	/**
	 * Get modified buffer associated with the specified storage index in the
	 * original file.
	 * @param buf data buffer
	 * @param id buffer ID
	 * @return data buffer or null if buffer has not been modified
	 * @throws IOException if an IO error occurs
	 */
	DataBuffer getBuffer(DataBuffer buf, int id) throws IOException {
		if (recoveryFile == null) {
			throw new IOException("Version file is closed");
		}
		int vfIndex;
		try {
			vfIndex = bufferIndexMap.get(id);
		}
		catch (NoValueException e) {
			return null;
		}
		recoveryFile.get(buf, vfIndex);
		return buf;
	}

	/**
	 * Returns list of buffer indexes stored within this file.
	 * These indexes reflect those buffers which have been modified and stored.
	 * @return the indexes
	 */
	int[] getBufferIndexes() {
		return bufferIndexMap.getKeys();
	}

	/**
	 * Returns file ID for original source buffer file which may be produced with this version file.
	 * @return the id
	 */
	long getSourceFileID() {
		return srcFileId;
	}

	/**
	 * Returns a list of parameters defined within the original buffer file.
	 * @return the names
	 * @throws IOException if the recovery file is null
	 */
	String[] getUserParameterNames() throws IOException {
		if (recoveryFile == null) {
			throw new IOException("Version file is closed");
		}
		String[] allNames = recoveryFile.getParameterNames();
		ArrayList<String> list = new ArrayList<>();
		for (String name : allNames) {
			if (!name.startsWith(RECOVERY_PARM_PREFIX)) {
				list.add(name);
			}
		}
		String[] names = new String[list.size()];
		list.toArray(names);
		return names;
	}

	/**
	 * Get a parameter value associated with the original buffer file.
	 * @param name parameter name
	 * @return parameter value
	 * @throws IOException if the recovery file is null
	 */
	int getParameter(String name) throws IOException {
		if (recoveryFile == null) {
			throw new IOException("Version file is closed");
		}
		return recoveryFile.getParameter(name);
	}

	/**
	 * Clear all user parameters
	 */
	void clearParameters() {
		setModified();

		// Remember recovery parameters
		String[] allNames = recoveryFile.getParameterNames();
		Hashtable<String, Integer> recoveryProps = new Hashtable<>();
		for (String name : allNames) {
			if (name.startsWith(RECOVERY_PARM_PREFIX)) {
				recoveryProps.put(name, recoveryFile.getParameter(name));
			}
		}

		// Clear all parameters
		recoveryFile.clearParameters();

		// Restore recovery parameters
		Iterator<String> iter = recoveryProps.keySet().iterator();
		while (iter.hasNext()) {
			String name = iter.next();
			recoveryFile.setParameter(
				name, recoveryProps.get(name).intValue());
		}
	}

	/**
	 * Set user parameter
	 * @param name the name
	 * @param value the value
	 */
	void setParameter(String name, int value) {
		setModified();
		recoveryFile.setParameter(name, value);
	}

}
