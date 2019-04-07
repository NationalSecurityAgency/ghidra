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

import ghidra.util.datastruct.IntArrayList;
import ghidra.util.datastruct.IntIntHashtable;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.NoValueException;

import java.io.File;
import java.io.IOException;
import java.util.*;

/**
 * <code>VersionFile</code> records buffer changes and parameters necessary to reconstruct an
 * older version of a LocalBufferFile.
 */
class VersionFile {

	private static final int MAGIC_NUMBER = 0x382D3435;

	// Version file parameter keys
	private static final String VERSION_PARM_PREFIX = "~VF.";
	private static final String MAGIC_NUMBER_PARM = VERSION_PARM_PREFIX + "VersionFile";
	private static final String ORIGINAL_FILE_ID_HI_PARM = VERSION_PARM_PREFIX + "OriginalIdHi";
	private static final String ORIGINAL_FILE_ID_LOW_PARM = VERSION_PARM_PREFIX + "OriginalIdLow";
	private static final String TARGET_FILE_ID_HI_PARM = VERSION_PARM_PREFIX + "TargetIdHi";
	private static final String TARGET_FILE_ID_LOW_PARM = VERSION_PARM_PREFIX + "TargetIdLow";
	private static final String ORIGINAL_BUFFER_COUNT_PARM = VERSION_PARM_PREFIX + "OrigBufCnt";
	private static final String MAP_BUFFER_INDEX_PARM = VERSION_PARM_PREFIX + "MapIndex";
	private static final String FREE_LIST_BUFFER_INDEX_PARM = VERSION_PARM_PREFIX + "FreeListIndex";
	private static final String FREE_LIST_SIZE_PARM = VERSION_PARM_PREFIX + "FreeListSize";
	
	// Exception messages
	private static final String BAD_FREE_LIST = "Version file is corrupt - bad free list";
	private static final String BAD_BUFFER_MAP = "Version file is corrupt - bad buffer map";
	
	// Used by both the Buffer Map and Free Index List
	private static final int NEXT_BUFFER_INDEX_OFFSET = 0;
	private static final int FIRST_ENTRY_OFFSET = 4;
	private static final int BUFFER_MAP_ENTRY_SIZE = 8;
	private static final int FREE_LIST_ENTRY_SIZE = 4;
	
	private File file;
	private long lastModified;
	private boolean readOnly;
	
	private int bufferSize;
	private int originalBufCount;
	private int initialBufCount;
	
	private BufferFile versionFile;
	private long targetFileId;
	private long originalFileId;
	private IndexProvider vfIndexProvider;
	private int[] freeIndexes; // sorted to facilitate binary search
	
	// maps buffer IDs to version file buffer indexes
	private IntIntHashtable bufferIndexMap;
	private IntArrayList newMapIds;
	private DataBuffer lastMapBuffer;
	private int lastMapIndex;
	private int nextMapEntryOffset;

	/**
	 * Construct a new version file for output.  
	 * @param originalBf the original buffer file which is to be reconstructed
	 * from this version file.
	 * @param targetBf the buffer file to which this version file will be applied.
	 * @param vfile version buffer file to be created
	 * @throws IOException if vfile already exists or an IO error occurs
	 */
	VersionFile(LocalBufferFile originalBf, LocalBufferFile targetBf, File vfile) throws IOException {
		
		bufferSize = originalBf.getBufferSize();
		originalBufCount = originalBf.getIndexCount();
		initialBufCount = 0; // new file
		
		file = vfile;
		readOnly = false;
		versionFile = new LocalBufferFile(vfile, bufferSize);
		vfIndexProvider = new IndexProvider();
		
		// Save magic number for version file
		versionFile.setParameter(MAGIC_NUMBER_PARM, MAGIC_NUMBER);
		
		// Save original and target file IDs as user paramater values
		originalFileId = originalBf.getFileId();
		versionFile.setParameter(ORIGINAL_FILE_ID_HI_PARM, (int)(originalFileId >> 32));
		versionFile.setParameter(ORIGINAL_FILE_ID_LOW_PARM, (int)(originalFileId & 0xffffffffL));
		targetFileId = targetBf.getFileId();
		
		// Save original buffer count
		versionFile.setParameter(ORIGINAL_BUFFER_COUNT_PARM, originalBufCount);
		
		// Create first map buffer (buffer ID is same as index)
		bufferIndexMap = new IntIntHashtable();
		newMapIds = new IntArrayList();
		lastMapBuffer = new DataBuffer(bufferSize);
		lastMapIndex = vfIndexProvider.allocateIndex();
		lastMapBuffer.setId(lastMapIndex);
		lastMapBuffer.putInt(NEXT_BUFFER_INDEX_OFFSET, -1);
		lastMapBuffer.putInt(FIRST_ENTRY_OFFSET, -1);
		nextMapEntryOffset = FIRST_ENTRY_OFFSET;
		versionFile.put(lastMapBuffer, lastMapIndex);
		versionFile.setParameter(MAP_BUFFER_INDEX_PARM, lastMapIndex);
		
		// Save original free list
		freeIndexes = originalBf.getFreeIndexes();
		Arrays.sort(freeIndexes);
		int freeListIndex = saveFreeIndexList();
		versionFile.setParameter(FREE_LIST_BUFFER_INDEX_PARM, freeListIndex);
		versionFile.setParameter(FREE_LIST_SIZE_PARM, freeIndexes.length);
		
		// Copy original parameter values
		String[] parmNames = originalBf.getParameterNames();
		for (int i = 0; i < parmNames.length; i++) {
			String name = parmNames[i];
			versionFile.setParameter(name, originalBf.getParameter(name));
		}
		
	}
	
	/**
	 * Construct a read-only version file.
	 * @param vfile an existing version file
	 * @throws IOException
	 */
	VersionFile(File vfile) throws IOException {
		file = vfile;
		readOnly = true;
		open();
	}
	
	/**
	 * Construct a read-only version file.
	 * @param versionFile an existing version file open read-only
	 * @throws IOException
	 */
	VersionFile(BufferFile versionFile) throws IOException {
		if (!versionFile.isReadOnly()) {
			throw new AssertException("Read-only buffer file expected");
		}
		readOnly = true;
		this.versionFile = versionFile;
		bufferSize = versionFile.getBufferSize();
		initialBufCount = versionFile.getIndexCount();
	}
	
	/**
	 * Abort the creation/update of this version file.
	 * This method should be invoked in place of close on a failure condition.
	 * An attempt is made to restore the version file to its initial state
	 * or remove it if it was new.
	 * @throws IOException
	 */
	void abort() throws IOException {
		
		if (versionFile == null)
			return;
		
		if (readOnly) {
			versionFile.close();
		}		
		else if (initialBufCount > 0) {
			LocalBufferFile updateVerFile = (LocalBufferFile)versionFile;
			updateVerFile.truncate(initialBufCount);
			updateVerFile.close();
		}
		else {
			versionFile.delete();
		}
		versionFile = null;
		file = null;
	}
	
	/**
	 * Close the version file.
	 */
	void close() throws IOException {
	
		if (versionFile == null)
			return;
			
		if (!readOnly) {

			if (!versionFile.isReadOnly()) {
				updateBufferMap();
			}
			
			// Set target file ID
			versionFile.setParameter(TARGET_FILE_ID_HI_PARM, (int)(targetFileId >> 32));
			versionFile.setParameter(TARGET_FILE_ID_LOW_PARM, (int)(targetFileId & 0xffffffffL));
		}
		versionFile.close();
		versionFile = null;	
		
		if (!readOnly) {
			lastModified = file.lastModified();
		}
	}
	
	/**
	 * Reopen version file as read-only
	 * @throws IOException
	 */
	void open() throws IOException {
		if (versionFile != null) {
			return;
		}
		if (file == null) {
			throw new IOException("Version file has been aborted");	
		}	
		readOnly = true;
		versionFile = new LocalBufferFile(file, true);
		bufferSize = versionFile.getBufferSize();
		initialBufCount = versionFile.getIndexCount();
		
		boolean goodFile = false;
		
		try {
			if (versionFile.getParameter(MAGIC_NUMBER_PARM) == MAGIC_NUMBER) {
				goodFile = true;
			}
		} catch (NoSuchElementException e1) {
		}
		if (!goodFile) {
			throw new IOException("Corrupt version file");
		}
		
		long mod = file.lastModified();
		if (mod != lastModified) {
			boolean success = false;
			try {
				parseFile();
				success = true;
			}
			finally {
				if (!success) {
					try {
						close();
					} catch (IOException e) {}		
				}
			}
			lastModified = mod;	
		}
	}
	
	private void parseFile() throws IOException {
		
		try {
			originalBufCount = versionFile.getParameter(ORIGINAL_BUFFER_COUNT_PARM);
			
			originalFileId = ((long)versionFile.getParameter(ORIGINAL_FILE_ID_HI_PARM) << 32) |
				(versionFile.getParameter(ORIGINAL_FILE_ID_LOW_PARM) & 0xffffffffL);
				
			targetFileId = ((long)versionFile.getParameter(TARGET_FILE_ID_HI_PARM) << 32) |
				(versionFile.getParameter(TARGET_FILE_ID_LOW_PARM) & 0xffffffffL);
				
			readBufferMap(versionFile.getParameter(MAP_BUFFER_INDEX_PARM));
			
			readFreeIndexList(versionFile.getParameter(FREE_LIST_BUFFER_INDEX_PARM),
				versionFile.getParameter(FREE_LIST_SIZE_PARM));
		
		} catch (NoSuchElementException e) {
			throw new IOException("Corrupt version file");
		}

	}
	
	private void updateBufferMap() throws IOException {

		int maxOffset = bufferSize - BUFFER_MAP_ENTRY_SIZE;
		
		// Save new map entries
		int cnt = newMapIds.size();
		for (int i = 0; i < cnt; i++) {
			
			int origIndex = newMapIds.get(i);
			int verIndex;
			try {
				verIndex = bufferIndexMap.get(origIndex);
			} catch (NoValueException e) {
				throw new AssertException();
			}

			if (nextMapEntryOffset > maxOffset) {
				int nextIndex = vfIndexProvider.allocateIndex();
				lastMapBuffer.putInt(NEXT_BUFFER_INDEX_OFFSET, nextIndex);
				versionFile.put(lastMapBuffer, lastMapIndex);

				nextMapEntryOffset = FIRST_ENTRY_OFFSET;
				lastMapIndex = nextIndex;
				lastMapBuffer.setId(lastMapIndex);
			}
			
			// Save map entry as single integer
			nextMapEntryOffset = lastMapBuffer.putInt(nextMapEntryOffset, origIndex);
			nextMapEntryOffset = lastMapBuffer.putInt(nextMapEntryOffset, verIndex);
		}
		
		// Mark end of list
		if (nextMapEntryOffset > maxOffset) {
			int nextIndex = vfIndexProvider.allocateIndex();
			lastMapBuffer.putInt(NEXT_BUFFER_INDEX_OFFSET, nextIndex);
			versionFile.put(lastMapBuffer, lastMapIndex);

			nextMapEntryOffset = FIRST_ENTRY_OFFSET;
			lastMapIndex = nextIndex;
			lastMapBuffer.setId(lastMapIndex);
		}
		lastMapBuffer.putInt(nextMapEntryOffset, -1);
		
		// Make sure last buffer is saved
		lastMapBuffer.putInt(NEXT_BUFFER_INDEX_OFFSET, -1);
		versionFile.put(lastMapBuffer, lastMapIndex);
		
		newMapIds.clear();
	}
	
	private void readBufferMap(int mapIndex) throws IOException {

		bufferIndexMap = new IntIntHashtable();
		
		int maxOffset = bufferSize - BUFFER_MAP_ENTRY_SIZE;
		
		lastMapIndex = mapIndex;
		lastMapBuffer = new DataBuffer();
		versionFile.get(lastMapBuffer, mapIndex);
		if (lastMapBuffer.isEmpty()) {
			throw new IOException(BAD_BUFFER_MAP);	
		}
		nextMapEntryOffset = FIRST_ENTRY_OFFSET;
		
		while (true) {
			if (nextMapEntryOffset > maxOffset) {
				// Get next map buffer
				mapIndex = lastMapBuffer.getInt(NEXT_BUFFER_INDEX_OFFSET);
				versionFile.get(lastMapBuffer, mapIndex);
				lastMapIndex = mapIndex;
				if (lastMapBuffer.isEmpty()) {
					throw new IOException(BAD_BUFFER_MAP);	
				}
				nextMapEntryOffset = FIRST_ENTRY_OFFSET;
			}
	
			// Read map entry - end of list signified by -1
			int origIndex = lastMapBuffer.getInt(nextMapEntryOffset);
			if (origIndex < 0) {
				return;
			}
			nextMapEntryOffset += 4;
			int verIndex = lastMapBuffer.getInt(nextMapEntryOffset);
			nextMapEntryOffset += 4;
			bufferIndexMap.put(origIndex, verIndex);
		}
	}
	
	private int saveFreeIndexList() throws IOException {
		
		int freeListIndex = vfIndexProvider.allocateIndex();
		int thisIndex = freeListIndex;
		int nextIndex = -1;

		int maxOffset = bufferSize - FREE_LIST_ENTRY_SIZE;
		
		DataBuffer buf = new DataBuffer(bufferSize);
		buf.setId(thisIndex);
		int offset = FIRST_ENTRY_OFFSET;
		
		// Save freeIndexes entries
		for (int i = 0; i < freeIndexes.length; i++) {

			if (offset > maxOffset) {
				nextIndex = vfIndexProvider.allocateIndex();
				buf.putInt(NEXT_BUFFER_INDEX_OFFSET, nextIndex);
				versionFile.put(buf, thisIndex);

				offset = FIRST_ENTRY_OFFSET;
				thisIndex = nextIndex;
				buf.setId(thisIndex);
			}
			
			// Save list entry as single integer
			offset = buf.putInt(offset, freeIndexes[i]);
		}
		
		// Mark end of list
		if (offset > maxOffset) {	
			nextIndex = vfIndexProvider.allocateIndex();
			buf.putInt(NEXT_BUFFER_INDEX_OFFSET, nextIndex);
			versionFile.put(buf, thisIndex);

			offset = FIRST_ENTRY_OFFSET;
			thisIndex = nextIndex;
			buf.setId(thisIndex);
		}
		buf.putInt(offset, -1);
		
		// Make sure last buffer is saved
		buf.putInt(NEXT_BUFFER_INDEX_OFFSET, -1);
		versionFile.put(buf, thisIndex);

		return freeListIndex;
	}
	
	private void readFreeIndexList(int listIndex, int size) throws IOException {

		freeIndexes = new int[size];
		
		int maxOffset = bufferSize - FREE_LIST_ENTRY_SIZE;
		
		DataBuffer listBuffer = new DataBuffer();
		versionFile.get(listBuffer, listIndex);
		if (listBuffer.isEmpty()) {
			throw new IOException(BAD_FREE_LIST);	
		}
		int offset = FIRST_ENTRY_OFFSET;
		int entryIx = 0;
		
		while (true) {
			if (offset > maxOffset) {
				// Get next list buffer
				listIndex = listBuffer.getInt(NEXT_BUFFER_INDEX_OFFSET);
				versionFile.get(listBuffer, listIndex);
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
	 * Change the file ID associated with the buffer file to which this version 
	 * file can be applied.
	 * @param fileId file ID
	 */
	void setTargetFileId(long fileId) throws IOException {
		if (versionFile == null) {
			throw new IOException("Version file is closed");
		}
		if (readOnly) {
			throw new IOException("Version file is read-only");	
		}
		targetFileId = fileId;
	}
	
	/**
	 * Returns true if this version file will accept old buffer data for the specified buffer index.
	 * @param index buffer index
	 */
	public boolean isPutOK(int index) {
		return (index >= 0 && index < originalBufCount && !bufferIndexMap.contains(index) && !isFreeIndex(index));
	}
	
	/**
	 * Returns true if the specified index was free in the original file.
	 * @param index
	 */
	private boolean isFreeIndex(int index) {
		int ix = Arrays.binarySearch(freeIndexes, index);
		return ix >= 0;
	}
	
	/**
	 * Returns the list of free indexes associated with the original
	 * buffer file.
	 */
	int[] getFreeIndexList() {
		return freeIndexes;
	}

	/**
	 * Store original buffer which has been modified in the target.  When reverting to 
	 * the original file version, these buffers should replace the newer version.
	 * @param buf old buffer
	 * @throws IOException if an IO error occurs
	 */
	void putOldBuffer(DataBuffer buf, int index) throws IOException {
		if (versionFile == null) {
			throw new IOException("Version file is closed");
		}
		if (readOnly) {
			throw new IOException("Version file is read-only");	
		}
		if (isPutOK(index)) {
			int vfIndex = vfIndexProvider.allocateIndex();
			versionFile.put(buf, vfIndex);
			bufferIndexMap.put(index, vfIndex);
			newMapIds.add(index);
		}
	}
	
	/**
	 * Get original buffer associated with the specified storage index in the 
	 * original file.
	 * @param buf data buffer
	 * @param index storage index
	 * @return data buffer or null if buffer has not been modified
	 * @throws IOException if an IO error occurs
	 */
	DataBuffer getOldBuffer(DataBuffer buf, int index) throws IOException {
		if (versionFile == null) {
			throw new IOException("Version file is closed");
		}
		int vfIndex;
		try {
			vfIndex = bufferIndexMap.get(index);
		} catch (NoValueException e) {
			return null;
		}
		versionFile.get(buf, vfIndex);
		return buf;
	}
	
	/**
	 * Returns list of original buffer indexes stored within this file.
	 * These indexes reflect those buffers which have been modified since
	 * the original version.
	 */
	int[] getOldBufferIndexes() {
		return bufferIndexMap.getKeys();
	}

	/**
	 * Returns file ID for buffer file to which this version file may be applied.
	 */
	long getTargetFileID() {
		return targetFileId;
	}

	/**
	 * Returns file ID for original buffer file which may be produced with this version file.
	 */
	long getOriginalFileID() {
		return originalFileId;
	}
	
	/**
	 * Returns buffer count for original buffer file. 
	 */
	public int getOriginalBufferCount() {
		return originalBufCount;
	}
	
	/**
	 * Returns a list of parameters defined within the original beffer file.
	 * @throws IOException
	 */
	String[] getOldParameterNames() throws IOException {
		if (versionFile == null) {
			throw new IOException("Version file is closed");
		}
		String[] allNames = versionFile.getParameterNames();
		ArrayList<String> list = new ArrayList<String>();
		for (int i = 0; i < allNames.length; i++) {
			if (!allNames[i].startsWith(VERSION_PARM_PREFIX)) {
				list.add(allNames[i]);	
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
	 * @throws IOException
	 */
	int getOldParameter(String name) throws IOException {
		if (versionFile == null) {
			throw new IOException("Version file is closed");
		}
		return versionFile.getParameter(name);
	}
	
}
