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

import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;

import java.io.File;
import java.io.IOException;
import java.util.NoSuchElementException;

import db.ChainedBuffer;

/**
 * <code>ChangeMapFile</code> tracks which buffers within a LocalBufferFile 
 * have been modified between an older and newer version.  The older
 * file is also referred to as the target file.
 */
public class ChangeMapFile {

	private static final int MAGIC_NUMBER = 0x73D9A3BC;
	private static final int CACHE_SIZE = 64*1024;

	// ModMap file parameter keys
	private static final String MODMAP_PARM_PREFIX = "~MF.";
	private static final String MAGIC_NUMBER_PARM = MODMAP_PARM_PREFIX + "ModMapFile";
	private static final String BUFFER_ID_PARM = MODMAP_PARM_PREFIX + "BufferId";
	private static final String TARGET_FILE_ID_HI_PARM = MODMAP_PARM_PREFIX + "TargetIdHi";
	private static final String TARGET_FILE_ID_LOW_PARM = MODMAP_PARM_PREFIX + "TargetIdLow";
	private static final String INDEX_CNT_PARM = MODMAP_PARM_PREFIX + "IndexCnt";
	private static final String INITIAL_VERSION_PARM = MODMAP_PARM_PREFIX + "InitialVersion";

	private File file;
	private BufferMgr bufMgr;
	private ChainedBuffer buffer;
	private int indexCnt;
	private boolean readOnly;

	/**
	 * Construct a map file for output.  If the file exists it will be updated,
	 * otherwise a new file will be created.
	 * @param file map file
	 * @param targetFile associated target buffer file
	 * @param create if true a new map file will be created
	 * @throws IOException if file already exists or an IO error occurs
	 */
	ChangeMapFile(File file, LocalManagedBufferFile oldFile, LocalManagedBufferFile newFile) throws IOException {

		this.file = file;
		readOnly = false;
		
		LocalBufferFile mapFile = null;
		boolean success = false;
		try {
			if (!file.exists()) {
	
				indexCnt = oldFile.getIndexCount();

				bufMgr = new BufferMgr(BufferMgr.DEFAULT_BUFFER_SIZE, CACHE_SIZE, 1);
				bufMgr.setParameter(MAGIC_NUMBER_PARM, MAGIC_NUMBER);
				int ver = oldFile.getVersion();
				bufMgr.setParameter(INITIAL_VERSION_PARM, ver);
				bufMgr.setParameter(INDEX_CNT_PARM, indexCnt);
				
				// Create chained buffer
				int size = ((indexCnt - 1) / 8) + 1;
				buffer = new ChainedBuffer(size, bufMgr);
				bufMgr.setParameter(BUFFER_ID_PARM, buffer.getId());
				
				// Mark all spare bits as changed
				
				
				int lastByteOffset = (indexCnt-1) / 8;
				byte lastByte = 0;
				int index = indexCnt;
				int bit;
				while((bit = index % 8) != 0) {
					int bitMask = 1 << bit;
					lastByte = (byte)(lastByte | bitMask);
					++index;
				}
				buffer.putByte(lastByteOffset, lastByte);
								
			}
			else {

				mapFile = new LocalBufferFile(file, true);
				if (mapFile.getParameter(MAGIC_NUMBER_PARM) != MAGIC_NUMBER) {
					throw new IOException("Bad modification map file: " + file);
				}
				
				long oldTargetFileId = ((long)mapFile.getParameter(TARGET_FILE_ID_HI_PARM) << 32) |
					(mapFile.getParameter(TARGET_FILE_ID_LOW_PARM) & 0xffffffffL);
				if (oldTargetFileId != oldFile.getFileId()) {
					throw new IOException("Modification map file does not correspond to target: " + file);
				}
				
				bufMgr = new BufferMgr(mapFile, CACHE_SIZE, 1);
				
				indexCnt = bufMgr.getParameter(INDEX_CNT_PARM);
				if (newFile.getIndexCount() < indexCnt) {
					throw new AssertException();
				}

				int id = bufMgr.getParameter(BUFFER_ID_PARM);
				buffer = new ChainedBuffer(bufMgr, id);
			}
			
			long targetFileId = newFile.getFileId();
			bufMgr.setParameter(TARGET_FILE_ID_HI_PARM, (int)(targetFileId >> 32));
			bufMgr.setParameter(TARGET_FILE_ID_LOW_PARM, (int)(targetFileId & 0xffffffffL));
			
			success = true;
		}
		catch (NoSuchElementException e) {
			throw new IOException("Required modification map paramater (" + e.getMessage() + ") not found: " + file);
		}
		finally {
			if (!success) {
				if (bufMgr != null) {
					bufMgr.dispose();
				}
				else if (mapFile != null) {
					mapFile.dispose();
				}
			}
		}
	}
	
	/**
	 * Construct map file for reading.  
	 * @param file existing map file
	 * @throws IOException if an IO error occurs
	 */
	ChangeMapFile(File file, LocalBufferFile targetFile) throws IOException {

		this.file = file;
		readOnly = true;
		
		LocalBufferFile mapFile = null;
		boolean success = false;
		try {
			mapFile = new LocalBufferFile(file, true);
			if (mapFile.getParameter(MAGIC_NUMBER_PARM) != MAGIC_NUMBER) {
				throw new IOException("Bad modification map file: " + file);
			}
			
			long oldTargetFileId = ((long)mapFile.getParameter(TARGET_FILE_ID_HI_PARM) << 32) |
				(mapFile.getParameter(TARGET_FILE_ID_LOW_PARM) & 0xffffffffL);
			if (oldTargetFileId != targetFile.getFileId()) {
				throw new IOException("Modification map file does not correspond to target: " + file);
			}
		
			bufMgr = new BufferMgr(mapFile, CACHE_SIZE, 1);
			
			indexCnt = bufMgr.getParameter(INDEX_CNT_PARM);
			if (targetFile.getIndexCount() < indexCnt) {
				throw new AssertException();
			}
			
			int id = bufMgr.getParameter(BUFFER_ID_PARM);
			buffer = new ChainedBuffer(bufMgr, id);
			success = true;
		}
		catch (NoSuchElementException e) {
			throw new IOException("Required modification map paramater (" + e.getMessage() + ") not found: " + file);
		}
		finally {
			if (!success) {
				if (bufMgr != null) {
					bufMgr.dispose();
				}
				else if (mapFile != null) {
					mapFile.dispose();
				}
			}
		}
	}

	/**
	 * Returns true if this change map corresponds to the specified target file.
	 * @param targetFile
	 */
	boolean isValidFor(LocalBufferFile targetFile) {
		long targetFileId = ((long)bufMgr.getParameter(TARGET_FILE_ID_HI_PARM) << 32) |
			(bufMgr.getParameter(TARGET_FILE_ID_LOW_PARM) & 0xffffffffL);
		return (targetFileId == targetFile.getFileId());
	}

	/**
	 * Abort the creation/update of this file.
	 * This method should be invoked in place of close on a failure condition.
	 * An attempt is made to restore the version file to its initial state
	 * or remove it if it was new.
	 */
	void abort() {
		if (bufMgr != null) {
			bufMgr.dispose();
			bufMgr = null;
		}
	}
	
	/**
	 * Close the file.
	 */
	void close() throws IOException {		
		LocalBufferFile mapFile = null;
		boolean success = false;
		try {
			if (!readOnly) {
				File tmpFile = new File(file.getParentFile(), file.getName() + LocalBufferFile.TEMP_FILE_EXT);
				mapFile = new LocalBufferFile(tmpFile, bufMgr.getBufferSize());
				bufMgr.saveAs(mapFile, true, null);
				bufMgr.dispose();
				bufMgr = null;
				file.delete();
				if (!tmpFile.renameTo(file)) {
					throw new IOException("Failed to update file: " + file);
				}
			}
			else {
				bufMgr.dispose();
				bufMgr = null;
			}
			success = true;
		} catch (CancelledException e) {
		}
		finally {
			if (!success) {
				if (mapFile != null) {
					mapFile.delete();
				}
				if (bufMgr != null) {
					bufMgr.dispose();
				}
			}
		}
	}

	/**
	 * Mark buffer as changed
	 * @param id
	 * @throws IOException
	 */
	void bufferChanged(int index, boolean empty) throws IOException {
		if (index >= indexCnt) {
			return; // no need to track new buffers
		}
		int byteOffset = index / 8;
		byte b;
		if (empty) {
			// Clear bit if buffer is removed
			int bitMask = ~(1 << (index % 8));
			b = (byte)(buffer.getByte(byteOffset) & bitMask);
		}
		else {
			// Set bit if buffer is set
			int bitMask = 1 << (index % 8);
			b = (byte)(buffer.getByte(byteOffset) | bitMask);
		}
		buffer.putByte(byteOffset, b);
	}

	/**
	 * Returns data suitable for use by the ChangeMap class.
	 * @throws IOException
	 * @see ChangeMap
	 */
	byte[] getModData() throws IOException {
		return buffer.get(0, buffer.length());
	}
	
}
