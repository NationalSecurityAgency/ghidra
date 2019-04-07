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

import ghidra.util.datastruct.IntIntHashtable;
import ghidra.util.exception.NoValueException;

import java.io.IOException;
import java.util.*;

/**
 * <code>VersionFileHandler</code> allows a set of VersionFile's to be used in
 * the dynamic reconstruction of an older BufferFile.  In an attempt to
 * conserve file handles, only one VersionFile is held open at any point
 * in time.
 * <p>
 * When constructed, this handler determines the set of VersionFile's needed to 
 * reconstruct an older version from a specified target version.
 */
public class VersionFileHandler {
	
	private VersionFile[] versionFiles;
	private int openFileIx;
	
	// maps buffer indexes to the corresponding versionFiles index
	private IntIntHashtable bufferMap = new IntIntHashtable();
	
	private int originalBufCount;
	private int maxBufCount;
	private long originalFileId;
	private int[] freeIndexes;
	private Hashtable<String,Integer> origParms = new Hashtable<String,Integer>();
	

	/**
	 * Construct a VersionFile handler.
	 * VersionFiles will be used to provide original BufferFile data
	 * for the version origVer.
	 * @param bf current buffer file which will use this version file
	 * handler to reconstruct an older version.
	 * @param targetFileId file ID of buffer file to which the version file
	 * buffers will be applied.
	 * @param targetVer version of target buffer file.
	 * @param origVer an older version number
	 * @throws IOException if an IO error occurs or data is missing
	 */
	VersionFileHandler(BufferFileManager bfMgr, long targetFileId, int targetVer, int origVer) throws IOException {

		versionFiles = new VersionFile[targetVer - origVer];
		long lastTargetFileId = 0;
		boolean success = false;
		try {
			openFileIx = -1;
			for (int v = origVer; v < targetVer; v++) {
				
				// Close previous version file
				if (openFileIx != -1) {
					versionFiles[openFileIx].close();
				}
				
				// Open next version file
				VersionFile vf = new VersionFile(bfMgr.getVersionFile(v));
				versionFiles[++openFileIx] = vf;
				
				// Use free index list and parameters from original version file only
				if (openFileIx == 0) {
					originalBufCount = vf.getOriginalBufferCount();
					freeIndexes = vf.getFreeIndexList();
					String[] names = vf.getOldParameterNames();
					for (int i = 0; i < names.length; i++) {
						origParms.put(names[i], new Integer(vf.getOldParameter(names[i])));
					}
					originalFileId = vf.getOriginalFileID();
				}
				else {
					if (lastTargetFileId != vf.getOriginalFileID())	{
						throw new IOException("Incorrect version file - wrong file ID");	
					}
				}
				lastTargetFileId = vf.getTargetFileID();
				if (maxBufCount < vf.getOriginalBufferCount()) {
					maxBufCount = vf.getOriginalBufferCount();
				}
				
				// Add buffer indexes to map which are not present in earlier version file
				int[] bufferIndexes = vf.getOldBufferIndexes();
				for (int i = 0; i < bufferIndexes.length; i++) {
					if (!bufferMap.contains(bufferIndexes[i])) {
						bufferMap.put(bufferIndexes[i], openFileIx);
					}
				}
			}
			if (lastTargetFileId != targetFileId)	{
				throw new IOException("Incorrect version file - wrong file ID");	
			}
			success = true;
		}
		finally {
			if (!success) {
				close();
			}
		}
		
	}

	/**
	 * Close all file resources.
	 */
	void close() {
		try {
			if (openFileIx != -1 && versionFiles[openFileIx] != null) {
				versionFiles[openFileIx].close();
			}
		} catch (IOException e) {
		}
	}
	
	/**
	 * Returns file ID associated with original buffer file.
	 */
	long getOriginalFileID() {
		return originalFileId;
	}
	
	/**
	 * Returns the list of free indexes associated with the original
	 * buffer file.
	 */
	int[] getFreeIndexList() {
		return freeIndexes;
	}
	
	private VersionFile getVersionFile(int vfIndex) throws IOException {
		if (openFileIx != vfIndex) {
			versionFiles[openFileIx].close();	
			openFileIx = vfIndex;
			versionFiles[openFileIx].open();
		}
		return versionFiles[openFileIx];
	}

	/**
	 * Get original buffer associated with the specified storage index in the 
	 * original file.
	 * @param buf data buffer
	 * @param index storage index
	 * @return data buffer or null if buffer is not empty and has not been modified
	 * @throws IOException if an IO error occurs
	 */
	DataBuffer getOldBuffer(DataBuffer buf, int index) throws IOException {
		try {
			int vfIndex = bufferMap.get(index);
			return getVersionFile(vfIndex).getOldBuffer(buf, index);
		} catch (NoValueException e) {
		}
		if (Arrays.binarySearch(freeIndexes, index) >= 0) {
			buf.setId(-1);
			buf.setEmpty(true);	
			buf.setDirty(false);
			return buf;
		}
		return null;
	}
	
	/**
	 * Returns a bit map corresponding to all buffers modified since
	 * the original version (e.g., oldest).  This identifies all buffers within the target
	 * version (e.g., latest) which must be reverted to rebuild the original version.
	 * NOTE: The bit mask may identify buffers which have been removed in the current version. 
	 */
	byte[] getReverseModMapData() {
		
		// Allocate map based upon number of buffers corresponding to latest version changes
		int bitMapSize = (maxBufCount + 7) / 8;
		byte[] data = new byte[bitMapSize];
		Arrays.fill(data, (byte)0);
		
		// Mark excess bits corresponding to maxBufCount and beyond as changed
		int excess = maxBufCount % 8;
		if (excess != 0) {
			data[bitMapSize-1] |= (byte)(0xff << excess);
		}
		for (int index : bufferMap.getKeys()) {
			if (index >= maxBufCount) {
				System.err.println("VersionFileHandler: unexpected buffer index");
				continue;
			}
			setMapDataBit(data, index);
		}
		return data;
	}
	
	/**
	 * Returns a bit map corresponding to all buffers modified since
	 * the original version (e.g., oldest).  This identifies all buffers contained within the original
	 * version (e.g., oldest) which have been modified during any revision up until the original version.
	 * NOTE: The bit mask may identify buffers which have been removed in the current version. 
	 */
	byte[] getForwardModMapData() {
		
		// Allocate map based upon number of buffers corresponding to latest version changes
		int bitMapSize = (originalBufCount + 7) / 8;
		byte[] data = new byte[bitMapSize];
		Arrays.fill(data, (byte)0);
		
		// Mark excess bits corresponding to maxBufCount and beyond as changed
		int excess = originalBufCount % 8;
		if (excess != 0) {
			data[bitMapSize-1] |= (byte)(0xff << excess);
		}
		for (int index : bufferMap.getKeys()) {
			if (index < originalBufCount) {
				setMapDataBit(data, index);
			}
		}
		return data;
	}
	
	private void setMapDataBit(byte[] data, int index) {
		int byteOffset = index / 8;
		int bitMask = 1 << (index % 8);
		data[byteOffset] = (byte)(data[byteOffset] | bitMask);
	}
	
	/**
	 * Returns buffer count for original buffer file. 
	 */
	public int getOriginalBufferCount() {
		return originalBufCount;
	}
	
	/**
	 * Returns a list of parameters defined within the original beffer file.
	 */
	String[] getOldParameterNames() {
		ArrayList<String> list = new ArrayList<String>();
		Enumeration<String> it = origParms.keys();
		while (it.hasMoreElements()) {
			String name = it.nextElement();
			list.add(name);
		}
		String[] names = new String[list.size()];
		list.toArray(names);
		return names;
	}
	
	/**
	 * Get a parameter value associated with the original buffer file.
	 * @param name parameter name
	 * @return parameter value
	 */
	int getOldParameter(String name) {
		Object obj = origParms.get(name);
		if (obj == null)
			throw new NoSuchElementException();
		return ((Integer) obj).intValue();
	}
	
}
