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

import java.io.IOException;

/**
 * <code>BufferFile</code> facilitates read/write access to buffer oriented file.
 * Access to related resources, such as parameters and change data, is also facilitated.
 */
public interface ManagedBufferFile extends BufferFile {
	
	/**
	 * Get the next change data file which corresponds to this buffer file.
	 * This method acts like an iterator which each successive invocation returning 
	 * the next available file.  Null is returned when no more files are available.
	 * The invoker is responsible for closing each file returned.  It is highly 
	 * recommended that each file be closed prior to requesting the next file.
	 * @param getFirst causes the iterator to reset and return the first available file.  
	 * @throws IOException if an I/O error occurs
	 */
	BufferFile getNextChangeDataFile(boolean getFirst) throws IOException;

	/**
	 * Returns a temporary change data buffer file which should be used to store a 
	 * application-level ChangeSet associated with this new buffer file version.  
	 * The getSaveFile method must be successfully invoked prior to invoking this method.
	 * @return change data file or null if one is not available.
	 * @throws IOException if an I/O error occurs
	 */
	BufferFile getSaveChangeDataFile() throws IOException;
	
	/**
	 * Returns a bit map corresponding to all buffers modified since oldVersion.
	 * This identifies all buffers contained within the oldVersion
	 * which have been modified during any revision up until this file version.
	 * Buffers added since oldVersion are not identified
	 * NOTE: The bit mask may identify empty/free buffers within this file version. 
	 * @param oldVersion indicates the older version of this file for which a change map
	 * will be returned.  This method may only be invoked if this file
	 * is at version 2 or higher, has an associated BufferFileManager and
	 * the oldVersion related files still exist.
	 * @return ModMap buffer change map data
	 * @throws IOException if an I/O error occurs
	 */
	byte[] getForwardModMapData(int oldVersion) throws IOException;

	/**
	 * Returns a Save file if available.  Returns null if
	 * a save can not be performed.  This method may block for an extended
	 * period of time if the pre-save process has not already completed.
	 * This method does not accept a monitor since a remote TaskMonitor does
	 * not yet exist.
	 * @throws IOException if an I/O error occurs
	 */
	ManagedBufferFile getSaveFile() throws IOException;

	/**
	 * After getting the save file, this method must be invoked to
	 * terminate the save.
	 * @param commit if true the save file will be reopened as read-only 
	 * for update.  If false, the save file will be deleted and the object will 
	 * become invalid.
	 * @throws IOException
	 */
	void saveCompleted(boolean commit) throws IOException;
	
	/**
	 * Returns true if a save file is provided for creating a new
	 * version of this buffer file.
	 * @throws IOException if an I/O error occurs
	 * @see #getSaveFile()
	 */
	boolean canSave() throws IOException;
	
	/**
	 * Set the comment which will be associated with this buffer file
	 * if saved.  The comment must be set prior to invoking close or
	 * setReadOnly.
	 * @param comment comment text
	 * @throws IOException if an I/O error occurs
	 */
	void setVersionComment(String comment) throws IOException;
	
	/**
	 * Returns the checkin ID corresponding to this buffer file.
	 * The returned value is only valid if this buffer file has an associated
	 * buffer file manager and is either being created (see isReadOnly) or
	 * is intended for update (see canSave).
	 * @throws IOException if an I/O error occurs
	 */
	long getCheckinID() throws IOException;
	
}
