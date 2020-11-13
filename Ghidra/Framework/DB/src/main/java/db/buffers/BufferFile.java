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

import java.io.EOFException;
import java.io.IOException;
import java.util.NoSuchElementException;

/**
 * <code>BufferFile</code> facilitates read/write access to buffer oriented file.
 * Access to related resources, such as parameters and change data, is also facilitated.
 */
public interface BufferFile {
	
	/**
	 * Returns true if this file may not be modified 
	 * via the buffer put method.  
	 * A read-only file may be considered "updateable" if the canSave
	 * method returns true.  The term "updateable" means that a Save file
	 * can be obtained via the getSaveFile method.
	 * @throws IOException if an I/O error occurs
	 */
	boolean isReadOnly() throws IOException;
	
	/**
	 * If file is open read-write, the modified contents are flushed
	 * and the file re-opened as read-only.  This is also used to commit
	 * a new version if the file had been modified for update.
	 * @return true if successfully transitioned from read-write to read-only
	 * @throws IOException if an I/O error occurs
	 */
	boolean setReadOnly() throws IOException;
	
	/**
	 * Get a the stored value for a named parameter.
	 * @param name parameter name
	 * @return integer value
	 * @throws NoSuchElementException thrown if parameter not found
	 * @throws IOException
	 */
	int getParameter(String name) throws NoSuchElementException, IOException;
	
	/**
	 * Set the integer value for a named parameter.
	 * @param name parameter name
	 * @param value parameter value
	 * @throws IOException
	 */
	public void setParameter(String name, int value) throws IOException;
	
	/**
	 * Deletes all parameters
	 * @throws IOException
	 */
	public void clearParameters() throws IOException;
	
	/**
	 * Returns a list of all parameter names.
	 * @throws IOException
	 */
	String[] getParameterNames() throws IOException;
	
	/**
	 * Return the actual size of a user data buffer.  This value should be 
	 * used when constructing DataBuffer objects.
	 * @return DataBuffer data size as a number of bytes
	 * @throws IOException if an I/O error occurs
	 */
	int getBufferSize() throws IOException;

	/**
	 * Returns the number of allocated buffer indexes.
	 * When a new buffer is allocated, and the file size
	 * grows, the buffer will remain allocated although it
	 * may be added to the list of free-indexes.  A file will
	 * never shrink in size due to this permanent allocation.
	 * @throws IOException
	 */
	int getIndexCount() throws IOException;
	
	/**
	 * Returns the list of free indexes sorted by value.
	 * The management of the free-index-list is implementation
	 * specific.
	 * @throws IOException
	 */
	int[] getFreeIndexes() throws IOException;
	
	/**
	 * Sets the list of free buffer indexes.
	 * The management of the free-index-list is implementation
	 * specific.
	 * @param indexes
	 * @throws IOException
	 */
	void setFreeIndexes(int[] indexes) throws IOException;
	
	/**
	 * Close the buffer file.  If the file was open for write access,
	 * all buffers are flushed and the file header updated.  Once closed,
	 * this object is immediately disposed and may no longer be used.
	 * @throws IOException if an I/O error occurs
	 */
	void close() throws IOException;

	/**
	 * Delete this buffer file if writable.  Once deleted,
	 * this object is immediately disposed and may no longer be used.
	 * @return true if deleted, false if the file is read-only
	 * @throws IOException if an I/O error occurs.
	 */
	boolean delete() throws IOException;
	
	/**
	 * Dispose of this buffer file object.  If file is not readOnly
	 * and has not been closed, an attempt will be made to delete the
	 * associated file(s).  Once disposed, it may no longer be used.
	 */
	void dispose();
	
	/**
	 * Get the specified buffer.
	 * DataBuffer data and flags are read from the file at index and 
	 * stored within the supplied DataBuffer object.  If the read buffer
	 * is empty, the DataBuffer's data field will remain unchanged (which could be null).
	 * @param buf a buffer whose data array will be filled-in or replaced.
	 * @param index index of buffer to be read.  First user buffer
	 * is at index 0.
	 * @throws EOFException if the requested buffer index is greater 
	 * than the number of available buffers of the end-of-file was
	 * encountered while reading the buffer.
	 * @throws IOException if an I/O error occurs
	 */ 
	DataBuffer get(DataBuffer buf, int index) throws IOException;

	/**
	 * Store a data buffer at the specified block index.
	 * @param buf data buffer
	 * @param index block index
	 * @throws IOException thrown if an IO error occurs
	 */
	void put(DataBuffer buf, int index) throws IOException;
	
}
