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
 * <code>ManagedBufferFileHandle</code> facilitates access to a ManagedBufferFile
 */
public interface ManagedBufferFileHandle extends BufferFileHandle {

	/**
	 * @see ManagedBufferFile#getSaveFile()
	 */
	public ManagedBufferFileHandle getSaveFile() throws IOException;

	/**
	 * @see ManagedBufferFile#saveCompleted(boolean)
	 */
	public void saveCompleted(boolean commit) throws IOException;

	/**
	 * @see ManagedBufferFile#canSave()
	 */
	public boolean canSave() throws IOException;

	/**
	 * @see ManagedBufferFile#setVersionComment(java.lang.String)
	 */
	public void setVersionComment(String comment) throws IOException;

	/**
	 * @see ManagedBufferFile#getNextChangeDataFile(boolean)
	 */
	public BufferFileHandle getNextChangeDataFile(boolean getFirst) throws IOException;

	/**
	 * @see ManagedBufferFile#getSaveChangeDataFile()
	 */
	public BufferFileHandle getSaveChangeDataFile() throws IOException;

	/**
	 * @see ManagedBufferFile#getCheckinID()
	 */
	public long getCheckinID() throws IOException;

	/**
	 * @see ManagedBufferFile#getForwardModMapData(int)
	 */
	public byte[] getForwardModMapData(int oldVersion) throws IOException;

	/**
	 * Provides local access to an input block stream for a given change map.  
	 * This method should only be used if the associated 
	 * {@link BufferFileAdapter#isRemote()} is <i>false</i>.
	 * @see ManagedBufferFileAdapter#getInputBlockStream(byte[])
	 */
	public InputBlockStream getInputBlockStream(byte[] changeMapData) throws IOException;

	/**
	 * Get an input block stream handle, for a given change map, which will facilitate 
	 * access to a remote InputBlockStream.  The handle will facilitate use of a 
	 * remote streaming interface.  This method should only be used 
	 * if the associated {@link BufferFileAdapter#isRemote()} is <i>true</i>. 
	 * @see ManagedBufferFileAdapter#getInputBlockStream(byte[])
	 */
	public BlockStreamHandle<InputBlockStream> getInputBlockStreamHandle(byte[] changeMapData)
			throws IOException;

}
