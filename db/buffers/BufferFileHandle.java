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
import java.util.NoSuchElementException;

/**
 * <code>BufferFileHandle</code> facilitates access to a BufferFile
 */
public interface BufferFileHandle {

	/**
	 * @see BufferFile#isReadOnly()
	 */
	public boolean isReadOnly() throws IOException;

	/**
	 * @see BufferFile#setReadOnly()
	 */
	public boolean setReadOnly() throws IOException;

	/**
	 * @see BufferFile#getParameter(java.lang.String)
	 */
	public int getParameter(String name) throws NoSuchElementException, IOException;

	/**
	 * @see BufferFile#setParameter(java.lang.String, int)
	 */
	public void setParameter(String name, int value) throws IOException;

	/**
	 * @see BufferFile#clearParameters()
	 */
	public void clearParameters() throws IOException;

	/**
	 * @see BufferFile#getParameterNames()
	 */
	public String[] getParameterNames() throws IOException;

	/**
	 * @see BufferFile#getBufferSize()
	 */
	public int getBufferSize() throws IOException;

	/**
	 * @see BufferFile#getIndexCount()
	 */
	public int getIndexCount() throws IOException;

	/**
	 * @see BufferFile#getFreeIndexes()
	 */
	public int[] getFreeIndexes() throws IOException;

	/**
	 * @see BufferFile#setFreeIndexes(int[])
	 */
	public void setFreeIndexes(int[] indexes) throws IOException;

	/**
	 * @see BufferFile#close()
	 */
	public void close() throws IOException;

	/**
	 * @see BufferFile#delete() }
	 */
	public boolean delete() throws IOException;

	/**
	 * @see BufferFile#get(DataBuffer, int)
	 */
	public DataBuffer get(int index) throws IOException;

	/**
	 * @see BufferFile#put(DataBuffer, int)
	 */
	public void put(DataBuffer buf, int index) throws IOException;

	/**
	 * @see BufferFile#dispose()
	 */
	public void dispose() throws IOException;

	/**
	 * Provides local access to an input block stream.  This method should only be used 
	 * if the associated {@link BufferFileAdapter#isRemote()} is <i>false</i>.
	 * @see BufferFileAdapter#getInputBlockStream()
	 */
	public InputBlockStream getInputBlockStream() throws IOException;

	/**
	 * Provides local access to an output block stream.  This method should only be used 
	 * if the associated {@link BufferFileAdapter#isRemote()} is <i>false</i>.
	 * @see BufferFileAdapter#getOutputBlockStream(int)
	 */
	public OutputBlockStream getOutputBlockStream(int blockCount) throws IOException;

	/**
	 * Get an input block stream handle which will facilitate access to a remote InputBlockStream.
	 * The handle will facilitate use of a remote streaming interface.  This method should only be used 
	 * if the associated {@link BufferFileAdapter#isRemote()} is <i>true</i>. 
	 * @see BufferFileAdapter#getInputBlockStream()
	 */
	public BlockStreamHandle<InputBlockStream> getInputBlockStreamHandle() throws IOException;

	/**
	 * Get an output block stream handle which will facilitate access to a remote InputBlockStream.
	 * The handle will facilitate use of a remote streaming interface.  This method should only be used 
	 * if the associated {@link BufferFileAdapter#isRemote()} is <i>true</i>. 
	 * @see BufferFileAdapter#getOutputBlockStream(int)
	 */
	public BlockStreamHandle<OutputBlockStream> getOutputBlockStreamHandle(int blockCount)
			throws IOException;

}
