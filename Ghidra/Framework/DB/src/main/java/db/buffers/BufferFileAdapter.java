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
import java.rmi.NoSuchObjectException;
import java.rmi.Remote;
import java.util.NoSuchElementException;

import ghidra.util.Msg;

/**
 * <code>BufferFileAdapter</code> provides a BufferFile implementation which
 * wraps a BufferFileHandle.
 */
public class BufferFileAdapter implements BufferFile {

	private BufferFileHandle bufferFileHandle;

	/**
	 * Constructor.
	 * @param remoteBufferFile  remote buffer file handle
	 */
	public BufferFileAdapter(BufferFileHandle remoteBufferFile) {
		this.bufferFileHandle = remoteBufferFile;
	}

	@Override
	public int getParameter(String name) throws NoSuchElementException, IOException {
		return bufferFileHandle.getParameter(name);
	}

	@Override
	public void setParameter(String name, int value) throws IOException {
		bufferFileHandle.setParameter(name, value);
	}

	@Override
	public void clearParameters() throws IOException {
		bufferFileHandle.clearParameters();
	}

	@Override
	public String[] getParameterNames() throws IOException {
		return bufferFileHandle.getParameterNames();
	}

	@Override
	public int getBufferSize() throws IOException {
		return bufferFileHandle.getBufferSize();
	}

	@Override
	public int getIndexCount() throws IOException {
		return bufferFileHandle.getIndexCount();
	}

	@Override
	public int[] getFreeIndexes() throws IOException {
		return bufferFileHandle.getFreeIndexes();
	}

	@Override
	public void setFreeIndexes(int[] indexes) throws IOException {
		bufferFileHandle.setFreeIndexes(indexes);
	}

	@Override
	public boolean isReadOnly() throws IOException {
		return bufferFileHandle.isReadOnly();
	}

	@Override
	public boolean setReadOnly() throws IOException {
		return bufferFileHandle.setReadOnly();
	}

	@Override
	public void close() throws IOException {
		bufferFileHandle.close();
	}

	@Override
	public boolean delete() throws IOException {
		return bufferFileHandle.delete();
	}

	@Override
	public void dispose() {
		try {
			bufferFileHandle.dispose();
		}
		catch (IOException e) {
			// handle may have already been disposed
			if (!(e instanceof NoSuchObjectException)) {
				Msg.error(this, e);
			}
		}
	}

	@Override
	public DataBuffer get(DataBuffer buf, int index) throws IOException {
		DataBuffer remoteBuf = bufferFileHandle.get(index);
		if (buf == null) {
			return remoteBuf;
		}
		buf.setEmpty(remoteBuf.isEmpty());
		buf.setId(remoteBuf.getId());
		if (remoteBuf.data != null) {
			buf.data = remoteBuf.data;
		}
		return buf;
	}

	@Override
	public void put(DataBuffer buf, int index) throws IOException {
		bufferFileHandle.put(buf, index);
	}

	/**
	 * Determine if this file is remotely accessed
	 * @return true if file is remote
	 */
	public boolean isRemote() {
		return (bufferFileHandle instanceof Remote);
	}

	/**
	 * Obtain a direct stream to read all blocks of this buffer file
	 * @return input block stream
	 * @throws IOException
	 */
	InputBlockStream getInputBlockStream() throws IOException {
		// NOTE: This may need to change in the future if other
		// non-RMI implementation require the use of InputBlockStreamHandle
		if (isRemote()) {
			// Use of remote communications handle required to indirectly
			// obtain InputBlockStream via InputBlockStreamHandle
			BlockStreamHandle<InputBlockStream> inputBlockStreamHandle =
				bufferFileHandle.getInputBlockStreamHandle();
			return inputBlockStreamHandle.openBlockStream();
		}
		return bufferFileHandle.getInputBlockStream();
	}

	/**
	 * Obtain a direct stream to write blocks to this buffer file
	 * @param blockCount number of blocks to be written
	 * @return output block stream
	 * @throws IOException
	 */
	OutputBlockStream getOutputBlockStream(int blockCount) throws IOException {
		// NOTE: This may need to change in the future if other
		// non-RMI implementation require the use of InputBlockStreamHandle
		if (isRemote()) {
			// Use of remote communications handle required to indirectly
			// obtain OutputBlockStream via OutputBlockStreamHandle
			BlockStreamHandle<OutputBlockStream> outputBlockStreamHandle =
				bufferFileHandle.getOutputBlockStreamHandle(blockCount);
			return outputBlockStreamHandle.openBlockStream();
		}
		return bufferFileHandle.getOutputBlockStream(blockCount);
	}

}
