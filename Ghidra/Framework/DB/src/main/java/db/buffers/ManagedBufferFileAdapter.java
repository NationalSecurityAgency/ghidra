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
import java.rmi.Remote;

/**
 * <code>ManagedBufferFileAdapter</code> provides a ManagedBufferFile implementation which
 * wraps a ManagedBufferFileHandle.
 */
public class ManagedBufferFileAdapter extends BufferFileAdapter implements ManagedBufferFile {

	private ManagedBufferFileHandle managedBufferFileHandle;

	/**
	 * Constructor.
	 * @param remoteManagedBufferFile remote buffer file handle
	 */
	public ManagedBufferFileAdapter(ManagedBufferFileHandle remoteManagedBufferFile) {
		super(remoteManagedBufferFile);
		this.managedBufferFileHandle = remoteManagedBufferFile;
	}

	@Override
	public ManagedBufferFile getSaveFile() throws IOException {
		ManagedBufferFileHandle rbf = managedBufferFileHandle.getSaveFile();
		return rbf != null ? new ManagedBufferFileAdapter(rbf) : null;
	}

	@Override
	public void saveCompleted(boolean commit) throws IOException {
		managedBufferFileHandle.saveCompleted(commit);
	}

	@Override
	public boolean canSave() throws IOException {
		return managedBufferFileHandle.canSave();
	}

	@Override
	public void setVersionComment(String comment) throws IOException {
		managedBufferFileHandle.setVersionComment(comment);
	}

	@Override
	public BufferFile getNextChangeDataFile(boolean getFirst) throws IOException {
		BufferFileHandle rbf = managedBufferFileHandle.getNextChangeDataFile(getFirst);
		return rbf != null ? new BufferFileAdapter(rbf) : null;
	}

	@Override
	public BufferFile getSaveChangeDataFile() throws IOException {
		BufferFileHandle rbf = managedBufferFileHandle.getSaveChangeDataFile();
		return rbf != null ? new BufferFileAdapter(rbf) : null;
	}

	@Override
	public long getCheckinID() throws IOException {
		return managedBufferFileHandle.getCheckinID();
	}

	@Override
	public byte[] getForwardModMapData(int oldVersion) throws IOException {
		return managedBufferFileHandle.getForwardModMapData(oldVersion);
	}

	/**
	 * Obtain a direct stream to read modified blocks of this buffer file based
	 * upon the specified changeMap
	 * @param changeMapData provides ChangeMap data which is used to identify which blocks
	 *            should be streamed
	 * @return input block stream
	 * @throws IOException
	 */
	InputBlockStream getInputBlockStream(byte[] changeMapData) throws IOException {
		// NOTE: This may need to change in the future if other
		// non-RMI implementation require the use of InputBlockStreamHandle
		if (managedBufferFileHandle instanceof Remote) {
			// Use of remote communications handle required to indirectly
			// obtain InputBlockStream via InputBlockStreamHandle
			BlockStreamHandle<InputBlockStream> inputBlockStreamHandle =
				managedBufferFileHandle.getInputBlockStreamHandle(changeMapData);
			return inputBlockStreamHandle.openBlockStream();
		}
		return managedBufferFileHandle.getInputBlockStream(changeMapData);
	}

}
