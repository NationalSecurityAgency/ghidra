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
package ghidra.server.remote;

import java.io.IOException;
import java.rmi.RemoteException;

import db.buffers.*;
import ghidra.server.stream.BlockStreamServer;
import ghidra.server.stream.RemoteInputBlockStreamHandle;

/**
 * <code>RemoteManagedBufferFileImpl</code> provides a Remote wrapper for a managed 
 * (i.e., version controlled) buffer file enabling it to be passed or returned by 
 * other remote methods.  At the time of construction, the new instance is exported 
 * for remote access.
 */
public class RemoteManagedBufferFileImpl extends RemoteBufferFileImpl
		implements RemoteManagedBufferFileHandle {

	private LocalManagedBufferFile managedBufferFile;

	/**
	 * Construct (on the server) a remote buffer file which wraps a local buffer file on the server
	 * @param managedBufferFile underlying managed buffer file
	 * @param owner associated repository handle instance
	 * @param associatedFilePath associated file path for logging
	 * @throws RemoteException if failed to instantiate remote object
	 */
	public RemoteManagedBufferFileImpl(LocalManagedBufferFile managedBufferFile,
			RepositoryHandleImpl owner, String associatedFilePath) throws RemoteException {
		super(managedBufferFile, owner, associatedFilePath);
		this.managedBufferFile = managedBufferFile;
	}

	@Override
	public RemoteManagedBufferFileHandle getSaveFile() throws IOException {
		try {
			LocalManagedBufferFile sf = (LocalManagedBufferFile) managedBufferFile.getSaveFile();
			return sf != null ? new RemoteManagedBufferFileImpl(sf, owner, associatedFilePath) : null;
		}
		catch (Throwable t) {
			throw RemoteExceptionUtil.dispatchIOException(t, "getSaveFile: " + associatedFilePath,
				user);
		}
	}

	@Override
	public boolean delete() {
		if (managedBufferFile.getVersion() == 1) {
			owner.getRepository().log(associatedFilePath, "aborting file creation",
				owner.getUserName());
		}
		return super.delete();
	}

	@Override
	public void saveCompleted(boolean commit) throws IOException {
		try {
			if (!commit) {
				int version = managedBufferFile.getVersion();
				owner.getRepository().log(associatedFilePath,
					"aborting file version " + version + " creation", owner.getUserName());
			}
			managedBufferFile.saveCompleted(commit);
		}
		catch (Throwable t) {
			throw RemoteExceptionUtil.dispatchIOException(t, "saveCompleted: " + associatedFilePath,
				user);
		}
	}

	@Override
	public boolean canSave() {
		return managedBufferFile.canSave();
	}

	@Override
	public void setVersionComment(String comment) {
		managedBufferFile.setVersionComment(comment);
	}

	@Override
	public RemoteBufferFileHandle getNextChangeDataFile(boolean getFirst) throws IOException {
		try {
			LocalBufferFile cf =
				(LocalBufferFile) managedBufferFile.getNextChangeDataFile(getFirst);
			return cf != null ? new RemoteBufferFileImpl(cf, owner, associatedFilePath) : null;
		}
		catch (Throwable t) {
			throw RemoteExceptionUtil.dispatchIOException(t,
				"getNextChangeDataFile: " + associatedFilePath, user);
		}
	}

	@Override
	public RemoteBufferFileHandle getSaveChangeDataFile() throws IOException {
		try {
			LocalBufferFile cf = (LocalBufferFile) managedBufferFile.getSaveChangeDataFile();
			return cf != null ? new RemoteBufferFileImpl(cf, owner, associatedFilePath) : null;
		}
		catch (Throwable t) {
			throw RemoteExceptionUtil.dispatchIOException(t,
				"getSaveChangeDataFile: " + associatedFilePath, user);
		}
	}

	@Override
	public long getCheckinID() {
		return managedBufferFile.getCheckinID();
	}

	@Override
	public byte[] getForwardModMapData(int oldVersion) throws IOException {
		try {
			return managedBufferFile.getForwardModMapData(oldVersion);
		}
		catch (Throwable t) {
			throw RemoteExceptionUtil.dispatchIOException(t,
				"getForwardModMapData: " + associatedFilePath, user);
		}
	}

	@Override
	public InputBlockStream getInputBlockStream(byte[] changeMapData) throws IOException {
		throw new IOException("use of InputBlockStreamHandle required");
	}

	@Override
	public BlockStreamHandle<InputBlockStream> getInputBlockStreamHandle(byte[] changeMapData)
			throws IOException {
		try {
			BlockStreamServer blockStreamServer = BlockStreamServer.getBlockStreamServer();
			InputBlockStream inputBlockStream =
				managedBufferFile.getInputBlockStream(changeMapData);
			RemoteInputBlockStreamHandle streamHandle =
				new RemoteInputBlockStreamHandle(blockStreamServer, inputBlockStream);
			if (!blockStreamServer.registerBlockStream(streamHandle, inputBlockStream)) {
				throw new IOException("request failed: block stream server not running");
			}
			return streamHandle;
		}
		catch (Throwable t) {
			throw RemoteExceptionUtil.dispatchIOException(t,
				"getInputBlockStream with map: " + associatedFilePath, user);
		}
	}

}
