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
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.rmi.server.Unreferenced;
import java.util.*;

import ghidra.framework.remote.RemoteRepositoryHandle;
import ghidra.server.RepositoryManager;
import ghidra.server.remote.*;
import ghidra.server.stream.*;

/**
 * <code>RemoteBufferFileImpl</code> provides a Remote wrapper for a buffer file
 * enabling it to be passed or returned by other remote methods.  At the time of construction, 
 * the new instance is exported for remote access.
 */
public class RemoteBufferFileImpl extends UnicastRemoteObject
		implements RemoteBufferFileHandle, Unreferenced {

	// Tracks open handles by user repository connection: maps repository handle instance to list of open file handles
	private static HashMap<RemoteRepositoryHandle, List<RemoteBufferFileImpl>> instanceOwnerMap =
		new HashMap<>();

	// Tracks open handles by path: maps "repo-name:<file-path>" to list of open buffer file handles
	private static HashMap<String, List<RemoteBufferFileImpl>> instancePathMap = new HashMap<>();

	protected final RepositoryHandleImpl owner;
	protected final String associatedFilePath;

	private LocalBufferFile bufferFile;
	private String clientHost;

	/**
	 * Construct a remote wrapper for a buffer file.
	 * @param bufferFile buffer file
	 * @param owner owner object to which this instance should be associated.
	 * @param associatedFilePath repository path of file item associated with this buffer file
	 * @throws RemoteException
	 */
	public RemoteBufferFileImpl(LocalBufferFile bufferFile, RepositoryHandleImpl owner,
			String associatedFilePath) throws RemoteException {
		super(ServerPortFactory.getRMISSLPort(), GhidraServer.getRMIClientSocketFactory(),
			GhidraServer.getRMIServerSocketFactory());
		this.bufferFile = bufferFile;
		this.owner = owner;
		this.associatedFilePath = associatedFilePath;
		if (owner == null || associatedFilePath == null) {
			throw new IllegalArgumentException("Missing one or more required arguments");
		}
		this.clientHost = RepositoryManager.getRMIClient();
		addInstance(this);
//System.out.println("Constructed remote buffer file (" + instanceID + "): " + bufferFile);
	}

	private static String getFilePathKey(RemoteBufferFileImpl rbf) {
		return getFilePathKey(rbf.owner.getRepository().getName(), rbf.associatedFilePath);
	}

	private static String getFilePathKey(String repoName, String filePath) {
		return repoName + ":" + filePath;
	}

	private static synchronized void addInstance(RemoteBufferFileImpl rbf) {
		// Keep a list of RemoteBufferFileImpl's for each owner
		List<RemoteBufferFileImpl> list = instanceOwnerMap.get(rbf.owner);
		if (list == null) {
			list = new ArrayList<>();
			instanceOwnerMap.put(rbf.owner, list);
		}
		list.add(rbf);

		String filePathKey = getFilePathKey(rbf);
		list = instancePathMap.get(filePathKey);
		if (list == null) {
			list = new ArrayList<>();
			instancePathMap.put(filePathKey, list);
		}
		list.add(rbf);
		rbf.owner.fireOpenFileCountChanged();
	}

	private static synchronized void removeOwnerInstance(RemoteBufferFileImpl rbf) {
		List<RemoteBufferFileImpl> list = instanceOwnerMap.get(rbf.owner);
		if (list != null && list.remove(rbf)) {
			if (list.isEmpty()) {
				instanceOwnerMap.remove(rbf.owner);
			}
			rbf.owner.fireOpenFileCountChanged();
		}
	}

	private static synchronized void removePathInstance(RemoteBufferFileImpl rbf) {
		String filePathKey = getFilePathKey(rbf);
		List<RemoteBufferFileImpl> list = instancePathMap.get(filePathKey);
		if (list != null && list.remove(rbf)) {
			if (list.isEmpty()) {
				instancePathMap.remove(filePathKey);
			}
		}
	}

	/**
	 * Get the number of open RemoteBufferFileHandle's associated with the 
	 * specified owner repository handle. 
	 * @param owner owner's repository handle
	 * @return number of open remote buffer file handles associated with owner
	 */
	public static synchronized int getOpenFileCount(RepositoryHandleImpl owner) {
		List<RemoteBufferFileImpl> list = instanceOwnerMap.get(owner);
		if (list != null) {
			return list.size();
		}
		return 0;
	}

	/**
	 * Return user name@host associated with open file handle.
	 */
	public String getUserClient() {
		if (clientHost != null) {
			return owner.getUserName() + "@" + clientHost;
		}
		return owner.getUserName();
	}

	/**
	 * Returns list of users with open handles associated with the specified filePath.
	 * @param filePath file path
	 */
	public static String[] getOpenFileUsers(String repoName, String filePath) {
		String filePathKey = getFilePathKey(repoName, filePath);
		List<RemoteBufferFileImpl> rbfList = instancePathMap.get(filePathKey);
		if (rbfList != null) {
			HashSet<String> set = new HashSet<>();
			for (RemoteBufferFileImpl rbf : rbfList) {
				set.add(rbf.getUserClient());
			}
			String[] names = new String[set.size()];
			int index = 0;
			for (String name : set) {
				names[index++] = name;
			}
			return names;
		}
		return null;
	}

	/**
	 * RMI callback when instance becomes unreferenced by any remote client
	 */
	@Override
	public void unreferenced() {
		dispose();
	}

	/**
	 * Dispose and unexport all RemoteBufferFileImpl instances associated with the 
	 * specified owner.
	 * @param owner
	 * @return true if one or more buffer files were disposed.
	 */
	public static synchronized boolean dispose(Object owner) {
		boolean found = false;
		List<RemoteBufferFileImpl> list = instanceOwnerMap.remove(owner);
		if (list != null) {
			for (RemoteBufferFileImpl rbf : list) {
				found = true;
				rbf.dispose();
			}
		}
		if (found) {
			// If files were found, may need to repeat since pre-save
			// files may have been constructed during dispose
			dispose(owner);
		}
		return found;
	}

	/**
	 * Dispose associated buffer file and unexport this instance.
	 */
	@Override
	public void dispose() {
		if (bufferFile != null) {
			try {
				unexportObject(this, true);
			}
			catch (NoSuchObjectException e) {
				// ignore
			}
			removeOwnerInstance(this);
			removePathInstance(this);
			bufferFile.dispose();
			bufferFile = null;
		}
	}

	@Override
	public int getParameter(String name) throws NoSuchElementException, IOException {
		return bufferFile.getParameter(name);
	}

	@Override
	public void setParameter(String name, int value) throws IOException {
		bufferFile.setParameter(name, value);
	}

	@Override
	public void clearParameters() throws IOException {
		bufferFile.clearParameters();
	}

	@Override
	public String[] getParameterNames() throws IOException {
		return bufferFile.getParameterNames();
	}

	@Override
	public int getBufferSize() throws IOException {
		return bufferFile.getBufferSize();
	}

	@Override
	public int getIndexCount() throws IOException {
		return bufferFile.getIndexCount();
	}

	@Override
	public int[] getFreeIndexes() throws IOException {
		return bufferFile.getFreeIndexes();
	}

	@Override
	public void setFreeIndexes(int[] indexes) throws IOException {
		bufferFile.setFreeIndexes(indexes);
	}

	@Override
	public boolean isReadOnly() throws IOException {
		return bufferFile.isReadOnly();
	}

	@Override
	public boolean setReadOnly() throws IOException {
		return bufferFile.setReadOnly();
	}

	@Override
	public void close() throws IOException {
		bufferFile.close();
		dispose();
	}

	@Override
	public boolean delete() throws IOException {
		boolean rc = false;
		try {
			rc = bufferFile.delete();
		}
		finally {
			dispose();
		}
		return rc;
	}

	@Override
	public DataBuffer get(int index) throws IOException {
		return bufferFile.get(new DataBuffer(), index);
	}

	@Override
	public void put(DataBuffer buf, int index) throws IOException {
		bufferFile.put(buf, index);
	}

	@Override
	public InputBlockStream getInputBlockStream() throws IOException {
		throw new IOException("use of InputBlockStreamHandle required");
	}

	@Override
	public OutputBlockStream getOutputBlockStream(int blockCount) throws IOException {
		throw new IOException("use of OutputBlockStreamHandle required");
	}

	@Override
	public BlockStreamHandle<InputBlockStream> getInputBlockStreamHandle() throws IOException {
		BlockStreamServer blockStreamServer = BlockStreamServer.getBlockStreamServer();
		InputBlockStream inputBlockStream = bufferFile.getInputBlockStream();
		RemoteInputBlockStreamHandle streamHandle =
			new RemoteInputBlockStreamHandle(blockStreamServer, inputBlockStream);
		if (!blockStreamServer.registerBlockStream(streamHandle, inputBlockStream)) {
			throw new IOException("request failed: block stream server not running");
		}
		return streamHandle;
	}

	@Override
	public BlockStreamHandle<OutputBlockStream> getOutputBlockStreamHandle(int blockCount)
			throws IOException {
		BlockStreamServer blockStreamServer = BlockStreamServer.getBlockStreamServer();
		OutputBlockStream outputBlockStream = bufferFile.getOutputBlockStream(blockCount);
		RemoteOutputBlockStreamHandle streamHandle = new RemoteOutputBlockStreamHandle(
			blockStreamServer, blockCount, outputBlockStream.getBlockSize());
		if (!blockStreamServer.registerBlockStream(streamHandle, outputBlockStream)) {
			throw new IOException("request failed: block stream server not running");
		}
		return streamHandle;
	}

}
