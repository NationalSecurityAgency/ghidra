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
package ghidra.framework.data;

import java.io.*;
import java.util.*;

import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.model.*;
import ghidra.framework.store.FileSystem;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.util.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

class GhidraFolderData {

	private ProjectFileManager fileManager;

	/**
	 * Folder change listener - change events only sent if folder is visited
	 * which is set when list of files or folders is requested.
	 * @see #getFileNames()
	 * @see #getFolderNames()
	 */
	private DomainFolderChangeListener listener;

	protected LocalFileSystem fileSystem;
	protected FileSystem versionedFileSystem;

	private GhidraFolderData parent;
	private String name;

	// folderList and fileList are only be used if visited is true
	private Set<String> folderList = new TreeSet<>();
	private Set<String> fileList = new TreeSet<>();
	private boolean visited; // true if full refresh was performed

	private Map<String, GhidraFileData> fileDataCache = new HashMap<>();
	private Map<String, GhidraFolderData> folderDataCache = new HashMap<>();

	private boolean folderExists;
	private boolean versionedFolderExists;

	/**
	 * General constructor reserved for root folder use only
	 * @param fileManager
	 * @param listener
	 */
	GhidraFolderData(ProjectFileManager fileManager, DomainFolderChangeListener listener) {
		this.fileManager = fileManager;
		this.fileSystem = fileManager.getLocalFileSystem();
		this.versionedFileSystem = fileManager.getVersionedFileSystem();
		this.listener = listener;
	}

	GhidraFolderData(GhidraFolderData parent, String name) throws FileNotFoundException {
		if (name == null || name.isEmpty()) {
			throw new FileNotFoundException("Bad folder name: blank or null");
		}
		this.parent = parent;
		this.name = name;

		this.fileManager = parent.getProjectFileManager();
		this.fileSystem = parent.getLocalFileSystem();
		this.versionedFileSystem = parent.getVersionedFileSystem();
		this.listener = parent.getChangeListener();

		try {
			updateExistenceState();
		}
		catch (Exception e) {
			// ignore
		}

		if (!folderExists && !versionedFolderExists) {
			throw new FileNotFoundException("folder " + name + " not found");
		}
	}

	/**
	 * Returns true if folder has complete list of children
	 */
	boolean visited() {
		return visited;
	}

	LocalFileSystem getLocalFileSystem() {
		return fileSystem;
	}

	FileSystem getVersionedFileSystem() {
		return versionedFileSystem;
	}

	LocalFileSystem getUserFileSystem() {
		return fileManager.getUserFileSystem();
	}

	DomainFolderChangeListener getChangeListener() {
		return listener;
	}

	ProjectFileManager getProjectFileManager() {
		return fileManager;
	}

	ProjectLocator getProjectLocator() {
		return fileManager.getProjectLocator();
	}

	GhidraFolderData getParentData() {
		return parent;
	}

	/**
	 * Get folder data for specified absolute or relative folderPath
	 * @param folderPath
	 * @param lazy if true folder will not be searched for if not already discovered - in
	 * this case null will be returned
	 * @return folder data or null if not found or lazy=true and not yet discovered
	 */
	GhidraFolderData getFolderPathData(String folderPath, boolean lazy) {
		if (parent == null) {
			if (folderPath.startsWith(FileSystem.SEPARATOR)) {
				folderPath = folderPath.substring(FileSystem.SEPARATOR.length());
			}
		}
		else if (folderPath.startsWith(FileSystem.SEPARATOR)) {
			return fileManager.getRootFolderData().getFolderPathData(folderPath, lazy);
		}
		if (folderPath.length() == 0) {
			return this;
		}
		int index = folderPath.indexOf(FileSystem.SEPARATOR);
		String nextPath = "";
		String nextName = folderPath;
		if (index > 0) {
			nextPath = folderPath.substring(index + 1);
			nextName = folderPath.substring(0, index);
		}
		else if (index == 0) {
			throw new IllegalArgumentException("Invalid path specified with double separator");
		}
		GhidraFolderData folderData = getFolderData(nextName, lazy);
		if (folderData == null) {
			return null;
		}
		if (nextPath.length() == 0) {
			return folderData;
		}
		return folderData.getFolderPathData(nextPath, lazy);
	}

	String getName() {
		return name;
	}

	GhidraFolder setName(String newName) throws InvalidNameException, IOException {
		synchronized (fileSystem) {
			if (parent == null || fileSystem.isReadOnly()) {
				throw new UnsupportedOperationException("setName not permitted on this folder");
			}
			updateExistenceState();
			checkInUse();
			boolean sendEvent = true;
			String oldName = name;
			String parentPath = parent.getPathname();
			if (folderExists) {
				fileSystem.renameFolder(parentPath, name, newName);
			}
			if (versionedFolderExists) {
				try {
					versionedFileSystem.renameFolder(parentPath, name, newName);
				}
				catch (IOException e) {
					sendEvent = false;
					if (folderExists) {
						fileSystem.renameFolder(parentPath, newName, name);
					}
					throw e;
				}
			}

			parent.folderDataCache.remove(name);

			name = newName;
			parent.folderDataCache.put(newName, this);

			fileDataCache.clear();
			folderDataCache.clear();

			GhidraFolder newFolder = getDomainFolder();

			if (parent.visited) {
				parent.folderList.remove(oldName);
				parent.folderList.add(newName);
				if (sendEvent) {
					listener.domainFolderRenamed(newFolder, oldName);
				}
			}
			return newFolder;
		}
	}

	private void checkInUse() throws FileInUseException {
		try {
			for (GhidraFolderData folder : folderDataCache.values()) {
				folder.checkInUse();
			}
			for (GhidraFileData file : fileDataCache.values()) {
				file.checkInUse();
			}
		}
		catch (FileInUseException e) {
			throw new FileInUseException(name + " has one or more files in use");
		}
	}

	String getPathname(String childName) {
		String path = getPathname();
		if (path.length() != FileSystem.SEPARATOR.length()) {
			path += FileSystem.SEPARATOR;
		}
		path += childName;
		return path;
	}

	String getPathname() {
		if (parent == null) {
			return FileSystem.SEPARATOR;
		}
		String path = parent.getPathname();
		if (path.length() != FileSystem.SEPARATOR.length()) {
			path += FileSystem.SEPARATOR;
		}
		path += name;
		return path;
	}

	boolean isEmpty() {
		try {
			refresh(false, false, null); // visited will be true upon return
			return folderList.isEmpty() && fileList.isEmpty();
		}
		catch (IOException e) {
			// ignore
		}
		return false;
	}

	List<String> getFileNames() {
		try {
			refresh(false, false, null); // visited will be true upon return
		}
		catch (IOException e) {
			Msg.error(this, "Folder refresh failed: " + e.getMessage());
			return new ArrayList<>();
		}
		return new ArrayList<>(fileList);
	}

	List<String> getFolderNames() {
		try {
			refresh(false, false, null); // visited will be true upon return
		}
		catch (IOException e) {
			Msg.error(this, "Folder refresh failed: " + e.getMessage());
			return new ArrayList<>();
		}
		return new ArrayList<>(folderList);
	}

	/**
	 * Update file list/cache based upon rename of file.
	 * If this folder has been visited listener will be notified with rename
	 * @param oldName
	 */
	void fileRenamed(String oldFileName, String newFileName) {
		GhidraFileData fileData;
		synchronized (fileSystem) {
			fileData = fileDataCache.remove(oldFileName);
			if (fileData == null || this != fileData.getParent() ||
				!newFileName.equals(fileData.getName())) {
				throw new AssertException();
			}
			if (visited) {
				fileList.remove(oldFileName);
			}
			if (visited) {
				fileList.add(newFileName);
			}
			fileDataCache.put(newFileName, fileData);
			if (visited) {
				listener.domainFileRenamed(getDomainFile(newFileName), oldFileName);
			}
		}
	}

	void fileMoved(GhidraFolderData newParent, String oldFileName, String newFileName) {
		GhidraFileData fileData;
		synchronized (fileSystem) {
			fileData = fileDataCache.remove(oldFileName);
			if (fileData == null || newParent != fileData.getParent() ||
				!newFileName.equals(fileData.getName())) {
				throw new AssertException();
			}
			if (visited) {
				fileList.remove(oldFileName);
			}
			if (newParent.visited) {
				newParent.fileList.add(newFileName);
			}
			newParent.fileDataCache.put(newFileName, fileData);
		}
		if (visited || newParent.visited) {
			listener.domainFileMoved(fileData.getDomainFile(), getDomainFolder(), oldFileName);
		}
	}

	/**
	 * Notification that the specified file has changed due to an add or remove of the
	 * underlying local or versioned file.  If this folder has been visited an appropriate
	 * add/remove/change notification will be provided to the listener.
	 * NOTE: Move and Rename situations are not handled
	 * @param fileName
	 */
	void fileChanged(String fileName) {
		synchronized (fileSystem) {
			GhidraFileData fileData = fileDataCache.get(fileName);
			if (fileData != null) {
				String fileID = fileData.getFileID();
				try {
					fileData.statusChanged();
				}
				catch (IOException e) {
					fileData.dispose();
					fileDataCache.remove(fileName);
					if (visited) {
						fileList.remove(fileName);
						listener.domainFileRemoved(getDomainFolder(), fileName, fileID);
					}
				}
				return;
			}
			if (visited) {
				try {
					fileData = addFileData(fileName);
				}
				catch (IOException e) {
					// ignore
				}
				if (fileData == null) {
					if (fileList.remove(fileName)) {
						listener.domainFileRemoved(getDomainFolder(), fileName, null);
					}
				}
				else if (fileList.add(fileName)) {
					listener.domainFileAdded(fileData.getDomainFile());
				}
				else {
					listener.domainFileStatusChanged(fileData.getDomainFile(), false);
				}
			}
		}
	}

	/**
	 * Notification that the specified subfolder has changed due to and add or remove of the
	 * underlying local or version folder.  If the subfolder previously existed, still exists,
	 * and had been visited a refresh on the subfolder will be forced, otherwise, if this folder has been 
	 * visited an appropriate add/remove/change notification will be provided to the listener.  
	 * NOTE: Care should be taken using this method as all sub-folder cache data may be disposed!
	 * NOTE: Move and Rename situations are not handled
	 * @param folderName
	 */
	void folderChanged(String folderName) throws IOException {
		synchronized (fileSystem) {
			GhidraFolderData folderData = folderDataCache.get(folderName);
			if (folderData != null) {
				try {
					folderData.updateExistenceState();
				}
				catch (IOException e) {
					// ignore
				}
				if (folderData.versionedFolderExists || folderData.folderExists) {
					// preserve subfolder data
					if (folderData.visited) {
						folderData.refresh(true, true, fileManager.getProjectDisposalMonitor());
					}
					return;
				}
				folderDataCache.remove(folderName);
				folderData.dispose();
				folderData = null;
			}
			if (visited) {
				folderData = addFolderData(folderName);
				if (folderData == null) {
					if (folderList.remove(folderName)) {
						listener.domainFolderRemoved(getDomainFolder(), folderName);
					}
				}
				else if (folderList.add(folderName)) {
					listener.domainFolderAdded(folderData.getDomainFolder());
				}
			}
		}
	}

	/**
	 * Remove and dispose specified subfolder data and notify listener of removal
	 * if this folder has been visited
	 * @param folderName
	 */
	void folderRemoved(String folderName) {
		synchronized (fileSystem) {
			GhidraFolderData folderData = folderDataCache.remove(folderName);
			if (folderData != null) {
				folderData.dispose();
			}
			if (visited && folderList.remove(folderName)) {
				listener.domainFolderRemoved(getDomainFolder(), folderName);
			}
		}
	}

	void dispose() {
		visited = false;
		folderList.clear();
		fileList.clear();
		for (GhidraFolderData folderData : folderDataCache.values()) {
			folderData.dispose();
		}
		folderDataCache.clear();
		for (GhidraFileData fileData : fileDataCache.values()) {
			fileData.dispose();
		}
		fileDataCache.clear();
// NOTE: clearing the following can cause issues since there may be some residual 
// activity/use which will get a NPE
//		parent = null;
//		fileManager = null;
//		listener = null;
	}

	/**
	 * Update the values for whether this pathname exists in the private and
	 * shared file systems.
	 */
	private void updateExistenceState() throws IOException {
		folderExists = fileSystem.folderExists(getPathname());
		versionedFolderExists =
			versionedFileSystem.isOnline() && versionedFileSystem.folderExists(getPathname());
	}

	/**
	 * Refresh set of sub-folder names and identify added/removed folders.
	 * @param recursive recurse into visited subfolders if true
	 * @param monitor recursion task monitor - break from recursion if cancelled
	 * @throws IOException
	 */
	private void refreshFolders(boolean recursive, TaskMonitor monitor) throws IOException {

		String path = getPathname();
		HashSet<String> newSet = new HashSet<>();

		if (folderExists) {
			try {
				String[] folders = fileSystem.getFolderNames(path);
				newSet.addAll(Arrays.asList(folders));
			}
			catch (IOException e) {
				if (parent != null) {
					parent.folderRemoved(name);
				}
				throw e;
			}
		}
		if (versionedFolderExists) {
			try {
				String[] folders = versionedFileSystem.getFolderNames(path);
				newSet.addAll(Arrays.asList(folders));
			}
			catch (Exception e) {
				Msg.error(this, "versioned folder refresh failed: " + e.getMessage());
				versionedFolderExists = false;
			}
		}

		HashSet<String> oldSet = new HashSet<>();
		for (String folder : folderList) {
			oldSet.add(folder);
		}
		HashSet<String> oldSetClone = new HashSet<>(oldSet);
		// find deleted folders
		oldSet.removeAll(newSet);
		for (String folderName : oldSet) {
			GhidraFolderData folderData = folderDataCache.remove(folderName);
			if (folderData != null) {
				folderData.dispose();
			}
			folderList.remove(folderName);
			if (visited) {
				listener.domainFolderRemoved(getDomainFolder(), folderName);
			}
		}

		// Recurse through pre-existing folders
		if (recursive) {
			for (String folderName : folderList) {
				if (monitor != null && monitor.isCancelled()) {
					break; // break-out from recursion on cancel
				}
				GhidraFolderData folderData = folderDataCache.get(folderName);
				if (folderData != null && folderData.visited) {
					folderData.refresh(true, true, monitor);
				}
			}
		}

		// find new folders
		newSet.removeAll(oldSetClone);
		for (String folderName : newSet) {
			GhidraFolderData folderData = addFolderData(folderName);
			if (folderData != null) {
				folderList.add(folderName);
				if (visited) {
					listener.domainFolderAdded(folderData.getDomainFolder());
				}
			}
		}
	}

	private void refreshFiles(TaskMonitor monitor) throws IOException {

		String path = getPathname();

		boolean hadError = false;

		HashSet<String> newSet = new HashSet<>();
		if (folderExists) {
			try {
				String[] items = fileSystem.getItemNames(path);
				newSet.addAll(Arrays.asList(items));
			}
			catch (IOException e) {
				if (parent != null) {
					parent.folderRemoved(name);
				}
				throw e;
			}
		}
		if (versionedFolderExists) {
			try {
				String[] items = versionedFileSystem.getItemNames(path);
				newSet.addAll(Arrays.asList(items));
			}
			catch (Exception e) {
				Msg.error(this, "versioned folder refresh failed: " + e.getMessage());
				versionedFolderExists = false;
			}
		}

		HashSet<String> oldSet = new HashSet<>();
		for (String file : fileList) {
			oldSet.add(file);
		}
		HashSet<String> oldSetClone = new HashSet<>(oldSet);

		// find deleted files
		oldSet.removeAll(newSet);
		for (String fileName : oldSet) {
			fileRemoved(fileName);
		}

		// refresh existing
		for (String fileName : fileList.toArray(new String[fileList.size()])) {
			GhidraFileData fileData = fileDataCache.get(fileName);
			if (fileData != null) {
				try {
					fileData.statusChanged();
				}
				catch (IOException e) {
					if (!(e instanceof FileNotFoundException)) {
						if (hadError) {
							throw e;
						}
						hadError = true; // tolerate single file error and remove file reference
						Msg.error(this,
							"Domain File error on " + fileData.getPathname() + ": " + e.toString());
					}
					fileRemoved(fileName);
				}
			}
		}

		// find new files
		newSet.removeAll(oldSetClone);
		for (String fileName : newSet) {
			if (monitor != null && monitor.isCancelled()) {
				break;
			}
			GhidraFileData fileData = addFileData(fileName);
			if (fileData != null) {
				fileList.add(fileName);
				if (visited) {
					listener.domainFileAdded(fileData.getDomainFile());
				}
			}
		}
	}

	private void fileRemoved(String filename) {
		String fileID = null;
		GhidraFileData fileData = fileDataCache.remove(filename);
		if (fileData != null) {
			fileID = fileData.getFileID();
			fileData.dispose();
		}
		fileList.remove(filename);
		if (visited) {
			listener.domainFileRemoved(getDomainFolder(), filename, fileID);
		}
	}

	/**
	 * Full refresh of names of children is performed.  This method
	 * should only be invoked when a full list of folders or
	 * children is requested - which may be in response to 
	 * a "folder changed" notification.
	 * @param recursive if true a recursive refresh will be done (force must also be true).
	 * Sub-folders will only be refreshed if they have been visited.
	 * @param force if true will refresh will be forced regardless
	 * of visited state, if false refresh is lazy and will not be 
	 * performed if a previous refresh set the visited state.
	 * @param monitor recursion task monitor - break from recursion if cancelled
	 * @throws IOException
	 */
	void refresh(boolean recursive, boolean force, TaskMonitor monitor) throws IOException {
		synchronized (fileSystem) {
			if (recursive && !force) {
				throw new IllegalArgumentException("force must be true when recursive");
			}
			if (monitor != null && monitor.isCancelled()) {
				return;
			}
			if (visited && !force) {
				return;
			}
			try {
				updateExistenceState();
			}
			catch (IOException e) {
				if (parent != null) {
					parent.folderRemoved(name);
				}
				throw e;
			}

			if (!folderExists && !versionedFolderExists) {
				if (parent != null) {
					parent.folderRemoved(name);
				}
				throw new FileNotFoundException("Folder not found: " + getPathname());
			}

			try {
				refreshFiles(monitor);

				if (monitor != null && monitor.isCancelled()) {
					return; // break-out from recursion on cancel
				}

				refreshFolders(recursive, monitor);
			}
			finally {
				visited = true;
			}
		}
	}

	/**
	 * Check for existence of subfolder.  If this folder visited, rely on folderList
	 * @param fileName
	 * @param doRealCheck if true do not rely on fileList
	 * @return
	 * @throws IOException
	 */
	boolean containsFolder(String folderName) throws IOException {
		synchronized (fileSystem) {
			if (folderDataCache.containsKey(folderName)) {
				return true;
			}
			if (visited) {
				return folderList.contains(folderName);
			}
			return addFolderData(folderName) != null;
		}
	}

	/**
	 * Create and add new subfolder data object to cache.  Data will not be created
	 * if folder does not exist or an IOException occurs.
	 * @param folderName
	 * @return folder data or null
	 */
	private GhidraFolderData addFolderData(String folderName) {
		GhidraFolderData folderData = folderDataCache.get(folderName);
		if (folderData == null) {
			try {
				folderData = new GhidraFolderData(this, folderName);
				folderDataCache.put(folderName, folderData);
			}
			catch (FileNotFoundException e) {
				// ignore
			}
		}
		return folderData;
	}

	/**
	 * Get folder data for child folder specified by folderName
	 * @param folderName
	 * @param lazy if true folder will not be searched for if not already discovered - in
	 * this case null will be returned
	 * @return folder data or null if not found or lazy=true and not yet discovered
	 */
	GhidraFolderData getFolderData(String folderName, boolean lazy) {
		synchronized (fileSystem) {
			try {
				if (lazy || containsFolder(folderName)) {
					GhidraFolderData folderData = folderDataCache.get(folderName);
					if (folderData == null) {
						folderData = addFolderData(folderName);
					}
					return folderData;
				}
			}
			catch (IOException e) {
				// ignore
			}
		}
		return null;
	}

	/**
	 * Check for existence of file.  If folder visited, rely on fileDataCache
	 * @param fileName the name of the file to check for
	 * @return true if this folder contains the fileName
	 * @throws IOException
	 */
	public boolean containsFile(String fileName) throws IOException {
		synchronized (fileSystem) {
			if (fileDataCache.containsKey(fileName)) {
				return true;
			}
			if (visited) {
				return fileList.contains(fileName);
			}
			return addFileData(fileName) != null;
		}
	}

	/**
	 * Create and add new file data object to cache.  Data will not be created
	 * if file does not exist or an IOException occurs.
	 * @param fileName
	 * @return file data or null
	 * @throws IOException
	 */
	private GhidraFileData addFileData(String fileName) throws IOException {
		GhidraFileData fileData = fileDataCache.get(fileName);
		if (fileData == null) {
			try {
				fileData = new GhidraFileData(this, fileName);
				fileDataCache.put(fileName, fileData);
				fileManager.updateFileIndex(fileData);
			}
			catch (FileNotFoundException e) {
				// ignore
			}
		}
		return fileData;
	}

	/**
	 * Get file data for child specified by fileName
	 * @param fileName
	 * @param lazy if true file will not be searched for if not already discovered - in
	 * this case null will be returned
	 * @return file data or null if not found or lazy=true and not yet discovered
	 */
	GhidraFileData getFileData(String fileName, boolean lazy) throws IOException {
		synchronized (fileSystem) {
			if (lazy || containsFile(fileName)) {
				GhidraFileData fileData = fileDataCache.get(fileName);
				if (fileData == null) {
					fileData = addFileData(fileName);
				}
				return fileData;
			}
		}
		return null;
	}

//	// TODO: Examine!
//	private void removeFolderX(String folderName) {
//		folderList.remove(folderName);
//		folderDataCache.remove(folderName);
//		listener.domainFolderRemoved(getDomainFolder(), folderName);
//	}
//
//	// TODO: Examine!
//	void removeFileX(String fileName) {
//		fileList.remove(fileName);
//		GhidraFileV2Data fileData = fileDataCache.remove(fileName);
//		if (fileData != null) {
//			fileData.dispose();
//		}
//// TODO: May need to eliminate presence of fileID in callback
//		listener.domainFileRemoved(getDomainFolder(), fileName, null /* fileID */);
//	}
//
//	/**
//	 * Handle addition of new file.  If this folder has been visited, listener
//	 * will be notified of new file addition or change
//	 * @param fileName
//	 * @return
//	 */
//	// TODO: Examine!
//	GhidraFile fileAddedX(String fileName) {
//		invalidateFile(fileName);
//		GhidraFile df = getDomainFile(fileName);
//		if (visited) {
//			getFileData(fileName, false);
//			if (fileList.add(fileName)) {
//				listener.domainFileAdded(df);
//			}
//			else {
//				listenerX.domainFileStatusChanged(df, fileID)
//			}
//		}
//		return df;
//	}
//

//
//	// TODO: Examine!
//	private GhidraFolder addFolderX(String folderName) {
//		invalidateFolder(folderName, false);
//		GhidraFolder folder = getDomainFolder(folderName);
//		if (folderList.add(folderName) && visited) {
//			listener.domainFolderAdded(folder);
//		}
//		return folder;
//	}

	GhidraFile getDomainFile(String fileName) {
		synchronized (fileSystem) {
			try {
				if (containsFile(fileName)) {
					return new GhidraFile(getDomainFolder(), fileName);
				}
			}
			catch (IOException e) {
				// ignore
			}
		}
		return null;
	}

	GhidraFolder getDomainFolder(String subfolderName) {
		synchronized (fileSystem) {
			try {
				if (containsFolder(subfolderName)) {
					return new GhidraFolder(getDomainFolder(), subfolderName);
				}
			}
			catch (IOException e) {
				// ignore
			}
		}
		return null;
	}

	GhidraFolder getDomainFolder() {
		return new GhidraFolder(parent.getDomainFolder(), name);
	}

	GhidraFile createFile(String fileName, DomainObject obj, TaskMonitor monitor)
			throws InvalidNameException, IOException, CancelledException {
		synchronized (fileSystem) {
			if (fileSystem.isReadOnly()) {
				throw new AssertException("createFile permitted within writeable project only");
			}
			DomainObjectAdapter doa = (DomainObjectAdapter) obj;

			if (doa.isClosed()) {
				throw new ClosedException();
			}
			if (!doa.lock(null)) {
				throw new IOException("Object is busy and can not be saved");
			}

			DomainFile oldDf = doa.getDomainFile();
			try {
				ContentHandler ch = DomainObjectAdapter.getContentHandler(doa);
				ch.createFile(fileSystem, null, getPathname(), fileName, obj, monitor);

				if (oldDf != null) {
					listener.domainFileObjectClosed(oldDf, doa);
				}

				fileChanged(fileName);

				GhidraFile file = getDomainFile(fileName);
				if (file == null) {
					throw new IOException("File creation failed for unknown reason");
				}

				fileManager.setDomainObject(file.getPathname(), doa);
				doa.setDomainFile(file);
				doa.setChanged(false);
				listener.domainFileObjectOpenedForUpdate(file, doa);

				return file;
			}
			finally {
				doa.unlock();
			}
		}
	}

	GhidraFile createFile(String fileName, File packFile, TaskMonitor monitor)
			throws InvalidNameException, IOException, CancelledException {
		synchronized (fileSystem) {
			if (fileSystem.isReadOnly()) {
				throw new AssertException("createFile permitted within writeable project only");
			}
			fileSystem.createFile(getPathname(), fileName, packFile, monitor,
				SystemUtilities.getUserName());

			fileChanged(fileName);

			GhidraFile file = getDomainFile(fileName);
			if (file == null) {
				throw new IOException("File creation failed for unknown reason");
			}
			return file;
		}
	}

	GhidraFolderData createFolder(String folderName) throws InvalidNameException, IOException {
		synchronized (fileSystem) {
			if (fileSystem.isReadOnly()) {
				throw new AssertException("createFile permitted within writeable project only");
			}
			fileSystem.createFolder(getPathname(), folderName);
			folderChanged(folderName);

			if (!containsFolder(folderName)) {
				throw new IOException("Folder creation failed for unknown reason");
			}
			return folderDataCache.get(folderName);
		}
	}

	void delete() throws IOException {
		synchronized (fileSystem) {
			if (fileSystem.isReadOnly()) {
				throw new AssertException("delete permitted within writeable project only");
			}
			checkInUse();
			try {
				fileSystem.deleteFolder(getPathname());
			}
			catch (FileNotFoundException e) {
				// ignore
			}
			parent.folderChanged(name);
		}
	}

	void deleteLocalFolderIfEmpty() {
		synchronized (fileSystem) {
			try {
				String path = getPathname();
				if (fileSystem.getFolderNames(path).length != 0) {
					return;
				}
				if (fileSystem.getItemNames(path).length != 0) {
					return;
				}
				delete();
			}
			catch (IOException e) {
				// ignore
			}
		}
	}

	GhidraFolder moveTo(GhidraFolderData newParent) throws IOException {
		synchronized (fileSystem) {
			if (newParent.getLocalFileSystem() != fileSystem || fileSystem.isReadOnly()) {
				throw new AssertException("moveTo permitted within writeable project only");
			}
			if (getPathname().equals(newParent.getPathname())) {
				throw new IllegalArgumentException("newParent must differ from current parent");
			}
			checkInUse();
			boolean sendEvent = true;

			updateExistenceState();
			try {
				if (newParent.containsFolder(name)) {
					throw new DuplicateFileException(
						"Folder named " + getName() + " already exists in " + newParent);
				}

				if (folderExists) {
					fileSystem.moveFolder(parent.getPathname(), name, newParent.getPathname());
				}
				if (versionedFolderExists) {
					try {
						versionedFileSystem.moveFolder(parent.getPathname(), name,
							newParent.getPathname());
					}
					catch (IOException e) {
						sendEvent = false;
						if (folderExists) {
							fileSystem.moveFolder(newParent.getPathname(), name,
								parent.getPathname());
						}
						throw e;
					}
				}

				DomainFolder oldParent = parent.getDomainFolder();

				if (parent.visited) {
					parent.folderList.remove(name);
				}
				parent.folderDataCache.remove(name);

				fileDataCache.clear();
				folderDataCache.clear();

				if (newParent.visited) {
					newParent.folderList.add(name);
				}
				newParent.folderDataCache.put(name, this);

				parent = newParent;
				GhidraFolder newFolder = getDomainFolder();

				if (sendEvent && (parent.visited || newParent.visited)) {
					listener.domainFolderMoved(newFolder, oldParent);
				}

				return newFolder;
			}
			catch (InvalidNameException e) {
				throw new AssertException("Unexpected error", e);
			}
		}
	}

	boolean isAncestor(GhidraFolderData folderData) {
		if (!folderData.fileManager.getProjectLocator().equals(fileManager.getProjectLocator())) {
			// check if projects share a common repository
			RepositoryAdapter myRepository = fileManager.getRepository();
			RepositoryAdapter otherRepository = folderData.fileManager.getRepository();
			if (myRepository == null || otherRepository == null ||
				!myRepository.getServerInfo().equals(otherRepository.getServerInfo()) ||
				!myRepository.getName().equals(otherRepository.getName())) {
				return false;
			}
		}
		GhidraFolderData checkParent = folderData;
		while (checkParent != null) {
			if (checkParent.equals(this)) {
				return true;
			}
			checkParent = checkParent.getParentData();
		}
		return false;
	}

	GhidraFolder copyTo(GhidraFolderData newParentData, TaskMonitor monitor)
			throws IOException, CancelledException {
		synchronized (fileSystem) {
			if (newParentData.fileSystem.isReadOnly()) {
				throw new ReadOnlyException("copyTo permitted to writeable project only");
			}
			if (isAncestor(newParentData)) {
				throw new IOException("self-referencing copy not permitted");
			}
			GhidraFolderData newFolderData = newParentData.getFolderData(name, false);

			if (newFolderData == null) {
				try {
					newFolderData = newParentData.createFolder(name);
				}
				catch (InvalidNameException e) {
					throw new AssertException("Unexpected error", e);
				}
			}
			List<String> files = getFileNames();
			for (String file : files) {
				monitor.checkCanceled();
				GhidraFileData fileData = getFileData(file, false);
				if (fileData != null) {
					fileData.copyTo(newFolderData, monitor);
				}
			}
			List<String> folders = getFolderNames();
			for (String folder : folders) {
				monitor.checkCanceled();
				GhidraFolderData folderData = getFolderData(folder, false);
				if (folderData != null) {
					folderData.copyTo(newFolderData, monitor);
				}
			}
			return newFolderData.getDomainFolder();
		}
	}

	/**
	 * used for testing
	 */
	boolean privateExists() {
		return folderExists;
	}

	/**
	 * used for testing
	 */
	boolean sharedExists() {
		return versionedFolderExists;
	}

	@Override
	public String toString() {
		return fileManager.getProjectLocator().getName() + ":" + getPathname();
	}

}
