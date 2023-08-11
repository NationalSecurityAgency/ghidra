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
import java.net.URL;
import java.util.*;

import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.model.*;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.framework.protocol.ghidra.TransientProjectData;
import ghidra.framework.store.FileSystem;
import ghidra.framework.store.FolderNotEmptyException;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.util.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * {@link GhidraFolderData} provides the managed object which represents a project folder that 
 * corresponds to matched folder paths across both a versioned and private 
 * filesystem and viewed as a single folder at the project level.  This class closely mirrors the
 * {@link DomainFolder} interface and is used by the {@link GhidraFolder} implementation; both of which
 * represent immutable folder references.  Changes made to this folder's name or path are not reflected 
 * in old {@link DomainFolder} instances and must be re-instantiated following such a change.  
 * Any long-term retention of {@link DomainFolder} and {@link DomainFile} instances requires an 
 * appropriate change listener to properly discard/reacquire such instances.
 */
class GhidraFolderData {

	private DefaultProjectData projectData;

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
	 * General constructor reserved for root folder instantiation
	 * @param projectData associated project data instance
	 * @param listener folder change listener
	 */
	GhidraFolderData(DefaultProjectData projectData, DomainFolderChangeListener listener) {
		this.projectData = projectData;
		this.fileSystem = projectData.getLocalFileSystem();
		this.versionedFileSystem = projectData.getVersionedFileSystem();
		this.listener = listener;
	}

	/**
	 * Construct a folder instance with a specified name and a correpsonding parent folder
	 * @param parent parent folder
	 * @param name folder name
	 * @throws FileNotFoundException if folder not found or error occured while checking
	 * for its existance
	 */
	GhidraFolderData(GhidraFolderData parent, String name) throws FileNotFoundException {
		if (name == null || name.isEmpty()) {
			throw new FileNotFoundException("Bad folder name: blank or null");
		}
		this.parent = parent;
		this.name = name;

		this.projectData = parent.getProjectData();
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
	 * @return true if folder has complete list of children
	 */
	boolean visited() {
		return visited;
	}

	/**
	 * @return local file system
	 */
	LocalFileSystem getLocalFileSystem() {
		return fileSystem;
	}

	/**
	 * @return versioned file system
	 */
	FileSystem getVersionedFileSystem() {
		return versionedFileSystem;
	}

	/**
	 * @return local user data file system
	 */
	LocalFileSystem getUserFileSystem() {
		return projectData.getUserFileSystem();
	}

	/**
	 * @return folder change listener
	 */
	DomainFolderChangeListener getChangeListener() {
		return listener;
	}

	/**
	 * @return project data instance
	 */
	DefaultProjectData getProjectData() {
		return projectData;
	}

	/**
	 * Get the project locator which identifies the system storage
	 * are for the local file system and other project related resources.
	 * @return local project locator
	 */
	ProjectLocator getProjectLocator() {
		return projectData.getProjectLocator();
	}

	/**
	 * @return this folder's parent folder or null if this is the root folder.
	 */
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
			return projectData.getRootFolderData().getFolderPathData(folderPath, lazy);
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

	/**
	 * Return this folder's name.
	 * @return the name
	 */
	String getName() {
		return name;
	}

	/**
	 * Set the name on this domain folder.
	 * @param newName domain folder name
	 * @return renamed domain file (the original DomainFolder object becomes invalid since it is 
	 * immutable)
	 * @throws InvalidNameException if newName contains illegal characters
	 * @throws DuplicateFileException if a folder named newName 
	 * already exists in this files domain folder.
	 * @throws FileInUseException if any file within this folder or its descendants is 
	 * in-use / checked-out.
	 * @throws IOException thrown if an IO or access error occurs.
	 */
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

	/**
	 * Returns the full path name to this folder
	 * @return the path name
	 */
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

	/**
	 * Determine if this folder contains any sub-folders or domain files.
	 * @return true if this folder is empty.
	 */
	boolean isEmpty() {
		try {
			refresh(false, false, null); // visited will be true upon return
			return folderList.isEmpty() && fileList.isEmpty();
		}
		catch (IOException e) {
			// TODO: what should we return if folder not found or error occurs?
			// True is returned to allow this method to be used to avoid continued access.
			return true;
		}
	}

	/**
	 * Get the list of names for all files contained within this folder.
	 * @return list of file names
	 */
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

	/**
	 * Get the list of names for all subfolders contained within this folder.
	 * @return list of file names
	 */
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
	 * Update file list/cache based upon rename of a file.
	 * If this folder has been visited the listener will be notified with rename
	 * @param oldFileName file name prior to rename
	 * @param newFileName file name after rename
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

	/**
	 * Update file list/cache based upon change of parent for a file.
	 * If this folder or the newParent has been visited the listener will be notified with add/move
	 * details.
	 * @param newParent new parent folder
	 * @param oldFileName file name prior to move
	 * @param newFileName file name after move
	 */
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
	 * @param fileName name of file which has changed
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
	 * @param folderName name of folder which has changed
	 * @throws IOException if an IO error occurs during associated refresh
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
						folderData.refresh(true, true, projectData.getProjectDisposalMonitor());
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
	 * @param folderName name of folder which was removed
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

	/**
	 * Disposes the cached data for this folder and all of its children recursively.
	 */
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
//		projectData = null;
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
	 * @throws IOException if an IO error occurs during the refresh
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
	 * @throws IOException if an IO error occurs during the refresh
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
	 * Check for existence of subfolder.  If this folder has previously been visited, 
	 * rely on the cached folderList.
	 * @param folderName name of folder to look for
	 * @return true if folder exists, else false
	 * @throws IOException if an IO error occurs when checking for folder's existance.
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
	 * @param folderName name of folder to be added
	 * @return folder data or null if folder does not exist
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
	 * @param folderName name of folder
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
	 * Check for existence of file.  If folder previously visited, rely on fileDataCache
	 * @param fileName the name of the file to look for
	 * @return true if this folder contains the fileName, else false
	 * @throws IOException if an IO error occurs while checking for file existance
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
	 * @param fileName name of file
	 * @return file data or null if not found
	 * @throws IOException if an IO error occurs while checking for file existance
	 */
	private GhidraFileData addFileData(String fileName) throws IOException {
		GhidraFileData fileData = fileDataCache.get(fileName);
		if (fileData == null) {
			try {
				fileData = new GhidraFileData(this, fileName);
				fileDataCache.put(fileName, fileData);
				projectData.updateFileIndex(fileData);
			}
			catch (FileNotFoundException e) {
				// ignore
			}
		}
		return fileData;
	}

	/**
	 * Get file data for child specified by fileName
	 * @param fileName name of file
	 * @param lazy if true file will not be searched for if not already discovered - in
	 * this case null will be returned
	 * @return file data or null if not found or lazy=true and not yet discovered
	 * @throws IOException if an IO error occurs while checking for file existance
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

	/**
	 * Get the domain file in this folder with the given fileName.
	 * @param fileName name of file in this folder to retrieve
	 * @return domain file or null if there is no file in this folder with the given name.
	 */
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

	/**
	 * Get the domain folder in this folder with the given subfolderName.
	 * @param subfolderName name of subfolder in this folder to retrieve
	 * @return domain folder or null if there is no file in this folder with the given name.
	 */
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

	/**
	 * @return a {@link DomainFolder} instance which corresponds to this folder
	 */
	GhidraFolder getDomainFolder() {
		return new GhidraFolder(parent.getDomainFolder(), name);
	}

	/**
	 * Add a domain object to this folder.
	 * @param fileName domain file name
	 * @param obj domain object to be stored
	 * @param monitor progress monitor
	 * @return domain file created as a result of adding
	 * the domain object to this folder
	 * @throws DuplicateFileException thrown if the file name already exists
	 * @throws InvalidNameException if name is an empty string
	 * or if it contains characters other than alphanumerics.
	 * @throws IOException if IO or access error occurs
	 * @throws CancelledException if the user cancels the create.
	 */
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
				ContentHandler<?> ch = DomainObjectAdapter.getContentHandler(doa);
				ch.createFile(fileSystem, null, getPathname(), fileName, obj, monitor);

				if (oldDf != null) {
					listener.domainFileObjectClosed(oldDf, doa);
				}

				fileChanged(fileName);

				GhidraFile file = getDomainFile(fileName);
				if (file == null) {
					throw new IOException("File creation failed for unknown reason");
				}

				projectData.setDomainObject(file.getPathname(), doa);
				doa.setDomainFile(file);
				doa.setChanged(false);

				projectData.trackDomainFileInUse(doa);

				listener.domainFileObjectOpenedForUpdate(file, doa);

				return file;
			}
			finally {
				doa.unlock();
			}
		}
	}

	/**
	 * Add a new domain file to this folder.
	 * @param fileName domain file name
	 * @param packFile packed file containing domain file data
	 * @param monitor progress monitor
	 * @return domain file created as a result of adding
	 * the domain object to this folder
	 * @throws DuplicateFileException thrown if the file name already exists
	 * @throws InvalidNameException if name is an empty string
	 * or if it contains characters other than alphanumerics.
	 * @throws IOException if IO or access error occurs
	 * @throws CancelledException if the user cancels the create.
	 */
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

	/**
	 * Create a subfolder within this folder.
	 * @param folderName sub-folder name
	 * @return the new folder
	 * @throws DuplicateFileException if a folder by this name already exists
	 * @throws InvalidNameException if name is an empty string of if it contains characters other 
	 * than alphanumerics.
	 * @throws IOException if IO or access error occurs
	 */
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

	/**
	 * Deletes this folder, if empty, from the local filesystem
	 * @throws IOException if IO or access error occurs
	 * @throws FolderNotEmptyException Thrown if the subfolder is not empty.
	 */
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

	/**
	 * Delete this folder from the local filesystem if empty
	 */
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

	/**
	 * Move this folder into the newParent folder.  If connected to a repository
	 * this moves both private and repository folders/files.  If not
	 * connected, only private folders/files are moved.
	 * @param newParent new parent folder within the same project
	 * @return the newly relocated folder (the original DomainFolder object becomes invalid since 
	 * it is immutable)
	 * @throws DuplicateFileException if a folder with the same name 
	 * already exists in newParent folder.
	 * @throws FileInUseException if this folder or one of its descendants 
	 * contains a file which is in-use / checked-out.
	 * @throws IOException thrown if an IO or access error occurs.
	 */
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

	/**
	 * Determine if the specified folder if an ancestor of this folder
	 * (i.e., parent, grand-parent, etc.).
	 * @param folderData folder to be checked
	 * @return true if the specified folder if an ancestor of this folder
	 */
	boolean isAncestor(GhidraFolderData folderData) {
		if (!folderData.projectData.getProjectLocator().equals(projectData.getProjectLocator())) {
			// check if projects share a common repository
			RepositoryAdapter myRepository = projectData.getRepository();
			RepositoryAdapter otherRepository = folderData.projectData.getRepository();
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

	/**
	 * Copy this folder into the newParent folder.
	 * @param newParent new parent folder
	 * @param monitor the task monitor
	 * @return the new copied folder
	 * @throws DuplicateFileException if a folder or file by
	 * this name already exists in the newParent folder
	 * @throws IOException thrown if an IO or access error occurs.
	 * @throws CancelledException if task monitor cancelled operation.
	 */
	GhidraFolder copyTo(GhidraFolderData newParent, TaskMonitor monitor)
			throws IOException, CancelledException {
		synchronized (fileSystem) {
			if (newParent.fileSystem.isReadOnly()) {
				throw new ReadOnlyException("copyTo permitted to writeable project only");
			}
			if (isAncestor(newParent)) {
				throw new IOException("self-referencing copy not permitted");
			}
			GhidraFolderData newFolderData = newParent.getFolderData(name, false);

			if (newFolderData == null) {
				try {
					newFolderData = newParent.createFolder(name);
				}
				catch (InvalidNameException e) {
					throw new AssertException("Unexpected error", e);
				}
			}
			List<String> files = getFileNames();
			for (String file : files) {
				monitor.checkCancelled();
				GhidraFileData fileData = getFileData(file, false);
				if (fileData != null) {
					fileData.copyTo(newFolderData, monitor);
				}
			}
			List<String> folders = getFolderNames();
			for (String folder : folders) {
				monitor.checkCancelled();
				GhidraFolderData folderData = getFolderData(folder, false);
				if (folderData != null) {
					folderData.copyTo(newFolderData, monitor);
				}
			}
			return newFolderData.getDomainFolder();
		}
	}

	/**
	 * Create a new link-file in the specified newParent which will reference this folder 
	 * (i.e., linked-folder). Restrictions:
	 * <ul>
	 * <li>Specified newParent must reside within a different project since internal linking is
	 * not currently supported.</li>
	 * </ul>
	 * If this folder is associated with a temporary transient project (i.e., not a locally 
	 * managed project) the generated link will refer to the remote folder with a remote
	 * Ghidra URL, otherwise a local project storage path will be used.
	 * @param newParent new parent folder where link-file is to be created
	 * @return newly created domain file (i.e., link-file) or null if link use not supported.
	 * @throws IOException if an IO or access error occurs.
	 */
	DomainFile copyToAsLink(GhidraFolderData newParent) throws IOException {
		synchronized (fileSystem) {
			String linkFilename = name;
			if (linkFilename == null) {
				if (projectData instanceof TransientProjectData) {
					linkFilename = projectData.getRepository().getName();
				}
				else {
					linkFilename = projectData.getProjectLocator().getName();
				}
			}
			return newParent.copyAsLink(projectData, getPathname(), linkFilename,
				FolderLinkContentHandler.INSTANCE);
		}
	}

	/**
	 * Create a link-file within this folder.  The link-file may correspond to various types of
	 * content (e.g., Program, Trace, Folder, etc.) based upon specified link handler.
	 * @param sourceProjectData referenced content project data within which specified path exists.
	 * @param pathname path of referenced content with source project data
	 * @param linkFilename name of link-file to be created within this folder.
	 * @param lh link file handler used to create specific link file.
	 * @return link-file 
	 * @throws IOException if IO error occurs during link creation
	 */
	DomainFile copyAsLink(ProjectData sourceProjectData, String pathname, String linkFilename,
			LinkHandler<?> lh) throws IOException {
		synchronized (fileSystem) {
			if (fileSystem.isReadOnly()) {
				throw new ReadOnlyException("copyAsLink permitted to writeable project only");
			}

			if (sourceProjectData == projectData) {
				// internal linking not yet supported
				Msg.error(this, "Internal file/folder links not yet supported");
				return null;
			}

			URL ghidraUrl = null;
			if (sourceProjectData instanceof TransientProjectData) {
				RepositoryAdapter repository = sourceProjectData.getRepository();
				ServerInfo serverInfo = repository.getServerInfo();
				ghidraUrl = GhidraURL.makeURL(serverInfo.getServerName(),
					serverInfo.getPortNumber(), repository.getName(), pathname);
			}
			else {
				ProjectLocator projectLocator = sourceProjectData.getProjectLocator();
				if (projectLocator.equals(projectData.getProjectLocator())) {
					return null; // local internal linking not supported
				}
				ghidraUrl = GhidraURL.makeURL(projectLocator, pathname, null);
			}

			String newName = linkFilename;
			int i = 1;
			while (true) {
				GhidraFileData fileData = getFileData(newName, false);
				if (fileData != null) {
					// return existing file if link URL matches
					if (ghidraUrl.equals(fileData.getLinkFileURL())) {
						return getDomainFile(newName);
					}
					newName = linkFilename + "." + i;
					++i;
				}
				break;
			}

			try {
				lh.createLink(ghidraUrl, fileSystem, getPathname(), newName);
			}
			catch (InvalidNameException e) {
				throw new IOException(e); // unexpected
			}

			fileChanged(newName);
			return getDomainFile(newName);
		}
	}

	/**
	 * Generate a non-conflicting file name for this folder based upon the specified preferred name.
	 * NOTE: This method is subject to race conditions where returned name could conflict by the
	 * time it is actually used.
	 * @param preferredName preferred file name
	 * @return non-conflicting file name
	 * @throws IOException if an IO error occurs during file checks
	 */
	String getTargetName(String preferredName) throws IOException {
		String newName = preferredName;
		int i = 1;
		while (getFileData(newName, false) != null) {
			newName = preferredName + "." + i;
			i++;
		}
		return newName;
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
		ProjectLocator projectLocator = projectData.getProjectLocator();
		if (projectLocator.isTransient()) {
			return projectData.getProjectLocator().getName() + getPathname();
		}
		return projectData.getProjectLocator().getName() + ":" + getPathname();
	}

}
