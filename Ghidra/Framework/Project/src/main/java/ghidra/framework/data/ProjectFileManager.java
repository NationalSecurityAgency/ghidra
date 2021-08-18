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

import generic.timer.GhidraSwinglessTimer;
import ghidra.framework.client.*;
import ghidra.framework.model.*;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.framework.remote.User;
import ghidra.framework.store.*;
import ghidra.framework.store.FileSystem;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.framework.store.remote.RemoteFileSystem;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateFileException;
import ghidra.util.task.*;
import utilities.util.FileUtilities;

/**
 * Helper class to manage files within a project.
 */
public class ProjectFileManager implements ProjectData {

	/**Name of folder that stores user's data*/
	public static final String MANGLED_DATA_FOLDER_NAME = "data";
	public static final String INDEXED_DATA_FOLDER_NAME = "idata";
	public static final String USER_FOLDER_NAME = "user";
	public static final String VERSIONED_FOLDER_NAME = "versioned";

	private static final String USER_DATA_FILE_PREFIX = "udf_";

	private static final String TEST_REPOSITORY_PATH = System.getProperty("Repository");

	private static final String SERVER_NAME = "SERVER";
	private static final String PORT_NUMBER = "PORT_NUMBER";
	private static final String REPOSITORY_NAME = "REPOSITORY_NAME";
	private static final String OWNER = "OWNER";
	private static final String PROPERTY_FILENAME = "project";

	private static final int USER_DATA_RECONCILE_DELAY_MS = 5 * 60 * 1000; // 5-minutes

	private GhidraSwinglessTimer userDataReconcileTimer;

	private Thread userDataReconcileThread;

	private ProjectLocator localStorageLocator;
	private File projectDir;
	private PropertyFile properties;
	private LocalFileSystem fileSystem;
	private FileSystem versionedFileSystem;
	private LocalFileSystem userFileSystem;
	private MyFileSystemListener versionedFSListener;
	private RepositoryAdapter repository;

	private DomainFileIndex fileIndex = new DomainFileIndex(this);
	private DomainFolderChangeListenerList listenerList =
		new DomainFolderChangeListenerList(fileIndex);

	private RootGhidraFolderData rootFolderData;

	private Map<String, DomainObjectAdapter> openDomainObjects =
		new HashMap<>();

	private TaskMonitorAdapter projectDisposalMonitor = new TaskMonitorAdapter();

	private String owner;

	/**
	 * Constructor for existing projects.
	 * @param localStorageLocator the location of the project
	 * @param isInWritableProject true if project content is writable, false if project is read-only
	 * @param resetOwner true to reset the project owner
	 * @throws IOException if an i/o error occurs
	 * @throws NotOwnerException if inProject is true and user is not owner
	 * @throws FileNotFoundException if project directory not found
	 */
	public ProjectFileManager(ProjectLocator localStorageLocator, boolean isInWritableProject,
			boolean resetOwner) throws NotOwnerException, IOException {

		this.localStorageLocator = localStorageLocator;
		init(false, isInWritableProject);
		if (resetOwner) {
			owner = SystemUtilities.getUserName();
			properties.putString(OWNER, owner);
			properties.writeState();
		}
		else if (isInWritableProject && !SystemUtilities.getUserName().equals(owner)) {
			if (owner == null) {
				throw new NotOwnerException("Older projects may only be opened as a View.\n" +
					"You must first create a new project or open an existing current project, \n" +
					"then use the \"Project->View\" menu action to open the older project as a view.\n" +
					"You can then drag old files into your active project.");
			}
			throw new NotOwnerException("Project is owned by " + owner);
		}

		synchronized (fileSystem) {
			getVersionedFileSystem(isInWritableProject);
			rootFolderData = new RootGhidraFolderData(this, listenerList);
			versionedFSListener = new MyFileSystemListener();
			versionedFileSystem.addFileSystemListener(versionedFSListener);
			scheduleUserDataReconcilation();
		}
	}

	/**
	 * Constructor for a new project.
	 * @param localStorageLocator the location of the project
	 * @param repository a repository if this is a shared project or null if it is a private project
	 * @param isInWritableProject true if project content is writable, false if project is read-only
	 * @throws IOException if an i/o error occurs
	 */
	public ProjectFileManager(ProjectLocator localStorageLocator, RepositoryAdapter repository,
			boolean isInWritableProject) throws IOException {
		this.localStorageLocator = localStorageLocator;
		this.repository = repository;
		init(true, isInWritableProject);
		synchronized (fileSystem) {
			createVersionedFileSystem();
			rootFolderData = new RootGhidraFolderData(this, listenerList);
			versionedFSListener = new MyFileSystemListener();
			versionedFileSystem.addFileSystemListener(versionedFSListener);
		}
	}

	ProjectFileManager(LocalFileSystem fileSystem, FileSystem versionedFileSystem) {
		this.localStorageLocator = new ProjectLocator(null, "Test");
		owner = SystemUtilities.getUserName();
		synchronized (fileSystem) {
			this.fileSystem = fileSystem;
			this.versionedFileSystem = versionedFileSystem;
			rootFolderData = new RootGhidraFolderData(this, listenerList);
			versionedFSListener = new MyFileSystemListener();
			versionedFileSystem.addFileSystemListener(versionedFSListener);
			scheduleUserDataReconcilation();
		}
	}

	private void init(boolean create, boolean isInWritableProject) throws IOException {
		projectDir = localStorageLocator.getProjectDir();
		properties = new PropertyFile(projectDir, PROPERTY_FILENAME, "/", PROPERTY_FILENAME);
		if (create) {
			if (projectDir.exists()) {
				throw new DuplicateFileException(
					"Project directory already exists: " + projectDir.getCanonicalPath());
			}
			projectDir.mkdir();
			localStorageLocator.getMarkerFile().createNewFile();
			owner = SystemUtilities.getUserName();
			properties.putString(OWNER, owner);
			properties.writeState();
		}
		else {
			if (!projectDir.isDirectory()) {
				throw new FileNotFoundException("Project directory not found: " + projectDir);
			}
			if (properties.exists()) {
				if (isInWritableProject && properties.isReadOnly()) {
					throw new ReadOnlyException(
						"Project " + localStorageLocator.getName() + " is read-only");
				}
				properties.readState();
				owner = properties.getString(OWNER, SystemUtilities.getUserName());
			}
			else if (isInWritableProject) {
				owner = SystemUtilities.getUserName();
				properties.putString(OWNER, owner);
				properties.writeState();
			}
			else {
				owner = "<unknown>"; // Unknown owner
			}
		}
		getPrivateFileSystem(create, isInWritableProject);
		getUserFileSystem(isInWritableProject);
	}

	@Override
	public int getMaxNameLength() {
		return fileSystem.getMaxNameLength();
	}

	@Override
	public void testValidName(String name, boolean isPath) throws InvalidNameException {
		fileSystem.testValidName(name, isPath);
	}

	@Override
	public User getUser() {
		if (repository != null) {
			try {
				return repository.getUser();
			}
			catch (IOException e) {
				return new User(SystemUtilities.getUserName(), User.READ_ONLY);
			}
		}
		return null;
	}

	private void createVersionedFileSystem() throws IOException {
		if (repository != null) {
			updatePropertiesFile(repository);
			versionedFileSystem = new RemoteFileSystem(repository);
		}
		else {
			File versionedFileSystemDir = new File(projectDir, VERSIONED_FOLDER_NAME);
			if (!versionedFileSystemDir.exists()) {
				versionedFileSystemDir.mkdir();
			}
			versionedFileSystem = LocalFileSystem.getLocalFileSystem(
				versionedFileSystemDir.getAbsolutePath(), true, true, false, true);
		}
	}

	private void updatePropertiesFile(RepositoryAdapter rep) throws IOException {
		ServerInfo info = rep.getServerInfo();
		if (info == null) {
			return;
		}
		properties.putString(SERVER_NAME, info.getServerName());
		properties.putString(REPOSITORY_NAME, rep.getName());
		properties.putInt(PORT_NUMBER, info.getPortNumber());
		properties.writeState();

	}

	private void getVersionedFileSystem(boolean isInWritableProject) throws IOException {

		if (TEST_REPOSITORY_PATH != null) {
			File versionedFileSystemDir = new File(TEST_REPOSITORY_PATH);
			if (versionedFileSystemDir.exists()) {
				versionedFileSystem = LocalFileSystem.getLocalFileSystem(
					versionedFileSystemDir.getAbsolutePath(), false, true, false, true);
				return;
			}
			Msg.error(this, "Test repository not found: " + TEST_REPOSITORY_PATH);
		}

		String serverName = properties.getString(SERVER_NAME, null);
		if (serverName == null) {
			File versionedFileSystemDir = new File(projectDir, VERSIONED_FOLDER_NAME);
			boolean create = false;
			if (!versionedFileSystemDir.exists()) {
				// could occur if transitioning from shared to non-shared project
				versionedFileSystemDir.mkdir();
				create = true;
			}
			versionedFileSystem = LocalFileSystem.getLocalFileSystem(
				versionedFileSystemDir.getAbsolutePath(), create, true, !isInWritableProject, true);
		}
		else {
			int port = properties.getInt(PORT_NUMBER, -1);
			repository = getRepositoryAdapter(serverName, port, isInWritableProject);
			versionedFileSystem = new RemoteFileSystem(repository);
		}
	}

	private RepositoryAdapter getRepositoryAdapter(String serverName, int port,
			boolean isInWritableProject) {

		String repositoryName = properties.getString(REPOSITORY_NAME, null);
// TODO: defer connect to project manager for active project
		RepositoryServerAdapter rsa =
			ClientUtil.getRepositoryServer(serverName, port, isInWritableProject);

		RepositoryAdapter rep = rsa.getRepository(repositoryName);
		if (rsa.isConnected()) {
			try {
				rep.connect();
			}
			catch (IOException e) {
				ClientUtil.handleException(rep, e, "Repository Connection", null);
			}
		}
		return rep;
	}

	FileSystem getVersionedFileSystem() {
		return versionedFileSystem;
	}

	LocalFileSystem getUserFileSystem() {
		return userFileSystem;
	}

	LocalFileSystem getLocalFileSystem() {
		return fileSystem;
	}

	@Override
	public Class<? extends LocalFileSystem> getLocalStorageClass() {
		return fileSystem.getClass();
	}

	/**
	 * Change the versioned filesystem associated with this project file manager.
	 * This method is provided for testing.  Care should be taken when using a
	 * LocalFileSystem in a shared capacity since locking is not supported.
	 * @param fs versioned filesystem
	 * @throws IOException if an IO error occurs
	 */
	void setVersionedFileSystem(FileSystem fs) throws IOException {
		if (!fs.isVersioned()) {
			throw new IllegalArgumentException("versioned filesystem required");
		}
		versionedFileSystem.removeFileSystemListener(versionedFSListener);
		versionedFileSystem = fs;
		versionedFileSystem.addFileSystemListener(versionedFSListener);
		rootFolderData.setVersionedFileSystem(versionedFileSystem);
	}

	private void getPrivateFileSystem(boolean create, boolean isInWritableProject)
			throws IOException {
		// Look for either the new indexed data folder or the legacy mangled data folder
		File fileSystemDir = new File(projectDir, INDEXED_DATA_FOLDER_NAME);
		if (!create && !fileSystemDir.isDirectory()) {
			// If opening existing project and indexed data not found, look
			// for legacy mangled data
			fileSystemDir = new File(projectDir, MANGLED_DATA_FOLDER_NAME);
		}
		if (!fileSystemDir.isDirectory()) {
			if (create && !fileSystemDir.exists()) {
				if (!fileSystemDir.mkdir()) {
					throw new IOException(
						"Failed to create project data directory: " + fileSystemDir);
				}
			}
			else {
				throw new IOException("Project data directory not found: " + fileSystemDir);
			}
		}
		fileSystem = LocalFileSystem.getLocalFileSystem(fileSystemDir.getAbsolutePath(), create,
			false, !isInWritableProject, true);
	}

	private void getUserFileSystem(boolean isInWritableProject) throws IOException {
		if (!isInWritableProject) {
			return;
		}
		File fileSystemDir = new File(projectDir, USER_FOLDER_NAME);
		boolean create = false;
		if (!fileSystemDir.isDirectory()) {
			if (fileSystemDir.exists() || !fileSystemDir.mkdir()) {
				throw new IOException("Failed to create project user directory: " + fileSystemDir);
			}
			create = true;
		}
		userFileSystem = LocalFileSystem.getLocalFileSystem(fileSystemDir.getAbsolutePath(), create,
			false, !isInWritableProject, true);
	}

	/**
	 * Returns the owner of the project that is associated with this 
	 * ProjectFileManager.  A value of null indicates an old multiuser
	 * project.
	 * @return the owner of the project 
	 */
	public String getOwner() {
		return owner;
	}

	@Override
	public GhidraFolder getRootFolder() {
		return rootFolderData.getDomainFolder();
	}

	@Override
	public DomainFolder getFolder(String path) {
		int len = path.length();
		if (len == 0 || path.charAt(0) != FileSystem.SEPARATOR_CHAR) {
			throw new IllegalArgumentException(
				"Absolute path must begin with '" + FileSystem.SEPARATOR_CHAR + "'");
		}
		try {
			return getRootFolder().getFolderPathData(path).getDomainFolder();
		}
		catch (FileNotFoundException e) {
			return null;
		}
	}

	@Override
	public int getFileCount() {

		int sharedFileCnt = 0;

		if (repository != null && repository.isConnected()) {
			sharedFileCnt = -1;
			try {
				if (repository != null && repository.isConnected()) {
					sharedFileCnt = versionedFileSystem.getItemCount();
				}
			}
			catch (Exception e) {
				return -1;
			}
		}

		// NOTE: we can't distinguish between files represented in both file counts so we will 
		// return the larger of the two counts obtained.

		int privateFileCnt = -1;
		try {
			privateFileCnt = fileSystem.getItemCount();
		}
		catch (Exception e) {
			return -1;
		}

		if (privateFileCnt <= 0) {
			return sharedFileCnt;
		}

		if (sharedFileCnt <= 0) {
			return privateFileCnt;
		}

		return Math.max(sharedFileCnt, privateFileCnt);
	}

	@Override
	public DomainFile getFile(String path) {
		int len = path.length();
		if (len == 0 || path.charAt(0) != FileSystem.SEPARATOR_CHAR) {
			throw new IllegalArgumentException(
				"Absolute path must begin with '" + FileSystem.SEPARATOR_CHAR + "'");
		}
		else if (path.charAt(len - 1) == FileSystem.SEPARATOR_CHAR) {
			throw new IllegalArgumentException("Missing file name in path");
		}
		int ix = path.lastIndexOf(FileSystem.SEPARATOR);

		DomainFolder folder;
		if (ix > 0) {
			folder = getFolder(path.substring(0, ix));
		}
		else {
			folder = getRootFolder();
		}
		if (folder != null) {
			return folder.getFile(path.substring(ix + 1));
		}
		return null;
	}

	@Override
	public DomainFile getFileByID(String fileID) {
		return fileIndex.getFileByID(fileID);
	}

	@Override
	public URL getSharedFileURL(String path) {
		if (repository != null) {
			DomainFile df = getFile(path);
			if (df != null && df.isVersioned()) {
				ServerInfo server = repository.getServerInfo();
				return GhidraURL.makeURL(server.getServerName(), server.getPortNumber(),
					repository.getName(), path);
			}
		}
		return null;
	}

	public void releaseDomainFiles(Object consumer) {
		for (DomainObjectAdapter domainObj : openDomainObjects.values()) {
			try {
				if (domainObj.getConsumerList().contains(consumer)) {
					domainObj.release(consumer);
				}
			}
			catch (IllegalArgumentException e) {
				// ignore
			}
		}
	}

	/**
	 * Finds all changed domain files and appends them to the specified list.
	 * @param list the list to receive the changed domain files
	 */
	@Override
	public void findOpenFiles(List<DomainFile> list) {
		for (DomainObjectAdapter domainObj : openDomainObjects.values()) {
			list.add(domainObj.getDomainFile());
		}
	}

	@Override
	public ProjectLocator getProjectLocator() {
		return localStorageLocator;
	}

	@Override
	public void addDomainFolderChangeListener(DomainFolderChangeListener l) {
		listenerList.addListener(l);
	}

	@Override
	public void removeDomainFolderChangeListener(DomainFolderChangeListener l) {
		listenerList.removeListener(l);
	}

	public FileSystem getPrivateFileSystem() {
		return fileSystem;
	}

	@Override
	public RepositoryAdapter getRepository() {
		return repository;
	}

	@Override
	public void refresh(boolean force) throws IOException {
		try {
			rootFolderData.refresh(true, true, projectDisposalMonitor);
		}
		catch (Exception e) {
			ClientUtil.handleException(repository, e, "Project Refresh", null);
		}
	}

	@Override
	public void convertProjectToShared(RepositoryAdapter newRepository, TaskMonitor monitor)
			throws IOException, CancelledException {

		newRepository.connect();
		if (!newRepository.isConnected()) {
			throw new IOException("new respository not connected");
		}
		if (repository != null) {
			throw new IllegalStateException("Only private project may be converted to shared");
		}

		// 1) Convert versioned files (including checked-out files) to private files
		convertFilesToPrivate(getRootFolder(), monitor);

		// 2) Update the properties with server info
		updatePropertiesFile(newRepository);

		// 3) Transition versioned filesystem and remove the old versioned filesystem
		versionedFileSystem.dispose();
		repository = newRepository;
		versionedFileSystem = new RemoteFileSystem(newRepository);
		File versionedFileSystemDir = new File(projectDir, VERSIONED_FOLDER_NAME);
		FileUtilities.deleteDir(versionedFileSystemDir);
	}

	@Override
	public void updateRepositoryInfo(RepositoryAdapter newRepository, TaskMonitor monitor)
			throws IOException, CancelledException {
		// 1) check for checked out files
		findCheckedOutFiles(getRootFolder(), monitor);

		// 2) Update the properties with server info
		updatePropertiesFile(newRepository);
	}

	private void findCheckedOutFiles(DomainFolder folder, TaskMonitor monitor)
			throws IOException, CancelledException {

		DomainFile[] files = folder.getFiles();
		for (DomainFile file : files) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			if (file.isCheckedOut()) {
				throw new IOException("File " + file.getPathname() + " is checked out.");
			}
		}
		DomainFolder[] folders = folder.getFolders();
		for (DomainFolder folder2 : folders) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			findCheckedOutFiles(folder2, monitor);
		}
	}

	private void convertFilesToPrivate(DomainFolder folder, TaskMonitor monitor)
			throws IOException, CancelledException {

		DomainFile[] files = folder.getFiles();
		for (DomainFile file : files) {
			((GhidraFile) file).convertToPrivateFile(monitor);
		}
		DomainFolder[] folders = folder.getFolders();
		for (DomainFolder folder2 : folders) {
			convertFilesToPrivate(folder2, monitor);
		}
	}

	/**
	 * Returns the standard user data filename associated with the specified file ID.
	 * @param associatedFileID the file id
	 * @return user data filename
	 */
	public static String getUserDataFilename(String associatedFileID) {
		return USER_DATA_FILE_PREFIX + associatedFileID;
	}

	private synchronized void scheduleUserDataReconcilation() {

		if (userFileSystem == null || SystemUtilities.isInHeadlessMode()) {
			return;
		}

		boolean notOnline = !versionedFileSystem.isOnline();

		if (userDataReconcileTimer != null) {
			if (notOnline) {
				userDataReconcileTimer.stop();
				Thread t = userDataReconcileThread;
				if (t != null) {
					t.interrupt();
				}
			}
			return;
		}
		else if (notOnline) {
			return;
		}

		userDataReconcileTimer = new GhidraSwinglessTimer(USER_DATA_RECONCILE_DELAY_MS, () -> {
			synchronized (ProjectFileManager.this) {
				startReconcileUserDataFiles();
			}
		});
		userDataReconcileTimer.setRepeats(false);
		userDataReconcileTimer.start();
	}

	private void startReconcileUserDataFiles() {
		userDataReconcileThread = new Thread(() -> reconcileUserDataFiles());
		userDataReconcileThread.setPriority(Thread.MIN_PRIORITY);
		userDataReconcileThread.start();
	}

	/**
	 * Reconcile user data files against all content files within the project.
	 * This must only be done while connected to the repository
	 */
	private void reconcileUserDataFiles() {

		int count = 0;

		if (userFileSystem == null || !versionedFileSystem.isOnline()) {
			return;
		}
		try {
			for (String itemName : userFileSystem.getItemNames("/")) {
				if (Thread.interrupted() || !versionedFileSystem.isOnline()) {
					break;
				}
				if (!itemName.startsWith(USER_DATA_FILE_PREFIX)) {
					continue;
				}
				String fileID = itemName.substring(USER_DATA_FILE_PREFIX.length());
				if (fileIndex.getFileByID(fileID) == null) {
					synchronized (fileSystem) {
						FolderItem item = userFileSystem.getItem("/", itemName);
						if (item != null) {
							++count;
							item.delete(-1, null);
						}
					}
				}
			}
		}
		catch (InterruptedIOException e) {
			// ignore
		}
		catch (IOException e) {
			Msg.error(this, "Error while reconciling user data files", e);
		}

		if (count != 0) {
			Msg.info(this, "Removed " + count + " user data files which were obsolete");
		}
	}

	class MyFileSystemListener implements FileSystemListener {
		@Override
		public void folderCreated(final String parentPath, final String name) {
			synchronized (fileSystem) {
				GhidraFolderData folderData = rootFolderData.getFolderPathData(parentPath, true);
				if (folderData != null) {
					try {
						folderData.folderChanged(name);
					}
					catch (IOException e) {
						// ignore
					}
				}
			}
		}

		@Override
		public void itemCreated(final String parentPath, final String name) {
			synchronized (fileSystem) {
				GhidraFolderData folderData = rootFolderData.getFolderPathData(parentPath, true);
				if (folderData != null) {
					folderData.fileChanged(name);
				}
			}
		}

		@Override
		public void folderDeleted(final String parentPath, final String folderName) {
			synchronized (fileSystem) {
				GhidraFolderData folderData = rootFolderData.getFolderPathData(parentPath, true);
				if (folderData != null) {
					try {
						folderData.folderChanged(folderName);
					}
					catch (IOException e) {
						// ignore
					}
				}
			}
		}

		@Override
		public void folderMoved(final String parentPath, final String folderName,
				final String newParentPath) {
			synchronized (fileSystem) {

				// TODO: This could be very inefficient by producing separate remove/add events
				// - a moved folder could require merging of local and shared trees

				GhidraFolderData folderData = rootFolderData.getFolderPathData(parentPath, true);
				if (folderData != null) {
					try {
						folderData.folderChanged(folderName);
					}
					catch (IOException e) {
						// ignore
					}
				}
				folderData = rootFolderData.getFolderPathData(newParentPath, true);
				if (folderData != null) {
					try {
						folderData.folderChanged(folderName);
					}
					catch (IOException e) {
						// ignore
					}
				}
			}
		}

		@Override
		public void folderRenamed(final String parentPath, final String oldFolderName,
				final String newFolderName) {
			synchronized (fileSystem) {
				GhidraFolderData folderData = rootFolderData.getFolderPathData(parentPath, true);
				if (folderData != null) {

					// TODO: This could be very inefficient by producing separate remove/add events

					try {
						folderData.folderChanged(oldFolderName);
					}
					catch (IOException e) {
						// ignore
					}
					try {
						folderData.folderChanged(newFolderName);
					}
					catch (IOException e) {
						// ignore
					}
				}
			}
		}

		@Override
		public void itemDeleted(final String folderPath, final String itemName) {
			GhidraFolderData folderData = rootFolderData.getFolderPathData(folderPath, true);
			if (folderData != null) {
				folderData.fileChanged(itemName);
			}
		}

		@Override
		public void itemRenamed(final String folderPath, final String oldItemName,
				final String newItemName) {
			synchronized (fileSystem) {
				GhidraFolderData folderData = rootFolderData.getFolderPathData(folderPath, true);
				if (folderData != null) {
					folderData.fileChanged(oldItemName);
					folderData.fileChanged(newItemName);
				}
			}
		}

		@Override
		public void itemMoved(final String parentPath, final String name,
				final String newParentPath, final String newName) {
			synchronized (fileSystem) {
				GhidraFolderData folderData = rootFolderData.getFolderPathData(parentPath, true);
				if (folderData != null) {
					folderData.fileChanged(name);
				}
				folderData = rootFolderData.getFolderPathData(newParentPath, true);
				if (folderData != null) {
					folderData.fileChanged(newName);
				}
			}
		}

		@Override
		public void itemChanged(final String parentPath, final String itemName) {
			synchronized (fileSystem) {
				GhidraFolderData folderData = rootFolderData.getFolderPathData(parentPath, true);
				if (folderData != null) {
					folderData.fileChanged(itemName);
				}
			}
		}

		@Override
		public void syncronize() {

			if (SystemUtilities.isInHeadlessMode()) {
				doSynchronize();
				return;
			}

			try {

				FileSystemSynchronizer.setSynchronizing(true);

				// This operation can hold a lock for a long period.  Block with a modal dialog to
				// prevent UI live lock situations.
				TaskLauncher.launchModal("Synchronizing Filesystem", this::doSynchronize);
			}
			finally {
				FileSystemSynchronizer.setSynchronizing(false);
			}
		}

		private void doSynchronize() {
			try {
				rootFolderData.refresh(true, true, projectDisposalMonitor);
				scheduleUserDataReconcilation();
			}
			catch (Exception e) {
				Msg.trace(this, "Exception synchronizing filesystem", e);
			}
		}
	}

	@Override
	public String makeValidName(String name) {
		int maxNameLength = getMaxNameLength();
		StringBuffer buf = new StringBuffer();
		for (int i = 0; i < name.length(); i++) {
			if (buf.length() == maxNameLength) {
				break;
			}
			char c = name.charAt(i);
			if (!LocalFileSystem.isValidNameCharacter(c)) {
				continue;
			}
			buf.append(c);
		}
		return buf.length() == 0 ? "unknown" : buf.toString();
	}

	public File getProjectDir() {
		return projectDir;
	}

	@Override
	public void close() {
		dispose();
	}

	public void dispose() {

		synchronized (this) {
			if (userDataReconcileTimer != null) {
				userDataReconcileTimer.stop();
			}
			if (userDataReconcileThread != null) {
				userDataReconcileThread.interrupt();
			}

			// stop any folder refresh currently in progress
			projectDisposalMonitor.cancel();

			listenerList.clearAll();
		}

		synchronized (fileSystem) {
			rootFolderData.dispose();
			fileSystem.dispose();
			versionedFileSystem.dispose();
			versionedFileSystem.removeFileSystemListener(versionedFSListener);
			if (repository != null) {
				repository.disconnect();
				repository = null;
			}
		}
	}

	GhidraFolderData getRootFolderData() {
		return rootFolderData;
	}

	/**
	 * Set the open domain object (opened for update) associated with a file. 
	 * NOTE: Caller is responsible for setting domain file on domain object after invoking this 
	 * method. If a domain object saveAs was done, the previous file association 
	 * will be removed.
	 * @param pathname the path name
	 * @param doa the domain object
	 */
	synchronized void setDomainObject(String pathname, DomainObjectAdapter doa) {
		if (openDomainObjects.containsKey(pathname)) {
			throw new RuntimeException("Attempted to re-open domain object: " + pathname);
		}
		DomainFile df = doa.getDomainFile();
		if (df instanceof GhidraFile) {
			openDomainObjects.remove(df.getPathname());
		}
		openDomainObjects.put(pathname, doa);
	}

	/**
	 * Returns the open domain object (opened for update) for the specified path.
	 * @param pathname the path name
	 * @return the domain object
	 */
	synchronized DomainObjectAdapter getOpenedDomainObject(String pathname) {
		return openDomainObjects.get(pathname);
	}

	/**
	 * Clears the previously open domain object which has been closed.
	 * @param pathname the path name
	 * @return true if previously open domain file was cleared, else false
	 */
	synchronized boolean clearDomainObject(String pathname) {
		DomainObjectAdapter doa = openDomainObjects.get(pathname);
		if (doa != null) {
			openDomainObjects.remove(pathname);
			return true;
		}
		return false;
	}

	/**
	 * Update the file index for the specified file data
	 * @param fileData file data
	 */
	public void updateFileIndex(GhidraFileData fileData) {
		fileIndex.updateFileEntry(fileData);
	}

	/**
	 * Remove specified fileID from index.
	 * @param fileID the file ID
	 */
	public void removeFromIndex(String fileID) {
		fileIndex.removeFileEntry(fileID);
	}

	/**
	 * Get monitor which will be cancelled if project is closed
	 * @return cancel monitor
	 */
	public TaskMonitor getProjectDisposalMonitor() {
		return projectDisposalMonitor;
	}
}
