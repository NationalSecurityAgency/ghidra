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
package ghidra.server;

import java.io.*;
import java.util.*;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import ghidra.framework.remote.*;
import ghidra.framework.store.FileSystem;
import ghidra.framework.store.FileSystemListener;
import ghidra.framework.store.local.*;
import ghidra.server.remote.RepositoryHandleImpl;
import ghidra.server.store.RepositoryFile;
import ghidra.server.store.RepositoryFolder;
import ghidra.util.InvalidNameException;
import ghidra.util.NamingUtilities;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.UserAccessException;
import ghidra.util.timer.GTimer;
import ghidra.util.timer.GTimerMonitor;

/**
 * <code>Repository</code> manages a versioned LocalFileSystem and a set of user's
 * and permissions.  
 */
public class Repository implements FileSystemListener, RepositoryLogger {
	static final Logger log = LogManager.getLogger(Repository.class);

	private final static String READ_ONLY_STR = "READ_ONLY";
	private final static String WRITE_STR = "WRITE";
	private final static String ADMIN_STR = "ADMIN";
	private final static String ANONYMOUS_STR = "=ANONYMOUS_ALLOWED";
	private final static String[] TYPE_NAMES = { READ_ONLY_STR, WRITE_STR, ADMIN_STR };

	private final static String INDEX_MIGRATION_MARKER_FILE = "~MIGRATE";

	private final static String ACCESS_CONTROL_FILENAME = "userAccess.acl";

	public static final User ANONYMOUS_USER =
		new User(UserManager.ANONYMOUS_USERNAME, User.READ_ONLY);

	private boolean valid;
	private GTimerMonitor clientCheckTimerMonitor;
	private RepositoryManager mgr;
	private LocalFileSystem fileSystem;
	private RepositoryFolder rootFolder;
	private String name;
	private File userAccessFile;
	private LinkedHashMap<String, User> userMap = new LinkedHashMap<>();
	private boolean anonymousAccessAllowed;
	private ArrayList<RepositoryHandleImpl> handleList = new ArrayList<>();
	private ArrayList<RepositoryChangeEvent> eventQueue = new ArrayList<>();
	private boolean dispatchSuspended = false;

	/**
	 * Create a new Repository at the given path; the directory has already
	 * been created.
	 * @param currentUser user creating the repository, or null if the
	 * repository exists
	 * @param rootFile root file for this repository
	 * @param initialize true means
	 * @throws IOException
	 */
	public Repository(RepositoryManager mgr, String currentUser, File rootFile, String name)
			throws IOException, UserAccessException {
		this.mgr = mgr;
		this.name = name;

		log.info("Loading " + name + " ...");

		long t = System.currentTimeMillis();

		boolean create = (rootFile.list().length == 0);

		boolean performMigration = !create && checkForIndexMigration(rootFile);

		fileSystem = LocalFileSystem.getLocalFileSystem(rootFile.getAbsolutePath(), create, true,
			false, false);

		if (performMigration) {
			fileSystem = performMigration(rootFile, fileSystem);
		}

		try {
			int count = fileSystem.getItemCount();
			log.info("   ... loading " + count + " files ...");
		}
		catch (UnsupportedOperationException e) {
			// ignore - count not supported by mangled file-system
		}

		fileSystem.setAssociatedRepositoryLogger(this);
		fileSystem.addFileSystemListener(this);
		rootFolder = new RepositoryFolder(this, fileSystem);

		userAccessFile = new File(rootFile, ACCESS_CONTROL_FILENAME);

		if (currentUser != null) {
			userMap.put(currentUser, new User(currentUser, User.ADMIN));
			writeUserList(currentUser, userMap, false);
		}
		else {
			readAccessFile();
		}

		valid = true;

		scheduleHandleCheck();

		log.info("   " + name + " load complete. " +
			(anonymousAccessAllowed() ? "(allows anonymous)" : ""));
		String loadTime = RepositoryManager.getElapsedTimeSince(t);
		if (loadTime != null) {
			log.info("   load time: " + loadTime);
		}
	}

	private boolean checkForIndexMigration(File rootFile) {
		File indexMigrationMarkerFile = new File(rootFile, INDEX_MIGRATION_MARKER_FILE);
		if (indexMigrationMarkerFile.exists()) {
			indexMigrationMarkerFile.delete();
			return true;
		}
		return false;
	}

	private LocalFileSystem performMigration(File rootFile, LocalFileSystem fs) throws IOException {

		if (fs instanceof IndexedV1LocalFileSystem) {
			return fs; // already at the latest
		}

		if (fs instanceof IndexedLocalFileSystem) {
			log(null, "Migrating repository to latest indexed filesystem version (V1)...", null);
			fs.dispose();
			IndexedV1LocalFileSystem.rebuild(rootFile);
		}
		else if (fs instanceof MangledLocalFileSystem) {
			log(null, "Migrating repository to indexed filesystem storage...", null);
			((MangledLocalFileSystem) fs).convertToIndexedLocalFileSystem();
		}
		else {
			return fs;
		}

		return LocalFileSystem.getLocalFileSystem(rootFile.getAbsolutePath(), false, true, false,
			false);
	}

	private void scheduleHandleCheck() {
		clientCheckTimerMonitor =
			GTimer.scheduleRunnable(RepositoryHandle.CLIENT_CHECK_PERIOD, () -> {
				synchronized (fileSystem) {
					RepositoryHandleImpl[] handles = getHandles();
					for (int i = 0; i < handles.length; i++) {
						handles[i].checkHandle();
					}
					scheduleHandleCheck();
				}
			});
	}

	/**
	 * Dispose server repository and all remote handles.
	 * Method will block until all clients are notified
	 */
	void dispose() {
		synchronized (fileSystem) {
			if (clientCheckTimerMonitor != null) {
				clientCheckTimerMonitor.cancel();
				clientCheckTimerMonitor = null;
			}

//			sendChangeEvent(new RepositoryChangeEvent(RepositoryChangeEvent.SERVER_SHUTDOWN_EVENT, null, null, null, null), true);

			RepositoryHandleImpl[] handles;
			synchronized (handleList) {
				handles = new RepositoryHandleImpl[handleList.size()];
				handleList.toArray(handles);
			}
			for (int i = 0; i < handles.length; i++) {
				handles[i].dispose();
			}
		}
	}

	/**
	 * Suspend the immediate dispatching of change events.
	 * Dispatching is resumed by invoking the flushChangeEvents method.
	 */
	public void suspendEventDispatching() {
		synchronized (eventQueue) {
			dispatchSuspended = true;
		}
	}

	private void sendChangeEvent(RepositoryChangeEvent event) {
		synchronized (eventQueue) {
			eventQueue.add(event);
		}
		if (!dispatchSuspended) {
			flushChangeEvents();
		}
	}

	/**
	 * Send all queued change events immediately.
	 * If event dispatching had been suspended, it will 
	 * resume with this call.
	 */
	public void flushChangeEvents() {

		RepositoryChangeEvent[] events;
		synchronized (eventQueue) {
			dispatchSuspended = false;
			if (eventQueue.isEmpty()) {
				return;
			}
			events = new RepositoryChangeEvent[eventQueue.size()];
			eventQueue.toArray(events);
			eventQueue.clear();
		}

		RepositoryHandleImpl[] handles = getHandles();
		for (int i = 0; i < handles.length; i++) {
			handles[i].dispatchEvents(events);
		}
	}

	private RepositoryHandleImpl[] getHandles() {
		RepositoryHandleImpl[] handles;
		synchronized (handleList) {
			handles = new RepositoryHandleImpl[handleList.size()];
			handleList.toArray(handles);
		}
		return handles;
	}

	/**
	 * Add a user handle to this repository.
	 * @param handle user repository handle
	 */
	public void addHandle(RepositoryHandleImpl handle) {
		synchronized (handleList) {
			handleList.add(handle);
		}
	}

	/**
	 * Drop the specified handle to this repository
	 * @param handle user repository handle
	 */
	public void dropHandle(RepositoryHandleImpl handle) {
		synchronized (handleList) {
			handleList.remove(handle);
		}
	}

	/**
	 * Get the name of this repository.
	 * @return name of the repository.
	 * @throws IOException
	 */
	public String getName() {
		return name;
	}

	/**
	 * @see FileSystem#getItemCount()
	 */
	public int getItemCount() throws IOException, UnsupportedOperationException {
		return fileSystem.getItemCount();
	}

	/**
	 * Returns the folder specified by folderPath.
	 * @param currentUser user that is getting/creating the folder, only required if create is true 
	 * @param folderPath absolute folder path
	 * @param create if true folder path will be created if necessary
	 * @return folder or null if not found and create is false
	 * @throws InvalidNameException if a path element is invalid and create is true
	 * @throws IOException if an IO error occurs
	 */
	public RepositoryFolder getFolder(String currentUser, String folderPath, boolean create)
			throws InvalidNameException, IOException {
		synchronized (fileSystem) {
			validate();
			if (!folderPath.startsWith(FileSystem.SEPARATOR)) {
				throw new IOException("Absolute path required");
			}
			RepositoryFolder folder = rootFolder;
			StringTokenizer st = new StringTokenizer(folderPath.substring(1), FileSystem.SEPARATOR);
			while (folder != null && st.hasMoreElements()) {
				String folderName = st.nextToken();
				RepositoryFolder next = folder.getFolder(folderName);
				if (next == null && create) {
					next = folder.createFolder(folderName, currentUser);
				}
				folder = next;
			}
			return folder;
		}
	}

	/**
	 * Convenience method for getting list of all "Known" users
	 * defined to the repository user manager.
	 * @param currentUser
	 * @return list of user names.
	 * @throws IOException
	 */
	public String[] getServerUserList(String currentUser) throws IOException {
		if (UserManager.ANONYMOUS_USERNAME.equals(currentUser)) {
			return new String[0];
		}
		return mgr.getUserManager().getUsers();
	}

	/**
	 * Set the user access list.
	 * @param currentUser user that is setting the access list on this
	 * repository; the current user must 
	 * @param users
	 * @param allowAnonymousAccess
	 * @throws UserAccessException
	 * @throws IOException
	 */
	public void setUserList(String currentUser, User[] users, boolean allowAnonymousAccess)
			throws UserAccessException, IOException {
		synchronized (fileSystem) {
			validate();
			validateAdminPrivilege(currentUser);

			LinkedHashMap<String, User> newUserMap = new LinkedHashMap<>();
			for (int i = 0; i < users.length; i++) {
				String userName = users[i].getName();
				if (UserManager.ANONYMOUS_USERNAME.equals(userName)) {
					continue; // ignore
				}
				newUserMap.put(userName, users[i]);
			}
			User user = newUserMap.get(currentUser);
			if (user == null || !user.isAdmin()) {
				throw new UserAccessException("User may not remove or change permissions for self");
			}

			try {
				anonymousAccessAllowed = allowAnonymousAccess && mgr.anonymousAccessAllowed();
				writeUserList(currentUser, newUserMap, anonymousAccessAllowed);
				if (allowAnonymousAccess != this.anonymousAccessAllowed) {
					log(null, "Enablement of Anonymous access setting ignored", currentUser);
				}
				userMap = newUserMap;
			}
			catch (FileNotFoundException e) {
				log.error("File not found for " + userAccessFile.getAbsolutePath());
			}
			catch (IOException e) {
				String msg = e.getMessage();
				if (msg == null) {
					msg = e.toString();
				}
				log.error("Failed to write user access file: " + msg);
			}
		}
	}

	/**
	 * Privileged method for adding a new repository admin
	 * @param sid user username
	 * @throws IOException
	 */
	void addAdmin(String username) throws IOException {
		synchronized (fileSystem) {
			userMap.remove(username);
			userMap.put(username, new User(username, User.ADMIN));
			writeUserList(userMap, anonymousAccessAllowed);
		}
	}

	/**
	 * Get the list of known users for this repository.
	 * @param currentUser user that is requesting the user list. 
	 * @throws UserAccessException
	 * @throws IOException
	 */
	public User[] getUserList(String currentUser) throws UserAccessException, IOException {
		synchronized (fileSystem) {
			validate();
			if (UserManager.ANONYMOUS_USERNAME.equals(currentUser)) {
				return new User[0];
			}
			validateReadPrivilege(currentUser);
			User[] users = new User[userMap.size()];
			int i = 0;
			Iterator<User> iter = userMap.values().iterator();
			while (iter.hasNext()) {
				users[i++] = iter.next();
			}
			return users;
		}
	}

	/**
	 * @return true if anonymous access is allowed for this repository
	 */
	public boolean anonymousAccessAllowed() {
		return anonymousAccessAllowed;
	}

	/**
	 * Get the specified user data.
	 * If the repository's user list if missing or currupt, this user
	 * will become its administrator.
	 * @param currentUser
	 * @return user data
	 */
	public User getUser(String currentUser) {
		synchronized (fileSystem) {
			if (anonymousAccessAllowed && UserManager.ANONYMOUS_USERNAME.equals(currentUser)) {
				return ANONYMOUS_USER;
			}
			if (userMap.isEmpty()) {
				log.error("Empty repository access list, will attempt repair (" + name + ")");
				log.warn("Adding user " + currentUser + " as Admin to repository (" + name + ")");
				userMap.put(currentUser, new User(currentUser, User.ADMIN));
				try {
					writeUserList(currentUser, userMap, anonymousAccessAllowed);
				}
				catch (Exception e) {
					log.error("Failed to repair repository access list: " + e.getMessage());
				}
			}
			User user = userMap.get(currentUser);
			if (user == null && anonymousAccessAllowed) {
				// allow authenticated user to access repository in read-only mode
				return new User(currentUser, User.READ_ONLY);
			}
			return user;
		}
	}

	/**
	 * Write user access list to local file.
	 * @param currentUser current user
	 * @param newUserMap user map
	 * @param allowAnonymous
	 * @throws UserAccessException
	 * @throws IOException
	 */
	private void writeUserList(String currentUser, LinkedHashMap<String, User> newUserMap,
			boolean allowAnonymous) throws UserAccessException, IOException {

		User user = newUserMap.get(currentUser);
		if (user == null || !user.isAdmin()) {
			throw new UserAccessException(currentUser + " must have ADMIN privilege!");
		}
		writeUserList(newUserMap, allowAnonymous);
	}

	/**
	 * Privileged method for updating user access list.
	 * @param newUserMap
	 * @param allowAnonymous
	 * @throws UserAccessException
	 * @throws IOException
	 */
	private void writeUserList(LinkedHashMap<String, User> newUserMap, boolean allowAnonymous)
			throws IOException {

		File temp = new File(userAccessFile.getParentFile(), "tempAccess.tmp");
		temp.delete();

		PrintWriter out = new PrintWriter(new FileOutputStream(temp));
		try {
			out.println(";");
			out.println("; User Access List for " + name + ": Auto-generated on " + new Date());
			out.println(";");

			if (allowAnonymous) {
				out.println(ANONYMOUS_STR);
			}

			Iterator<User> iter = newUserMap.values().iterator();
			while (iter.hasNext()) {
				User user = iter.next();
				String line = user.getName() + "=" + TYPE_NAMES[user.getPermissionType()];
				out.println(line);
			}
			out.flush();
		}
		finally {
			out.close();
		}

		userAccessFile.delete();
		temp.renameTo(userAccessFile);
	}

	/**
	 * Delete this repository and its contents.
	 * <P>
	 * NOTE: This method is not yet implemented.  Server admin should stop server
	 * and simply delete those repository directories which are unwanted.
	 * @param currentUser current user
	 * @throws IOException
	 * @throws UserAccessException
	 */
	void delete(String currentUser) throws IOException, UserAccessException {
		synchronized (fileSystem) {
			validate();
			validateAdminPrivilege(currentUser);

			// TODO Delete repository contents
			throw new IOException("Delete repository not yet implemented");
		}
	}

	/**
	 * Print to stdout the user access permissions to the specified repository.
	 * This is intended to be used with the svrAdmin console command
	 * @param repositoryDir repository directory
	 * @param pad padding string to be prefixed to each output line
	 */
	static void listUserPermissions(File repositoryDir, String pad) {
		File userAccessFile = new File(repositoryDir, ACCESS_CONTROL_FILENAME);
		try {
			ArrayList<User> list = new ArrayList<>();
			boolean anonymousAccessAllowed = readAccessFile(userAccessFile, list);
			Collections.sort(list);
			if (anonymousAccessAllowed) {
				System.out.println(pad + "* Anonymous read-only access permitted *");
			}
			for (User user : list) {
				System.out.println(pad + user);
			}
		}
		catch (IOException e) {
			System.out.println(pad + "Failed to read repository access file: " + e.getMessage());
		}
	}

	/**
	 * Read user access list from local file.
	 * @throws IOException
	 */
	private void readAccessFile() throws IOException {
		if (!userAccessFile.exists()) {
			return;
		}

		ArrayList<User> list = new ArrayList<>();
		anonymousAccessAllowed =
			readAccessFile(userAccessFile, list) && mgr.anonymousAccessAllowed();

		LinkedHashMap<String, User> newUserMap = new LinkedHashMap<>();
		Iterator<User> iter = list.iterator();
		boolean hasAdmin = false;
		while (iter.hasNext()) {
			User user = iter.next();
			hasAdmin |= user.isAdmin();
			newUserMap.put(user.getName(), user);
		}
		if (!hasAdmin) {
			throw new IOException("Repository does not have an Admin");
		}
		userMap = newUserMap;
	}

	/**
	 * Read list of user permissions from userAccessFile and determine if anonymous read-only
	 * access is permitted
	 * @param userAccessFile repository user access file
	 * @param users list to be populated with user permissions defined by userAccessFile
	 * @return true if anonymous read-only access is permitted, else false 
	 * @throws IOException
	 */
	private static boolean readAccessFile(File userAccessFile, List<User> users)
			throws IOException {
		boolean allowAnonymous = false;
		try (BufferedReader reader = new BufferedReader(new FileReader(userAccessFile))) {
			String line = "";
			while (true) {
				line = reader.readLine();
				if (line == null) {
					break;
				}
				if (line.startsWith(";")) {
					continue;
				}
				line = line.trim();
				if (ANONYMOUS_STR.equals(line)) {
					allowAnonymous = true;
					continue;
				}
				User user = processAccessLine(line);
				if (user != null) {
					users.add(user);
				}
			}
		}
		return allowAnonymous;
	}

	/**
	 * Parse input line from user access list
	 * @param line text line from user access file
	 * @return
	 */
	private static User processAccessLine(String line) {

		int pos = line.indexOf('=');
		if (pos > 0) {
			String userName = line.substring(0, pos).trim();
			String typeName = line.substring(pos + 1).trim();
			for (int i = 0; i < TYPE_NAMES.length; i++) {
				if (typeName.equals(TYPE_NAMES[i])) {
					return new User(userName, i);
				}
			}
		}
		return null;
	}

	/**
	 * Validate this repository.
	 * @throws IOException if repository no longer exists
	 */
	public void validate() throws IOException {
		if (!valid) {
			throw new IOException("Repository has been deleted");
		}
	}

	/**
	 * Verify that the specified currentUser has Admin privilege within this repository.
	 * @param currentUser current user
	 * @return user object for currentUser
	 * @throws UserAccessException thrown if currentUser does not have Admin privilege
	 */
	public User validateAdminPrivilege(String currentUser) throws UserAccessException {
		synchronized (fileSystem) {
			User user = getUser(currentUser);
			if (user == null) {
				throw new UserAccessException("User " + currentUser + " was not found in the '" +
					name + "' repository access list.");
			}
			if (!user.isAdmin()) {
				throw new UserAccessException(
					"User " + currentUser + " does not have Admin privilege.");
			}
			return user;
		}
	}

	/**
	 * Verify that the specified currentUser has Write privilege within this repository.
	 * @param currentUser current user
	 * @return user object for currentUser
	 * @throws UserAccessException thrown if currentUser does not have Write privilege
	 */
	public User validateWritePrivilege(String currentUser) throws UserAccessException {
		synchronized (fileSystem) {
			User user = getUser(currentUser);
			if (user == null) {
				throw new UserAccessException("User " + currentUser + " was not found in the '" +
					name + "' repository access list.");
			}
			if (user.isReadOnly()) {
				throw new UserAccessException(
					"User " + currentUser + " does not have write privilege.");
			}
			return user;
		}
	}

	/**
	 * Verify that the specified currentUser has Read privilege within this repository.
	 * @param currentUser current user
	 * @return user object for currentUser
	 * @throws UserAccessException thrown if currentUser does not have Read privilege
	 */
	public User validateReadPrivilege(String currentUser) throws UserAccessException {
		synchronized (fileSystem) {
			User user = getUser(currentUser);
			if (user == null) {
				throw new UserAccessException("User " + currentUser + " was not found in the '" +
					name + "' repository access list.");
			}
			return user;
		}
	}

	/**
	 * Generate RepositoryChangeEvent following the creation of a new folder.
	 * @see ghidra.framework.store.FileSystemListener#folderCreated(java.lang.String, java.lang.String)
	 */
	@Override
	public void folderCreated(String parentPath, String folderName) {

		// Make sure new RepositoryFolder exists
		try {
			RepositoryFolder folder = getFolder(null, parentPath, false);
			if (folder == null || folder.getFolder(folderName) == null) {
				RepositoryManager.log(name, RepositoryFolder.makePathname(parentPath, folderName),
					"ERROR! folder not found", null);
				return;
			}
		}
		catch (InvalidNameException e) {
			throw new AssertException();
		}
		catch (IOException e) {
			RepositoryManager.log(name, RepositoryFolder.makePathname(parentPath, folderName),
				"ERROR! " + e.getMessage(), null);
		}

		RepositoryChangeEvent event = new RepositoryChangeEvent(
			RepositoryChangeEvent.REP_FOLDER_CREATED, parentPath, folderName, null, null);
		sendChangeEvent(event);
	}

	/**
	 * Generate RepositoryChangeEvent following the creation of a new item.
	 * @see ghidra.framework.store.FileSystemListener#itemCreated(java.lang.String, java.lang.String)
	 */
	@Override
	public void itemCreated(String parentPath, String itemName) {

		// Make sure new RepositoryFile exists
		try {
			RepositoryFolder folder = getFolder(null, parentPath, false);
			if (folder == null || folder.getFile(itemName) == null) {
				RepositoryManager.log(name, RepositoryFolder.makePathname(parentPath, itemName),
					"file not found", null);
				return;
			}
		}
		catch (InvalidNameException e) {
			throw new AssertException();
		}
		catch (IOException e) {
			RepositoryManager.log(name, RepositoryFolder.makePathname(parentPath, itemName),
				"ERROR! " + e.getMessage(), null);
		}

		RepositoryChangeEvent event = new RepositoryChangeEvent(
			RepositoryChangeEvent.REP_ITEM_CREATED, parentPath, itemName, null, null);
		sendChangeEvent(event);
	}

	/**
	 * Generate RepositoryChangeEvent following the removal of a folder.
	 * @see ghidra.framework.store.FileSystemListener#folderDeleted(java.lang.String, java.lang.String)
	 */
	@Override
	public void folderDeleted(String parentPath, String folderName) {

		// Make sure RepositoryFile is removed
		try {
			RepositoryFolder folder =
				getFolder(null, RepositoryFolder.makePathname(parentPath, folderName), false);
			if (folder != null) {
				folder.delete();
			}
		}
		catch (InvalidNameException e) {
			throw new AssertException();
		}
		catch (IOException e) {
			RepositoryManager.log(name, parentPath, "ERROR! " + e.getMessage(), null);
		}

		RepositoryChangeEvent event = new RepositoryChangeEvent(
			RepositoryChangeEvent.REP_FOLDER_DELETED, parentPath, folderName, null, null);
		sendChangeEvent(event);
	}

	/**
	 * Generate RepositoryChangeEvent following the movement of a folder.
	 * @see ghidra.framework.store.FileSystemListener#folderMoved(java.lang.String, java.lang.String, java.lang.String)
	 */
	@Override
	public void folderMoved(String parentPath, String folderName, String newParentPath) {
		RepositoryChangeEvent event = new RepositoryChangeEvent(
			RepositoryChangeEvent.REP_FOLDER_MOVED, parentPath, folderName, newParentPath, null);
		sendChangeEvent(event);
	}

	/**
	 * Generate RepositoryChangeEvent following the renaming of a folder.
	 * @see ghidra.framework.store.FileSystemListener#folderRenamed(java.lang.String, java.lang.String, java.lang.String)
	 */
	@Override
	public void folderRenamed(String parentPath, String oldFolderName, String newFolderName) {
		RepositoryChangeEvent event =
			new RepositoryChangeEvent(RepositoryChangeEvent.REP_FOLDER_RENAMED, parentPath,
				oldFolderName, null, newFolderName);
		sendChangeEvent(event);
	}

	/**
	 * Generate RepositoryChangeEvent following the removal of an item.
	 * @see ghidra.framework.store.FileSystemListener#itemDeleted(java.lang.String, java.lang.String)
	 */
	@Override
	public void itemDeleted(String parentPath, String itemName) {
		RepositoryChangeEvent event = new RepositoryChangeEvent(
			RepositoryChangeEvent.REP_ITEM_DELETED, parentPath, itemName, null, null);
		sendChangeEvent(event);
	}

	/**
	 * Generate RepositoryChangeEvent following the renaming of an item.
	 * @see ghidra.framework.store.FileSystemListener#itemRenamed(java.lang.String, java.lang.String, java.lang.String)
	 */
	@Override
	public void itemRenamed(String parentPath, String oldItemName, String newItemName) {
		RepositoryChangeEvent event = new RepositoryChangeEvent(
			RepositoryChangeEvent.REP_ITEM_RENAMED, parentPath, oldItemName, null, newItemName);
		sendChangeEvent(event);
	}

	/**
	 * Generate RepositoryChangeEvent following the movement of an item.
	 * @see ghidra.framework.store.FileSystemListener#itemMoved(java.lang.String, java.lang.String, java.lang.String, java.lang.String)
	 */
	@Override
	public void itemMoved(String parentPath, String itemName, String newParentPath,
			String newName) {
		RepositoryChangeEvent event = new RepositoryChangeEvent(
			RepositoryChangeEvent.REP_ITEM_MOVED, parentPath, itemName, newParentPath, newName);
		sendChangeEvent(event);
	}

	/**
	 * Generate RepositoryChangeEvent following the status change of an item.
	 * @see ghidra.framework.store.FileSystemListener#itemChanged(java.lang.String, java.lang.String)
	 */
	@Override
	public void itemChanged(String parentPath, String itemName) {

		boolean syncErr = true;
		RepositoryFolder parentFolder;
		try {
			parentFolder = getFolder(null, parentPath, false);
			if (parentFolder != null) {
				RepositoryFile rf = parentFolder.getFile(itemName);
				if (rf != null) {
					rf.itemChanged();
					syncErr = false;
				}
			}
		}
		catch (InvalidNameException e) {
			throw new AssertException();
		}
		catch (IOException e) {
			RepositoryManager.log(name, RepositoryFolder.makePathname(parentPath, itemName),
				"ERROR! " + e.getMessage(), null);
		}
		if (syncErr) {
			RepositoryManager.log(name, null, "ERROR! Repository instance may be out-of-sync",
				null);
			return;
		}

		RepositoryChangeEvent event = new RepositoryChangeEvent(
			RepositoryChangeEvent.REP_ITEM_CHANGED, parentPath, itemName, null, null);
		sendChangeEvent(event);
	}

	/*
	 * @see ghidra.framework.store.FileSystemListener#syncronize()
	 */
	@Override
	public void syncronize() {
		// not required
	}

	@Override
	public void log(String path, String msg, String user) {
		RepositoryManager.log(name, path, msg, user);
	}

	static boolean markRepositoryForIndexMigration(File serverDir, String repositoryName,
			boolean silent) {
		File repoDir = new File(serverDir, NamingUtilities.mangle(repositoryName));
		if (!repoDir.isDirectory() ||
			repositoryName.startsWith(LocalFileSystem.HIDDEN_DIR_PREFIX)) {
			System.err.println("Repository '" + repositoryName + "' not found");
			return false;
		}
		String rootPath = repoDir.getAbsolutePath();
		boolean isIndexed = IndexedLocalFileSystem.isIndexed(rootPath);
		if (isIndexed) {
			try {
				int indexVersion = IndexedLocalFileSystem.readIndexVersion(rootPath);
				if (indexVersion >= IndexedLocalFileSystem.LATEST_INDEX_VERSION) {
					if (!silent) {
						System.err.println(
							"Repository '" + repositoryName + "' is already indexed!");
					}
					return false;
				}
			}
			catch (IOException e) {
				System.err.println(
					"Repository access error (" + repositoryName + "): " + e.getMessage());
				return false;
			}
		}
		// Mark repository for index migration
		File indexMigrationMarkerFile = new File(repoDir, INDEX_MIGRATION_MARKER_FILE);
		try {
			indexMigrationMarkerFile.createNewFile();
			System.out.println(
				"Repository '" + repositoryName + "' marked for index migration on server restart");
		}
		catch (IOException e) {
			System.err.println("Failed to mark repository for migration: " + e.getMessage());
		}
		return true;
	}

	/**
	 * @return object to be used for synchronization of a specific repository.
	 */
	public Object getSyncObject() {
		return fileSystem;
	}

}
