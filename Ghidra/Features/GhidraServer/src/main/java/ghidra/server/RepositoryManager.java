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

import java.io.File;
import java.io.IOException;
import java.net.UnknownHostException;
import java.rmi.server.ServerNotActiveException;
import java.util.*;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import ghidra.framework.remote.InetNameLookup;
import ghidra.framework.store.local.IndexedLocalFileSystem;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.server.remote.RepositoryServerHandleImpl;
import ghidra.util.NamingUtilities;
import ghidra.util.StringUtilities;
import ghidra.util.exception.*;
import utilities.util.FileUtilities;

/**
 * Class to manage a set of Repositories under a root directory.
 */
public class RepositoryManager {
	static final Logger log = LogManager.getLogger(RepositoryManager.class);

	private static Map<Thread, String> clientNameMap = new WeakHashMap<>();

	private File rootDirFile;
	private HashMap<String, Repository> repositoryMap; // maps name to Repository
	private ArrayList<RepositoryServerHandleImpl> handleList = new ArrayList<>();
	private UserManager userMgr;
	private boolean anonymousAccessAllowed;

	/**
	 * Construct a new RepositoryManager.
	 * @param rootDir directory where repositories will be created; this
	 * path contains a list of users that can access the repositories 
	 * being managed.
	 * @param enableLocalPasswords if true user passwords will be maintained 
	 * 			within local 'users' file
	 * @param defaultPasswordExpirationDays password expiration in days when 
	 * 			local passwords are enabled (0 = no expiration)
	 * @param anonymousAccessAllowed if true server permits anonymous access
	 * to repositories.  
	 * @throws IOException if IO error occurs
	 */
	public RepositoryManager(File rootDir, boolean enableLocalPasswords,
			int defaultPasswordExpirationDays, boolean anonymousAccessAllowed) throws IOException {
		rootDirFile = rootDir;
		log.info("Instantiating Repository Manager for " + rootDirFile.getAbsolutePath());
		if (!rootDirFile.isDirectory()) {
			throw new IOException(rootDirFile + " is not a directory");
		}
		if (!rootDirFile.canWrite()) {
			throw new IOException(rootDirFile + " can not be written to");
		}
		this.anonymousAccessAllowed = anonymousAccessAllowed;
		this.userMgr = new UserManager(this, enableLocalPasswords, defaultPasswordExpirationDays);
		repositoryMap = new HashMap<>();
		initialize();
	}

	public boolean anonymousAccessAllowed() {
		return anonymousAccessAllowed;
	}

	private boolean isAnonymousUser(String user) {
		if (anonymousAccessAllowed) {
			return UserManager.ANONYMOUS_USERNAME.equals(user);
		}
		return false;
	}

	/**
	 * Dispose this repository manager and all repository instances
	 */
	public synchronized void dispose() {
		Iterator<Repository> iter = repositoryMap.values().iterator();
		while (iter.hasNext()) {
			Repository rep = iter.next();
			rep.dispose();
		}
	}

	/**
	 * Return repositories root directory
	 */
	File getRootDir() {
		return rootDirFile;
	}

	/**
	 * Create a new Repository.
	 * @param currentUser user creating the repository
	 * @param name name of the repository
	 * @return a new Repository
	 * @throws DuplicateNameException if another repository exists with the
	 * given name
	 * @throws UserAccessException if the user does not exist in
	 * the list of known users for this manager
	 * @throws IOException if there was an error creating the repository
	 */
	public synchronized Repository createRepository(String currentUser, String name)
			throws IOException {

		if (isAnonymousUser(currentUser)) {
			throw new UserAccessException("Anonymous user not permitted to create repository");
		}

		validateUser(currentUser);

		if (!NamingUtilities.isValidProjectName(name)) {
			throw new IOException("Invalid repository name: " + name);
		}
		if (repositoryMap.containsKey(name)) {
			throw new DuplicateFileException("Repository named " + name + " already exists");
		}

		File f = new File(rootDirFile, NamingUtilities.mangle(name));
		if (!f.mkdir()) {
			throw new IOException("Failed to make directory for " + f.getAbsolutePath());
		}

		Repository rep = new Repository(this, currentUser, f, name);
		log(name, null, "repository created", currentUser);
		repositoryMap.put(name, rep);
		return rep;
	}

	/**
	 * Get the Repository with the given name.
	 * @param currentUser user making the request.
	 * @param name name of the repository
	 * @return null if no repository exists with the given name
	 * @throws UserAccessException if the currentUser does not have
	 * access to the repository
	 */
	public synchronized Repository getRepository(String currentUser, String name)
			throws UserAccessException {

		if (!isAnonymousUser(currentUser)) {
			validateUser(currentUser);
		}

		Repository rep = repositoryMap.get(name);
		if (rep != null) {
			rep.validateReadPrivilege(currentUser);
		}
		return rep;
	}

	/**
	 * Get the repository for privileged use.
	 * @param name repository name
	 * @return null if no repository exists with the given name
	 */
	synchronized Repository getRepository(String name) {
		return repositoryMap.get(name);
	}

	/**
	 * Delete a specified repository.
	 * @param currentUser current user
	 * @param name repository name
	 * @throws IOException
	 */
	public synchronized void deleteRepository(String currentUser, String name) throws IOException {

		if (isAnonymousUser(currentUser)) {
			throw new UserAccessException("Anonymous user not permitted to delete repository");
		}

		validateUser(currentUser);

		Repository rep = repositoryMap.get(name);
		if (rep == null) {
			return;
		}

		rep.delete(currentUser);

		File f = new File(rootDirFile, NamingUtilities.mangle(name));
		if (!FileUtilities.deleteDir(f)) {
			throw new IOException("Failed to remove directory for " + f.getAbsolutePath());
		}

		repositoryMap.remove(name);
	}

	/**
	 * Get the names of the known repositories which are accessable by the specified user.
	 * @param currentUser name of user requesting repository list
	 * @return sorted array of names
	 */
	public synchronized String[] getRepositoryNames(String currentUser) {

		ArrayList<String> list = new ArrayList<>();
		Iterator<Repository> iter = repositoryMap.values().iterator();
		while (iter.hasNext()) {
			Repository rep = iter.next();
			if (isAnonymousUser(currentUser)) {
				if (rep.anonymousAccessAllowed()) {
					list.add(rep.getName());
				}
			}
			else if (rep.getUser(currentUser) != null) {
				list.add(rep.getName());
			}
		}
		Collections.sort(list);
		String[] names = new String[list.size()];
		return list.toArray(names);
	}

	/**
	 * Get all defined users. If currentUser is an
	 * Anonymous user an empty array will be returned.
	 * @param currentUser current user
	 * @return array of users known to this manager or empty array if 
	 * we should not reveal to currentUser.
	 */
	public synchronized String[] getAllUsers(String currentUser) throws IOException {
		if (isAnonymousUser(currentUser)) {
			return new String[0];
		}
		try {
			return userMgr.getUsers();
		}
		catch (IOException e) {
			log.error("Error while accessing user list: " + e.getMessage());
			throw new IOException("Failed to read user list");
		}
	}

	public UserManager getUserManager() {
		return userMgr;
	}

	/**
	 * Verify that the specified currentUser is a known user
	 * @param currentUser current user
	 * @throws UserAccessException
	 */
	private void validateUser(String currentUser) throws UserAccessException {
		if (!userMgr.isValidUser(currentUser)) {
			throw new UserAccessException(currentUser + " is unknown to this repository manager");
		}
	}

	/**
	 * Scan for existing repositories and build repositoryMap.
	 * @throws IOException
	 */
	private void initialize() throws IOException {

		log.info("Known Repositories:");
		String[] names = getRepositoryNames(rootDirFile);
		for (String name : names) {
			log.info("   " + name);
		}
		if (names.length == 0) {
			log.info("   <none>");
		}
		for (String name : names) {
			File f = new File(rootDirFile, NamingUtilities.mangle(name));
			if (!f.isDirectory()) {
				log.error("Error while processing repository " + name +
					", directory not found: " + f);
				continue;
			}
			if (!f.canWrite()) {
				throw new IOException(f.getAbsolutePath() + " can not be written to");
			}
			try {
				Repository rep = new Repository(this, null, f, name);
				repositoryMap.put(name, rep);
			}
			catch (UserAccessException e) {
				// ignore
			}
			catch (Exception e) {
				log.error("Error while processing repository " + name + ", " + e.getMessage());
				continue;
			}
		}

		userMgr.updateUserList(true);
	}

	static String getElapsedTimeSince(long t) {
		t = System.currentTimeMillis() - t;

		if (t < 1000) {
			return null;
		}

		int hours = (int) (t / 3600000);
		int mins = (int) ((t - (hours * 3600000)) / 60000);
		int secs = (int) ((t % 60000) / 1000);

		StringBuilder tbuf = new StringBuilder();
		String units = "secs";
		tbuf.append(StringUtilities.pad(Integer.toString(secs), '0', 2));
		if (t >= 60000) {
			units = "mins:" + units;
			tbuf.insert(0, ":");
			tbuf.insert(0, StringUtilities.pad(Integer.toString(mins), '0', 2));
			if (t >= 3600000) {
				units = "hours:" + units;
				tbuf.insert(0, ":");
				tbuf.insert(0, StringUtilities.pad(Integer.toString(hours), '0', 2));
			}
		}
		return tbuf.toString() + " (" + units + ")";
	}

	/**
	 * Add a user handle to this repository server.
	 * @param handle user repository server handle
	 */
	public void addHandle(RepositoryServerHandleImpl handle) {
		synchronized (handleList) {
			handleList.add(handle);
		}
	}

	/**
	 * Drop the specified handle to this repository server
	 * @param handle user repository server handle
	 */
	public void dropHandle(RepositoryServerHandleImpl handle) {
		synchronized (handleList) {
			handleList.remove(handle);
		}
	}

	/**
	 * Get a sorted array of repository names contained within the specified server root directory.
	 * @param rootDirFile server root directory
	 * @return array of repository names
	 */
	static String[] getRepositoryNames(File rootDirFile) {
		File[] dirList = rootDirFile.listFiles();
		if (dirList == null) {
			//throw new FileNotFoundException("Folder " + rootDirFile + " not found");
			return new String[0];
		}
		ArrayList<String> list = new ArrayList<>(dirList.length);
		for (File element : dirList) {
			if (!element.isDirectory() ||
				LocalFileSystem.isHiddenDirName(element.getName())) {
				continue;
			}
			if (!NamingUtilities.isValidMangledName(element.getName())) {
				log.warn("Ignoring repository directory with bad name: " + element);
				continue;
			}
			list.add(NamingUtilities.demangle(element.getName()));
		}
		Collections.sort(list);
		String[] names = new String[list.size()];
		return list.toArray(names);
	}

	public static String getRMIClient() {
		Thread currentThread = Thread.currentThread();
		if (!currentThread.getName().startsWith("RMI TCP Connection")) {
			return null;
		}
		String host;
		synchronized (clientNameMap) {
			host = clientNameMap.get(currentThread);
			if (host != null) {
				return host;
			}
		}
		try {
			host = sun.rmi.transport.tcp.TCPTransport.getClientHost();
			try {
				host = InetNameLookup.getCanonicalHostName(host);
			}
			catch (UnknownHostException e) {
				log.warn("Failed to resolve hostname: " + host);
			}
			synchronized (clientNameMap) {
				clientNameMap.put(currentThread, host);
			}
		}
		catch (ServerNotActiveException e1) {
			// ignore
		}
		return host;
	}

	public static void log(String repositoryName, String path, String msg, String user) {
		StringBuffer buf = new StringBuffer();
		if (repositoryName != null) {
			buf.append("[");
			buf.append(repositoryName);
			buf.append("]");
		}
		String host = RepositoryManager.getRMIClient();
		String userStr = user;
		if (userStr != null) {
			if (host != null) {
				userStr += "@" + host;
			}
		}
		else {
			userStr = host;
		}
		if (path != null) {
			buf.append(path);
		}
		if (repositoryName != null || path != null) {
			buf.append(": ");
		}
		buf.append(msg);
		if (userStr != null) {
			buf.append(" (");
			buf.append(userStr);
			buf.append(")");
		}
		log.info(buf.toString());
	}

	/**
	 * Print to stdout the set of repository names defined within the specified repositories root.
	 * This is intended to be used with the svrAdmin console command
	 * @param repositoriesRootDir repositories root directory
	 * @param includeUserAccessDetails
	 */
	static void listRepositories(File repositoriesRootDir, boolean includeUserAccessDetails) {
		String[] names = RepositoryManager.getRepositoryNames(repositoriesRootDir);
		System.out.println("\nRepositories:");
		if (names.length == 0) {
			System.out.println("   <No repositories have been created>");
		}
		else {
			for (String name : names) {
				File repoDir = new File(repositoriesRootDir, NamingUtilities.mangle(name));
				String rootPath = repoDir.getAbsolutePath();
				boolean isIndexed = IndexedLocalFileSystem.isIndexed(rootPath);
				String type;
				if (isIndexed || IndexedLocalFileSystem.hasIndexedStructure(rootPath)) {
					type = "Indexed Filesystem";
					try {
						int indexVersion = IndexedLocalFileSystem.readIndexVersion(rootPath);
						if (indexVersion == IndexedLocalFileSystem.LATEST_INDEX_VERSION) {
							type = null;
						}
						else {
							type += " (V" + indexVersion + ")";
						}
					}
					catch (IOException e) {
						type += "(unknown)";
					}
				}
				else {
					type = "Mangled Filesystem";
				}

				System.out.println("  " + name + (type == null ? "" : (" - uses " + type)));

				if (includeUserAccessDetails) {
					Repository.listUserPermissions(repoDir, "    ");
				}
			}
		}
	}

	static void markAllRepositoriesForIndexMigration(File serverDir) {
		String[] names = RepositoryManager.getRepositoryNames(serverDir);
		if (names.length == 0) {
			System.err.println("No repositories found!");
			return;
		}
		int count = 0;
		for (String name : names) {
			if (Repository.markRepositoryForIndexMigration(serverDir, name, true)) {
				++count;
			}
		}
		if (count == 0) {
			System.out.println("All repositories are already indexed");
		}
	}

}
