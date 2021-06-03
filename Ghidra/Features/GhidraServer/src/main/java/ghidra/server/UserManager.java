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
import java.util.regex.Pattern;

import javax.security.auth.login.FailedLoginException;
import javax.security.auth.x500.X500Principal;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import ghidra.framework.remote.User;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.util.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * <code>UserManager</code> manages the set of users associated with a running GhidraServer.
 * Support is also provided for managing and authenticating local user passwords when 
 * needed.
 */
public class UserManager {

	static final Logger log = LogManager.getLogger(UserManager.class);

	public static final String X500_NAME_FORMAT = X500Principal.RFC2253;

	public static final String ANONYMOUS_USERNAME = User.ANONYMOUS_USERNAME;

	public static final String USER_PASSWORD_FILE = "users";
	public static final String DN_LOG_FILE = "UnknownDN.log";

	private static final String SSH_KEY_FOLDER = LocalFileSystem.HIDDEN_DIR_PREFIX + "ssh";
	private static final String SSH_PUBKEY_EXT = ".pub";

	private static final char[] DEFAULT_PASSWORD = "changeme".toCharArray();

	private static final int DEFAULT_PASSWORD_TIMEOUT_DAYS = 1; // 24-hours
	private static final int NO_EXPIRATION = -1;

	private RepositoryManager repositoryMgr;

	private final File userFile;
	private final File sshDir;

	private boolean enableLocalPasswords;
	private long defaultPasswordExpirationMS;

	private PrintWriter dnLogOut;

	private LinkedHashMap<String, UserEntry> userList = new LinkedHashMap<>();
	private HashMap<X500Principal, UserEntry> dnLookupMap = new HashMap<>();
	private long lastUserListChange;
	private boolean userListUpdateInProgress = false;

	/**
	 * Construct server user manager
	 * @param repositoryMgr repository manager (used for queued command processing)
	 * @param enableLocalPasswords if true user passwords will be maintained 
	 * 			within local 'users' file
	 * @param defaultPasswordExpirationDays password expiration in days when 
	 * 			local passwords are enabled (0 = no expiration)
	 */
	UserManager(RepositoryManager repositoryMgr, boolean enableLocalPasswords,
			int defaultPasswordExpirationDays) {
		this.repositoryMgr = repositoryMgr;
		this.enableLocalPasswords = enableLocalPasswords;
		if (defaultPasswordExpirationDays < 0) {
			defaultPasswordExpirationDays = DEFAULT_PASSWORD_TIMEOUT_DAYS;
		}
		this.defaultPasswordExpirationMS = defaultPasswordExpirationDays * 24L * 3600L * 1000L;
		log.info("Instantiating User Manager " +
			(enableLocalPasswords ? "(w/password management)" : ""));

		userFile = new File(repositoryMgr.getRootDir(), USER_PASSWORD_FILE);
		try {
			// everything must be constructed before processing commands
			updateUserList(false);
			log.info("User file contains " + userList.size() + " entries");
		}
		catch (FileNotFoundException e) {
			log.error("Existing User file not found.");
		}
		catch (IOException e) {
			log.error(e);
		}

		log.info("Known Users:");
		Iterator<String> iter = userList.keySet().iterator();
		while (iter.hasNext()) {
			String name = iter.next();
			String dnStr = "";
			UserEntry entry = userList.get(name);
			if (entry != null) {
				X500Principal x500User = entry.x500User;
				if (x500User != null) {
					dnStr = " DN={" + x500User.getName() + "}";
				}
			}
			log.info("   " + name + dnStr);
		}

		sshDir = new File(repositoryMgr.getRootDir(), SSH_KEY_FOLDER);
		initSSH();
	}

	private void initSSH() {

		if (!sshDir.exists()) {
			sshDir.mkdir();
			return;
		}

		String[] list = sshDir.list((dir, name) -> name.endsWith(SSH_PUBKEY_EXT));
		if (list.length == 0) {
			return;
		}

		log.info("Users with stored SSH public key:");
		for (String fname : list) {
			String user = fname.substring(0, fname.length() - SSH_PUBKEY_EXT.length());
			if (!userList.containsKey(user)) {
				continue; // ignore invalid user
			}
			log.info("   " + user);
		}
	}

	/**
	 * Get the SSH public key file for the specified user
	 * if it exists.
	 * @param user
	 * @return SSH public key file or null if key unavailable
	 */
	public File getSSHPubKeyFile(String user) {
		if (!userList.containsKey(user)) {
			return null;
		}
		File f = new File(sshDir, user + SSH_PUBKEY_EXT);
		if (f.isFile()) {
			return f;
		}
		return null;
	}

	/**
	 * Add a user.
	 * @param username user name/SID
	 * @param passwordHash MD5 hash of initial password or null if explicit password reset required
	 * @param dn X500 distinguished name for user (may be null)
	 * @throws DuplicateNameException if username already exists
	 * @throws IOException if IO error occurs
	 */
	private synchronized void addUser(String username, char[] passwordHash, X500Principal x500User)
			throws DuplicateNameException, IOException {
		if (username == null) {
			throw new IllegalArgumentException();
		}
		updateUserList(true);
		if (userList.containsKey(username)) {
			throw new DuplicateNameException("User " + username + " already exists");
		}
		UserEntry entry = new UserEntry();
		entry.username = username;
		entry.passwordHash = passwordHash;
		entry.passwordTime = (new Date()).getTime();
		entry.x500User = x500User;
		userList.put(username, entry);
		if (x500User != null) {
			dnLookupMap.put(x500User, entry);
		}
		writeUserList();
	}

	/**
	 * Add a user.
	 * @param username user name/SID
	 * @throws DuplicateNameException if username already exists
	 * @throws IOException if IO error occurs
	 */
	public void addUser(String username) throws DuplicateNameException, IOException {
		addUser(username, (char[]) null);
	}

	/**
	 * Add a user with optional salted password hash.
	 * @param username user name/SID
	 * @param saltedPasswordHash optional user password hash (may be null)
	 * @throws DuplicateNameException if username already exists
	 * @throws IOException if IO error occurs
	 */
	void addUser(String username, char[] saltedPasswordHash)
			throws DuplicateNameException, IOException {
		if (saltedPasswordHash == null && enableLocalPasswords) {
			saltedPasswordHash = getDefaultPasswordHash();
		}
		addUser(username, saltedPasswordHash, null);
	}

	/**
	 * Add a user.
	 * @param username user name/SID
	 * @param x500User X500 distinguished name for user (may be null)
	 * @throws DuplicateNameException if username already exists
	 * @throws IOException if IO error occurs
	 */
	public void addUser(String username, X500Principal x500User)
			throws DuplicateNameException, IOException {
		char[] passwordHash = enableLocalPasswords ? getDefaultPasswordHash() : null;
		addUser(username, passwordHash, x500User);
	}

	/**
	 * Returns the X500 distinguished name for the specified user.
	 * @param username user name/SID
	 * @return X500 distinguished name
	 * @throws IOException
	 */
	public synchronized X500Principal getDistinguishedName(String username) throws IOException {
		updateUserList(true);
		UserEntry entry = userList.get(username);
		if (entry != null) {
			return entry.x500User;
		}
		return null;
	}

	/**
	 * Returns the username associated with the specified distinguished name
	 * @param x500User a user's X500 distinguished name
	 * @return username or null if not found
	 */
	public synchronized String getUserByDistinguishedName(X500Principal x500User)
			throws IOException {
		updateUserList(true);
		UserEntry entry = dnLookupMap.get(x500User);
		return entry != null ? entry.username : null;
	}

	/**
	 * Sets the X500 distinguished name for a user
	 * @param username user name/SID
	 * @param x500User X500 distinguished name
	 * @return true if successful, false if user not found
	 * @throws IOException
	 */
	public synchronized boolean setDistinguishedName(String username, X500Principal x500User)
			throws IOException {
		updateUserList(true);
		UserEntry oldEntry = userList.remove(username);
		if (oldEntry != null) {
			if (oldEntry.x500User != null) {
				dnLookupMap.remove(oldEntry.x500User);
			}
			UserEntry entry = new UserEntry();
			entry.username = username;
			entry.passwordHash = oldEntry.passwordHash;
			entry.x500User = x500User;
			userList.put(username, entry);
			if (x500User != null) {
				dnLookupMap.put(x500User, entry);
			}
			writeUserList();
			return true;
		}
		return false;
	}

	private void checkValidPasswordHash(char[] saltedPasswordHash) throws IOException {
		if (saltedPasswordHash == null ||
			saltedPasswordHash.length != HashUtilities.SHA256_SALTED_HASH_LENGTH) {
			throw new IOException("Invalid password hash");
		}
		for (int i = 0; i < HashUtilities.SALT_LENGTH; i++) {
			if (!isLetterOrDigit(saltedPasswordHash[i])) {
				throw new IOException(
					"Password set failed due invalid salt: " + (new String(saltedPasswordHash)) +
						" (" + i + "," + saltedPasswordHash[i] + ")");
			}
		}
		for (int i = HashUtilities.SALT_LENGTH; i < saltedPasswordHash.length; i++) {
			if (!isLowercaseHexDigit(saltedPasswordHash[i])) {
				throw new IOException(
					"Password set failed due to invalid hash: " + (new String(saltedPasswordHash)) +
						" (" + i + "," + saltedPasswordHash[i] + ")");
			}
		}
	}

	private boolean isLetterOrDigit(char c) {
		if (c < '0') {
			return false;
		}
		if (c > '9' && c < 'A') {
			return false;
		}
		if (c > 'Z' && c < 'a') {
			return false;
		}
		return c <= 'z';
	}

	private boolean isLowercaseHexDigit(char c) {
		if (c < '0') {
			return false;
		}
		if (c > '9' && c < 'a') {
			return false;
		}
		return c <= 'f';
	}

	/**
	 * Sets the local password hash for a user
	 * @param username user name/SID
	 * @param saltedSHA256PasswordHash 4-character salt followed by 64-hex digit SHA256 password hash for new password
	 * @param isTemporary if true password will be set to expire
	 * @return true if successful, false if user not found
	 * @throws IOException
	 */
	public synchronized boolean setPassword(String username, char[] saltedSHA256PasswordHash,
			boolean isTemporary) throws IOException {
		if (!enableLocalPasswords) {
			throw new IOException("Local passwords are not used");
		}

		checkValidPasswordHash(saltedSHA256PasswordHash);

		updateUserList(true);
		UserEntry oldEntry = userList.remove(username);
		if (oldEntry != null) {
			UserEntry entry = new UserEntry();
			entry.username = username;
			entry.passwordHash = saltedSHA256PasswordHash;
			entry.passwordTime = isTemporary ? (new Date()).getTime() : NO_EXPIRATION;
			entry.x500User = oldEntry.x500User;
			userList.put(username, entry);
			if (entry.x500User != null) {
				dnLookupMap.put(entry.x500User, entry);
			}
			writeUserList();
			return true;
		}
		return false;
	}

	/**
	 * Returns true if local passwords are in use and can be changed by the user.
	 * @see #setPassword(String, char[])
	 */
	public boolean canSetPassword(String username) {
		UserEntry userEntry = userList.get(username);
		return (enableLocalPasswords && userEntry != null && userEntry.passwordHash != null);
	}

	/**
	 * Returns the amount of time in milliseconds until the 
	 * user's password will expire.
	 * @param username user name
	 * @return time until expiration or -1 if it will not expire
	 */
	public long getPasswordExpiration(String username) throws IOException {
		updateUserList(true);

		UserEntry userEntry = userList.get(username);

		// indicate immediate expiration for users with short hash (non salted SHA-256)
		if (userEntry != null && userEntry.passwordHash != null &&
			userEntry.passwordHash.length != HashUtilities.SHA256_SALTED_HASH_LENGTH) {
			return 0;
		}

		return getPasswordExpiration(userEntry);
	}

	/**
	 * Returns the amount of time in milliseconds until the 
	 * user's password will expire.
	 * @param user user entry
	 * @return time until expiration or -1 if it will not expire
	 */
	private long getPasswordExpiration(UserEntry user) {
		long timeRemaining = 0;
		if (user != null) {
			// Expiration only applies to default password
			if (defaultPasswordExpirationMS == 0 || user.passwordTime == NO_EXPIRATION) {
				return -1;
			}
			if (user.passwordTime != 0) {
				timeRemaining =
					defaultPasswordExpirationMS - ((new Date()).getTime() - user.passwordTime);
				if (timeRemaining <= 0) {
					timeRemaining = 0;
				}
			}
		}
		return timeRemaining;
	}

	/**
	 * Reset the local password to the 'changeme' for the specified user.
	 * @param username
	 * @param saltedPasswordHash optional user password hash (may be null)
	 * @return true if password updated successfully.
	 * @throws IOException
	 */
	public boolean resetPassword(String username, char[] saltedPasswordHash) throws IOException {
		if (!enableLocalPasswords) {
			return false;
		}
		return setPassword(username,
			saltedPasswordHash != null ? saltedPasswordHash : getDefaultPasswordHash(), true);
	}

	private char[] getDefaultPasswordHash() {
		return HashUtilities.getSaltedHash(HashUtilities.SHA256_ALGORITHM, DEFAULT_PASSWORD);
	}

	/**
	 * Remove the specified user from the server access list
	 * @param username user name/SID
	 * @throws IOException
	 */
	public synchronized void removeUser(String username) throws IOException {
		updateUserList(true);
		UserEntry oldEntry = userList.remove(username);
		if (oldEntry != null) {
			if (oldEntry.x500User != null) {
				dnLookupMap.remove(oldEntry.x500User);
			}
			writeUserList();
		}
	}

	/**
	 * Get list of all users known to server.
	 * @return list of known users
	 * @throws IOException
	 */
	public synchronized String[] getUsers() throws IOException {
		updateUserList(true);
		String[] names = new String[userList.size()];
		Iterator<String> iter = userList.keySet().iterator();
		int i = 0;
		while (iter.hasNext()) {
			names[i++] = iter.next();
		}
		return names;
	}

	/**
	 * Refresh the server's user list and process any pending UserAdmin commands.
	 * @param processCmds TODO
	 * @throws IOException
	 */
	synchronized void updateUserList(boolean processCmds) throws IOException {
		if (userListUpdateInProgress) {
			return;
		}
		userListUpdateInProgress = true;
		try {
			readUserListIfNeeded();
			clearExpiredPasswords();
			if (processCmds) {
				UserAdmin.processCommands(repositoryMgr);
			}
		}
		finally {
			userListUpdateInProgress = false;
		}
	}

	/**
	 * Clear all local user passwords which have expired.
	 * @throws IOException
	 */
	private void clearExpiredPasswords() throws IOException {
		if (defaultPasswordExpirationMS == 0) {
			return;
		}
		boolean dataChanged = false;
		Iterator<UserEntry> it = userList.values().iterator();
		while (it.hasNext()) {
			UserEntry entry = it.next();
			if (enableLocalPasswords && getPasswordExpiration(entry) == 0) {
				entry.passwordHash = null;
				entry.passwordTime = 0;
				dataChanged = true;
				log.warn("Default password expired for user '" + entry.username + "'");
			}
		}
		if (dataChanged) {
			writeUserList();
		}
	}

	/**
	 * Read user data from file if the timestamp on the file has changed.
	 * 
	 * @throws IOException
	 */
	private void readUserListIfNeeded() throws IOException {

		long lastMod = userFile.lastModified();
		if (lastUserListChange == lastMod) {
			if (lastMod == 0) {
				// Create empty file if it does not yet exist
				writeUserList();
			}
			return;
		}

		LinkedHashMap<String, UserEntry> list = new LinkedHashMap<>();
		HashMap<X500Principal, UserEntry> lookupMap = new HashMap<>();

		readUserList(userFile, list, lookupMap);

		userList = list;
		dnLookupMap = lookupMap;
		lastUserListChange = lastMod;
	}

	/**
	 * Print to stdout the set of user names with access to the specified repositories root.
	 * This is intended to be used with the svrAdmin console command
	 * @param repositoriesRootDir repositories root directory
	 */
	static void listUsers(File repositoriesRootDir) {
		File userFile = new File(repositoriesRootDir, USER_PASSWORD_FILE);

		LinkedHashMap<String, UserEntry> list = new LinkedHashMap<>();
		HashMap<X500Principal, UserEntry> lookupMap = new HashMap<>();

		try {
			readUserList(userFile, list, lookupMap);

			System.out.println("\nRepository Server Users:");
			if (list.isEmpty()) {
				System.out.println("   <No users have been added>");
			}
			else {
				for (String name : list.keySet()) {
					System.out.println("  " + name);
				}
			}
		}
		catch (IOException e) {
			System.out.println("\nFailed to read user file: " + e.getMessage());
		}
	}

	private static void readUserList(File file, Map<String, UserEntry> usersIndexByName,
			Map<X500Principal, UserEntry> x500LookupMap) throws IOException {
		try (BufferedReader br = new BufferedReader(new FileReader(file))) {
			String line;
			while ((line = br.readLine()) != null) {
				if (line.startsWith("#")) {
					continue;
				}
				try {
					StringTokenizer st = new StringTokenizer(line, ":");
					UserEntry entry = new UserEntry();
					entry.username = st.nextToken();
					if (!isValidUserName(entry.username)) {
						log.error("Invalid user name, skipping: " + entry.username);
						continue;
					}

					// Password Hash
					if (st.hasMoreTokens()) {
						entry.passwordHash = st.nextToken().toCharArray();

						// Password Time
						if (st.hasMoreTokens()) {
							try {
								String timeStr = st.nextToken();
								if ("*".equals(timeStr)) {
									entry.passwordTime = NO_EXPIRATION;
								}
								else {
									entry.passwordTime = NumericUtilities.parseHexLong(timeStr);
								}
							}
							catch (NumberFormatException e) {
								log.error(
									"Invalid password time - forced expiration: " + entry.username);
								entry.passwordTime = 0;
							}

							// Distinguished Name
							if (st.hasMoreTokens()) {
								String dn = st.nextToken();
								if (dn.length() > 0) {
									entry.x500User = new X500Principal(dn);
								}

							}
						}
					}
					usersIndexByName.put(entry.username, entry);
					if (entry.x500User != null) {
						x500LookupMap.put(entry.x500User, entry);
					}
				}
				catch (NoSuchElementException e) {
					// skip entry
				}
			}
		}
	}

	/**
	 * Write user data to file.
	 * @throws IOException
	 */
	private void writeUserList() throws IOException {
		try (BufferedWriter bw = new BufferedWriter(new FileWriter(userFile))) {
			for (UserEntry entry : userList.values()) {
				bw.write(entry.username);
				bw.write(":");
				if (entry.passwordHash != null) {
					bw.write(entry.passwordHash);
					bw.write(':');
					if (entry.passwordTime == NO_EXPIRATION) {
						bw.write('*');
					}
					else {
						bw.write(Long.toHexString(entry.passwordTime));
					}
				}
				else {
					bw.write("*:*");
				}
				if (entry.x500User != null) {
					bw.write(":");
					bw.write(entry.x500User.getName());
				}
				bw.newLine();
			}
		}
		lastUserListChange = userFile.lastModified();
	}

	/**
	 * Returns true if the specified user is known to server.
	 * @param username user name/SID
	 * @return
	 */
	public synchronized boolean isValidUser(String username) {
		try {
			updateUserList(true);
		}
		catch (IOException e) {
			// ignore
		}
		return userList.containsKey(username);
	}

	/**
	 * Verify that the specified password corresponds to the local
	 * password set for the specified user.
	 * @param username user name/SID
	 * @param password password data
	 * @throws IOException
	 * @throws FailedLoginException if authentication fails
	 */
	public synchronized void authenticateUser(String username, char[] password)
			throws IOException, FailedLoginException {
		if (username == null || password == null) {
			throw new FailedLoginException("Invalid authentication data");
		}
		updateUserList(true);
		UserEntry entry = userList.get(username);
		if (entry == null) {
			throw new FailedLoginException("Unknown user: " + username);
		}

		if (entry.passwordHash == null ||
			entry.passwordHash.length < HashUtilities.MD5_UNSALTED_HASH_LENGTH) {
			throw new FailedLoginException("User password not set, must be reset");
		}

		// Support deprecated unsalted hash
		if (entry.passwordHash.length == HashUtilities.MD5_UNSALTED_HASH_LENGTH && Arrays.equals(
			HashUtilities.getHash(HashUtilities.MD5_ALGORITHM, password), entry.passwordHash)) {
			return;
		}

		char[] salt = new char[HashUtilities.SALT_LENGTH];
		System.arraycopy(entry.passwordHash, 0, salt, 0, HashUtilities.SALT_LENGTH);

		if (entry.passwordHash.length == HashUtilities.MD5_SALTED_HASH_LENGTH) {
			if (!Arrays.equals(
				HashUtilities.getSaltedHash(HashUtilities.MD5_ALGORITHM, salt, password),
				entry.passwordHash)) {
				throw new FailedLoginException("Incorrect password");
			}
		}
		else if (entry.passwordHash.length == HashUtilities.SHA256_SALTED_HASH_LENGTH) {
			if (!Arrays.equals(
				HashUtilities.getSaltedHash(HashUtilities.SHA256_ALGORITHM, salt, password),
				entry.passwordHash)) {
				throw new FailedLoginException("Incorrect password");
			}
		}
		else {
			throw new FailedLoginException("User password not set, must be reset");
		}
	}

	/**
	 * <code>UserEntry</code> class used to hold user data
	 */
	private static class UserEntry {
		private String username;
		private X500Principal x500User;
		private char[] passwordHash;
		private long passwordTime;
	}

	private PrintWriter getDNLog() throws IOException {
		if (dnLogOut == null) {
			File dnLog = new File(userFile.getParentFile(), DN_LOG_FILE);
			dnLogOut = new PrintWriter(new FileOutputStream(dnLog, true), true);
		}
		return dnLogOut;
	}

	/**
	 * Log a new or unknown X500 principal to facilitate future addition to
	 * user file.
	 * @param username user name/SID which corresponds to unknown principal
	 * @param principal X500 principal data which contains user's distinguished name
	 */
	public void logUnknownDN(String username, X500Principal principal) {
		try {
			getDNLog().println(username + "; " + principal);
		}
		catch (IOException e) {
			// ignore
		}
	}

	/*
	 * Regex: matches if the entire string is alpha, digit, ".", "-", "_", fwd or back slash.
	 */
	private static final Pattern VALID_USERNAME_REGEX = Pattern.compile("[a-zA-Z0-9.\\-_/\\\\]+");

	/**
	 * Ensures a name only contains valid characters and meets length limitations.
	 * 
	 * @param s name string
	 * @return boolean true if valid name, false if not valid
	 */
	public static boolean isValidUserName(String s) {
		return VALID_USERNAME_REGEX.matcher(s).matches() &&
			s.length() <= NamingUtilities.MAX_NAME_LENGTH;
	}

}
