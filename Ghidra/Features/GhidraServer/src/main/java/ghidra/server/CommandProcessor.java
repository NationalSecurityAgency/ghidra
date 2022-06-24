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

import javax.security.auth.x500.X500Principal;

import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import ghidra.framework.remote.User;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.util.exception.DuplicateNameException;
import utilities.util.FileUtilities;

/**
 * <code>CommandProcessor</code> provides server processing of commands
 * queued by the {@link ServerAdmin} class which corresponds to the <code>svrAdmin</code>
 * shell command.
 */
public class CommandProcessor {
	static final Logger log = LogManager.getLogger(CommandProcessor.class);

	// Queued commands
	static final String ADD_USER_COMMAND = "-add";
	static final String REMOVE_USER_COMMAND = "-remove";
	static final String RESET_USER_COMMAND = "-reset";
	static final String SET_USER_DN_COMMAND = "-dn";
	static final String GRANT_USER_COMMAND = "-grant";
	static final String REVOKE_USER_COMMAND = "-revoke";

	static final String PASSWORD_OPTION = "--p"; // applies to add and reset commands

	private static final String ADMIN_CMD_DIR = LocalFileSystem.HIDDEN_DIR_PREFIX + "admin";
	private static final String COMMAND_FILE_EXT = ".cmd";

//	private static final int LOCK_TIMEOUT = 30000;

	/**
	 * Command file filter
	 */
	static final FileFilter CMD_FILE_FILTER =
		f -> f.isFile() && f.getName().endsWith(COMMAND_FILE_EXT);

	/**
	 * File date comparator
	 */
	static final Comparator<File> FILE_DATE_COMPARATOR = (f1, f2) -> {
		long t1 = f1.lastModified();
		long t2 = f2.lastModified();
		long diff = t1 - t2;
		if (diff == 0) {
			return 0;
		}
		return diff < 0 ? -1 : 1;
	};

	private CommandProcessor() {
	}

	/**
	 * Split a command string into individual arguments.
	 * @param cmd command string
	 * @return array of command arguments
	 */
	private static String[] splitCommand(String cmd) {
		ArrayList<String> argList = new ArrayList<>();
		int startIx = 0;
		int endIx = 0;
		int len = cmd.length();
		boolean insideQuote = false;
		while (endIx < len) {
			char c = cmd.charAt(endIx);
			if (!insideQuote && startIx == endIx) {
				if (c == ' ' || c == '\"') {
					insideQuote = (c == '\"');
					startIx = ++endIx;
					continue;
				}
			}
			if (c == (insideQuote ? '\"' : ' ')) {
				argList.add(cmd.substring(startIx, endIx));
				startIx = ++endIx;
				insideQuote = false;
			}
			else {
				++endIx;
			}
		}
		if (startIx != endIx) {
			argList.add(cmd.substring(startIx, endIx));
		}
		String[] args = new String[argList.size()];
		argList.toArray(args);
		return args;
	}

	/**
	 * Process the specified command.
	 * @param repositoryMgr server's repository manager
	 * @param cmd command string
	 * @throws IOException if IO error occurs while processing command
	 */
	private static void processCommand(RepositoryManager repositoryMgr, String cmd)
			throws IOException {
		UserManager userMgr = repositoryMgr.getUserManager();
		String[] args = splitCommand(cmd);
		switch (args[0]) {
			case ADD_USER_COMMAND:  // add user
				String sid = args[1];
				char[] pwdHash = null;
				if (args.length == 4 && args[2].contentEquals(PASSWORD_OPTION)) {
					pwdHash = args[3].toCharArray();
				}
				try {
					userMgr.addUser(sid, pwdHash);
				}
				catch (DuplicateNameException e) {
					log.error("Add User Failed: " + e.getMessage());
				}
				break;
			case REMOVE_USER_COMMAND: // remove user
				sid = args[1];
				if (!userMgr.removeUser(sid)) {
					log.info("User not found: '" + sid + "'");
				}
				break;
			case RESET_USER_COMMAND: // reset user
				sid = args[1];
				pwdHash = null;
				if (args.length == 4 && args[2].contentEquals(PASSWORD_OPTION)) {
					pwdHash = args[3].toCharArray();
				}
				if (!userMgr.resetPassword(sid, pwdHash)) {
					log.info("Failed to reset password for user '" + sid + "'");
				}
				else if (pwdHash != null) {
					log.info("User '" + sid + "' password reset to specified password");
				}
				else {
					log.info("User '" + sid + "' password reset to default password");
				}
				break;
			case SET_USER_DN_COMMAND: // set/add user with DN for PKI
				sid = args[1];
				X500Principal x500User = new X500Principal(args[2]);
				if (userMgr.isValidUser(sid)) {
					userMgr.setDistinguishedName(sid, x500User);
				}
				else {
					try {
						userMgr.addUser(sid, x500User);
					}
					catch (DuplicateNameException e) {
						// should never occur
					}
				}
				log.info("User '" + sid + "' DN set (" + x500User.getName() + ")");
				break;
			case GRANT_USER_COMMAND: // grant repository access
				sid = args[1];
				int permission = parsePermission(args[2]);
				String repName = args[3];
				if (!userMgr.isValidUser(sid)) {
					log.error(
						"Failed to grant access for '" + sid +
							"', user has not been added to server.");
					return;
				}
				if (permission < 0) {
					log.error("Failed to process grant command.  Invalid permission: " + args[2]);
					return;
				}
				Repository rep = repositoryMgr.getRepository(repName);
				if (rep == null) {
					log.error("Failed to grant access for '" + sid + "', repository '" + repName +
						"' not found.");
				}
				rep.setUserPermission(sid, permission);
				break;
			case REVOKE_USER_COMMAND: // grant repository access
				sid = args[1];
				repName = args[2];
				rep = repositoryMgr.getRepository(repName);
				if (rep == null) {
					log.error("Failed to revoke access for '" + sid + "', repository '" + repName +
						"' not found.");
				}
				rep.removeUser(sid);
				break;
			default:
				log.error("Failed to process unrecognized command: " + args[0]);
		}
	}

	static int parsePermission(String permissionStr) {
		if ("+r".equals(permissionStr)) {
			return User.READ_ONLY;
		}
		if ("+w".equals(permissionStr)) {
			return User.WRITE;
		}
		if ("+a".equals(permissionStr)) {
			return User.ADMIN;
		}
		return -1;
	}

	static File getCommandDir(File serverRootDir) {
		return new File(serverRootDir, ADMIN_CMD_DIR);
	}

	static File getOrCreateCommandDir(RepositoryManager repositoryMgr) {
		File cmdDir = getCommandDir(repositoryMgr.getRootDir());
		if (!cmdDir.exists()) {
			// ensure process owner creates queued command directory
			cmdDir.mkdir();
		}
		return cmdDir;
	}

	/**
	 * Process all queued commands for the specified server.
	 * @param repositoryMgr server's repository manager
	 * @throws IOException
	 */
	static void processCommands(RepositoryManager repositoryMgr) throws IOException {
		File cmdDir = getOrCreateCommandDir(repositoryMgr);
		File[] files = cmdDir.listFiles(CMD_FILE_FILTER);
		if (files == null) {
			log.error("Failed to access command queue " + cmdDir.getAbsolutePath() +
				": possible permission problem");
			return;
		}
		if (files.length == 0) {
			return;
		}

		log.info("Processing queued commands");
		Arrays.sort(files, FILE_DATE_COMPARATOR);
		for (File file : files) {
			List<String> cmdList = FileUtilities.getLines(file);
			for (String cmdStr : cmdList) {
				if (cmdStr.isBlank()) {
					continue;
				}
				try {
					processCommand(repositoryMgr, cmdStr.trim());
				}
				catch (ArrayIndexOutOfBoundsException e) {
					log.error("Error occured processing command: " + cmdStr);
				}
			}
			file.delete();
		}
	}

	/**
	 * Store a list of command strings to a new command file.
	 * @param cmdList list of command strings
	 * @param cmdDir command file directory (must exist)
	 * @throws IOException
	 */
	static void writeCommands(List<String> cmdList, File cmdDir) throws IOException {
		File cmdTempFile = null;
		try {
			// Write command to temp file
			cmdTempFile = File.createTempFile("adm", ".tmp", cmdDir);
			FileUtils.writeLines(cmdTempFile, cmdList);

			// Rename temp file to *.cmd file
			String cmdFilename = cmdTempFile.getName();
			cmdFilename = cmdFilename.substring(0, cmdFilename.length() - 4) + COMMAND_FILE_EXT;
			File cmdFile = new File(cmdTempFile.getParentFile(), cmdFilename);
			if (!cmdTempFile.renameTo(cmdFile)) {
				throw new IOException("file error");
			}
			cmdTempFile = null;
		}
		finally {
			if (cmdTempFile != null) {
				cmdTempFile.delete();
			}
		}
	}

}
