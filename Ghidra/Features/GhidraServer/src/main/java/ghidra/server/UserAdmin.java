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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import ghidra.framework.store.local.LocalFileSystem;
import ghidra.util.exception.DuplicateNameException;
import utilities.util.FileUtilities;

/**
 * <code>UserAdmin</code> is an Application for generating administrative 
 * commands to be processed by the UserManager.  Static methods are also 
 * provided which enable the UserManager to process such commands.
 */
public class UserAdmin {
	static final Logger log = LogManager.getLogger(UserAdmin.class);

	// Queued commands
	static final String ADD_USER_COMMAND = "-add";
	static final String REMOVE_USER_COMMAND = "-remove";
	static final String RESET_USER_COMMAND = "-reset";
	static final String SET_USER_DN_COMMAND = "-dn";
	static final String SET_ADMIN_COMMAND = "-admin";

	static final String PASSWORD_OPTION = "--p"; // applies to add and reset commands

	static final String ADMIN_CMD_DIR = LocalFileSystem.HIDDEN_DIR_PREFIX + "admin";
	static final String COMMAND_FILE_EXT = ".cmd";

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

	private UserAdmin() {
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
	 * @throws IOException
	 */
	private static void processCommand(RepositoryManager repositoryMgr, String cmd)
			throws IOException {
		UserManager userMgr = repositoryMgr.getUserManager();
		String[] args = splitCommand(cmd);
		if (ADD_USER_COMMAND.equals(args[0])) {  // add user
			String sid = args[1];
			char[] pwdHash = null;
			if (args.length == 4 && args[2].contentEquals(PASSWORD_OPTION)) {
				pwdHash = args[3].toCharArray();
			}
			try {
				userMgr.addUser(sid, pwdHash);
				log.info("User '" + sid + "' added");
			}
			catch (DuplicateNameException e) {
				log.error("Add User Failed: user '" + sid + "' already exists");
			}
		}
		else if (REMOVE_USER_COMMAND.equals(args[0])) { // remove user
			String sid = args[1];
			userMgr.removeUser(sid);
			log.info("User '" + sid + "' removed");
		}
		else if (RESET_USER_COMMAND.equals(args[0])) { // reset user
			String sid = args[1];
			char[] pwdHash = null;
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
		}
		else if (SET_USER_DN_COMMAND.equals(args[0])) { // set/add user with DN for PKI
			String sid = args[1];
			X500Principal x500User = new X500Principal(args[2]);
			if (userMgr.isValidUser(sid)) {
				userMgr.setDistinguishedName(sid, x500User);
				log.info("User '" + sid + "' DN set (" + x500User.getName() + ")");
			}
			else {
				try {
					userMgr.addUser(sid, x500User);
					log.info("User '" + sid + "' added with DN (" + x500User.getName() +
						") and default password");
				}
				catch (DuplicateNameException e) {
					// should never occur
				}
			}
		}
		else if (SET_ADMIN_COMMAND.equals(args[0])) { // set/add repository admin
			String sid = args[1];
			String repName = args[2];
			if (!userMgr.isValidUser(sid)) {
				try {
					userMgr.addUser(sid);
					log.info("User '" + sid + "' added");
				}
				catch (DuplicateNameException e) {
					return; // should never occur
				}
			}
			Repository rep = repositoryMgr.getRepository(repName);
			if (rep == null) {
				log.error("Failed to add '" + sid + "' as admin, repository '" + repName +
					"' not found.");
			}
			else {
				rep.addAdmin(sid);
			}
		}
	}

	/**
	 * Process all queued commands for the specified server.
	 * @param repositoryMgr server's repository manager
	 * @param serverDir Ghidra server directory
	 * @throws IOException
	 */
	static void processCommands(RepositoryManager repositoryMgr) throws IOException {
		File cmdDir = new File(repositoryMgr.getRootDir(), ADMIN_CMD_DIR);
		if (!cmdDir.exists()) {
			// ensure process owner creates queued command directory
			cmdDir.mkdir();
			return;
		}
		File[] files = cmdDir.listFiles(CMD_FILE_FILTER);
		if (files == null) {
			log.error("Failed to access command queue " + cmdDir.getAbsolutePath() +
				": possible permission problem");
			return;
		}
		Arrays.sort(files, FILE_DATE_COMPARATOR);

		if (files.length == 0) {
			return;
		}
		log.info("Processing " + files.length + " queued commands");

		for (File file : files) {
			List<String> cmdList = FileUtilities.getLines(file);
			for (String cmdStr : cmdList) {
				if (cmdStr.isBlank()) {
					continue;
				}
				processCommand(repositoryMgr, cmdStr.trim());
			}
			file.delete();
		}
	}

	/**
	 * Store a list of command strings to a new command file.
	 * @param cmdList list of command strings
	 * @param cmdDir command file directory
	 * @throws IOException
	 */
	static void writeCommands(ArrayList<String> cmdList, File cmdDir) throws IOException {
		File cmdFile = File.createTempFile("adm", ".tmp", cmdDir);
		String cmdFilename = cmdFile.getName();
		cmdFilename = cmdFilename.substring(0, cmdFilename.length() - 4) + COMMAND_FILE_EXT;
		PrintWriter pw = new PrintWriter(new BufferedOutputStream(new FileOutputStream(cmdFile)));
		boolean success = false;
		try {
			Iterator<String> it = cmdList.iterator();
			while (it.hasNext()) {
				String cmd = it.next();
				pw.println(cmd);
			}
			pw.close();
			if (!cmdFile.renameTo(new File(cmdFile.getParentFile(), cmdFilename))) {
				throw new IOException("file error");
			}
			success = true;
		}
		finally {
			if (!success) {
				cmdFile.delete();
			}
		}
	}

}
