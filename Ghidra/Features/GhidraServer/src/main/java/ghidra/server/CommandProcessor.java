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
import java.io.FileFilter;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import ghidra.framework.remote.User;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.util.exception.DuplicateNameException;
import utilities.util.FileUtilities;
import utility.function.ExceptionalCallback;
import utility.function.ExceptionalConsumer;

/**
 * <code>CommandProcessor</code> provides server processing of commands queued
 * by the {@link ServerAdmin} class which corresponds to the
 * <code>svrAdmin</code> shell command.
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
	private static final String COMMAND_FILE_PREFIX = "seq";
	private static final String COMMAND_FILE_EXT = ".cmd";
	private static final String BAD_COMMAND_FILE_EXT = ".bad";
	private static final long SEQUENCE_WRAP_POINT = Long.MAX_VALUE >>> 1;

	private static final String LOCK_NAME = "command.lock";

	// No construct - static utility
	private CommandProcessor() {
	}

	/**
	 * Command file filter.  A rejected command file (see {@link #rejectCommandFile(File)}) no
	 * longer ends with {@value #COMMAND_FILE_EXT} and so is excluded here, leaving it neither
	 * processed nor counted as a queued command.
	 */
	static final FileFilter CMD_FILE_FILTER = f -> f.isFile() &&
		f.getName().endsWith(COMMAND_FILE_EXT);

	/**
	 * Command file sequence comparator, establishing the order in which queued commands are
	 * processed.  Only files whose name yields a sequence number may be compared, so any file
	 * rejected by {@link #getCommandSequence(File)} must be filtered out beforehand.
	 */
	static final Comparator<File> FILE_SEQUENCE_COMPARATOR =
		(f1, f2) -> Long.compare(getCommandSequence(f1), getCommandSequence(f2));

	/**
	 * Recover the sequence number encoded within a command file name (see
	 * {@link #writeCommands(List, File)}).
	 * @param f command file
	 * @return the sequence number, or -1 if the name does not encode one
	 */
	private static long getCommandSequence(File f) {
		String name = f.getName();
		if (name.startsWith(COMMAND_FILE_PREFIX) && name.endsWith(COMMAND_FILE_EXT)) {
			String seqStr = name.substring(COMMAND_FILE_PREFIX.length(),
				name.length() - COMMAND_FILE_EXT.length());
			try {
				long seq = Long.parseLong(seqStr, 16);
				if (seq >= 0) {
					return seq;
				}
			}
			catch (NumberFormatException e) {
				// fall-through to rejection below
			}
		}
		return -1;
	}

	/**
	 * Split a command string into individual arguments.
	 * 
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
			} else {
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
	 * 
	 * @param repositoryMgr server's repository manager
	 * @param cmd           command string
	 * @throws IOException if IO error occurs while processing command
	 */
	private static void processCommand(RepositoryManager repositoryMgr, String cmd) throws IOException {
		UserManager userMgr = repositoryMgr.getUserManager();
		String[] args = splitCommand(cmd);
		switch (args[0]) {
			case ADD_USER_COMMAND: // add user
				String sid = args[1];
				char[] pwdHash = null;
				if (args.length == 4 && args[2].contentEquals(PASSWORD_OPTION)) {
					pwdHash = args[3].toCharArray();
				}
				try {
					userMgr.addUser(sid, pwdHash);
				} catch (DuplicateNameException e) {
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
				} else if (pwdHash != null) {
					log.info("User '" + sid + "' password reset to specified password");
				} else {
					log.info("User '" + sid + "' password reset to default password");
				}
				break;
			case SET_USER_DN_COMMAND: // set/add user with DN for PKI
				sid = args[1];
				X500Principal x500User = new X500Principal(args[2]);
				if (userMgr.isValidUser(sid)) {
					userMgr.setDistinguishedName(sid, x500User);
				} else {
					try {
						userMgr.addUser(sid, x500User);
					} catch (DuplicateNameException e) {
						log.error("Add User Failed: " + e.getMessage());
						return;
					}
				}
				log.info("User '" + sid + "' DN set (" + x500User.getName() + ")");
				break;
			case GRANT_USER_COMMAND: // grant repository access
				sid = args[1];
				int permission = parsePermission(args[2]);
				String repName = args[3];
				if (!userMgr.isValidUser(sid)) {
					log.error("Failed to grant access for '" + sid + "', user has not been added to server.");
					return;
				}
				if (permission < 0) {
					log.error("Failed to process grant command.  Invalid permission: " + args[2]);
					return;
				}
				Repository rep = repositoryMgr.getRepository(repName);
				if (rep == null) {
					log.error("Failed to grant access for '" + sid + "', repository '" + repName + "' not found.");
					return;
				}
				rep.setUserPermission(sid, permission);
				break;
			case REVOKE_USER_COMMAND: // grant repository access
				sid = args[1];
				repName = args[2];
				rep = repositoryMgr.getRepository(repName);
				if (rep == null) {
					log.error("Failed to revoke access for '" + sid + "', repository '" + repName + "' not found.");
					return;
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
	
	static File getOrCreateCommandDir(File serverRootDir) {
		if (!serverRootDir.isDirectory() || !serverRootDir.canWrite()) {
			System.err.println("Insufficient privilege or server not started!");
			System.exit(-1);
		}
		File cmdDir = new File(serverRootDir, ADMIN_CMD_DIR);
		if (!cmdDir.exists()) {
			// ensure process owner creates queued command directory
			cmdDir.mkdir();
		}
		return cmdDir;
	}

	/**
	 * Process all queued commands for the specified server.
	 * <p>
	 * Commands are processed in the order they were queued, which is established by the sequence
	 * number within each command file name.  A file whose name does not provide one is rejected
	 * (see {@link #rejectCommandFile(File)}): its position within the queue is unknown, and
	 * processing it out of order could apply user and permission changes in the wrong sequence.
	 *
	 * @param repositoryMgr server's repository manager
	 * @throws IOException
	 */
	static void processCommands(RepositoryManager repositoryMgr) throws IOException {
		File cmdDir = getCommandDir(repositoryMgr.getRootDir());
		if (!cmdDir.isDirectory()) {
			return;
		}
		withLock(cmdDir, () -> {
			File[] allFiles = cmdDir.listFiles(CMD_FILE_FILTER);
			if (allFiles == null) {
				log.error(
						"Failed to access command queue " + cmdDir.getAbsolutePath() + ": possible permission problem");
				return;
			}

			// Reject any command file whose name does not establish its place in the queue
			List<File> files = new ArrayList<>();
			for (File file : allFiles) {
				if (getCommandSequence(file) < 0) {
					rejectCommandFile(file);
					continue;
				}
				files.add(file);
			}

			if (files.isEmpty()) {
				return;
			}

			log.info("Processing queued commands");
			files.sort(FILE_SEQUENCE_COMPARATOR);

			for (File file : files) {
				List<String> cmdList = FileUtilities.getLines(file);

				for (String cmdStr : cmdList) {
					if (cmdStr.isBlank()) {
						continue;
					}
					try {
						processCommand(repositoryMgr, cmdStr.trim());
					} catch (ArrayIndexOutOfBoundsException e) {
						log.error("Error occured processing command: " + cmdStr);
					}
				}
				file.delete();
			}
		});
	}

	/**
	 * Reject a command file whose name does not establish its place within the queue, by appending
	 * the {@value #BAD_COMMAND_FILE_EXT} extension to its name.  The renamed file no longer
	 * matches {@link #CMD_FILE_FILTER}, so its content is retained for an administrator to inspect
	 * while it is neither processed nor reported again.
	 * <p>
	 * A failure to rename is reported and otherwise ignored so that the remaining queued commands
	 * are still processed; the file will be reported again on the next pass.
	 *
	 * @param file command file to be rejected
	 */
	private static void rejectCommandFile(File file) {
		File badFile = new File(file.getParentFile(), file.getName() + BAD_COMMAND_FILE_EXT);
		try {
			Files.move(file.toPath(), badFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
			log.error("Unrecognized command file was not processed and has been renamed to '" +
				badFile.getName() + "': " + file.getAbsolutePath());
		}
		catch (IOException e) {
			log.error("Unrecognized command file was not processed and could not be renamed to '" +
				badFile.getName() + "' (" + e.getMessage() + "): " + file.getAbsolutePath());
		}
	}

	/**
	 * Check for need to wrap sequence number, but only do so if no command are
	 * currently queued
	 */
	private static long checkSequence(File cmdDir, long seq) throws FileNotFoundException {
		if (seq >= 0 && seq < SEQUENCE_WRAP_POINT) {
			return seq;
		}
		File[] files = cmdDir.listFiles(CMD_FILE_FILTER);
		if (files == null) {
			throw new FileNotFoundException("Missing command directory: " + cmdDir);
		}
		return files.length == 0 ? 1 : seq;
	}
	
	/**
	 * Reads the current sequence, increments it, performs an write action while
	 * locked, updates the lock file, and flushes to disk.
	 */
	@SuppressWarnings("unused") // relates to 'lock' variable
	private static void withSequenceLock(File cmdDir, ExceptionalConsumer<Long, IOException> writeAction)
			throws IOException {
		// Open channel for both reading and writing
		Path lockFilePath = new File(cmdDir, LOCK_NAME).toPath();
		try (FileChannel channel = FileChannel.open(lockFilePath, StandardOpenOption.READ, StandardOpenOption.WRITE,
				StandardOpenOption.CREATE); FileLock lock = channel.lock()) {

			ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
			long currentSeq = 0;
			if (channel.size() >= Long.BYTES) {
				channel.read(buffer, 0); // Reads file offset 0 into buffer
				currentSeq = buffer.getLong(0); // Absolute index read (no flip needed!)
			}

			// Increment command sequence number
			long newSeq = checkSequence(cmdDir, currentSeq + 1);

			// Invoke write action
			writeAction.accept(newSeq);

			// Update stored sequence number
			buffer.putLong(0, newSeq); // Absolute index write (no flip needed!)
			buffer.clear(); // reset file position to start
			channel.write(buffer, 0); // Writes buffer to file offset 0
			channel.force(true);
		}
	}

	/**
	 * Holds the lock open while performing a read action
	 */
	@SuppressWarnings("unused")
	private static void withLock(File cmdDir, ExceptionalCallback<IOException> readAction) throws IOException {
		// Open channel for both reading and writing
		Path lockFilePath = new File(cmdDir, LOCK_NAME).toPath();
		try (FileChannel channel = FileChannel.open(lockFilePath, StandardOpenOption.READ, StandardOpenOption.WRITE,
				StandardOpenOption.CREATE); FileLock lock = channel.lock()) {

			// Invoke read action
			readAction.call();
		}
	}

	/**
	 * Store a list of command strings to a new command file.
	 * 
	 * @param cmdList list of command strings
	 * @param cmdDir  command file directory (must exist)
	 * @throws IOException
	 */
	static void writeCommands(List<String> cmdList, File cmdDir) throws IOException {

		withSequenceLock(cmdDir, s -> {
			File cmdTempFile = null;
			try {
				// Write command to temporary file
				cmdTempFile = File.createTempFile("cmd", ".tmp", cmdDir);
				FileUtils.writeLines(cmdTempFile, cmdList);

				// Rename temporary file to "seq<hexSequenceStr>.cmd" file
				String hexSequenceStr = "%016X".formatted(s);
				String cmdFilename = COMMAND_FILE_PREFIX + hexSequenceStr + COMMAND_FILE_EXT;
				File cmdFile = new File(cmdTempFile.getParentFile(), cmdFilename);
				if (!cmdTempFile.renameTo(cmdFile)) {
					throw new IOException("file error");
				}
				cmdTempFile = null;
				
			} finally {
				if (cmdTempFile != null) {
					cmdTempFile.delete();
				}
			}
		});
	}

}
