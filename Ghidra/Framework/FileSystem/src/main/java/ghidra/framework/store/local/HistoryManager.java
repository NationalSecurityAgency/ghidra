/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.framework.store.local;

import ghidra.framework.store.Version;

import java.io.*;
import java.util.*;

/**
 * <code>HistoryManager</code> manages version data for a versioned LocalFolderItem.
 * History data is maintained within the file 'historyt.dat' located within the
 * items data directory.
 */
class HistoryManager {

	static final String HISTORY_FILE = "history.dat";

	private LocalFolderItem item;
	private int minVersion;
	private int curVersion;
	private Version[] versions;

	/**
	 * Constructor.
	 * @param item folder item
	 * @param create if true an empty history data file is written,
	 * else the initial data is read from the file.
	 * @throws IOException
	 */
	HistoryManager(LocalFolderItem item, boolean create) throws IOException {
		this.item = item;
		if (create) {
			versions = new Version[0];
		}
	}

	/**
	 * Returns the file which contains version history data.  Content of this
	 * file is managed by the HistoryManager.
	 */
	private File getHistoryFile() {
		return new File(item.getDataDir(), HISTORY_FILE);
	}

	/**
	 * Add and/or remove history entries to agree with specified minimum and current versions.
	 * @param minVersion minimum version
	 * @param curVersion current version
	 * @return true if a version correction was performed
	 */
	synchronized boolean fixHistory(int minVersion, int curVersion) throws IOException {
		validate();
		if (minVersion == this.minVersion && curVersion == this.curVersion) {
			return false;
		}

		if (minVersion < 1 || curVersion < minVersion) {
			throw new IllegalArgumentException();
		}

		Version[] newVersions = new Version[curVersion - minVersion + 1];

		int newIx = 0;
		int oldIx = 0;
		int version = minVersion;
		if (minVersion < this.minVersion) {
			while (version < this.minVersion && version <= curVersion) {
				// Add missing versions	
				newVersions[newIx++] = new Version(version++, 0, "<Unknown>", "<Recovered>");
			}
		}
		if (version >= this.minVersion && version <= this.curVersion) {
			// keep as many existing version entries as possible	
			while (versions[oldIx].getVersion() < version) {
				++oldIx;
			}
			while (version <= this.curVersion && version <= curVersion) {
				newVersions[newIx++] = versions[oldIx++];
				++version;
			}
		}
		while (version <= curVersion) {
			// Add missing versions	
			newVersions[newIx++] = new Version(version++, 0, "<Unknown>", "<Recovered>");
		}

		versions = newVersions;
		this.minVersion = minVersion;
		this.curVersion = curVersion;
		writeHistoryFile();

		return true;
	}

	/**
	 * Record the creation of a new item version.
	 * @param version version number
	 * @param user user who created version
	 */
	synchronized void versionAdded(int version, long time, String comment, String user)
			throws IOException {
		validate();

		// Validate version
		if (version != curVersion + 1) {
			// Check should have been performed by item
			item.log("ERROR! unexpected version " + version + " created, expected version " +
				(curVersion + 1), user);
			return;
		}

		item.log("version " + version + " created", user);
		Version ver = new Version(version, time, user, comment);

		appendHistoryFile(ver);

		Version[] newVersions = new Version[versions.length + 1];
		System.arraycopy(versions, 0, newVersions, 0, versions.length);
		newVersions[versions.length] = ver;
		versions = newVersions;
		curVersion = version;
		if (version == 1) {
			minVersion = 1;
		}
	}

	/**
	 * Remove the specified version from the history data.
	 * This method only modifies the data if the minimum or
	 * latest version is specified.
	 * @param version minimum or latest version
	 */
	synchronized void versionDeleted(int version, String user) throws IOException {
		validate();
		if (versions.length <= 1) {
			// Check should have been performed by item - item should be deleted instead
			item.log("ERROR! version " + version + " deleted illegally, min=" + minVersion +
				", max=" + curVersion, user);
			return;
		}

		Version[] newVersions = new Version[versions.length - 1];
		if (version == versions[0].getVersion()) {
			System.arraycopy(versions, 1, newVersions, 0, versions.length - 1);
			minVersion = newVersions[0].getVersion();
		}
		else if (version == versions[versions.length - 1].getVersion()) {
			System.arraycopy(versions, 0, newVersions, 0, versions.length - 1);
			curVersion = newVersions[newVersions.length - 1].getVersion();
		}
		else {
			// Check should have been performed by item
			item.log("ERROR! version " + version + " deleted illegally, min=" + minVersion +
				", max=" + curVersion, user);
			return;
		}
		item.log("version " + version + " deleted", user);
		versions = newVersions;
		writeHistoryFile();
	}

//	int getMinimumVersion() {
//		validate();
//		return minVersion;
//	}
//	
//	int getCurrentVersion() {
//		validate();
//		return curVersion;
//	}

	/**
	 * Return all versions contained within the history.  Versions are
	 * ordered oldest to newest (i.e., minumum to latest).
	 * @throws IOException if an IO error occurs.
	 */
	synchronized Version[] getVersions() throws IOException {
		validate();
		return versions.clone();
	}

	/**
	 * Return specific version.
	 * @param version item version
	 * @return version object or null if not found
	 * @throws IOException if an IO error occurs.
	 */
	synchronized Version getVersion(int version) throws IOException {
		validate();
		if (version >= minVersion && version < curVersion) {
			return versions[version - minVersion];
		}
		return null;
	}

	/**
	 * If validationRequired is true and the history data file has been 
	 * updated, the history data will be re-initialized from the file.
	 * This is undesirable and is only required when mulitple instances 
	 * of a LocalFolderItem are used for a specific item path (e.g., unit testing).
	 */
	private void validate() throws IOException {

		if (LocalFileSystem.isRefreshRequired()) {
			versions = null;
			minVersion = 0;
			curVersion = 0;
		}
		File historyFile = getHistoryFile();
		if (historyFile.exists()) {
			Version[] oldVersions = versions;
			int oldMinVersion = minVersion;
			int oldCurVersion = curVersion;
			boolean success = false;
			try {
				readHistoryFile();
				success = true;
			}
			finally {
				if (!success) {
					versions = oldVersions;
					minVersion = oldMinVersion;
					curVersion = oldCurVersion;
				}
			}
		}
		else {
			versions = new Version[0];
		}
	}

	/**
	 * Read data from history file.
	 * @throws IOException
	 */
	private void readHistoryFile() throws IOException {

		ArrayList<Version> list = new ArrayList<Version>();
		minVersion = 0;
		curVersion = 0;

		File historyFile = getHistoryFile();
		BufferedReader in = new BufferedReader(new FileReader(historyFile));
		try {
			String line = in.readLine();
			while (line != null) {
				Version ver;
				try {
					ver = decodeVersion(line);
				}
				catch (Exception e) {
					throw new IOException("Bad history file: " + historyFile);
				}
				int version = ver.getVersion();
				if (curVersion != 0 && version != (curVersion + 1)) {
					// Versions must be in sequential order
					throw new IOException("Bad history file" + historyFile);
				}
				if (minVersion == 0) {
					minVersion = version;
				}
				curVersion = version;
				list.add(ver);
				line = in.readLine();
			}
		}
		finally {
			in.close();
		}

		versions = new Version[list.size()];
		list.toArray(versions);
	}

	/**
	 * Write all history data to file.
	 */
	private void writeHistoryFile() {

		File historyFile = getHistoryFile();
		try {
			File tmpFile = new File(historyFile.getParentFile(), historyFile.getName() + ".new");
			tmpFile.delete();

			BufferedWriter out = new BufferedWriter(new FileWriter(tmpFile));
			for (int i = 0; i < versions.length; i++) {
				out.write(encodeVersion(versions[i]));
				out.newLine();
			}
			out.close();

			// Rename files
			File oldFile = null;
			if (historyFile.exists()) {
				oldFile = new File(historyFile.getParentFile(), historyFile.getName() + ".bak");
				oldFile.delete();
				if (!historyFile.renameTo(oldFile)) {
					throw new IOException("file is in use");
				}
			}
			if (!tmpFile.renameTo(historyFile)) {
				if (oldFile != null) {
					oldFile.renameTo(historyFile);
				}
				throw new IOException("file error - backup may exist");
			}
			if (oldFile != null) {
				oldFile.delete();
			}
		}
		catch (IOException e) {
			item.log("ERROR! failed to update history file: " + e.toString(), null);
		}
	}

	/**
	 * Write new version data to file.
	 * @param ver new version data (must be latest version)
	 */
	private void appendHistoryFile(Version ver) {
		File historyFile = getHistoryFile();
		try {
			BufferedWriter out = new BufferedWriter(new FileWriter(historyFile, true));
			out.write(encodeVersion(ver));
			out.newLine();
			out.close();
		}
		catch (IOException e) {
			item.log("ERROR! failed to update history file: " + e.toString(), null);
		}
	}

	/**
	 * Encode item version data for file output.
	 * @param ver version data
	 * @return
	 */
	private String encodeVersion(Version ver) {
		StringBuffer buf = new StringBuffer();
		buf.append(ver.getVersion());
		buf.append(';');
		buf.append(ver.getUser());
		buf.append(';');
		buf.append(ver.getCreateTime());
		buf.append(';');
		encodeString(ver.getComment(), buf);
		return buf.toString();
	}

	/**
	 * Decode item version data from file.
	 * @param line file input line
	 * @return parsed version data
	 * @throws NumberFormatException
	 * @throws NoSuchElementException
	 */
	private Version decodeVersion(String line) throws NumberFormatException, NoSuchElementException {
		StringTokenizer st = new StringTokenizer(line, ";");
		int version = Integer.parseInt(st.nextToken());
		String user = st.nextToken();
		long time = Long.parseLong(st.nextToken());
		String comment = "";
		if (st.hasMoreTokens()) {
			comment = decodeString(st.nextToken());
		}
		return new Version(version, time, user, comment);
	}

	/**
	 * Escape special characters within a string and output to string buffer.
	 * @param text text string to be escaped
	 * @param buf output buffer
	 */
	private void encodeString(String text, StringBuffer buf) {
		if (text == null) {
			return;
		}
		for (int i = 0; i < text.length(); i++) {
			char next = text.charAt(i);
			switch (next) {
				case '\n':
					buf.append("\\n");
					break;
				case '\r':
					buf.append("\\r");
					break;
				case ';':
					buf.append("\\s");
					break;
				case '\\':
					buf.append("\\\\");
					break;
				default:
					buf.append(next);
			}
		}
	}

	/**
	 * Decode an escaped string.
	 * @param text string containing escaped characters.
	 * @return decoded string
	 */
	private String decodeString(String text) {
		if (text == null) {
			return "";
		}
		StringBuffer buf = new StringBuffer();
		boolean controlChar = false;
		for (int i = 0; i < text.length(); i++) {
			char next = text.charAt(i);
			if (next == '\\') {
				controlChar = true;
			}
			else if (controlChar) {
				switch (next) {
					case 'n':
						buf.append('\n');
						break;
					case 'r':
						buf.append('\r');
						break;
					case 's':
						buf.append(';');
						break;
					default:
						buf.append(next);
				}
				controlChar = false;
			}
			else {
				buf.append(next);
			}
		}
		return buf.toString();
	}

}
