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
package generic.util;

import java.io.*;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Properties;

import ghidra.util.HTMLUtilities;
import ghidra.util.SystemUtilities;

public class FileLocker {

	private static final String META_TAG = "<META> ";
	private static final String LOCK_TYPE_KEY = META_TAG + "Supports File Channel Locking";
	private static final String FILE_LOCK_TYPE = "File Lock";
	private static final String[] PROPERTY_KEYS =
		{ "Username", "Hostname", "Timestamp", "OS Name", "OS Architecture", "OS Version" };
	private static final DateFormat DATE_FORMAT = new SimpleDateFormat();

	protected final File lockFile;
	protected final Properties existingLockProperties;
	protected Properties createdLockProperties;
	protected final String existingLockType;
	protected boolean isLocked;

	protected FileLocker(File lockFile) {
		this.lockFile = lockFile;

		existingLockProperties = loadExistingLockFile();
		if (existingLockProperties != null) {
			existingLockType = existingLockProperties.getProperty(LOCK_TYPE_KEY);
		}
		else {
			existingLockType = null;
		}
	}

	public boolean lock() {
		if (existingLockProperties == null) {
			return createLockFile();
		}

		// can't create a primitive lock if one already exists
		return false;
	}

	public boolean isLocked() {
		return isLocked;
	}

	public void release() {
		if (isLockOwner()) {
			lockFile.delete();
		}
		isLocked = false;
	}

	public boolean canForceLock() {
		return FILE_LOCK_TYPE.equals(existingLockType);
	}

	public boolean forceLock() {
		if (canForceLock()) {
			return createLockFile();
		}
		return false;
	}

	private Properties loadExistingLockFile() {
		if (!lockFile.exists()) {
			return null;
		}

		Properties properties = new Properties();

		InputStream is = null;
		try {
			is = new FileInputStream(lockFile);
			properties.load(is);
			return properties;
		}
		catch (FileNotFoundException e) {
			// should never happen
		}
		catch (IOException e) {
			// ignore
		}
		finally {
			if (is != null) {
				try {
					is.close();
				}
				catch (IOException e) {
					// we tried!
				}
			}
		}
		return null;
	}

	public String getExistingLockFileInformation() {
		if (existingLockProperties == null) {
			return "no properties in lock file";
		}

		StringBuilder buf = new StringBuilder("<p><table border=0>");
		for (String name : PROPERTY_KEYS) {
			buf.append("<tr><td>");
			buf.append("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;");
			buf.append(HTMLUtilities.escapeHTML(name));
			buf.append(": ");
			buf.append("</td><td>");
			buf.append(HTMLUtilities.escapeHTML(existingLockProperties.get(name).toString()));
			buf.append("</td></tr>");
		}
		buf.append("</table>");
		return buf.toString();
	}

	protected String getLockType() {
		return FILE_LOCK_TYPE;
	}

	protected boolean createLockFile() {
		Properties properties = new Properties();

		// user info
		properties.put("Username", System.getProperty("user.name"));
		String hostname = "<Unknown>";
		try {
			hostname = InetAddress.getLocalHost().getHostName();
		}
		catch (UnknownHostException e) {
			// use default
		}
		properties.put("Hostname", hostname);

		properties.put("Timestamp", DATE_FORMAT.format(new Date()));

		// system info
		properties.put("OS Name", System.getProperty("os.name"));
		properties.put("OS Architecture", System.getProperty("os.arch"));
		properties.put("OS Version", System.getProperty("os.version"));

		// meta info
		properties.put(LOCK_TYPE_KEY, getLockType());

		// store the data
		if (!storeProperties(properties)) {
			return false;
		}

		if (lockFile.exists()) {
			createdLockProperties = properties;
			isLocked = true;
			return true;
		}
		return false;
	}

	private boolean storeProperties(Properties properties) {

		OutputStream os = null;
		try {
			os = new FileOutputStream(lockFile);
			properties.store(os, "Ghidra Lock File");
			return true;
		}
		catch (IOException e) {
			return false;
		}
		finally {
			if (os != null) {
				try {
					os.close();
				}
				catch (IOException e) {
					// don't care; we tried
				}
			}
		}
	}

	private boolean isLockOwner() {
		if (createdLockProperties == null) {
			return false; // we never created a lock file
		}

		Properties currentLockProperties = loadExistingLockFile();
		if (currentLockProperties == null) {
			return false; // no lock file, someone deleted ours
		}

		for (String key : PROPERTY_KEYS) {
			String originalProperty = createdLockProperties.getProperty(key);
			String currentProperty = currentLockProperties.getProperty(key);
			if (!SystemUtilities.isEqual(originalProperty, currentProperty)) {
				return false;
			}
		}
		return true;
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + lockFile;
	}
}
