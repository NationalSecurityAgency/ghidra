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
package ghidra.framework.client;

import java.io.*;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.util.*;

import javax.swing.event.ChangeListener;

import com.google.gson.*;

import ghidra.framework.Application;
import ghidra.framework.store.local.LockFile;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.exception.FileInUseException;
import utility.function.ExceptionalCallback;

/**
 * {@link UrlAllowListManager} provides management of the Server URL Allow List persistent cache.
 */
public class UrlAllowListManager {

	// Set false to disable allowing localhost access by default (intended for test use only)
	public static boolean alwaysAllowLocalAccess = true;

	private static int FILE_FORMAT_VERSION = 1;

	private static final int LOCK_TIMEOUT_MS = 5000; // max time to wait for file lock
	private static final long MIN_REFRESH_TIME_MS = 5000; // minimum time between file reads 

	private static final String SERVER_ALLOW_LIST_FILENAME = "serverAllowList.json";
	private static final String SERVER_ALLOW_LIST_LOCKFILE = "serverAllowList.lock";

	private static Map<ServerSpecification, AccessRecord> serverAccessMap;
	private static LockFile lockFile;
	private static long lastMod; // file modification when last read
	private static long lastCheck; // system time when file last checked

	private static WeakSet<ChangeListener> changeListeners =
		WeakDataStructureFactory.createCopyOnWriteWeakSet();

	private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

	/**
	 * Add listener to be notified when allow list changes are made.
	 * NOTE: This is intended for Swing use only and notification will be provided within
	 * the Swing thread.
	 * 
	 * @param listener change listener
	 */
	public static synchronized void addChangeListener(ChangeListener listener) {
		changeListeners.add(listener);
	}

	/**
	 * Remove existing change listener.
	 * 
	 * @param listener change listener
	 */
	public static synchronized void removeChangeListener(ChangeListener listener) {
		changeListeners.remove(listener);
	}

	private static boolean hasStaleAccessMap() {
		if (serverAccessMap == null) {
			return true;
		}
		long sysTime = System.currentTimeMillis();
		long timeSinceRead = System.currentTimeMillis() - lastCheck;
		if (timeSinceRead < MIN_REFRESH_TIME_MS) {
			// Avoid checking lastModified too often
			return false;
		}
		lastCheck = sysTime;
		return getAllowListFile().lastModified() != lastMod;
	}

	private static Map<ServerSpecification, AccessRecord> getServerAccessMap() {
		if (hasStaleAccessMap()) {
			readServerAllowList();
		}
		return serverAccessMap;
	}

	/**
	 * Determine if the specified server access is allowed.
	 * This method will return true for all {@code localhost/127.0.0.1} URLs if
	 * {@code alwaysAllowLocalAccess} is true.
	 * 
	 * @param protocol URL protocol
	 * @param host server host
	 * @param port server port
	 * @return true if server access is allowed, false if disallowed, null if no server entry was found
	 */
	public static synchronized Boolean getAccess(String protocol, String host, int port) {

		// Always allow access to localhost if alwaysAllowLocalAccess is true
		if (alwaysAllowLocalAccess && ("localhost".equals(host) || "127.0.0.1".equals(host))) {
			return true;
		}

		try {
			AccessRecord rec =
				getServerAccessMap().get(new ServerSpecification(protocol, host, port));
			if (rec == null) {
				return null;
			}
			return rec.accessAllowed();
		}
		catch (IllegalArgumentException e) {
			// NOTE: Caller must handle non-server URLs or opaque URLs
		}
		return false;
	}

	/**
	 * Determine if the specified server access is allowed.
	 * This method will return true for opaque or non-server URLs.
	 * This method will return true for all {@code localhost/127.0.0.1} URLs if 
	 * {@code alwaysAllowLocalAccess} is true.
	 * 
	 * @param url server URL
	 * @return true if server access is allowed, false if disallowed, null if no server entry was found
	 */
	public static synchronized Boolean getAccess(URL url) {

		try {
			if (url.toURI().isOpaque() || url.getAuthority() == null) {
				return true;
			}
		}
		catch (URISyntaxException e) {
			throw new IllegalArgumentException("Unsupported URL: " + url, e);
		}

		return getAccess(url.getProtocol(), url.getHost(), ServerSpecification.getPort(url));
	}

	/**
	 * Update the access for the specified server within the cached allow list.
	 * Changes to {@code localhost/127.0.0.1} server access will be ignored if 
	 * {@code alwaysAllowLocalAccess} is true.
	 * 
	 * @param protocol URL protocol (e.g., {@code https}, {@code ghidra}, {@code ghidra:<ext>}).
	 * @param host host name or IP address
	 * @param port connection port (positive value)
	 * @param allowAccess true allows access, false disallows access
	 * @throws IllegalArgumentException if an invalid parameter is specified
	 */
	public static synchronized void updateAccess(String protocol, String host, int port,
			boolean allowAccess)
			throws IllegalArgumentException {

		if (alwaysAllowLocalAccess && ("localhost".equals(host) || "127.0.0.1".equals(host))) {
			return;
		}

		ServerSpecification server = new ServerSpecification(protocol, host, port);
		AccessRecord accessRec =
			new AccessRecord(allowAccess, System.currentTimeMillis());

		try {
			withLock(() -> {
				if (getAccess(protocol, host, port) != Boolean.valueOf(allowAccess)) {
					Map<ServerSpecification, AccessRecord> map = getServerAccessMap();
					map.put(server, accessRec);

					writeServerAllowList(map);

					Msg.info(UrlAllowListManager.class, "Server Allow List has been updated: " +
						(allowAccess ? "ALLOW " : "DISALLOW ") + server.toUrlString());
				}
			});
		}
		catch (IOException e) {
			Msg.error(UrlAllowListManager.class, "Failed to update Server Allow List (" +
				e.getMessage() + "): " + getAllowListFile());
		}
	}

	/**
	 * Update the access for the specified server URL within the cached allow list.
	 * Changes to {@code localhost/127.0.0.1} server access will be ignored if
	 * {@code alwaysAllowLocalAccess} is true.
	 * 
	 * @param url remote server URL (local and opaque URLs not permitted)
	 * @param allowAccess true allows access, false disallows access
	 * @throws IllegalArgumentException if an invalid, local or opaque URL is specified.
	 */
	public static synchronized void updateAccess(URL url, boolean allowAccess)
			throws IllegalArgumentException {

		try {
			if (url.toURI().isOpaque() || url.getAuthority() == null) {
				throw new IllegalArgumentException("Server URL required");
			}
		}
		catch (URISyntaxException e) {
			throw new IllegalArgumentException("Server URL required", e);
		}

		updateAccess(url.getProtocol(), url.getHost(), ServerSpecification.getPort(url),
			allowAccess);
	}

	/**
	 * Clear the access entry for the specified server.  This is intended to be used along with
	 * {@link #getAccessMap()} for managing the existing access map.
	 * Changes to {@code localhost/127.0.0.1} server access will be ignored if
	 * {@code alwaysAllowLocalAccess} is true.
	 * 
	 * @param server server entry to be removed
	 */
	public static synchronized void clearAccessEntry(ServerSpecification server) {

		if ("localhost".equals(server.hostname()) || "127.0.0.1".equals(server.hostname())) {
			return;
		}

		try {
			withLock(() -> {
				Map<ServerSpecification, AccessRecord> map = getServerAccessMap();
				if (map.remove(server) != null) {
					writeServerAllowList(map);

					Msg.info(UrlAllowListManager.class,
						"Server Allow List has been updated: CLEAR " +
							server.toUrlString());
				}
			});
		}
		catch (IOException e) {
			Msg.error(UrlAllowListManager.class, "Failed to update Server Allow List (" +
				e.getMessage() + "): " + getAllowListFile());
		}
	}

	/**
	 * Clear the access entry for the specified server URL. 
	 * Changes to {@code localhost/127.0.0.1} server access will be ignored if
	 * {@code alwaysAllowLocalAccess} is true.
	 * 
	 * @param url remote server URL (local and opaque URLs not permitted)
	 */
	public static synchronized void clearAccessEntry(URL url) {

		try {
			if (url.toURI().isOpaque() || url.getAuthority() == null) {
				throw new IllegalArgumentException("Server URL required");
			}
		}
		catch (URISyntaxException e) {
			throw new IllegalArgumentException("Server URL required", e);
		}

		clearAccessEntry(ServerSpecification.get(url));
	}

	/**
	 * Clear all server access entries.
	 */
	public static synchronized void clearAll() {
		try {
			withLock(() -> {
				serverAccessMap = new HashMap<>();
				writeServerAllowList(serverAccessMap);
				Msg.info(UrlAllowListManager.class, "Server Allow List has been cleared.");
			});
		}
		catch (IOException e) {
			Msg.error(UrlAllowListManager.class, "Failed to update Server Allow List (" +
				e.getMessage() + "): " + getAllowListFile());
		}
	}

	/**
	 * {@return copy of current server access map}
	 */
	public static synchronized Map<ServerSpecification, AccessRecord> getAccessMap() {
		Map<ServerSpecification, AccessRecord> map = getServerAccessMap();
		return new HashMap<>(map);
	}

	private static File getAllowListFile() {
		return new File(Application.getUserSettingsDirectory(), SERVER_ALLOW_LIST_FILENAME);
	}

	private static void withLock(ExceptionalCallback<IOException> mapModifier) throws IOException {
		LockFile fileLock = getFileLock();
		try {
			lock(fileLock);
			mapModifier.call();
		}
		finally {
			if (fileLock.haveLock()) {
				fileLock.removeLock();
			}
		}
	}

	private static void writeServerAllowList(Map<ServerSpecification, AccessRecord> map)
			throws IOException {
		File file = getAllowListFile();
		try {
			AllowListFile contentWrapper = AllowListFile.fromMap(map);
			try (Writer w = new FileWriter(file)) {
				w.write(GSON.toJson(contentWrapper));
			}
		}
		catch (IOException e) {
			throw new IOException(
				"Failed to store Server Allow List (" + e.getMessage() + "): " + file);
		}
		finally {
			Swing.runLater(() -> {
				for (ChangeListener listener : changeListeners) {
					listener.stateChanged(null);
				}
			});
		}
	}

	/**
	 * Read map from file.
	 */
	private static void readServerAllowList() {
		File file = getAllowListFile();
		try {
			withLock(() -> {
				serverAccessMap = new HashMap<>();
				if (!file.exists() || file.length() == 0) {
					return;
				}
				lastCheck = System.currentTimeMillis();
				lastMod = file.lastModified();
				String json = Files.readString(file.toPath());
				AllowListFile contentWrapper = GSON.fromJson(json, AllowListFile.class);
				if (contentWrapper.version != FILE_FORMAT_VERSION) {
					throw new IOException("Unsupported version: " + contentWrapper.version);
				}
				serverAccessMap.putAll(contentWrapper.toMap());
			});
		}
		catch (IOException | JsonParseException e) {
			Msg.error(UrlAllowListManager.class,
				"Failed to read Server Allow List - file may be replaced (" + e.getMessage() +
					"): " + file);
		}
		finally {
			Swing.runLater(() -> {
				for (ChangeListener listener : changeListeners) {
					listener.stateChanged(null);
				}
			});
		}
	}

	private UrlAllowListManager() {
		// no construct allowed
	}

	/**
	 * Obtain a lock hold on the allow list file for reading or writing.
	 * @throws FileInUseException if lock is already active and failed to acquire
	 */
	private static void lock(LockFile fileLock)
			throws FileInUseException {
		if (!lockFile.createLock(LOCK_TIMEOUT_MS, true)) {
			String msg = "File is in use - '" + lockFile + "'";
			String user = lockFile.getLockOwner();
			if (user != null) {
				msg += " by " + user;
			}
			throw new FileInUseException(msg);
		}
	}

	/**
	 * {@return server allow list lock file}
	 */
	private static LockFile getFileLock() {
		if (lockFile == null) {
			lockFile =
				new LockFile(Application.getUserSettingsDirectory(), SERVER_ALLOW_LIST_LOCKFILE);
		}
		return lockFile;
	}

	/**
	 * {@link ServerAccessRecord} combines {@link ServerSpecification} and {@link AccessRecord} into 
	 * a single record for json serialization use only.
	 */
	private static record ServerAccessRecord(String protocol, String hostname, int port,
			boolean accessAllowed, long time) {}

	/**
	 * {@link AllowListFile} provides a json serialization wrapper with version to facilitate 
	 * storage in list form.
	 */
	private static record AllowListFile(int version, List<ServerAccessRecord> allowList) {

		static AllowListFile fromMap(Map<ServerSpecification, AccessRecord> map) {
			List<ServerAccessRecord> allowList = new ArrayList<>();
			map.forEach(
				(svrSpec, access) -> allowList.add(new ServerAccessRecord(svrSpec.protocol(),
					svrSpec.hostname(), svrSpec.port(), access.accessAllowed(), access.time())));
			return new AllowListFile(FILE_FORMAT_VERSION, allowList);
		}

		Map<ServerSpecification, AccessRecord> toMap() {
			Map<ServerSpecification, AccessRecord> map = new HashMap<>();
			if (allowList != null) {
				allowList.forEach(
					rec -> map.put(new ServerSpecification(rec.protocol, rec.hostname, rec.port),
						new AccessRecord(rec.accessAllowed, rec.time)));
			}
			return map;
		}
	}
}
