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
package ghidra.features.bsim.query;

import java.io.Closeable;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Objects;

import org.apache.commons.lang3.StringUtils;

public class BSimServerInfo implements Comparable<BSimServerInfo> {

	/**
	 * Default port used for {@link DBType#postgres} server
	 */
	public static final int DEFAULT_POSTGRES_PORT = 5432;

	/**
	 * Default port used for {@link DBType#elastic} server
	 */
	public static final int DEFAULT_ELASTIC_PORT = 9200;

	/**
	 * File extension imposed for {@link DBType#file} server.
	 * This is a rigid H2 database convention.
	 */
	public static final String H2_FILE_EXTENSION = ".mv.db";

	/**
	 * Enumerated Database Types
	 */
	public enum DBType {
		postgres, elastic, file;
	}

	private final DBType dbType;
	private final String host;
	private final int port;
	private final String dbName;

	private String shortDbName; // lazy: short DB Name 

	/**
	 * Construct a new {@link BSimServerInfo} object
	 * @param dbType BSim DB type
	 * @param host host name (ignored for {@link DBType#file})
	 * @param port port number (ignored for {@link DBType#file})
	 * @param dbName name of database (simple database name except for {@link DBType#file}
	 * which should reflect an absolute file path.  On Windows OS the path may start with a
	 * drive letter.
	 * @throws IllegalArgumentException if invalid arguments are specified
	 */
	public BSimServerInfo(DBType dbType, String host, int port, String dbName) {
		Objects.requireNonNull(dbType, "DBType must be specified");
		this.dbType = dbType;

		if ((dbType == DBType.postgres || dbType == DBType.elastic) && StringUtils.isEmpty(host)) {
			throw new IllegalArgumentException("host required");
		}
		this.host = host;

		if (port <= 0) {
			port = -1;
		}
		if (dbType == DBType.postgres && port <= 0) {
			port = DEFAULT_POSTGRES_PORT;
		}
		if (dbType == DBType.elastic && port <= 0) {
			port = DEFAULT_ELASTIC_PORT;
		}
		this.port = port;

		dbName = dbName.trim();
		if (StringUtils.isEmpty(dbName)) {
			throw new IllegalArgumentException("Non-empty dbName required");
		}
		if (dbType == DBType.file) {
			// transform dbName into acceptable H2 DB file path
			dbName = dbName.replace("\\", "/");
			if ((!dbName.startsWith("/") && !isWindowsFilePath(dbName)) || dbName.endsWith("/")) {
				throw new IllegalArgumentException("Invalid absolute file path: " + dbName);
			}
			if (!dbName.endsWith(H2_FILE_EXTENSION)) {
				dbName += H2_FILE_EXTENSION;
			}
		}
		else if (dbName.contains("/") || dbName.contains("\\")) { // may want additional validation
			throw new IllegalArgumentException("Invalid " + dbType + " dbName: " + dbName);
		}
		this.dbName = dbName;
	}

	/**
	 * Construct a new {@link BSimServerInfo} object from a suitable database URL
	 * (i.e., {@code postgresql:}, {@code https:}, {@code elastic:}, {@code file:}).
	 * @param url supported BSim database URL
	 * @throws IllegalArgumentException if unsupported URL protocol specified
	 */
	public BSimServerInfo(URL url) throws IllegalArgumentException {

		DBType t = null;
		String path = url.getPath();
		String protocol = url.getProtocol();
		if (protocol.equals("postgresql")) {
			t = DBType.postgres;
			host = checkURLField(url.getHost(), "host");
			int p = url.getPort();
			port = p <= 0 ? DEFAULT_POSTGRES_PORT : p;
		}
		else if (protocol.equals("https") || protocol.equals("elastic")) {
			t = DBType.elastic;
			host = checkURLField(url.getHost(), "host");
			int p = url.getPort();
			port = p <= 0 ? DEFAULT_ELASTIC_PORT : p;
		}
		else if (protocol.startsWith("file")) {
			t = DBType.file;
			host = null;
			port = -1;
			if (!"".equals(url.getHost())) {
				throw new IllegalArgumentException("Remote file URL not supported: " + url);
			}
		}
		else {
			throw new IllegalArgumentException("Unsupported BSim URL protocol: " + protocol);
		}
		dbType = t;

		if (dbType == DBType.postgres || dbType == DBType.elastic) {
			if (!path.startsWith("/")) {
				throw new IllegalArgumentException("Missing dbName in URL: " + url);
			}
			path = path.substring(1).strip();
		}
		path = checkURLField(path, "path");
		if (dbType == DBType.file) {
			if (path.endsWith("/")) {
				throw new IllegalArgumentException("Missing DB filepath in URL: " + url);
			}
			if (!path.endsWith(H2_FILE_EXTENSION)) {
				path += H2_FILE_EXTENSION;
			}
			// TODO: handle Windows path with drive letter - need to remove leading '/'
		}
		else if (path.contains("/")) {
			throw new IllegalArgumentException("Invalid dbName in URL: " + path);
		}
		dbName = path;
	}

	private static String checkURLField(String val, String name) {
		if (StringUtils.isEmpty(val)) {
			throw new IllegalArgumentException("Invalid " + name + " in URL");
		}
		return val.trim();
	}

	/**
	 * Determine if this server info corresponds to Windows OS file path.
	 * @return true if this server info corresponds to Windows OS file path.
	 */
	public boolean isWindowsFilePath() {
		return dbType == DBType.file && isWindowsFilePath(dbName);
	}

	/**
	 * Check for Windows path after all '/' chars have been converted to '\' chars.
	 * Example:  {@code C:/a/b/c}
	 * @param path absolute file path
	 * @return true if path appears to be windows path with a drive letter
	 */
	private static boolean isWindowsFilePath(String path) {
		if (path.length() < 4) {
			return false;
		}
		if (!Character.isLetter(path.charAt(0)) || path.charAt(1) != ':') {
			return false;
		}
		char c = path.charAt(2);
		if (c != '/') {
			return false;
		}
		c = path.charAt(3);
		return c != '/';
	}

	/**
	 * Return BSim server info in URL format
	 * @return BSim server info in URL format
	 */
	public String toURLString() {
		switch (dbType) {
			case postgres:
				return "postgresql://" + host + getPortString() + "/" + dbName;

			case elastic:
				return "https://" + host + getPortString() + "/" + dbName;

			case file: // h2:
				return "file:" + dbName;
		}
		throw new RuntimeException("Unsupported DBType: " + dbType);
	}

	private String getPortString() {
		return port > 0 ? (":" + Integer.toString(port)) : "";
	}

	/**
	 * Return BSim server info in URL
	 * @return BSim server info in URL
	 * @throws MalformedURLException if unable to form supported URL
	 */
	public URL toURL() throws MalformedURLException {
		return new URL(toURLString());
	}

	/**
	 * @return BSim database type
	 */
	public DBType getDBType() {
		return dbType;
	}

	/**
	 * Get the server hostname or IP address as originally specified.
	 * @return hostname or IP address as originally specified
	 */
	public String getServerName() {
		return host;
	}

	/**
	 * Get the port number.
	 * @return port number
	 */
	public int getPort() {
		return port;
	}

	/**
	 * Get the DB Name
	 * @return DB name
	 */
	public String getDBName() {
		return dbName;
	}

	/**
	 * Get the DB Name.  In the case of {@link DBType#file} the directory path will
	 * be excluded from returned name.
	 * @return shortened DB Name
	 */
	public String getShortDBName() {
		if (shortDbName != null) {
			return shortDbName;
		}
		shortDbName = dbName;
		if (dbType == DBType.file) {
			int ix = dbName.lastIndexOf('/');
			if (ix >= 0) {
				shortDbName = dbName.substring(ix + 1);
			}
		}
		return shortDbName;
	}

	@Override
	public int hashCode() {
		// use dbType.ordinal; enum hashcodes vary from run to run
		return Objects.hash(dbName, dbType.ordinal(), host, port);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (obj instanceof BSimServerInfo other) {
			return Objects.equals(dbName, other.dbName) && dbType == other.dbType &&
				Objects.equals(host, other.host) && port == other.port;
		}
		return false;
	}

	@Override
	public String toString() {
		switch (dbType) {
			case file:
				return getShortDBName() + "  (" + dbName + ");";
			default:
				return dbName + "  (" + dbType + ": " + host + ")";
		}
	}

	/**
	 * Get a BSim {@link FunctionDatabase} instance which corresponds to this DB server info.
	 * The {@link Closeable} instance should be closed when no longer in-use to ensure that 
	 * any associated database connection and resources are properly closed.
	 * @param async true if database commits should be asynchronous (may not be applicable)
	 * @return BSim function database instance
	 */
	public FunctionDatabase getFunctionDatabase(boolean async) {
		return BSimClientFactory.buildClient(this, async);
	}

	@Override
	public int compareTo(BSimServerInfo o) {
		return toString().compareTo(o.toString());
	}
}
