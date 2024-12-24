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
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

import org.apache.commons.dbcp2.BasicDataSource;
import org.apache.commons.lang3.StringUtils;

import ghidra.framework.client.ClientUtil;

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
	private final String userinfo; // username[:password]
	private final String host;
	private final int port;
	private final String dbName;

	private String shortDbName; // lazy: short DB Name 

	/**
	 * Construct a new {@link BSimServerInfo} object
	 * 
	 * @param dbType BSim DB type
	 * @param userinfo connection user info, {@code username[:password]}  (ignored for {@link DBType#file}).  
	 *   If blank, {@link ClientUtil#getUserName()} is used.
	 * @param host host name (ignored for {@link DBType#file})
	 * @param port port number (ignored for {@link DBType#file})
	 * @param dbName name of database (simple database name except for {@link DBType#file}
	 * which should reflect an absolute file path.  On Windows OS the path may start with a
	 * drive letter.
	 * @throws IllegalArgumentException if invalid arguments are specified
	 */
	public BSimServerInfo(DBType dbType, String userinfo, String host, int port, String dbName) {
		Objects.requireNonNull(dbType, "DBType must be specified");
		this.dbType = dbType;

		if ((dbType == DBType.postgres || dbType == DBType.elastic) && StringUtils.isEmpty(host)) {
			throw new IllegalArgumentException("host required");
		}

		dbName = dbName.trim();
		if (StringUtils.isEmpty(dbName)) {
			throw new IllegalArgumentException("Non-empty dbName required");
		}

		if (dbType == DBType.file) {
			host = null;
			port = -1;
			userinfo = null;
			dbName = cleanupFilename(dbName);
		}
		else {
			if (dbName.contains("/") || dbName.contains("\\")) { // may want additional validation
				throw new IllegalArgumentException("Invalid " + dbType + " dbName: " + dbName);
			}
			userinfo = cleanupUserInfo(userinfo);
			if (port <= 0) {
				port = -1;
			}
			if (dbType == DBType.postgres && port <= 0) {
				port = DEFAULT_POSTGRES_PORT;
			}
			if (dbType == DBType.elastic && port <= 0) {
				port = DEFAULT_ELASTIC_PORT;
			}
		}

		this.userinfo = userinfo;
		this.host = host;
		this.port = port;
		this.dbName = dbName;
	}

	/**
	 * Construct a new {@link BSimServerInfo} object.  For non-file database the user's defaut 
	 * username is used (see {@link ClientUtil#getUserName()}).
	 * 
	 * @param dbType BSim DB type
	 * @param host host name (ignored for {@link DBType#file})
	 * @param port port number (ignored for {@link DBType#file})
	 * @param dbName name of database (simple database name except for {@link DBType#file}
	 * which should reflect an absolute file path.  On Windows OS the path may start with a
	 * drive letter.
	 * @throws IllegalArgumentException if invalid arguments are specified
	 */
	public BSimServerInfo(DBType dbType, String host, int port, String dbName) {
		this(dbType, null, host, port, dbName);
	}

	/**
	 * Construct a new {@link BSimServerInfo} object for a {@link DBType#file} type database.
	 * 
	 * @param dbName name of database which should reflect an absolute file path.  
	 * On Windows OS the path may start with a drive letter.
	 * @throws IllegalArgumentException if invalid arguments are specified
	 */
	public BSimServerInfo(String dbName) {
		dbType = DBType.file;
		userinfo = null;
		host = null;
		port = -1;
		dbName = dbName.trim();
		if (StringUtils.isEmpty(dbName)) {
			throw new IllegalArgumentException("Non-empty dbName required");
		}
		this.dbName = cleanupFilename(dbName);
	}

	/**
	 * Construct a new {@link BSimServerInfo} object from a suitable database URL
	 * (i.e., {@code postgresql:}, {@code https:}, {@code elastic:}, {@code file:}).
	 * 
	 * @param url supported BSim database URL.  For non-file URLs, the hostname or 
	 * address may be preceeded by a DB username (e.g., postgresql://user@host:port/dbname
	 * @throws IllegalArgumentException if unsupported URL protocol specified
	 */
	public BSimServerInfo(URL url) throws IllegalArgumentException {

		DBType t = null;
		String path = url.getPath();
		String protocol = url.getProtocol();
		if (protocol.equals("postgresql")) {
			t = DBType.postgres;
			host = checkURLField(url.getHost(), "host");
			userinfo = getURLUserInfo(url);
			int p = url.getPort();
			port = p <= 0 ? DEFAULT_POSTGRES_PORT : p;
		}
		else if (protocol.equals("https") || protocol.equals("elastic")) {
			t = DBType.elastic;
			host = checkURLField(url.getHost(), "host");
			userinfo = getURLUserInfo(url);
			int p = url.getPort();
			port = p <= 0 ? DEFAULT_ELASTIC_PORT : p;
		}
		else if (protocol.startsWith("file")) {
			t = DBType.file;
			host = null;
			userinfo = null;
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
		path = urlDecode(checkURLField(path, "path"));
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

	private static String getURLUserInfo(URL url) {

		String userinfo = url.getUserInfo();
		if (userinfo == null) {
			return null;
		}

		int pwSep = userinfo.indexOf(':');
		String urlUserInfo;
		if (pwSep >= 0) {
			urlUserInfo = urlDecode(userinfo.substring(0, pwSep)) + ":" +
				urlDecode(userinfo.substring(pwSep + 1));
		}
		else {
			urlUserInfo = urlDecode(userinfo);
		}
		return cleanupUserInfo(urlUserInfo);
	}

	private static String cleanupUserInfo(String userinfo) {
		if (StringUtils.isBlank(userinfo)) {
			return null;
		}
		userinfo = userinfo.trim();
		int pwdSep = userinfo.indexOf(':');
		if (pwdSep == 0) {
			throw new IllegalArgumentException("Invalid userinfo specified");
		}
		else if (pwdSep > 0 && (userinfo.length() - pwdSep) == 0) {
			throw new IllegalArgumentException("Invalid userinfo specified");
		}
		return userinfo;
	}

	private static String cleanupFilename(String name) {
		// transform dbName into acceptable H2 DB file path
		String dbName = name.trim();
		dbName = dbName.replace("\\", "/");
		if ((!dbName.startsWith("/") && !isWindowsFilePath(dbName)) || dbName.endsWith("/")) {
			throw new IllegalArgumentException("Invalid absolute file path: " + dbName);
		}
		if (!dbName.endsWith(H2_FILE_EXTENSION)) {
			dbName += H2_FILE_EXTENSION;
		}
		return dbName;
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
	 * Return BSim server info in URL format.
	 * Warning: If userinfo with password has been specified it will be returned in the URL.
	 * @return BSim server info in URL format
	 */
	public String toURLString() {
		switch (dbType) {
			case postgres:
				return "postgresql://" + formatURLUserInfo() + host + getPortString() + "/" +
					urlEncode(dbName);

			case elastic:
				return "https://" + formatURLUserInfo() + host + getPortString() + "/" +
					urlEncode(dbName);

			case file: // h2:
				return "file:" + urlEncode(dbName);
		}
		throw new RuntimeException("Unsupported DBType: " + dbType);
	}

	private static String urlEncode(String text) {
		return URLEncoder.encode(text, StandardCharsets.UTF_8);
	}

	private static String urlDecode(String text) {
		return URLDecoder.decode(text, StandardCharsets.UTF_8);
	}

	private String formatURLUserInfo() {
		if (userinfo == null) {
			return "";
		}
		int pwSep = userinfo.indexOf(':');
		String urlUserInfo;
		if (pwSep >= 0) {
			urlUserInfo = urlEncode(userinfo.substring(0, pwSep)) + ":" +
				urlEncode(userinfo.substring(pwSep + 1));
		}
		else {
			urlUserInfo = urlEncode(userinfo);
		}
		return urlUserInfo + "@";
	}

	private String getPortString() {
		return port > 0 ? (":" + Integer.toString(port)) : "";
	}

	/**
	 * Return BSim server info in URL.
	 * Warning: If userinfo with password has been specified it will be returned in the URL.
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

	public void setUserInfo(BasicDataSource bds) {
		bds.setUsername(getUserName());
		if (hasPassword()) {
			bds.setPassword(userinfo.substring(userinfo.indexOf(':') + 1));
		}
	}

	/**
	 * Determine if user information includes password.
	 * NOTE: Use of passwords with this object and URLs is discouraged.
	 * @return true if user information includes password which
	 */
	public boolean hasPassword() {
		return userinfo != null && userinfo.contains(":");
	}

	/**
	 * Determine of user info was stipulated during construction
	 * @return true if user info was stipulated during construction
	 */
	public boolean hasDefaultLogin() {
		return userinfo == null;
	}

	/**
	 * Get the remote database user name to be used when establishing a connection.
	 * User name obtained from the user information which was provided during instantiation.
	 * @return remote database user information (null for {@link DBType#file}).
	 */
	public String getUserName() {
		if (dbType == DBType.file) {
			return null;
		}
		if (userinfo == null) {
			return ClientUtil.getUserName();
		}
		String username = userinfo;
		int pwdSep = userinfo.indexOf(':');
		if (pwdSep > 0) {
			username = userinfo.substring(0, pwdSep);
		}
		return username;
	}

	/**
	 * Get the remote database user information to be used when establishing a connection.
	 * @return remote database user information (null for {@link DBType#file}).
	 */
	public String getUserInfo() {
		return userinfo;
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
		int hashcode = Objects.hash(dbName, dbType.ordinal(), host, port);
		// Due to the use of hashcode by BSimServerManager for persisting server entries 
		// we cannot change the hashing function above and must only incorporate inclusion
		// of userinfo if it is specified.
		if (userinfo != null) {
			hashcode = 31 * hashcode + userinfo.hashCode();
		}
		return hashcode;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (obj instanceof BSimServerInfo other) {
			return Objects.equals(dbName, other.dbName) && dbType == other.dbType &&
				Objects.equals(userinfo, other.userinfo) && Objects.equals(host, other.host) &&
				port == other.port;
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
