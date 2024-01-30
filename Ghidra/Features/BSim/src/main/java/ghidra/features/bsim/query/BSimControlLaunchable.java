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

import java.io.*;
import java.net.Authenticator;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.security.KeyStore.PasswordProtection;
import java.sql.*;
import java.util.*;

import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.DestroyFailedException;

import org.apache.commons.lang3.StringUtils;
import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;

import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.features.bsim.query.ingest.BSimLaunchable;
import ghidra.framework.*;
import ghidra.framework.client.ClientUtil;
import ghidra.net.ApplicationKeyManagerUtils;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.NonThreadedXmlPullParserImpl;
import ghidra.xml.XmlPullParser;
import utilities.util.FileUtilities;

public class BSimControlLaunchable implements GhidraLaunchable {

	// bsim_ctl commands
	public final static String COMMAND_START = "start";
	public final static String COMMAND_STOP = "stop";
	public final static String COMMAND_RESET_PASSWORD = "resetpassword";
	public final static String COMMAND_CHANGE_PRIVILEGE = "changeprivilege";
	public final static String COMMAND_ADDUSER = "adduser";
	public final static String COMMAND_DROPUSER = "dropuser";
	public final static String COMMAND_CHANGEAUTH = "changeauth";

	// Options that require a value argument
	public static final String CAFILE_OPTION = "--cafile";
	public static final String AUTH_OPTION = "--auth";
	public static final String DN_OPTION = "--dn";

	// Global options that require a value argument
	public static final String PORT_OPTION = "--port";
	public static final String USER_OPTION = "--user";
	public static final String CERT_OPTION = "--cert";

	// Define set of options that require a second value argument
	private static final Set<String> VALUE_OPTIONS =
		Set.of(PORT_OPTION, USER_OPTION, CERT_OPTION, CAFILE_OPTION, AUTH_OPTION, DN_OPTION);

	private static final Set<String> GLOBAL_OPTIONS = Set.of(PORT_OPTION, USER_OPTION, CERT_OPTION);

	// Boolean options
	public static final String NO_LOCAL_AUTH_OPTION = "--noLocalAuth";
	public static final String FORCE_OPTION = "--force";

	private static final Map<String, String> SHORTCUT_OPTION_MAP = new HashMap<>();
	static {
		SHORTCUT_OPTION_MAP.put("-a", AUTH_OPTION);
		SHORTCUT_OPTION_MAP.put("-p", PORT_OPTION);
		SHORTCUT_OPTION_MAP.put("-u", USER_OPTION);
	}

	//@formatter:off
	// Populate ALLOWED_OPTION_MAP for each command
	private static final Set<String> START_OPTIONS = 
			Set.of(AUTH_OPTION, DN_OPTION, NO_LOCAL_AUTH_OPTION, CAFILE_OPTION);
	private static final Set<String> STOP_OPTIONS = 
			Set.of(FORCE_OPTION);
	private static final Set<String> RESET_PASSWORD_OPTIONS = Set.of();
	private static final Set<String> CHANGE_PRIVILEGE_OPTIONS = Set.of();
	private static final Set<String> ADDUSER_OPTIONS = 
			Set.of(DN_OPTION);
	private static final Set<String> DROPUSER_OPTIONS = Set.of();
	private static final Set<String> CHANGEAUTH_OPTIONS = Set.of(
		AUTH_OPTION, NO_LOCAL_AUTH_OPTION, CAFILE_OPTION);
	
	//@formatter:on
	private static final Map<String, Set<String>> ALLOWED_OPTION_MAP = new HashMap<>();
	static {
		ALLOWED_OPTION_MAP.put(COMMAND_START, START_OPTIONS);
		ALLOWED_OPTION_MAP.put(COMMAND_STOP, STOP_OPTIONS);
		ALLOWED_OPTION_MAP.put(COMMAND_RESET_PASSWORD, RESET_PASSWORD_OPTIONS);
		ALLOWED_OPTION_MAP.put(COMMAND_CHANGE_PRIVILEGE, CHANGE_PRIVILEGE_OPTIONS);
		ALLOWED_OPTION_MAP.put(COMMAND_ADDUSER, ADDUSER_OPTIONS);
		ALLOWED_OPTION_MAP.put(COMMAND_DROPUSER, DROPUSER_OPTIONS);
		ALLOWED_OPTION_MAP.put(COMMAND_CHANGEAUTH, CHANGEAUTH_OPTIONS);
	}

	private final static String POSTGRES = "postgresql";
	private final static String POSTGRES_BUILD_SCRIPT = "Ghidra/Features/BSim/make-postgres.sh";
	private final static String POSTGRES_CONFIGFILE = "postgresql.conf";
	private final static String POSTGRES_CONNECTFILE = "pg_hba.conf";
	private final static String POSTGRES_IDENTFILE = "pg_ident.conf";
	private final static String POSTGRES_ROOTCA = "root.crt";
	private final static String PASSWORD_METHOD = "scram-sha-256";
	private final static String TRUST_METHOD = "trust";
	private final static String CERTIFICATE_METHOD = "cert";
	private final static String CERTIFICATE_OPTIONS = "map=mymap clientcert=verify-full";
//	private final static String CERTIFICATE_OPTIONS = "map=mymap clientcert=1";     // For PKI certificates prior to PostgreSQL 12
	private final static String POSTGRES_MAP_IDENTIFIER = "mymap";
	private final static String DEFAULT_PASSWORD = "changeme";
	private final static int AUTHENTICATION_NONE = 0;
	private final static int AUTHENTICATION_PASSWORD = 1;
	private final static int AUTHENTICATION_PKI = 2;

	private GhidraApplicationLayout layout;

	private File dataDirectory;			// Directory containing postgres datafiles
	private File postgresRoot;			// Directory containing postgres software
	private File postgresControl;		// "pg_ctl" utility within postgres software
	private File certAuthorityFile;		// Certificate authority file provided by the user
	private String certParameter;		// Path to certificate provided by user
	private String distinguishedName;	// Certificate distinguished name provided by the user
	private String commonName;			// Common name extracted from distinguishedName
	private String connectingUserName;	// User-name used to establish connection
	private String specifiedUserName;	// -username- (add/drop) operation is being performed on
	private boolean adminPrivilegeRequested;	// true is attempting to give user admin privileges
	private boolean forceShutdown;		// Whether or not to force a shutdown (--force)
	private String loadLibraryVar;		// Environment variable pointing to postgres shared libraries
	private String loadLibraryValue;	// Directory containing shared libraries within postgres software
	private int port;					// Port over which to connect to postgres server, (-1 indicates default port is used)
	private int localAuthentication;	// Type of authentication required for local connections
	private int hostAuthentication;		// Type of authentication for remote connections
	private boolean authConfigPresent;	// True if the [auth=..] option or the [--noLocalAuth] is present
	private File passwordFile;			// File containing newly established password
	private char[] adminPasswordData;	// Password data being sent to postgres server for authentication

	// Database connection that can be persisted so we don't need to recreate one
	// for every call.
	private Connection localConnection;

	/**
	 * Constructor for launching from the console
	 */
	public BSimControlLaunchable() {
	}

	private void clearParams() {
		dataDirectory = null;
		postgresRoot = null;
		postgresControl = null;
		certAuthorityFile = null;
		certParameter = null;
		distinguishedName = null;
		commonName = null;
		connectingUserName = null;
		specifiedUserName = null;
		adminPrivilegeRequested = false;
		forceShutdown = false;
		loadLibraryVar = null;
		loadLibraryValue = null;
		port = -1;
		localAuthentication = AUTHENTICATION_NONE;
		hostAuthentication = AUTHENTICATION_NONE;
		authConfigPresent = false;
		passwordFile = null;
		adminPasswordData = null;
	}

	/**
	 * Read required parameters followed by optional parameters
	 * @param params is the original array of command line parameters
	 */
	private String readCommandLine(String[] params) throws IllegalArgumentException, IOException {

		int slot = 0;

		checkRequiredParam(params, slot, "command");
		String command = params[slot++];

		switch (command) {
			case COMMAND_START:
				scanDataDirectory(params, slot++);
				break;
			case COMMAND_STOP:
				scanDataDirectory(params, slot++);
				break;
			case COMMAND_ADDUSER:
				scanDataDirectory(params, slot++);
				scanUsername(params, slot++);
				break;
			case COMMAND_DROPUSER:
				scanDataDirectory(params, slot++);
				scanUsername(params, slot++);
				break;
			case COMMAND_RESET_PASSWORD:
				scanUsername(params, slot++);
				break;
			case COMMAND_CHANGEAUTH:
				scanDataDirectory(params, slot++);
				break;
			case COMMAND_CHANGE_PRIVILEGE:
				scanUsername(params, slot++);
				scanPrivilege(params, slot++);
				break;
			default:
				throw new IllegalArgumentException("Unknown command: " + command);
		}

		readOptions(command, params, slot);

		return command;
	}

	/**
	 * Read in any optional parameters, strip them from the parameter stream
	 * @param command command name
	 * @param params is the original array of command line parameters
	 * @param discard number of params already consumed
	 */
	private void readOptions(String command, String[] params, int discard) {

		boolean sawNoLocalAuth = false;

		Set<String> allowedParams = ALLOWED_OPTION_MAP.get(command);
		if (allowedParams == null) {
			throw new IllegalArgumentException("Unsupported command: " + command);
		}

		for (int i = discard; i < params.length; ++i) {
			String optionName = params[i];
			String value = null;

			if (optionName.startsWith("-")) {
				// although not prefered, allow option value to be specified as --option=value
				int ix = optionName.indexOf("=");
				if (ix > 1) {
					value = optionName.substring(ix + 1);
					optionName = optionName.substring(0, ix);
				}
			}

			String option = optionName;

			if (optionName.startsWith("-") && !optionName.startsWith("--")) {
				option = SHORTCUT_OPTION_MAP.get(optionName); // map option to -- long form
				if (option == null) {
					throw new IllegalArgumentException("Unsupported option use: " + optionName);
				}
			}

			if (!option.startsWith("--")) {
				throw new IllegalArgumentException("Unexpected argument: " + option);
			}

			if (!GLOBAL_OPTIONS.contains(option) && !allowedParams.contains(option)) {
				throw new IllegalArgumentException("Unsupported option use: " + optionName);
			}

			if (!VALUE_OPTIONS.contains(option)) {
				// option without value arg
				if (value != null) {
					throw new IllegalArgumentException(
						"Unsupported option specification: " + optionName + "=");
				}
			}
			else if (StringUtils.isBlank(value)) {
				// consume next param as option value
				if (++i == params.length) {
					throw new IllegalArgumentException("Missing option value: " + optionName);
				}
				value = params[i];
			}

			switch (option) {
				case PORT_OPTION:
					port = parsePositiveIntegerOption(optionName, value);
					break;
				case USER_OPTION:
					connectingUserName = value;
					break;
				case CERT_OPTION:
					certParameter = value;
					break;
				case CAFILE_OPTION:
					certAuthorityFile = new File(value);
					break;
				case AUTH_OPTION:
					authConfigPresent = true;
					String type = value;
					if (type.equals("pki")) {
						hostAuthentication = AUTHENTICATION_PKI;
						localAuthentication = AUTHENTICATION_PKI;
					}
					else if (type.equals("password")) {
						hostAuthentication = AUTHENTICATION_PASSWORD;
						localAuthentication = AUTHENTICATION_PASSWORD;
					}
					else if (type.equals("trust") || type.equals("none")) {
						hostAuthentication = AUTHENTICATION_NONE;
						localAuthentication = AUTHENTICATION_NONE;
					}
					else {
						throw new IllegalArgumentException("Unknown authentication method: " +
							type + " : options are trust, password or pki");
					}
					break;
				case DN_OPTION:
					distinguishedName = value;
					validateDistinguishedName();
					break;
				case NO_LOCAL_AUTH_OPTION:
					sawNoLocalAuth = true;
					break;
				case FORCE_OPTION:
					forceShutdown = true;
					break;
				default:
					throw new AssertionError("Missing option handling: " + option);
			}
		}

		if (sawNoLocalAuth) {	// Turn off authentication for local connections
			authConfigPresent = true;
			localAuthentication = AUTHENTICATION_NONE;
		}
		if (connectingUserName == null) {
			connectingUserName = ClientUtil.getUserName();
		}
	}

	private void checkRequiredParam(String[] params, int index, String name) {
		if (params.length <= index) {
			throw new IllegalArgumentException("Missing required parameter: " + name);
		}
		String p = params[index];
		if (p.startsWith("--")) {
			throw new IllegalArgumentException(
				"Missing required parameter (" + name + ") before specified option: " + p);
		}
	}

	private int parsePositiveIntegerOption(String option, String optionValue) {
		try {
			int value = Integer.valueOf(optionValue);
			if (value < 0) {
				throw new IllegalArgumentException("Negative value not permitted for " + option);
			}
			return value;
		}
		catch (NumberFormatException e) {
			throw new IllegalArgumentException("Invalid integer value specified for " + option);
		}
	}

	/**
	 * Verify that the given file is a PEM certificate
	 * @param testFile the file to test
	 * @return true if testFile looks like a PEM certificate
	 * @throws IOException if there is a problem reading the given file
	 */
	private static boolean verifyPEMFormat(File testFile) throws IOException {
		BufferedReader reader = new BufferedReader(new FileReader(testFile));
		try {
			// All we currently do is search for the certificate header in the first 200 lines
			for (int i = 0; i < 200; ++i) {
				String line = reader.readLine();
				if (line == null) {
					break;
				}
				if (line.startsWith(ApplicationKeyManagerUtils.BEGIN_CERT)) {
					return true;
				}
			}
		}
		finally {
			reader.close();
		}
		return false;
	}

	/**
	 * Parse the -distinguishedName- String, verifying it is has the correct format for a
	 * X509 certificate distinguished name. Try to extract the common name portion of the
	 * distinguished name and assign it to -commonName- 
	 * @throws IllegalArgumentException if the distinguished name is improperly formatted or the common name is missing
	 */
	private void validateDistinguishedName() throws IllegalArgumentException {
		if (distinguishedName == null) {
			return;
		}
		commonName = null;
		try {
			LdapName ldapName = new LdapName(distinguishedName);
			for (Rdn rdn : ldapName.getRdns()) {
				if (rdn.getType().equalsIgnoreCase("CN")) {
					commonName = rdn.getValue().toString();
					break;
				}
			}
			if (commonName == null) {
				throw new IllegalArgumentException("Missing common name attribute");
			}
		}
		catch (Exception e) {
			throw new IllegalArgumentException("Improperly formatted distinguished name");
		}
	}

	/**
	 * @return true if the server (referred to by -postgresRoot-) is running
	 * @throws IOException if there is a problem running the command
	 * @throws InterruptedException if there is a problem running the command
	 */
	private boolean isServerRunning() throws IOException, InterruptedException {
		File createCommand = new File(postgresRoot, "bin/pg_isready");
		List<String> command = new ArrayList<String>();
		command.add(createCommand.getAbsolutePath());
		if ((port != -1) && (port != 5432)) {	// Non-default port
			command.add("-p");
			command.add(Integer.toString(port));
		}
		int ret = runCommand(null, command, loadLibraryVar, loadLibraryValue);
		return (ret == 0);
	}

	private char[] requestPassword(String prompt) {
		String host = "localhost";
		InetAddress addr = InetAddress.getLoopbackAddress();
		String protocol = "postgresql";
		String scheme = "NO_NAME";
		return Authenticator
				.requestPasswordAuthentication(host, addr, port, protocol, prompt, scheme)
				.getPassword();
	}

	/**
	 * (For a new postgres server) Establish an administrative password, by requesting the password
	 * from the user, and then having the user re-enter the password. The password is stored in
	 * the character array -adminPasswordData- and written to the file -passwordFile-
	 * for access by the postgres "init" process
	 * @throws IOException if there is a problem obtaining the password
	 */
	private void establishAdminPassword() throws IOException {
		for (;;) {
			adminPasswordData = requestPassword("Set admin(" + connectingUserName + ") password:");
			if (adminPasswordData == null) {
				throw new IOException("Unable to obtain password");
			}
			char[] repeatPass = requestPassword("Please re-enter password:");
			boolean match = comparePasswordData(adminPasswordData, repeatPass);
			clearPasswordData(repeatPass);
			if (match) {
				break;
			}
			cleanupPasswordData();
			System.out.println("Passwords do not match");
		}
		passwordFile = Files
				.createTempFile("bsim", ".dat",
					PosixFilePermissions
							.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
				.toFile();
		FileWriter writer = new FileWriter(passwordFile);
		writer.write(adminPasswordData);
		writer.close();
	}

	/**
	 * Clear (sensitive) data for a particular character array so it is no longer accessible from the heap
	 * @param password is the array of sensitive characters
	 */
	private static void clearPasswordData(char[] password) {
		if (password != null) {
			for (int i = 0; i < password.length; ++i) {
				password[i] = ' ';
			}
		}
	}

	/**
	 * Compare that two character arrays contain exactly the same data
	 * @param password password to compare
	 * @param repeatPass password to compare
	 * @return true if the character sequences are non-null and identical
	 */
	private static boolean comparePasswordData(char[] password, char[] repeatPass) {
		if (password == null || repeatPass == null) {
			return false;
		}
		if (password.length != repeatPass.length) {
			return false;
		}
		for (int i = 0; i < repeatPass.length; ++i) {
			if (repeatPass[i] != password[i]) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Make sure password data, stored either in the heap or in a temporary file, is scrubbed
	 * @throws IOException if the password file cannot be deleted
	 */
	private void cleanupPasswordData() throws IOException {

		clearPasswordData(adminPasswordData);
		adminPasswordData = null;

		if (passwordFile != null) {
			if (!passwordFile.delete()) {
				throw new IOException(
					"Unable to delete password file: " + passwordFile.getAbsolutePath());
			}
			passwordFile = null;
		}
	}

	/**
	 * Servers that allow SSL connections are required to have a certificate that allows it to
	 * authenticate itself to users.  The BSim server does not authenticate itself to clients, but
	 * a certificate must still be present.  We generate a self-signed certificate.
	 * @param certFile will hold the public portion of the generated certificate
	 * @param passFile will hold the private portion
	 * @throws IOException if the password file cannot be opened for writing
	 * @throws GeneralSecurityException if the keystore cannot be created
	 */
	private void generateSelfSignedCertificate(File certFile, File passFile)
			throws IOException, GeneralSecurityException {

		String alias = "bsimroot";
		char[] password = "unusedpassword".toCharArray();

		PasswordProtection pp = new PasswordProtection(password);
		try {
			// TODO: should subjectAlternativeNames be supported?
			KeyStore keyStore = ApplicationKeyManagerUtils.createKeyStore(alias, "CN=BSimServer",
				365 * 2, null, null, "JKS", null, password);

			ApplicationKeyManagerUtils.exportX509Certificates(keyStore.getCertificateChain(alias),
				certFile);
			Key key = keyStore.getKey(alias, password);

			try (FileOutputStream fout = new FileOutputStream(passFile);
					PrintWriter writer = new PrintWriter(fout)) {
				writer.print("-----BEGIN PRIVATE KEY-----");
				writer.println();
				String base64 = Base64.getEncoder().encodeToString(key.getEncoded());
				while (base64.length() != 0) {
					int endIndex = Math.min(44, base64.length());
					String line = base64.substring(0, endIndex);
					writer.println(line);
					base64 = base64.substring(endIndex);
				}
				writer.println("-----END PRIVATE KEY-----");
				writer.println();
			}

			passFile.setExecutable(false, false);		// Clear execute permission for everybody
			passFile.setReadable(false, false);			// Clear read permission for everybody
			passFile.setWritable(false, false);			// Clear write permission for everybody
			passFile.setReadable(true, true);			// Let owner read the file
		}
		catch (NoSuchAlgorithmException | UnrecoverableEntryException e) {
			throw new KeyStoreException("Failed to generate BSim server certificate", e);
		}
		finally {
			Arrays.fill(password, ' ');
			try {
				pp.destroy();
			}
			catch (DestroyFailedException e) {
				throw new AssertException(e); // unexpected for simple password clearing
			}
		}
	}

	/**
	 * Create a local connection to a postgres server. A full SSL connection is created using
	 * Ghidra's infrastructure.  If the initial connection fails because password authentication
	 * was requested, collect the administrative password from the user, and try the connection again
	 * @return the established connection object.  Respect any command-line "port= .." option.
	 * @throws SQLException if the db connection cannot be established
	 * @throws IOException if the user password cannot be retrieved
	 */
	private Connection createLocalConnection() throws SQLException, IOException {
		Properties properties = new Properties();
		properties.setProperty("sslmode", "require");
		properties.setProperty("sslfactory", "ghidra.net.ApplicationSSLSocketFactory");
		properties.setProperty("user", connectingUserName);
		StringBuilder buffer = new StringBuilder();
		buffer.append("jdbc:postgresql://localhost");
		if ((port != -1) && (port != 5432)) {	// Non-default port
			buffer.append(':');
			buffer.append(port);
		}
		buffer.append("/template1");
		String connstring = buffer.toString();
		if (adminPasswordData == null) {
			try {
				Connection pdb = DriverManager.getConnection(connstring, properties);
				return pdb;
			}
			catch (SQLException e) {
				if (!e.getMessage().contains("password-based authentication") &&
					!e.getMessage().contains("SCRAM-based authentication")) {
					throw e;
				}
			}
			adminPasswordData = requestPassword("User " + connectingUserName + " password:");
			if (adminPasswordData == null) {
				throw new IOException("Unable to obtain password");
			}
		}
		String passString = new String(adminPasswordData);
		properties.setProperty("password", passString);
		return DriverManager.getConnection(connstring, properties);			// Try again providing driver a password		
	}

	/**
	 * Execute SQL statement on a connection that returns nothing.
	 * If execution fails, the connection is closed before throwing exception
	 * @param pdb is the connection
	 * @param statementString is the SQL statement
	 * @throws SQLException if the sql statement cannot be created or executed
	 */
	private static void executeSQLStatement(Connection pdb, String statementString)
			throws SQLException {
		try (Statement st = pdb.createStatement()) {
			st.executeUpdate(statementString);
		}
		catch (SQLException err) {
			pdb.close();
			throw err;
		}
	}

	/**
	 * On a running server, establish a local connection and enable the BSim specific extension for that server
	 * @throws SQLException if the sql statement cannot be executed
	 * @throws IOException if the db connection cannot be established
	 */
	private void enableLSHExtension() throws SQLException, IOException {
		Connection pdb = createLocalConnection();

		try {
			executeSQLStatement(pdb, "CREATE EXTENSION IF NOT EXISTS lshvector");
		}
		finally {
			pdb.close();
		}

	}

	/**
	 * Invoke an external executable/command, display the output and error streams on the console,
	 * the exit condition of the command is returned.  If the exit condition indicates and error,
	 * but a line of the error stream matches a provided String, the error is suppressed 
	 * @param directory	 is the working directory for the command
	 * @param command    is the command-line (including arguments)
	 * @param envvar     if non-null, is an environment variable to set for the command
	 * @param value      is the corresponding environment variable value
	 * @return the exit status of the command (0=no error)
	 * @throws IOException if the process cannot be started
	 * @throws InterruptedException if there is a problem waiting for the process to finish
	 */
	private int runCommand(File directory, List<String> command, String envvar, String value)
			throws IOException, InterruptedException {
		ProcessBuilder processBuilder = new ProcessBuilder(command);
		processBuilder.directory(directory);		// Set the working directory
		if (envvar != null) {
			Map<String, String> environment = processBuilder.environment();
			environment.put(envvar, value);
		}
		Process process = processBuilder.start();

		new IOThread(process.getInputStream(), true).start();
		IOThread errThread = new IOThread(process.getErrorStream(), true);
		errThread.start();

		int retval = process.waitFor();
		return retval;
	}

	/**
	 * Tune the postgres configuration and authentication files (postgresql.conf and pg_hba.conf)
	 * based on the command-line options passed in by the user and the ghidra specific configuration options
	 * @param inputFile is the unmodified postgresql.conf file
	 * @param outputFile will hold the new modified version of postgresql.conf
	 * @param inHbaFile is the original pg_hba.conf file
	 * @param outHbaFile will hold the new modified version of pg_hba.conf
	 * @param serverConfigFile is the XML file holding ghidra specific BSim configuration options
	 * @throws SAXException if the xml pull parser cannot be created
	 * @throws IOException if the authentication fails
	 */
	private void tuneConfig(File inputFile, File outputFile, File inHbaFile, File outHbaFile,
			File serverConfigFile) throws SAXException, IOException {
		ErrorHandler handler = SpecXmlUtils.getXmlHandler();
		XmlPullParser parser = new NonThreadedXmlPullParserImpl(serverConfigFile, handler, false);
		ServerConfig serverConfig = new ServerConfig();
		serverConfig.restoreXml(parser);
		if ((port != -1) && (port != 5432)) {
			serverConfig.addKey("port", Integer.toString(port));
		}
		if (localAuthentication == AUTHENTICATION_NONE) {
			serverConfig.setLocalAuthentication(TRUST_METHOD, null);
		}
		else if (localAuthentication == AUTHENTICATION_PASSWORD) {
			serverConfig.setLocalAuthentication(PASSWORD_METHOD, null);
		}
		else if (localAuthentication == AUTHENTICATION_PKI) {
			serverConfig.setLocalAuthentication(CERTIFICATE_METHOD, CERTIFICATE_OPTIONS);
		}
		else {
			throw new IOException("Unsupported local authentication type");
		}
		if (hostAuthentication == AUTHENTICATION_NONE) {
			serverConfig.setHostAuthentication(TRUST_METHOD, null);
		}
		else if (hostAuthentication == AUTHENTICATION_PASSWORD) {
			serverConfig.setHostAuthentication(PASSWORD_METHOD, null);
		}
		else if (hostAuthentication == AUTHENTICATION_PKI) {
			serverConfig.setHostAuthentication(CERTIFICATE_METHOD, CERTIFICATE_OPTIONS);
		}
		else {
			throw new IOException("Unsupported host authentication type");
		}
		if (hostAuthentication == AUTHENTICATION_PKI || localAuthentication == AUTHENTICATION_PKI) {
			serverConfig.addKey("ssl_ca_file", '\'' + POSTGRES_ROOTCA + '\'');	// Turn on certificate authority			
		}
		serverConfig.patchConfig(inputFile, outputFile);
		serverConfig.patchConnect(inHbaFile, outHbaFile);
	}

	/**
	 * Set-up the PostgreSQL shared library environment variable for this Ghidra installation
	 */
	private void setupPostgresSharedLibrary() {
		if (Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.MAC_OS_X) {
			loadLibraryVar = "DYLD_LIBRARY_PATH";
		}
		else {
			loadLibraryVar = "LD_LIBRARY_PATH";
		}
		File postgresLibrary = new File(postgresRoot, "lib");
		loadLibraryValue = postgresLibrary.getAbsolutePath();
	}

	/**
	 * Locate the "pg_ctl" executable within the PostgreSQL installation. Unpack the installation
	 * if it is not already.
	 * @throws IOException if postgres folder cannot be determined
	 */
	private void discoverPostgresInstall() throws IOException {
		try {
			postgresRoot = Application.getOSFile(POSTGRES);	// find PostgreSQL build for os
			postgresControl = new File(postgresRoot, "bin/pg_ctl");
			if (!postgresControl.isFile()) {
				throw new IOException("PostgreSQL pg_ctl command not found: " + postgresControl);
			}
			setupPostgresSharedLibrary();
		}
		catch (OSFileNotFoundException e) {
			throw new IOException("PostgreSQL not found and must be built (see " +
				POSTGRES_BUILD_SCRIPT + ", view script for details)");
		}
	}

	/**
	 * Recover the parameter settings from a previously initialized server
	 * @param configFile is main configuration file: port, adminPassword, hostAuthentication
	 * @param hbaFile is the connection file
	 * @throws IOException if the server port is invalid
	 */
	private void recoverConfigurationParameters(File configFile, File hbaFile) throws IOException {
		ServerConfig serverConfig = new ServerConfig();
		serverConfig.addKey("port", "");
		serverConfig.scanConfig(configFile);
		String value = serverConfig.getValue("port");
		int scannedPort = 5432;
		if (value.length() != 0) {
			scannedPort = Integer.parseInt(value);
		}
		if (port != -1 && (scannedPort != port)) {
			throw new IOException("Server is configured to run on port " +
				Integer.toString(scannedPort) + ": Change in " + POSTGRES_CONFIGFILE);
		}
		port = scannedPort;

		serverConfig.scanConnect(hbaFile);
		String localMethod = serverConfig.getLocalAuthentication();
		if (localMethod == null || localMethod.equals(TRUST_METHOD)) {
			localAuthentication = AUTHENTICATION_NONE;
		}
		else if (localMethod.equals(PASSWORD_METHOD)) {
			localAuthentication = AUTHENTICATION_PASSWORD;
		}
		else if (localMethod.equals(CERTIFICATE_METHOD)) {
			localAuthentication = AUTHENTICATION_PKI;
		}
		String hostMethod = serverConfig.getHostAuthentication();
		if (hostMethod == null || hostMethod.equals(TRUST_METHOD)) {
			hostAuthentication = AUTHENTICATION_NONE;
		}
		else if (hostMethod.equals(PASSWORD_METHOD)) {
			hostAuthentication = AUTHENTICATION_PASSWORD;
		}
		else if (hostMethod.equals(CERTIFICATE_METHOD)) {
			hostAuthentication = AUTHENTICATION_PKI;
		}
	}

	/**
	 * Make sure certificate authority needed for pki was provided by user, otherwise throw exception
	 * @throws IOException if the cert file is invalid
	 * @throws GeneralSecurityException if the cert file is not a valid certificate
	 */
	private void checkCertAuthorityFile() throws IOException, GeneralSecurityException {
		if (certAuthorityFile == null) {
			throw new IOException(
				"PKI authentication requested, but certificate authority file not provided");
		}
		if (!certAuthorityFile.isFile()) {
			throw new IOException(
				certAuthorityFile.getAbsolutePath() + " is not a valid certification authority");
		}
		if (!verifyPEMFormat(certAuthorityFile)) {
			throw new GeneralSecurityException(
				"File " + certAuthorityFile.getName() + " does not appear to be a certificate");
		}
	}

	/**
	 * Locate the PostgreSQL configuration and authentication files (postgresql.conf and pg_hba.conf)
	 * and recover the settings pertinent to BSimControl.  If the data directory has not been initialized yet,
	 * run PostgreSQL's init command to perform the initialization and then tailor the configuration
	 * based on BSimControl's command-line options and the Ghidra specific configuration options
	 * @throws IOException if the module data file cannot be retrieved
	 * @throws InterruptedException if the postgres command is interrupted
	 * @throws SAXException if tuneConfig fails
	 * @throws GeneralSecurityException if the cert file cannot be processed
	 */
	private void initializeDataDirectory()
			throws IOException, InterruptedException, SAXException, GeneralSecurityException {
		File configFile = new File(dataDirectory, POSTGRES_CONFIGFILE);
		File hbaFile = new File(dataDirectory, POSTGRES_CONNECTFILE);
		if (configFile.exists()) {
			recoverConfigurationParameters(configFile, hbaFile);
			return;
		}
		File serverConfigFile = Application.getModuleDataFile("serverconfig.xml").getFile(false);
		if (hostAuthentication == AUTHENTICATION_PKI) {
			checkCertAuthorityFile();
			System.out.println("Remote client authentication with PKI certificates");
		}
		else if (hostAuthentication == AUTHENTICATION_PASSWORD) {
			System.out.println("Remote client authentication via password");
		}
		else {
			System.out.println("No client authentication");
		}
		System.out.println("Initializing data directory");
		List<String> command = new ArrayList<String>();
		command.add(postgresControl.getAbsolutePath());
		command.add("init");
		command.add("-o");
		command.add("'--username=" + connectingUserName + '\'');
		if (hostAuthentication == AUTHENTICATION_PASSWORD) {
			establishAdminPassword();
			command.add("-o");
			command.add("'--pwfile=" + passwordFile.getAbsolutePath() + '\'');
		}
		else if (hostAuthentication == AUTHENTICATION_PKI) {
			if (commonName == null) {
				throw new GeneralSecurityException(
					"Distinguished name option (--dn) required for " + connectingUserName);
			}
			checkCertAuthorityFile();
		}
		command.add("-D");
		command.add(dataDirectory.getAbsolutePath());
		int res = runCommand(null, command, loadLibraryVar, loadLibraryValue);
		if (res != 0) {
			throw new IOException("Error initializing postgres database");
		}
		File configCopy = new File(dataDirectory, POSTGRES_CONFIGFILE + ".orig");

		if (hostAuthentication == AUTHENTICATION_PKI || localAuthentication == AUTHENTICATION_PKI) {
			File rootCA = new File(dataDirectory, POSTGRES_ROOTCA);
			FileUtilities.copyFile(certAuthorityFile, rootCA, false, null);
			addCertificateName(connectingUserName);
		}

		// Move the original configuration file
		if (!configFile.renameTo(configCopy)) {
			throw new IOException("Error copying original configuration file");
		}

		File hbaCopy = new File(dataDirectory, POSTGRES_CONNECTFILE + ".orig");

		// Move the original connection file
		if (!hbaFile.renameTo(hbaCopy)) {
			throw new IOException("Error copying original connection file");
		}
		// Patch the configuration
		tuneConfig(configCopy, configFile, hbaCopy, hbaFile, serverConfigFile);
		System.out.println("Generating servers SSL certificate");
		generateSelfSignedCertificate(new File(dataDirectory, "server.crt"),
			new File(dataDirectory, "server.key"));
	}

	/**
	 * Scan the PostgreSQL data directory from the command-line
	 * Make sure the directory exists and establish the File object -dataDirectory-
	 * @param params are the command-line arguments
	 * @param slot is the position to retrieve the data directory argument
	 * @throws IllegalArgumentException if the data directory is invalid
	 * @throws IOException if the canonical file cannot be retrieved
	 */
	private void scanDataDirectory(String[] params, int slot)
			throws IllegalArgumentException, IOException {
		if (params.length <= slot) {
			throw new IllegalArgumentException("Missing data directory");
		}
		dataDirectory = new File(params[slot]);
		if (!dataDirectory.isDirectory()) {
			throw new IllegalArgumentException(
				"Data directory " + dataDirectory.getAbsolutePath() + " does not exist");
		}
		dataDirectory = dataDirectory.getCanonicalFile();
	}

	/**
	 * Scan the username from the command-line
	 * @param params are the command-line arguments
	 * @param slot is the position to retrieve the username argument
	 * @throws IllegalArgumentException if the user name is not in the given params
	 */
	private void scanUsername(String[] params, int slot) throws IllegalArgumentException {
		if (params.length <= slot) {
			throw new IllegalArgumentException("Missing username");
		}
		specifiedUserName = params[slot];
	}

	/**
	 * Scan command-line for a particular privilege level. Administrator privileges are
	 * requested with the exact String "admin", anything is a request for a read-only user 
	 * @param params are the command-line arguments
	 * @param slot is the position to retrieve the user name argument
	 * @throws IllegalArgumentException the privilege parameter is missing
	 */
	private void scanPrivilege(String[] params, int slot) throws IllegalArgumentException {
		if (params.length <= slot) {
			throw new IllegalArgumentException("Missing desired privilege (admin or user)");
		}
		if (params[slot].equals("admin")) {
			adminPrivilegeRequested = true;
		}
		else if (params[slot].equals("user")) {
			adminPrivilegeRequested = false;
		}
		else {
			throw new IllegalArgumentException("Expecting privilege option (admin or user)");
		}
	}

	/**
	 * Start a PostgreSQL server, configured for BSim, on the local host.
	 * If the data directory is already populated, the server process is simply restarted.
	 * If the data directory is empty, a new server configuration is established, and the server is started.
	 * Authentication may be necessary, either via password or certificate, in order to enable
	 * the BSim extension on the server
	 * 
	 * @throws IOException if postgres cannot be started 
	 * @throws InterruptedException if the process fails during the run
	 * @throws SAXException if the data directory cannot be initialized
	 * @throws GeneralSecurityException if the authentication fails
	 */
	private void startCommand()
			throws IOException, InterruptedException, SAXException, GeneralSecurityException {
		discoverPostgresInstall();
		initializeDataDirectory();

		if (localAuthentication == AUTHENTICATION_PKI && certParameter == null) {
			throw new GeneralSecurityException(
				"Path to certificate necessary to start server (--cert /path/to/cert)");
		}
		File logFile = new File(dataDirectory, "logfile");
		List<String> command = new ArrayList<String>();
		command.add(postgresControl.getAbsolutePath());
		command.add("start");
		command.add("-w");
		command.add("-D");
		command.add(dataDirectory.getAbsolutePath());
		command.add("-l");
		command.add(logFile.getAbsolutePath());
		int res = runCommand(null, command, loadLibraryVar, loadLibraryValue);
		if (res != 0) {
			throw new IOException("Could not start postgres server process");
		}

		System.out.println("Server started");
		boolean extensionEnabled = true;
		try {
			enableLSHExtension();
		}
		catch (SQLException e) {
			System.out.println(e.getMessage());
			extensionEnabled = false;
		}
		if (extensionEnabled) {
			System.out.println("BSim extension enabled");
		}
		else {
			forceShutdown = true;			// Force a shutdown, because extension isn't enabled
			stopCommand();
		}
	}

	/**
	 * Stop the running PostgreSQL processes on the local host. No authentication is required to shutdown
	 * the server.  User must be the process owner.
	 * @throws IOException if postgres cannot be discovered or stopped
	 * @throws InterruptedException if the stop command is interrupted
	 */
	private void stopCommand() throws IOException, InterruptedException {
		discoverPostgresInstall();
		List<String> command = new ArrayList<String>();
		command.add(postgresControl.getAbsolutePath());
		command.add("stop");
		command.add("-D");
		command.add(dataDirectory.getAbsolutePath());
		if (forceShutdown) {
			command.add("-m");
			command.add("fast");		// Does not wait for clients to disconnect, all active transactions rolled back
		}
		int res = runCommand(null, command, loadLibraryVar, loadLibraryValue);
		if (res != 0) {
			throw new IOException("Error shutting down postgres server process");
		}
		System.out.println("Server shutdown complete");
	}

	/**
	 * Trigger a server running on the local host to rescan its identity file to pickup
	 * any changes to the user mapping
	 * @throws IOException if creating a new user fails
	 * @throws InterruptedException if the reload command is interrupted
	 */
	private void reloadIdent() throws IOException, InterruptedException {
		List<String> command = new ArrayList<String>();
		command.add(postgresControl.getAbsolutePath());
		command.add("reload");
		command.add("-D");
		command.add(dataDirectory.getAbsolutePath());
		command.add("-s");
		int res = runCommand(null, command, loadLibraryVar, loadLibraryValue);
		if (res != 0) {
			throw new IOException("Error creating new user");
		}
	}

	/**
	 * Update the PostgreSQL identity map (pg_ident.conf) adding a map from
	 * the currently active -commonName- to -username-
	 * @param username the user name to add
	 * @throws IOException if the postgres ident file is invalid
	 */
	private void addCertificateName(String username) throws IOException {
		File identFile = new File(dataDirectory, POSTGRES_IDENTFILE);
		File copyFile = new File(dataDirectory, POSTGRES_IDENTFILE + ".copy");
		if (!identFile.isFile()) {
			throw new IOException("Missing ident file: " + identFile.getAbsolutePath());
		}
		ServerConfig.patchIdent(identFile, copyFile, POSTGRES_MAP_IDENTIFIER, commonName, username,
			true);
		FileUtilities.copyFile(copyFile, identFile, false, null);
	}

	/**
	 * Add a new user to the currently running server on the local host.
	 * A connection is established, using the local interface, and the "CREATE ROLE" command
	 * is executed. If the server is configured to require certificate authentication on
	 * remote connections, the user must have provided a distinguished name associated with
	 * the certificate, which is then mapped to the new username. 
	 * @throws GeneralSecurityException if using PKI and no Distinguished Name is found
	 * @throws Exception if there's a problem initializing the Application of discovering the Postgres installation
	 */
	private void addUserCommand() throws GeneralSecurityException, Exception {
		discoverPostgresInstall();
		initializeDataDirectory();			// Needed to pick up authentication settings
		if (hostAuthentication == AUTHENTICATION_PKI) {
			if (distinguishedName == null || commonName == null) {
				throw new GeneralSecurityException("Distinguished name required (dn=\"..\")");
			}
		}
		StringBuilder resultMessage = new StringBuilder();
		resultMessage.append("Added user: ");
		resultMessage.append(specifiedUserName);
		boolean resetPassword = (hostAuthentication == AUTHENTICATION_PASSWORD);

		adminPasswordData = null;

		localConnection = getOrCreateLocalConnection();

		StringBuilder buffer = new StringBuilder();
		buffer.append("CREATE ROLE \"");
		buffer.append(specifiedUserName);
		buffer.append("\" WITH LOGIN");

		try (Statement st = localConnection.createStatement()) {
			st.executeUpdate(buffer.toString());
		}
		catch (SQLException err) {
			if (!err.getMessage().contains("already exists")) {		// Suppress already exists error message
				throw err;
			}
			resultMessage.append(" (already present)");				// Record that user is already added
			resetPassword = false;
		}
		finally {
			if (resetPassword) {
				resetPassword(localConnection, specifiedUserName);
			}
			localConnection.close();
		}

		if (hostAuthentication == AUTHENTICATION_PKI) {
			addCertificateName(specifiedUserName);
			reloadIdent();
			System.out.println("Linking distinguished name to user: " + specifiedUserName);
			return;
		}
		System.out.println(resultMessage.toString());
	}

	/**
	 * Returns a connection to a local Postgres database. If a connection has not yet
	 * been established, it creates one.
	 * 
	 * @return the database connection
	 * @throws Exception  if there's an error creating the connection
	 */
	private Connection getOrCreateLocalConnection() throws Exception {

		try {
			if (localConnection == null || localConnection.isClosed()) {
				localConnection = createLocalConnection();
			}
		}
		catch (SQLException | IOException e) {
			Msg.error(this, "Error creating connection to Postgres database", e);
			throw e;
		}
		return localConnection;
	}

	/**
	 * On a server running on the local host, remove the specified username.
	 * A local connection is created and the "DROP ROLE" command is run. If
	 * the server uses PKI authentication, the PostgreSQL identity file is
	 * scanned, and any mapping that matches dropped name is also removed. 
	 * @throws Exception 
	 */
	private void dropUserCommand() throws Exception {
		discoverPostgresInstall();
		initializeDataDirectory();
		boolean userDoesNotExist = false;
		localConnection = getOrCreateLocalConnection();
		StringBuilder buffer = new StringBuilder();
		buffer.append("DROP ROLE \"");
		buffer.append(specifiedUserName);
		buffer.append('\"');

		try (Statement st = localConnection.createStatement()) {
			st.executeUpdate(buffer.toString());
		}
		catch (SQLException err) {
			if (!err.getMessage().contains("does not exist")) {
				throw err;
			}
			userDoesNotExist = true;
		}
		finally {
			localConnection.close();
		}

		if (hostAuthentication == AUTHENTICATION_PKI || localAuthentication == AUTHENTICATION_PKI) {
			File identFile = new File(dataDirectory, POSTGRES_IDENTFILE);
			File copyFile = new File(dataDirectory, POSTGRES_IDENTFILE + ".copy");
			if (!identFile.isFile()) {
				throw new IOException("Missing ident file: " + identFile.getAbsolutePath());
			}
			ServerConfig.patchIdent(identFile, copyFile, POSTGRES_MAP_IDENTIFIER, commonName,
				specifiedUserName, false);
			FileUtilities.copyFile(copyFile, identFile, false, null);
			reloadIdent();
		}
		if (userDoesNotExist) {
			System.out.println("User " + specifiedUserName + " does not exist");
		}
		else {
			System.out.println("Removed user: " + specifiedUserName);
		}
	}

	/**
	 * The data directory for a server (which must not be running) is reconfigured
	 * with new local and remote authentication options, and the port may be reconfigured as well.
	 * Database records are unaltered.
	 * The user submits "auth=..", "localAuth=..", and "port=.." options on the command line:
	 * among those submitted, any option that doesn't match the current configuration is changed.
	 * @throws IOException if the postgres installation cannot be found
	 * @throws InterruptedException if the postgres installation cannot be found
	 * @throws SAXException if the {@link #tuneConfig(File, File, File, File, File)} call fails
	 * @throws GeneralSecurityException if there is no Distinguished Name supplied
	 */
	private void changeAuthCommand()
			throws IOException, InterruptedException, SAXException, GeneralSecurityException {
		discoverPostgresInstall();
		File configFile = new File(dataDirectory, POSTGRES_CONFIGFILE);
		File hbaFile = new File(dataDirectory, POSTGRES_CONNECTFILE);
		if (!configFile.exists()) {
			throw new IOException("Data directory not initialized: run \"bsim_ctl start\" first");
		}
		int requestedLocalAuth = localAuthentication;
		int requestedHostAuth = hostAuthentication;
		int requestedPort = port;
		port = -1;
		recoverConfigurationParameters(configFile, hbaFile);
		if (isServerRunning()) {
			throw new IOException("Cannot modify settings on running server");
		}
		if ((!authConfigPresent || (requestedHostAuth == hostAuthentication &&
			requestedLocalAuth == localAuthentication)) &&
			(requestedPort == -1 || requestedPort == port)) {
			System.out.println("No changes to make");
			return;
		}

		File serverConfigFile = Application.getModuleDataFile("serverconfig.xml").getFile(false);
		File configCopy = new File(dataDirectory, POSTGRES_CONFIGFILE + ".orig");
		if (!configCopy.exists()) {
			throw new IOException(
				"Original configuration file not present: " + configCopy.getAbsolutePath());
		}
		File hbaCopy = new File(dataDirectory, POSTGRES_CONNECTFILE + ".orig");
		if (!hbaCopy.exists()) {
			throw new IOException(
				"Original connection file not present: " + hbaCopy.getAbsolutePath());
		}
		if (requestedPort != -1 && requestedPort != port) {
			port = requestedPort;
			System.out.println("Server will now listen on port " + Integer.toString(port));
		}
		boolean newRemotePki = false;		// Are we newly enabling remote pki
		boolean newLocalPki = false;		// Are we newly enabling local pki

		if (authConfigPresent && requestedLocalAuth != localAuthentication) {
			localAuthentication = requestedLocalAuth;
			System.out.print("New local authentication: ");
			if (localAuthentication == AUTHENTICATION_PASSWORD) {
				System.out.println("password");
			}
			else if (localAuthentication == AUTHENTICATION_PKI) {
				System.out.println("pki");
				newLocalPki = true;
				if (commonName == null) {
					throw new GeneralSecurityException("Distinguished name required (dn=\"..\")");
				}
			}
			else if (localAuthentication == AUTHENTICATION_NONE) {
				System.out.println("none");
			}
		}
		if (authConfigPresent && requestedHostAuth != hostAuthentication) {
			hostAuthentication = requestedHostAuth;
			System.out.print("New host authentication: ");
			if (hostAuthentication == AUTHENTICATION_NONE) {
				System.out.println("none");
			}
			else if (hostAuthentication == AUTHENTICATION_PASSWORD) {
				System.out.println("password");
			}
			else if (hostAuthentication == AUTHENTICATION_PKI) {
				System.out.println("pki");
				newRemotePki = true;
			}
			else {
				System.out.println("unknown");
			}
		}
		if (newLocalPki || newRemotePki) {
			checkCertAuthorityFile();
			File rootCA = new File(dataDirectory, POSTGRES_ROOTCA);
			FileUtilities.copyFile(certAuthorityFile, rootCA, false, null);
		}
		if (newLocalPki) {
			addCertificateName(connectingUserName);
		}

		tuneConfig(configCopy, configFile, hbaCopy, hbaFile, serverConfigFile);
	}

	/**
	 * Reset the password for -username- to DEFAULT_PASSWORD
	 * @param pdb is the connection over which to issue the command
	 * @param username is the user name to reset
	 * @throws SQLException if the sql query fails
	 */
	private void resetPassword(Connection pdb, String username) throws SQLException {
		StringBuilder buffer = new StringBuilder();
		buffer.append("ALTER ROLE \"");
		buffer.append(username);
		buffer.append("\" WITH PASSWORD '");
		buffer.append(DEFAULT_PASSWORD);
		buffer.append('\'');
		executeSQLStatement(pdb, buffer.toString());
	}

	/**
	 * Reset the PostgreSQL password associated with the specified user name on the local server.
	 * The user submitting this request on behalf of the specified user may need to
	 * enter their own password or passphrase to authenticate with the server.
	 * @throws Exception if there's a problem getting a connection to the Postgres database
	 */
	private void passwordCommand() throws Exception {
		localConnection = getOrCreateLocalConnection();
		System.out.println("Resetting password for user: " + specifiedUserName);

		try {
			resetPassword(localConnection, specifiedUserName);
			System.out.println("Password reset complete");
		}
		finally {
			localConnection.close();
		}
	}

	private void changePrivilegeCommand() throws Exception {
		localConnection = getOrCreateLocalConnection();
		try {
			if (adminPrivilegeRequested) {
				System.out.println("Granting admin privileges to " + specifiedUserName);
				executeSQLStatement(localConnection,
					"ALTER ROLE " + specifiedUserName + " SUPERUSER CREATEROLE CREATEDB");
			}
			else {
				System.out.println("Revoking admin privileges from " + specifiedUserName);
				executeSQLStatement(localConnection,
					"ALTER ROLE " + specifiedUserName + " NOSUPERUSER NOCREATEROLE NOCREATEDB");
			}
		}
		finally {
			localConnection.close();
		}
	}

	/**
	 * Runs the command specified by the given set of params.
	 * 
	 * @param params the parameters specifying the command
	 * @throws IllegalArgumentException if invalid params have been specified
	 * @throws Exception if there's an error during the operation
	 * @throws CancelledException if processing is cancelled
	 */
	public void run(String[] params) throws Exception {
		try {
			clearParams();

			String command = readCommandLine(params);

			initializeApplication();

			switch (command) {
				case COMMAND_START:
					startCommand();
					break;
				case COMMAND_STOP:
					stopCommand();
					break;
				case COMMAND_ADDUSER:
					addUserCommand();
					break;
				case COMMAND_DROPUSER:
					dropUserCommand();
					break;
				case COMMAND_CHANGEAUTH:
					changeAuthCommand();
					break;
				case COMMAND_RESET_PASSWORD:
					passwordCommand();
					break;
				case COMMAND_CHANGE_PRIVILEGE:
					changePrivilegeCommand();
					break;
				default:
					throw new IllegalArgumentException("Unknown command: " + command);
			}
		}
		finally {
			try {
				cleanupPasswordData();
			}
			catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	private static void printUsage() {
		//@formatter:off
		System.err.println("\n" + 
			"USAGE: bsim_ctl [command]  required-args... [OPTIONS...}\n\n" +
			"                start      </datadir-path> [--auth|-a pki|password|trust] [--noLocalAuth] [--cafile \"</cacert-path>\"] [--dn \"<distinguished-name>\"]\n" +
			"                stop       </datadir-path> [--force]\n" +
			"                adduser    </datadir-path> <username> [--dn \"<distinguished-name>\"]\n" +
			"                dropuser   </datadir-path> <username>\n" +
			"                changeauth </datadir-path> [--auth|-a pki|password|trust] [--noLocalAuth] [--cafile \"</cacert-path>\"]\n" +
			"                resetpassword   <username>\n" +
			"                changeprivilege <username> admin|user\n" + 
			"\n" + 
			"Global options:\n" +
			"   --port|-p <portnum>\n" + 
			"   --user|-u <username>\n" + 
			"   --cert </certfile-path>\n" +
			"\n" +
			"NOTE: Options with values may also be specified using the form: --option=value\n");
		//@formatter:on
	}

	@Override
	public void launch(GhidraApplicationLayout ghidraLayout, String[] params) {
		if (params.length <= 1) {
			printUsage();
			return;
		}
		layout = ghidraLayout;		// Save layout for when we need to initialize application
		boolean success = false;
		try {
			run(params);
			success = true;
		}
		catch (SAXException e1) {
			System.err.println("Error in server configuation data");
			System.err.println(e1.getMessage());
		}
		catch (InterruptedException e) {
			System.err.println("Command was interrupted");
			System.err.println(e.getMessage());
		}
		catch (SQLException e) {
			System.err.println("Error connecting to the database");
			System.err.println(e.getMessage());
		}
		catch (GeneralSecurityException e) {
			System.err.println("Error establishing server certificate");
			System.err.println(e.getMessage());
		}
		catch (IllegalArgumentException e) {
			System.err.println("Error in command line arguments");
			System.err.println(e.getMessage());
		}
		catch (Exception e) {
			System.err.println("Unexpected error");
			e.printStackTrace();
		}

		if (!success) {
			System.exit(1);
		}
	}

	/**
	 * Initialize enough of Ghidra to allow navigation of configuration files and to allow SSL connections
	 * @throws IOException if the headless authenticator cannot be initialized
	 * @throws ClassNotFoundException if the postgres driver class cannot be found
	 */
	private void initializeApplication() throws IOException, ClassNotFoundException {
		if (layout != null) {
			// Initialize application environment consistent with bsim command
			BSimLaunchable.initializeApplication(layout, 0, connectingUserName, certParameter);
		}
	}

	/**
	 * Class for processing standard output or standard error for processes invoked by BSimControl
	 * The streams can be optionally suppressed or dumped to System.out
	 */
	private class IOThread extends Thread {
		private BufferedReader shellOutput;		// Reader for the particular output stream
		private boolean suppressOutput;			// If false, shell output is printed on the console

		public IOThread(InputStream input, boolean suppressOut) {
			shellOutput = new BufferedReader(new InputStreamReader(input));
			suppressOutput = suppressOut;
		}

		@Override
		public void run() {
			String line = null;
			try {
				while ((line = shellOutput.readLine()) != null) {
					if (!suppressOutput) {
						System.out.println(line);
					}
				}
			}
			catch (Exception e) {
				// DO NOT USE LOGGING HERE (class loader)
				System.err.println("Unexpected Exception: " + e.getMessage());
				e.printStackTrace(System.err);
			}
		}
	}

}
