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
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.*;
import java.util.*;
import java.util.Date;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.net.ssl.X509ExtendedKeyManager;

import org.apache.commons.lang3.StringUtils;
import org.postgresql.core.Utils;
import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;

import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.features.bsim.query.ingest.BSimLaunchable;
import ghidra.framework.*;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.client.HeadlessClientAuthenticator;
import ghidra.net.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.NonThreadedXmlPullParserImpl;
import ghidra.xml.XmlPullParser;
import utilities.util.FileUtilities;

public class BSimControlLaunchable implements GhidraLaunchable {

	// bsim_ctl commands
	public final static String COMMAND_START = "start";
	public final static String COMMAND_STOP = "stop";
	public final static String COMMAND_STATUS = "status";
	public final static String COMMAND_RESET_PASSWORD = "resetpassword";
	public final static String COMMAND_CHANGE_PRIVILEGE = "changeprivilege";
	public final static String COMMAND_ADDUSER = "adduser";
	public final static String COMMAND_DROPUSER = "dropuser";
	public final static String COMMAND_LISTUSERS = "listusers";
	public final static String COMMAND_INIT = "init";
	public final static String COMMAND_CONFIGURE = "configure";
	public final static String COMMAND_RESTART = "restart";
	public final static String COMMAND_INSTALL_SERVICE = "install-service";
	public final static String COMMAND_UNINSTALL_SERVICE = "uninstall-service";

	// Options that require a value argument
	public static final String CAFILE_OPTION = "--cafile";
	public static final String AUTH_OPTION = "--auth";
	public static final String DN_OPTION = "--dn";
	public static final String KEYSTORE_OPTION = "--keystore";
	public static final String OS_USER_OPTION = "--os-user";
	public static final String PORT_OPTION = "--port";

	// Global options that require a value argument
	public static final String USER_OPTION = "--user";
	public static final String CERT_OPTION = "--cert";
	public static final String VERBOSE_OPTION = "--verbose";

	// Define set of options that require a second value argument
	private static final Set<String> VALUE_OPTIONS =
		Set.of(USER_OPTION, CERT_OPTION, CAFILE_OPTION, AUTH_OPTION, DN_OPTION,
			KEYSTORE_OPTION, OS_USER_OPTION, PORT_OPTION);

	private static final Set<String> GLOBAL_OPTIONS = 
		Set.of(USER_OPTION, CERT_OPTION, VERBOSE_OPTION);

	// Boolean options
	public static final String NO_LOCAL_AUTH_OPTION = "--noLocalAuth";
	public static final String FORCE_OPTION = "--force";

	private static final Map<String, String> SHORTCUT_OPTION_MAP = new HashMap<>();
	static {
		// NOTE: --cert intentionally has no shortcut (-c is used by --config within BSimLaunchable)
		SHORTCUT_OPTION_MAP.put("-a", AUTH_OPTION);
		SHORTCUT_OPTION_MAP.put("-ca", CAFILE_OPTION);
		SHORTCUT_OPTION_MAP.put("-dn", DN_OPTION);
		SHORTCUT_OPTION_MAP.put("-f", FORCE_OPTION);
		SHORTCUT_OPTION_MAP.put("-k", KEYSTORE_OPTION);
		SHORTCUT_OPTION_MAP.put("-p", PORT_OPTION);
		SHORTCUT_OPTION_MAP.put("-u", USER_OPTION);
		SHORTCUT_OPTION_MAP.put("-v", VERBOSE_OPTION);
	}

	//@formatter:off
	// Populate ALLOWED_OPTION_MAP for each command
	private static final Set<String> INIT_OPTIONS =
			Set.of(AUTH_OPTION, NO_LOCAL_AUTH_OPTION, CAFILE_OPTION, KEYSTORE_OPTION,
					PORT_OPTION, OS_USER_OPTION);
	private static final Set<String> CONFIGURE_OPTIONS =
			Set.of(AUTH_OPTION, NO_LOCAL_AUTH_OPTION, CAFILE_OPTION, KEYSTORE_OPTION,
				PORT_OPTION);
	private static final Set<String> START_OPTIONS = Set.of();
	private static final Set<String> STOP_OPTIONS =	Set.of(FORCE_OPTION);
	private static final Set<String> RESTART_OPTIONS = Set.of(FORCE_OPTION);
	private static final Set<String> STATUS_OPTIONS = Set.of();
	private static final Set<String> INSTALL_SERVICE_OPTIONS = Set.of();
	private static final Set<String> UNINSTALL_SERVICE_OPTIONS = Set.of();
	private static final Set<String> RESET_PASSWORD_OPTIONS = Set.of(PORT_OPTION);
	private static final Set<String> CHANGE_PRIVILEGE_OPTIONS = Set.of(PORT_OPTION);
	private static final Set<String> ADDUSER_OPTIONS = Set.of(DN_OPTION);
	private static final Set<String> DROPUSER_OPTIONS = Set.of();
	private static final Set<String> LISTUSERS_OPTIONS = Set.of();

	//@formatter:on
	private static final Map<String, Set<String>> ALLOWED_OPTION_MAP = new HashMap<>();
	static {
		ALLOWED_OPTION_MAP.put(COMMAND_INIT, INIT_OPTIONS);
		ALLOWED_OPTION_MAP.put(COMMAND_CONFIGURE, CONFIGURE_OPTIONS);
		ALLOWED_OPTION_MAP.put(COMMAND_START, START_OPTIONS);
		ALLOWED_OPTION_MAP.put(COMMAND_STOP, STOP_OPTIONS);
		ALLOWED_OPTION_MAP.put(COMMAND_RESTART, RESTART_OPTIONS);
		ALLOWED_OPTION_MAP.put(COMMAND_STATUS, STATUS_OPTIONS);
		ALLOWED_OPTION_MAP.put(COMMAND_INSTALL_SERVICE, INSTALL_SERVICE_OPTIONS);
		ALLOWED_OPTION_MAP.put(COMMAND_UNINSTALL_SERVICE, UNINSTALL_SERVICE_OPTIONS);
		ALLOWED_OPTION_MAP.put(COMMAND_RESET_PASSWORD, RESET_PASSWORD_OPTIONS);
		ALLOWED_OPTION_MAP.put(COMMAND_CHANGE_PRIVILEGE, CHANGE_PRIVILEGE_OPTIONS);
		ALLOWED_OPTION_MAP.put(COMMAND_ADDUSER, ADDUSER_OPTIONS);
		ALLOWED_OPTION_MAP.put(COMMAND_DROPUSER, DROPUSER_OPTIONS);
		ALLOWED_OPTION_MAP.put(COMMAND_LISTUSERS, LISTUSERS_OPTIONS);
	}

	private final static String POSTGRES = "postgresql";
	private final static String POSTGRES_BUILD_SCRIPT =
		"Ghidra/Features/BSim/support/make-postgres.sh";
	private final static String POSTGRES_CONFIGFILE = "postgresql.conf";
	private final static String POSTGRES_CONNECTFILE = "pg_hba.conf";
	private final static String POSTGRES_IDENTFILE = "pg_ident.conf";
	private static final String POSTGRES_CERTFILE = "server.crt"; // always required
	private static final String POSTGRES_KEYFILE = "server.key"; // always required
	private final static String POSTGRES_ROOTCA = "root.crt"; // only needed for PKI authentication mode
	private final static String SERVICE_MARKER = "bsim-service.properties";
	private final static String SYSTEMD_SYSTEM_DIR = "/etc/systemd/system";

	// BSim deployment configuration record: holds only those settings which cannot be recovered
	// from the PostgreSQL configuration files (see recoverConfigurationParameters)
	private final static String BSIM_CONFIG_FILE = "bsim-config.properties";
	private final static int BSIM_CONFIG_VERSION = 1;
// TODO: add GHIDRA_VERSION to config file (version used to update config)
	private final static String PROP_CONFIG_VERSION = "configVersion";
	private final static String PROP_AUTH_MODE = "authMode";

	private final static int MAX_DN_ENTRY_LENGTH = 256;
	private final static String PASSWORD_METHOD = "scram-sha-256";
	private final static String TRUST_METHOD = "trust";
	private final static String CERTIFICATE_METHOD = "cert";
	private final static String CERTIFICATE_OPTIONS = "map=mymap clientcert=verify-full";

	// The name which the PostgreSQL server matches against its identity map (pg_ident.conf) when a
	// client presents a certificate.  Appending clientname=DN matches the certificate's full
	// distinguished name (PostgreSQL 12 and later), rendered in RFC 2253 form; its absence leaves
	// the PostgreSQL default of matching only the common name, which is what legacy BSim
	// deployments were established with (see recoverCertificateNameMode).
	//
	// NOTE: PostgreSQL permits this option on "hostssl" entries ONLY - it rejects the whole
	// connection file otherwise, leaving the server unable to start.  Every entry BSim generates is
	// hostssl (the UNIX-socket "local" entry of serverconfig.xml is commented out, so "local" here
	// means loopback TLS), which must remain the case for the entries written by tuneConfig.
	private final static String CLIENTNAME_OPTION = "clientname";
	private final static String CLIENTNAME_DN_OPTION = CLIENTNAME_OPTION + "=DN";
	private final static String POSTGRES_MAP_IDENTIFIER = "mymap";
	
	// Client certificate key types considered when recovering the admin user's PKI identity
	private final static String[] CLIENT_KEY_TYPES = { PKIUtils.RSA_TYPE, "EC" };
	private final static String DEFAULT_PASSWORD = "changeme";
	
	private final static int AUTHENTICATION_NONE = 0;
	private final static int AUTHENTICATION_PASSWORD = 1;
	private final static int AUTHENTICATION_PKI = 2;

	private GhidraApplicationLayout layout;

	private boolean verbose;			// If enable, output command execution details to console
	private File dataDirectory;			// Directory containing postgres datafiles
	private File postgresRoot;			// Directory containing postgres software
	private File postgresControl;		// "pg_ctl" utility within postgres software
	private File certAuthorityFile;		// Certificate authority file provided by the user (--cafile)
	private File activeCertAuthorityFile;	// CA file loaded/validated (--cafile or installed root.crt)
	private List<X509Certificate> certAuthorities;	// Validated CAs from activeCertAuthorityFile
	private String certParameter;		// Path to certificate provided by user
	private File keystoreFile;			// Server certificate key store provided by user (--keystore)
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
	private boolean authOptionPresent;	// True if the [--auth] option is present
	private boolean remoteAccessConfigured;	// True if recovered config binds a non-loopback interface
	private boolean useDistinguishedName;	// True if the PKI identity map registers the full DN, false for CN only
	private File passwordFile;			// File containing newly established password
	private char[] adminPasswordData;	// Password data being sent to postgres server for authentication

	// Principal data when adding a user for PKI authentication mode
	private String distinguishedName;   // Certificate Distinguished Name (DN) of user
	private String commonName;			// Common Name (CN) of user extracted from DN (legacy only)

	// Deployment identity / privilege model (Linux)
	private String osUserOption;		// --os-user value (OS account; init only, root only)
	private String ownerName;			// OWNER: OS account owning data directory & postgres process
	private String ownerGroup;			// OWNER's primary group
	private String invokingUserName;	// OS account invoking bsim_ctl (id -un)
	private Boolean runningAsRoot;		// cached root check (id -u == 0)
	private boolean dropPrivileges;		// true when root must run postgres tools/files as OWNER

	// Database connection that can be persisted so we don't need to recreate one
	// for every call.
	private Connection localConnection;

	/**
	 * Constructor for launching from the console
	 */
	public BSimControlLaunchable() {
	}

	private void clearParams() {
		verbose = false;
		dataDirectory = null;
		postgresRoot = null;
		postgresControl = null;
		certAuthorityFile = null;
		activeCertAuthorityFile = null;
		certAuthorities = null;
		certParameter = null;
		keystoreFile = null;
		distinguishedName = null;
		commonName = null;
		connectingUserName = null;
		specifiedUserName = null;
		adminPrivilegeRequested = false;
		forceShutdown = false;
		loadLibraryVar = null;
		loadLibraryValue = null;
		port = -1;
		localAuthentication = AUTHENTICATION_PASSWORD;
		hostAuthentication = AUTHENTICATION_PASSWORD;
		authConfigPresent = false;
		authOptionPresent = false;
		remoteAccessConfigured = false;
		useDistinguishedName = true;	// new deployments register the full DN (see recoverCertificateNameMode)
		passwordFile = null;
		adminPasswordData = null;
		osUserOption = null;
		ownerName = null;
		ownerGroup = null;
		invokingUserName = null;
		runningAsRoot = null;
		dropPrivileges = false;
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
		
			case COMMAND_INIT:
				scanDataDirectory(params, slot++, false);
				break;
				
			case COMMAND_CONFIGURE:
			case COMMAND_START:
			case COMMAND_STOP:
			case COMMAND_RESTART:
			case COMMAND_STATUS:
			case COMMAND_INSTALL_SERVICE:
			case COMMAND_UNINSTALL_SERVICE:
			case COMMAND_LISTUSERS:
				scanDataDirectory(params, slot++, true);
				break;
				
			case COMMAND_ADDUSER:
				scanDataDirectory(params, slot++, true);
				scanUsername(params, slot++);
				break;
				
			case COMMAND_DROPUSER:
				scanDataDirectory(params, slot++, true);
				scanUsername(params, slot++);
				break;
				
			case COMMAND_RESET_PASSWORD:
				scanUsername(params, slot++);
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
					port = parsePortValue(optionName, value, BSimServerInfo.DEFAULT_POSTGRES_PORT);
					break;
				case USER_OPTION:
					connectingUserName = value;
					break;
				case CERT_OPTION:
					certParameter = value;
					break;
				case KEYSTORE_OPTION:
					keystoreFile = new File(value);
					break;
				case OS_USER_OPTION:
					osUserOption = value;
					break;
				case CAFILE_OPTION:
					certAuthorityFile = new File(value);
					break;
				case AUTH_OPTION:
					authConfigPresent = true;
					authOptionPresent = true;
					// --auth establishes the remote (host) authentication mode; local connections
					// use the same mode unless downgraded by --noLocalAuth below
					hostAuthentication = parseAuthMode(value);
					localAuthentication = hostAuthentication;
					break;
				case DN_OPTION:
					distinguishedName = value;
					validateDistinguishedName(); // also assigns commonName if present
					break;
				case NO_LOCAL_AUTH_OPTION:
					sawNoLocalAuth = true;
					break;
				case FORCE_OPTION:
					forceShutdown = true;
					break;
				case VERBOSE_OPTION:
					verbose = true;
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

	private int parsePortValue(String option, String optionValue, int defaultValue) {
		try {
			int value = Integer.valueOf(optionValue);
			if (value <= 0 || value > 65535) {
				System.out.println("Invalid " + option + " value ignored - using default: " + defaultValue);
				value = defaultValue;
			}
			return value;
		}
		catch (NumberFormatException e) {
			throw new IllegalArgumentException("Invalid integer value specified for " + option);
		}
	}

	/**
	 * Translate an authentication mode name, as specified with the {@code --auth} option or as
	 * recorded within the BSim configuration record, to its corresponding authentication constant.
	 * @param mode the authentication mode name (pki, password, trust or none)
	 * @return AUTHENTICATION_PKI, AUTHENTICATION_PASSWORD or AUTHENTICATION_NONE
	 * @throws IllegalArgumentException if the mode name is not recognized
	 */
	private static int parseAuthMode(String mode) throws IllegalArgumentException {
		switch (mode.trim()) {
			case "pki":
				return AUTHENTICATION_PKI;
			case "password":
				return AUTHENTICATION_PASSWORD;
			case "trust":
			case "none":
				return AUTHENTICATION_NONE;
			default:
				throw new IllegalArgumentException("Unknown authentication method: " + mode +
					" : options are trust, password or pki");
		}
	}

	/**
	 * Translate an authentication constant to its {@code --auth} option mode name.
	 * @param authentication AUTHENTICATION_PKI, AUTHENTICATION_PASSWORD or AUTHENTICATION_NONE
	 * @return the corresponding authentication mode name
	 */
	private static String authModeName(int authentication) {
		switch (authentication) {
			case AUTHENTICATION_PKI:
				return "pki";
			case AUTHENTICATION_PASSWORD:
				return "password";
			case AUTHENTICATION_NONE:
				return "trust";
			default:
				throw new AssertionError("Unsupported authentication type: " + authentication);
		}
	}

	/**
	 * @return the {@value #CERTIFICATE_METHOD} method options for {@value #POSTGRES_CONNECTFILE},
	 *   which request matching of the full distinguished name unless the deployment registers only
	 *   the common name (see {@link #recoverCertificateNameMode(ServerConfig)})
	 */
	private String certificateMethodOptions() {
		return useDistinguishedName ? CERTIFICATE_OPTIONS + ' ' + CLIENTNAME_DN_OPTION
				: CERTIFICATE_OPTIONS;
	}

	/**
	 * @return the certificate name which the server will match against its identity map for the
	 *   user whose PKI identity is currently established (see {@link #establishPkiIdentity()} and
	 *   the {@code --dn} option): their full distinguished name, or only its common name for a
	 *   deployment which registers that instead
	 */
	private String certificateSystemName() {
		return useDistinguishedName ? distinguishedName : commonName;
	}

	/**
	 * @return a description of the certificate name registered within the deployment's identity
	 *   map, for reporting purposes
	 */
	private String certificateNameLabel() {
		return useDistinguishedName ? "Distinguished Name (DN)" : "Common Name (CN)";
	}

	/**
	 * Determine whether the deployment's identity map ({@value #POSTGRES_IDENTFILE}) registers each
	 * user's full distinguished name or only their common name, which is decided by the
	 * {@value #CLIENTNAME_OPTION} option of the {@value #CERTIFICATE_METHOD} entry within
	 * {@value #POSTGRES_CONNECTFILE}.
	 * <p>
	 * That entry is authoritative because it is what the server itself applies when matching a
	 * presented certificate.  Legacy deployments were established with the PostgreSQL default of
	 * matching only the common name and must retain it: their users are already registered that
	 * way, and the mappings cannot be re-derived here since the certificates they were taken from
	 * are held by those users rather than by the administrator.
	 * @param serverConfig the recovered connection file configuration
	 * @return true if the full distinguished name is registered, false for the common name only
	 */
	private boolean recoverCertificateNameMode(ServerConfig serverConfig) {
		if (CERTIFICATE_METHOD.equals(serverConfig.getLocalAuthentication())) {
			return isClientNameDN(serverConfig.getLocalAuthenticationOptions());
		}
		if (CERTIFICATE_METHOD.equals(serverConfig.getHostAuthentication())) {
			return isClientNameDN(serverConfig.getHostAuthenticationOptions());
		}
		// There is no certificate entry to recover from: either pki is not configured at all, or it
		// is configured only for remote connections which are currently disabled (no entry is
		// retained for those).  In neither case is the server presently matching any user's
		// certificate, so the new-deployment default applies.
		return true;
	}

	/**
	 * Determine whether a set of {@value #CERTIFICATE_METHOD} method options, as they appear within
	 * {@value #POSTGRES_CONNECTFILE}, select matching of the full distinguished name.
	 * <p>
	 * The value is accepted without regard to case, whereas PostgreSQL requires it upper case.  A
	 * lower case value is therefore taken as the distinguished name having been intended, so that
	 * the intent is preserved (and the option rewritten as PostgreSQL requires it) rather than
	 * quietly reverting a hand-edited entry to common name matching.
	 * @param options the authentication method options, which may be null
	 * @return true if {@value #CLIENTNAME_DN_OPTION} is specified; false for the PostgreSQL default
	 *   of matching only the certificate common name
	 */
	private static boolean isClientNameDN(String options) {
		if (options == null) {
			return false;
		}
		for (String option : options.trim().split("\\s+")) {
			int ix = option.indexOf('=');
			if (ix > 0 && option.substring(0, ix).equalsIgnoreCase(CLIENTNAME_OPTION)) {
				return option.substring(ix + 1).replace("\"", "").equalsIgnoreCase("DN");
			}
		}
		return false;
	}

	/**
	 * Parse the -distinguishedName- String, verifying it is has the correct format for a
	 * X509 certificate distinguished name. Try to extract the common name portion of the
	 * distinguished name and assign it to {@code commonName}, which is left null if the distinguished
	 * name does not specify one.
	 * <p>
	 * The common name is only required by a deployment whose identity map registers it in place of
	 * the full distinguished name (see {@link #recoverCertificateNameMode(ServerConfig)}), which is
	 * not known until the server's configuration has been recovered; it is enforced at the point of
	 * use by {@link #addUserCommand()} rather than here.
	 * @throws IllegalArgumentException if the distinguished name is improperly formatted
	 */
	private void validateDistinguishedName() throws IllegalArgumentException {
		if (distinguishedName == null || distinguishedName.trim().isEmpty()) {
			throw new IllegalArgumentException("--dn input cannot be null or empty.");
		}
		if (distinguishedName.length() > MAX_DN_ENTRY_LENGTH) { // enforce reasonable length limits
			throw new IllegalArgumentException("--dn input exceeds maximum allowed length: " +
				distinguishedName.length() + " > " + MAX_DN_ENTRY_LENGTH);
		}
		commonName = null;
		LdapName ldapName;
		try {
			ldapName = new LdapName(distinguishedName);
			distinguishedName = ldapName.toString(); // ensure DN is properly escaped
			commonName = PKIUtils.getCommonName(distinguishedName);
		}
		catch (InvalidNameException e) {
			throw new IllegalArgumentException("Improperly formatted --dn distinguished name");
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
		int ret = runPostgresCommand(command);
		return (ret == 0);
	}

	private char[] requestPassword(String prompt) {
		try {
			return HeadlessClientAuthenticator.getPassword(null, prompt);
		}
		catch (IOException e) {
			System.err.println("Password entry error: " + e.getMessage());
			System.exit(-1);
			return null;
		}
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
			adminPasswordData = requestPassword("Set " + connectingUserName + " (admin) DB password:");
			if (adminPasswordData == null) {
				throw new IOException("Failed to obtain password");
			}
			char[] repeatPass = requestPassword("Please re-enter DB password:");
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
		char[] pwd = DefaultKeyManagerFactory.DEFAULT_PASSWORD.toCharArray();
		try {
			// Self-signed fallback: restrict SANs to loopback names only (server binds loopback).
			KeyStore keyStore = PKIUtils.createKeyStore(alias, "CN=BSimServer", 365, null,
				false, null, "JKS", List.of("127.0.0.1", "localhost"), pwd);

			PKIUtils.exportX509Certificates(keyStore.getCertificateChain(alias), certFile);
			Key key = keyStore.getKey(alias, pwd);
			writePrivateKeyPem(key, passFile);
		}
		catch (NoSuchAlgorithmException | UnrecoverableEntryException e) {
			throw new KeyStoreException("Failed to generate BSim server certificate", e);
		}
		finally {
			Arrays.fill(pwd, (char) 0);
		}
	}

	/**
	 * Import a server certificate and private key from a user-provided, password-protected
	 * PKCS#12 (or JKS) key store, writing PEM {@link #POSTGRES_CERTFILE} (certificate chain) and
	 * {@link #POSTGRES_KEYFILE} (private key) for PostgreSQL.  The key store password is prompted for on
	 * the console and never accepted on the command line.
	 * @param keyStoreSource the user-provided key store file
	 * @param certFile PEM output for the certificate chain (server.crt)
	 * @param passFile PEM output for the private key (server.key, owner-read-only)
	 * @throws IOException if the key store cannot be read (e.g., wrong password) or a file write fails
	 * @throws GeneralSecurityException if the key store lacks a usable server key/certificate
	 */
	private void importServerCertificate(File keyStoreSource, File certFile, File passFile)
			throws IOException, GeneralSecurityException {
		if (!keyStoreSource.isFile()) {
			throw new IOException("Key store file not found: " + keyStoreSource.getAbsolutePath());
		}
		char[] password =
			requestPassword("Enter key store password (" + keyStoreSource.getName() + "):");
		if (password == null) {
			throw new IOException("Key store password required");
		}
		try {
			KeyStore keyStore =
				PKIUtils.getKeyStoreInstance(keyStoreSource.getAbsolutePath(), password);
			String alias = null;
			Enumeration<String> aliases = keyStore.aliases();
			while (aliases.hasMoreElements()) {
				String a = aliases.nextElement();
				if (keyStore.isKeyEntry(a)) {
					if (alias != null) {
						throw new GeneralSecurityException(
							"Key store contains multiple private key entries; expected exactly one");
					}
					alias = a;
				}
			}
			if (alias == null) {
				throw new GeneralSecurityException(
					"No private key entry found in key store: " + keyStoreSource.getName());
			}
			Certificate[] chain = keyStore.getCertificateChain(alias);
			if (chain == null || chain.length == 0) {
				throw new GeneralSecurityException(
					"No certificate chain found for key store entry: " + alias);
			}
			if (chain[0] instanceof X509Certificate leaf) {
				leaf.checkValidity();		// throws if expired or not yet valid
				List<String> eku = leaf.getExtendedKeyUsage();
				if (eku != null && !eku.contains("1.3.6.1.5.5.7.3.1")) {	// id-kp-serverAuth
					System.out.println(
						"Warning: server certificate is missing 'serverAuth' extended key usage");
				}
				System.out.println(
					"Imported server certificate: " + leaf.getSubjectX500Principal().getName());
			}
			Key key = keyStore.getKey(alias, password);
			if (key == null) {
				throw new GeneralSecurityException(
					"Unable to recover private key from key store entry: " + alias);
			}
			PKIUtils.exportX509Certificates(chain, certFile);
			writePrivateKeyPem(key, passFile);
		}
		finally {
			Arrays.fill(password, (char) 0);
		}
	}

	/**
	 * Write a private key to a file in unencrypted PKCS#8 PEM form and restrict its permissions to
	 * owner-read-only (required by PostgreSQL for {@code ssl_key_file}).
	 * @param key the private key
	 * @param passFile the output file (server.key)
	 * @throws IOException if the file cannot be written
	 */
	private static void writePrivateKeyPem(Key key, File passFile) throws IOException {
		// The key is written unencrypted (PostgreSQL requires this of ssl_key_file), so the file
		// must be owner-only from the moment it exists - restricting it after the key had been
		// written would leave it readable by other local users in between
		try (OutputStream fout = FileUtilities.newOwnerPrivateFileOutputStream(passFile);
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

	/**
	 * Create a local connection to a PostgreSQL server. A full SSL connection is created using
	 * Ghidra's infrastructure.  If the initial connection fails because password authentication
	 * was requested, collect the administrative password from the user, and try the connection again
	 * @return the established connection object.  Respect any command-line "port= .." option.
	 * @throws SQLException if the db connection cannot be established
	 * @throws IOException if the user password cannot be retrieved
	 */
	private Connection createLocalConnection() throws SQLException, IOException {
		Properties properties = new Properties();
		properties.setProperty("sslmode", "require");
		properties.setProperty("sslfactory", "ghidra.net.DefaultSSLSocketFactory");
		properties.setProperty("user", connectingUserName);
		StringBuilder buffer = new StringBuilder();
		buffer.append("jdbc:postgresql://localhost");
		if ((port != -1) && (port != BSimServerInfo.DEFAULT_POSTGRES_PORT)) {	// Non-default port
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
			adminPasswordData = requestPassword(connectingUserName + " (admin) DB password:");
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
	 * and return the exit value of the command.  
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
		if (verbose) {
			System.out.println("Command: " + command);
		}
		ProcessBuilder processBuilder = new ProcessBuilder(command);
		processBuilder.directory(directory);		// Set the working directory
		if (envvar != null) {
			Map<String, String> environment = processBuilder.environment();
			environment.put(envvar, value);
		}
		Process process = processBuilder.start();

		IOThread inThread = new IOThread(process.getInputStream(), true);
		inThread.start();

		IOThread errThread = new IOThread(process.getErrorStream(), false);
		errThread.start();
		errThread.join(); // Ensure all stderr output is processed to avoid mixed-up console output
		inThread.join();

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
	 * @param keystorePresent true if a server certificate key store is configured (enables remote
	 *   access and all-interface binding); false for loopback-only self-signed operation
	 * @param initialize true at init (generate the full config including the user-tunable block);
	 *   false at reconfigure (regenerate only the managed block, preserving the tunable block)
	 * @throws SAXException if the xml pull parser cannot be created
	 * @throws IOException if the authentication fails
	 */
	private void tuneConfig(File inputFile, File outputFile, File inHbaFile, File outHbaFile,
			File serverConfigFile, boolean keystorePresent, boolean initialize)
			throws SAXException, IOException {
		ErrorHandler handler = SpecXmlUtils.getXmlHandler();
		XmlPullParser parser = new NonThreadedXmlPullParserImpl(serverConfigFile, handler, false);
		ServerConfig serverConfig = new ServerConfig();
		serverConfig.restoreXml(parser);
		if ((port != -1) && (port != BSimServerInfo.DEFAULT_POSTGRES_PORT)) {
			serverConfig.addKey("port", Integer.toString(port));
		}

		if (localAuthentication == AUTHENTICATION_NONE) {
			serverConfig.setLocalAuthentication(TRUST_METHOD, null);
		}
		else if (localAuthentication == AUTHENTICATION_PASSWORD) {
			serverConfig.setLocalAuthentication(PASSWORD_METHOD, null);
		}
		else if (localAuthentication == AUTHENTICATION_PKI) {
			serverConfig.setLocalAuthentication(CERTIFICATE_METHOD, certificateMethodOptions());
		}
		else {
			throw new IOException("Unsupported local authentication type");
		}

		// Interface binding and remote access are derived from server-certificate (key store)
		// presence and authentication mode.  When either a key store has not been specified
		// or using 'trust' hostAuthentication server will listen to loopback interfaces only 
		// and remote access is removed entirely.
		boolean listenLocalOnly = true;
		if (keystorePresent) {
			if (hostAuthentication == AUTHENTICATION_NONE) {
				serverConfig.setHostAuthentication(TRUST_METHOD, null);
			}
			else if (hostAuthentication == AUTHENTICATION_PASSWORD) {
				serverConfig.setHostAuthentication(PASSWORD_METHOD, null);
			}
			else if (hostAuthentication == AUTHENTICATION_PKI) {
				serverConfig.setHostAuthentication(CERTIFICATE_METHOD, certificateMethodOptions());
			}
			else {
				throw new IOException("Unsupported host authentication type");
			}
			if (hostAuthentication == AUTHENTICATION_NONE) {
				System.out.println("Warning: remote access is enabled without client " +
					"authentication (trust); consider --auth password or --auth pki");
			}
			else {
				listenLocalOnly = false;
			}
		}

		if (listenLocalOnly) {
			warnLoopbackOnly();
			serverConfig.removeHostAuthentication();	// loopback-only: no remote access permitted
			serverConfig.addKey("listen_addresses", "'localhost'");
		}
		else {
			serverConfig.addKey("listen_addresses", "'*'");
		}

		if (hostAuthentication == AUTHENTICATION_PKI || localAuthentication == AUTHENTICATION_PKI) {
			serverConfig.addKey("ssl_ca_file", '\'' + POSTGRES_ROOTCA + '\'');	// Turn on certificate authority
		}
		if (initialize) {
			serverConfig.writePostgresConfig(inputFile, outputFile, true);
		}
		else {
			// Reconfigure: regenerate only the managed block within the current postgresql.conf,
			// preserving the user-editable performance-tuning block and any other edits.
			serverConfig.writePostgresConfig(outputFile, outputFile, false);
		}
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
		serverConfig.addKey("listen_addresses", "");
		serverConfig.scanConfig(configFile);
		String value = serverConfig.getValue("port");

		if (value.length() != 0) {
			try {
				port = Integer.parseInt(value);
			}
			catch (NumberFormatException e) {
				// ignore
			}
			if (port <= 0 || port > 65535) {
				throw new IOException(
					"Server has an invalid port assignment. Change in " + POSTGRES_CONFIGFILE);
			}
		}
		else {
			port = BSimServerInfo.DEFAULT_POSTGRES_PORT;
		}

		remoteAccessConfigured = isRemoteListen(serverConfig.getValue("listen_addresses"));

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

		// Whether each user is registered within the identity map by their full distinguished name
		// or by their common name alone follows the deployment as it was configured, so that the
		// user entries an existing deployment already holds remain the ones the server matches
		useDistinguishedName = recoverCertificateNameMode(serverConfig);

		// The non-local (remote) connection entry is only present when remote access is enabled
		// (i.e., a server certificate key store is configured).  Without it the configured --auth
		// mode cannot be recovered from the connection file and must come from the BSim
		// configuration record.  When the entry is present the connection file remains
		// authoritative, with the record serving only as a consistency check.
		if (hostMethod == null) {
			int recordedAuth = readRecordedAuthMode();
			if (recordedAuth >= 0) {
					hostAuthentication = recordedAuth;
			}
		}
	}

	/**
	 * Recover the {@code --auth} mode which was recorded within the data directory when the server
	 * was initialized or last configured.  This record is the only source for the configured mode
	 * when remote access is disabled, since no remote connection entry is retained within
	 * {@value #POSTGRES_CONNECTFILE} in that case.
	 * @return the recorded authentication constant, or -1 if no mode has been recorded (which is
	 *   the case for a deployment initialized before this record was introduced)
	 * @throws IOException if the record cannot be read, is malformed, or was written by a newer
	 *   version of Ghidra
	 */
	private int readRecordedAuthMode() throws IOException {
		File file = new File(dataDirectory, BSIM_CONFIG_FILE);
		if (!file.isFile()) {
			return -1;
		}
		Properties props = new Properties();
		try (FileInputStream in = new FileInputStream(file)) {
			props.load(in);
		}
		String version = props.getProperty(PROP_CONFIG_VERSION, "1").trim();
		try {
			if (Integer.parseInt(version) > BSIM_CONFIG_VERSION) {
				throw new IOException(dataDirectory.getAbsolutePath() +
					" was configured by a newer version of Ghidra (" + BSIM_CONFIG_FILE +
					" version " + version + ")");
			}
		}
		catch (NumberFormatException e) {
			throw new IOException("Invalid " + PROP_CONFIG_VERSION + " in " +
				file.getAbsolutePath() + ": " + version);
		}
		String mode = props.getProperty(PROP_AUTH_MODE);
		if (mode == null) {
			return -1;
		}
		try {
			return parseAuthMode(mode);
		}
		catch (IllegalArgumentException e) {
			throw new IOException(
				"Invalid " + PROP_AUTH_MODE + " in " + file.getAbsolutePath() + ": " + mode);
		}
	}

	/**
	 * Record the configured {@code --auth} mode within the data directory so it can be recovered by
	 * subsequent invocations.  Only the mode itself is recorded; the effective local and host
	 * authentication are derived from it where needed, with the local authentication (and hence any
	 * {@code --noLocalAuth} downgrade) always recoverable from {@value #POSTGRES_CONNECTFILE}.
	 * <p>
	 * This is a no-op if the mode is not actually known (see {@code authModeKnown}), so that an
	 * assumed mode is never recorded as though it had been configured.
	 * @throws IOException if the record cannot be written
	 * @throws InterruptedException if interrupted while adjusting ownership/permissions
	 */
	private void saveDeploymentConfig() throws IOException, InterruptedException {
		Properties props = new Properties();
		props.setProperty(PROP_CONFIG_VERSION, Integer.toString(BSIM_CONFIG_VERSION));
		props.setProperty(PROP_AUTH_MODE, authModeName(hostAuthentication));
		File file = new File(dataDirectory, BSIM_CONFIG_FILE);
		File tmpFile = new File(dataDirectory, BSIM_CONFIG_FILE + ".tmp");
		try (FileOutputStream out = new FileOutputStream(tmpFile)) {
			props.store(out, "BSim PostgreSQL configuration - do not edit");
		}
		Files.move(tmpFile.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING);
		setPosixMode(file, "600");
		if (dropPrivileges) {
			chownToOwner(file, false);
		}
	}

	/**
	 * Determine whether a {@code listen_addresses} value binds any non-loopback interface.
	 * @param listen the recovered listen_addresses value (may be quoted or null)
	 * @return true if the value indicates remote (non-loopback) binding
	 */
	private static boolean isRemoteListen(String listen) {
		if (listen == null) {
			return false;
		}
		String v = listen.trim().replace("'", "");
		if (v.isEmpty()) {
			return false;		// unset -> PostgreSQL default is loopback
		}
		return !NetworkUtils.isLoopbackAddress(v);
	}

	private void warnLoopbackOnly() {
		System.out.println(
			"WARNING: server will listen to localhost connections only when keystore " +
				"has not been configured or using 'trust' auhthentication.");
	}

	/**
	 * When pki authentication is not in effect, warn that a specified certificate authority file is
	 * not used.  The authority is only consulted to authenticate client certificates, so unless
	 * either connection type uses pki it would neither be installed nor have any effect.
	 */
	private void warnUnusedCertAuthorityOption() {
		if (certAuthorityFile != null) {
			System.out.println("Warning: without 'pki' authentication the following option is ignored: " + 
				CAFILE_OPTION);
		}
	}

	// ==================================================================================
	// Deployment identity and privilege model (Linux)
	//
	// OWNER is the OS account that owns the data directory and runs the postgres process.  For
	// "init" it is established from --os-user (root) or the invoking user (non-root); for all other
	// data-directory commands it is read from the data directory owner.  When running as root
	// against a data directory owned by a different account, postgres tools and file operations are
	// performed as OWNER (via runuser) and any root-created files are re-owned to OWNER.
	// ==================================================================================

	/**
	 * @return true if bsim_ctl is running with effective UID 0 (root)
	 */
	private boolean isRoot() throws IOException, InterruptedException {
		if (runningAsRoot == null) {
			runningAsRoot = "0".equals(execCapture(List.of("id", "-u")));
		}
		return runningAsRoot;
	}

	/**
	 * @return the name of the OS account invoking bsim_ctl
	 */
	private String getInvokingUserName() throws IOException, InterruptedException {
		if (invokingUserName == null) {
			invokingUserName = execCapture(List.of("id", "-un"));
		}
		return invokingUserName;
	}

	/**
	 * Run a command and return its trimmed standard output, throwing if it exits non-zero.
	 * @param command the command and arguments
	 * @return the trimmed standard output
	 * @throws IOException if the command cannot be run or exits non-zero
	 * @throws InterruptedException if interrupted while waiting
	 */
	private static String execCapture(List<String> command)
			throws IOException, InterruptedException {
		Process process = new ProcessBuilder(command).start();
		byte[] out = process.getInputStream().readAllBytes();
		process.getErrorStream().readAllBytes();		// drain stderr
		int rc = process.waitFor();
		if (rc != 0) {
			throw new IOException("Command failed (exit " + rc + "): " + String.join(" ", command));
		}
		return new String(out, "UTF-8").trim();
	}

	/**
	 * @param user an account name
	 * @return true if the account exists on this system
	 * @throws InterruptedException if interrupted
	 */
	private static boolean accountExists(String user) throws InterruptedException {
		try {
			Process process = new ProcessBuilder("id", user).start();
			process.getInputStream().readAllBytes();
			process.getErrorStream().readAllBytes();
			return process.waitFor() == 0;
		}
		catch (IOException e) {
			return false;
		}
	}

	/**
	 * @param user an account name
	 * @return the account's primary group name
	 * @throws IOException if the group cannot be determined
	 * @throws InterruptedException if interrupted
	 */
	private static String getPrimaryGroup(String user) throws IOException, InterruptedException {
		return execCapture(List.of("id", "-gn", user));
	}

	/**
	 * @param file a file or directory
	 * @return the name of the file's owning account
	 * @throws IOException if the owner cannot be determined
	 */
	private static String getFileOwner(File file) throws IOException {
		return Files.getOwner(file.toPath()).getName();
	}

	/**
	 * Establish the data-directory OWNER and enforce the invocation authorization rules (design
	 * section 4).  Must be called before any postgres tool invocation or data-directory file
	 * operation.
	 * @param newDataDir true for "init" (OWNER from --os-user / invoker); false for commands
	 *   operating on an existing data directory (OWNER = data directory owner)
	 * @param requireRoot true if the command may only be run as root
	 * @throws IOException if authorization fails or the owner cannot be established
	 * @throws InterruptedException if interrupted while resolving identities
	 */
	private void resolveDeployment(boolean newDataDir, boolean requireRoot)
			throws IOException, InterruptedException {
		boolean root = isRoot();
		String invoker = getInvokingUserName();
		if (requireRoot && !root) {
			throw new IOException("This command must be run as root (use sudo)");
		}
		if (newDataDir) {
			if (root) {
				if (osUserOption == null) {
					throw new IOException("--os-user <account> is required when running \"" +
						COMMAND_INIT + "\" as root");
				}
				if (!accountExists(osUserOption)) {
					throw new IOException("Account does not exist: " + osUserOption);
				}
				ownerName = osUserOption;
			}
			else {
				if (osUserOption != null) {
					throw new IOException("--os-user may only be specified when running as root");
				}
				ownerName = invoker;
			}
		}
		else {
			if (!dataDirectory.exists()) {
				throw new IOException(
					"Data directory does not exist: " + dataDirectory.getAbsolutePath());
			}
			ownerName = getFileOwner(dataDirectory);
			if (!root && !ownerName.equals(invoker)) {
				throw new IOException("This command must be run by the data directory owner (" +
					ownerName + ") or root");
			}
			if (root && osUserOption != null && !osUserOption.equals(ownerName)) {
				throw new IOException("--os-user (" + osUserOption +
					") does not match the data directory owner (" + ownerName + ")");
			}
		}
		if ("root".equals(ownerName)) {
			throw new IOException("PostgreSQL may not run as root; specify a non-root --os-user");
		}
		ownerGroup = getPrimaryGroup(ownerName);
		dropPrivileges = root && !ownerName.equals(invoker);
	}

	/**
	 * Run a PostgreSQL tool (initdb, pg_ctl, pg_isready, ...), dropping privileges to OWNER via
	 * {@code runuser} when running as root against a data directory owned by a different account.
	 * @param command the tool command and arguments
	 * @return the tool exit status
	 * @throws IOException if the tool cannot be run
	 * @throws InterruptedException if interrupted while waiting
	 */
	private int runPostgresCommand(List<String> command) throws IOException, InterruptedException {
		List<String> toRun = command;
		if (dropPrivileges) {
			toRun = new ArrayList<>();
			toRun.add("runuser");
			toRun.add("-u");
			toRun.add(ownerName);
			toRun.add("--");
			toRun.add("env");
			if (loadLibraryVar != null) {
				toRun.add(loadLibraryVar + "=" + loadLibraryValue);
			}
			toRun.addAll(command);
		}
		return runCommand(null, toRun, loadLibraryVar, loadLibraryValue);
	}

	/**
	 * Create a new, empty data directory owned by OWNER with 0700 permissions (for "init").
	 * @throws IOException if the directory exists and is not empty, or cannot be created
	 * @throws InterruptedException if interrupted while adjusting ownership/permissions
	 */
	private void createDataDirectory() throws IOException, InterruptedException {
		if (dataDirectory.exists()) {
			String[] entries = dataDirectory.list();
			if (entries != null && entries.length != 0) {
				throw new IOException(
					"Data directory is not empty: " + dataDirectory.getAbsolutePath());
			}
		}
		else if (!dataDirectory.mkdirs()) {
			throw new IOException(
				"Failed to create data directory: " + dataDirectory.getAbsolutePath());
		}
		setPosixMode(dataDirectory, "700");
		if (dropPrivileges) {
			chownToOwner(dataDirectory, false);
		}
	}

	/**
	 * After a root-run mutation of the data directory, recursively assign ownership to OWNER and
	 * re-assert sensitive permissions.  A no-op when not dropping privileges.
	 * @throws IOException if a chown/chmod fails
	 * @throws InterruptedException if interrupted
	 */
	private void normalizeOwnership() throws IOException, InterruptedException {
		if (!dropPrivileges) {
			return;
		}
		chownToOwner(dataDirectory, true);
		setPosixMode(dataDirectory, "700");
		File serverKey = new File(dataDirectory, "server.key");
		if (serverKey.isFile()) {
			setPosixMode(serverKey, "600");
		}
	}

	private void setPosixMode(File file, String mode) throws IOException, InterruptedException {
		List<String> command = new ArrayList<>(List.of("chmod", mode, file.getAbsolutePath()));
		if (runCommand(null, command, null, null) != 0) {
			throw new IOException("Failed to set permissions on " + file.getAbsolutePath());
		}
	}

	private void chownToOwner(File file, boolean recursive)
			throws IOException, InterruptedException {
		List<String> command = new ArrayList<>();
		command.add("chown");
		if (recursive) {
			command.add("-R");
		}
		command.add(ownerName + ":" + ownerGroup);
		command.add(file.getAbsolutePath());
		if (runCommand(null, command, null, null) != 0) {
			throw new IOException("Failed to set ownership of " + file.getAbsolutePath());
		}
	}

	// ==================================================================================
	// systemd service management (Linux, root only)
	// ==================================================================================

	/**
	 * @return true if running on Linux (where systemd service management is supported)
	 */
	private static boolean isLinux() {
		return Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.LINUX;
	}

	/**
	 * @return the deterministic systemd unit name for the current data directory
	 */
	private String getServiceUnitName() {
		String base = dataDirectory.getName().replaceAll("[^A-Za-z0-9]", "-");
		String hash = Integer.toHexString(dataDirectory.getAbsolutePath().hashCode() & 0x7fffffff);
		return "bsim-postgresql-" + base + "-" + hash + ".service";
	}

	/**
	 * @return true if a service marker is present for the current data directory
	 */
	private boolean isServiceInstalled() {
		return new File(dataDirectory, SERVICE_MARKER).isFile();
	}

	/**
	 * @return the service marker properties, or null if no marker is present
	 * @throws IOException if the marker cannot be read
	 */
	private Properties readServiceMarker() throws IOException {
		File marker = new File(dataDirectory, SERVICE_MARKER);
		if (!marker.isFile()) {
			return null;
		}
		Properties props = new Properties();
		try (FileInputStream in = new FileInputStream(marker)) {
			props.load(in);
		}
		return props;
	}

	/**
	 * Write the service marker recording the installed unit and OWNER.
	 * @param unitName the installed systemd unit name
	 * @throws IOException if the marker cannot be written
	 * @throws InterruptedException if interrupted while adjusting ownership
	 */
	private void writeServiceMarker(String unitName) throws IOException, InterruptedException {
		Properties props = new Properties();
		props.setProperty("unitName", unitName);
		props.setProperty("scope", "system");
		props.setProperty("user", ownerName);
		props.setProperty("pgHome", postgresRoot.getAbsolutePath());
		File marker = new File(dataDirectory, SERVICE_MARKER);
		try (FileOutputStream out = new FileOutputStream(marker)) {
			props.store(out, "BSim PostgreSQL service marker - do not edit");
		}
		setPosixMode(marker, "600");
		if (dropPrivileges) {
			chownToOwner(marker, false);
		}
	}

	/**
	 * @return the generated systemd unit file contents for the current data directory
	 */
	private String generateLinuxSystemdServiceUnit() {
		String datadir = dataDirectory.getAbsolutePath();
		String pgctl = postgresControl.getAbsolutePath();
		String pgLib = new File(postgresRoot, "lib").getAbsolutePath();
		String logfile = new File(dataDirectory, "logfile").getAbsolutePath();
		String pidfile = new File(dataDirectory, "postmaster.pid").getAbsolutePath();
		StringBuilder sb = new StringBuilder();
		sb.append("[Unit]\n");
		sb.append("Description=BSim PostgreSQL database (").append(datadir).append(")\n");
		sb.append("After=network-online.target\n");
		sb.append("Wants=network-online.target\n\n");
		sb.append("[Service]\n");
		sb.append("Type=forking\n");
		sb.append("User=").append(ownerName).append('\n');
		sb.append("Group=").append(ownerGroup).append('\n');
		// Environment= and Exec* command lines are whitespace-split by systemd, so any value that
		// may contain spaces (e.g., a Ghidra installation path) must be double-quoted.  PIDFile=,
		// Description=, User=, and Group= take the literal remainder of the line and are not quoted.
		sb.append("Environment=").append(sdQuote(loadLibraryVar + "=" + pgLib)).append('\n');
		sb.append("Environment=").append(sdQuote("PGDATA=" + datadir)).append('\n');
		sb.append("PIDFile=").append(pidfile).append('\n');
		sb.append("ExecStart=").append(sdQuote(pgctl)).append(" start -D ").append(sdQuote(datadir))
			.append(" -w -s -l ").append(sdQuote(logfile)).append('\n');
		sb.append("ExecStop=").append(sdQuote(pgctl)).append(" stop -D ").append(sdQuote(datadir))
			.append(" -m fast -s -w\n");
		sb.append("ExecReload=").append(sdQuote(pgctl)).append(" reload -D ").append(
			sdQuote(datadir)).append(" -s\n");
		sb.append("Restart=on-failure\n");
		sb.append("RestartSec=5\n");
		sb.append("TimeoutStartSec=120\n");
		sb.append("TimeoutStopSec=120\n\n");
		sb.append("[Install]\n");
		sb.append("WantedBy=multi-user.target\n");
		return sb.toString();
	}

	/**
	 * Quote a systemd command-line argument or {@code Environment=} assignment so embedded
	 * whitespace (e.g., a Ghidra installation path containing spaces) is preserved.  systemd
	 * performs C-style unescaping within double quotes, so backslashes and double quotes are
	 * escaped.
	 * @param value the raw value
	 * @return the double-quoted, escaped value
	 */
	private static String sdQuote(String value) {
		return '"' + value.replace("\\", "\\\\").replace("\"", "\\\"") + '"';
	}

	/**
	 * Run a systemctl command.
	 * @param args systemctl subcommand and arguments
	 * @return the systemctl exit status
	 * @throws IOException if systemctl cannot be run
	 * @throws InterruptedException if interrupted
	 */
	private int runSystemctl(String... args) throws IOException, InterruptedException {
		List<String> command = new ArrayList<>();
		command.add("systemctl");
		for (String a : args) {
			command.add(a);
		}
		return runCommand(null, command, null, null);
	}

	/**
	 * Run a command and return its trimmed standard output, ignoring a non-zero exit status.
	 * @param command the command and arguments
	 * @return the trimmed standard output (empty on failure)
	 * @throws InterruptedException if interrupted
	 */
	private static String execCaptureAllowFail(List<String> command) throws InterruptedException {
		try {
			Process process = new ProcessBuilder(command).start();
			byte[] out = process.getInputStream().readAllBytes();
			process.getErrorStream().readAllBytes();
			process.waitFor();
			return new String(out, "UTF-8").trim();
		}
		catch (IOException e) {
			return "";
		}
	}

	/**
	 * @param subcommand a systemctl query subcommand (e.g., is-enabled, is-active)
	 * @param unit the unit name
	 * @return the reported state word (e.g., enabled, active), or empty
	 * @throws InterruptedException if interrupted
	 */
	private static String systemctlQuery(String subcommand, String unit)
			throws InterruptedException {
		return execCaptureAllowFail(List.of("systemctl", subcommand, unit));
	}

	/**
	 * @return true if a postmaster is running against the current data directory
	 * @throws IOException if pg_ctl cannot be run
	 * @throws InterruptedException if interrupted
	 */
	private boolean isPostmasterRunning() throws IOException, InterruptedException {
		List<String> command = new ArrayList<>();
		command.add(postgresControl.getAbsolutePath());
		command.add("status");
		command.add("-D");
		command.add(dataDirectory.getAbsolutePath());
		return runPostgresCommand(command) == 0;		// 0 = running, 3 = stopped
	}

	/**
	 * Install a systemd service for the current (initialized) data directory.  Root only.
	 * @throws IOException if installation fails
	 * @throws InterruptedException if interrupted
	 */
	private void installServiceCommand() throws IOException, InterruptedException {
		if (!isLinux()) {
			throw new IOException("Service installation is only supported on Linux (systemd)");
		}
		resolveDeployment(false, true);		// require root; OWNER from data directory owner
		discoverPostgresInstall();
		File configFile = new File(dataDirectory, POSTGRES_CONFIGFILE);
		if (!configFile.exists()) {
			throw new IOException("Data directory not initialized: run \"bsim_ctl " + COMMAND_INIT +
				" " + dataDirectory.getAbsolutePath() + "\" first");
		}
		if (isServiceInstalled()) {
			throw new IOException("A service is already installed for this data directory; run \"" +
				COMMAND_UNINSTALL_SERVICE + "\" first");
		}
		if (isPostmasterRunning()) {
			throw new IOException(
				"Server is running; stop it before installing the service (bsim_ctl stop)");
		}
		String unit = getServiceUnitName();
		File unitFile = new File(SYSTEMD_SYSTEM_DIR, unit);
		if (unitFile.exists()) {
			throw new IOException("Service unit already exists: " + unitFile.getAbsolutePath());
		}
		try (FileWriter writer = new FileWriter(unitFile)) {
			writer.write(generateLinuxSystemdServiceUnit());
		}
		setPosixMode(unitFile, "644");
		if (runSystemctl("daemon-reload") != 0) {
			throw new IOException("systemctl daemon-reload failed");
		}
		if (runSystemctl("enable", unit) != 0) {
			throw new IOException("systemctl enable failed for " + unit);
		}
		writeServiceMarker(unit);
		System.out.println("Installed service: " + unit + " (User=" + ownerName + ")");
		System.out.println("Run \"bsim_ctl " + COMMAND_START + " " + dataDirectory.getAbsolutePath() +
			"\" to start it.");
	}

	/**
	 * Uninstall the systemd service for the current data directory.  Root only.  Leaves the data
	 * directory intact.
	 * @throws IOException if uninstallation fails
	 * @throws InterruptedException if interrupted
	 */
	private void uninstallServiceCommand() throws IOException, InterruptedException {
		if (!isLinux()) {
			throw new IOException("Service uninstall is only supported on Linux (systemd)");
		}
		resolveDeployment(false, true);		// require root
		Properties marker = readServiceMarker();
		String unit;
		if (marker != null) {
			unit = marker.getProperty("unitName");
		}
		else {
			unit = getServiceUnitName();
			System.out.println("Warning: service marker not found; using derived unit name " + unit);
		}
		runSystemctl("stop", unit);			// ignore failure (may not be running)
		runSystemctl("disable", unit);		// ignore failure (may not be enabled)
		File unitFile = new File(SYSTEMD_SYSTEM_DIR, unit);
		if (unitFile.exists() && !unitFile.delete()) {
			throw new IOException("Failed to remove unit file: " + unitFile.getAbsolutePath());
		}
		runSystemctl("daemon-reload");
		File markerFile = new File(dataDirectory, SERVICE_MARKER);
		if (markerFile.exists() && !markerFile.delete()) {
			throw new IOException("Failed to remove service marker: " + markerFile.getAbsolutePath());
		}
		System.out.println("Uninstalled service: " + unit);
	}

	/**
	 * Delegate a lifecycle action (start/stop/restart) to systemctl for an installed service.
	 * @param action the systemctl action
	 * @throws IOException if not root or the action fails
	 * @throws InterruptedException if interrupted
	 */
	private void systemctlLifecycle(String action) throws IOException, InterruptedException {
		if (!isRoot()) {
			throw new IOException("Server is installed as a service; \"" + action +
				"\" must be run as root (use sudo)");
		}
		Properties marker = readServiceMarker();
		if (marker == null) {
			throw new IOException("Service marker missing for " + dataDirectory.getAbsolutePath());
		}
		String unit = marker.getProperty("unitName");
		if (runSystemctl(action, unit) != 0) {
			throw new IOException("systemctl " + action + " failed for " + unit);
		}
		System.out.println("Service " + action + " complete: " + unit);
	}

	/**
	 * Establish the admin user's PKI identity for the authentication mode being configured: their
	 * distinguished name, and its common name, are obtained from the client certificate specified
	 * with the global {@code --cert} option and verified against the certificate authorities which
	 * the PostgreSQL server will use (see {@link #checkCertAuthorityFile()}).
	 * <p>
	 * The identity is always derived from the certificate itself rather than accepted as text, so
	 * that the identity mapping written to {@value #POSTGRES_IDENTFILE} is guaranteed to match the
	 * certificate the admin user will actually present; a mistyped name would otherwise leave them
	 * unable to authenticate once the configuration takes effect.
	 * <p>
	 * The certificate key store is opened, and its password prompted for, during application
	 * initialization (see {@link #initializeApplication()}) and the resulting key manager is cached
	 * by {@link DefaultKeyManagerFactory}, so neither this method nor the subsequent SSL connection
	 * to the server requires a further password entry.
	 * @throws IOException if the certificate authority file is missing or unreadable
	 * @throws GeneralSecurityException if no client certificate is available, it has expired, it
	 *   does not specify a common name, or the server would not accept it
	 */
	private void establishPkiIdentity() throws IOException, GeneralSecurityException {
		checkCertAuthorityFile();
		if (certParameter == null) {
			throw new GeneralSecurityException("PKI authentication requires the certificate of " +
				connectingUserName + " (admin) to be specified: " + CERT_OPTION +
				" </certfile-path>");
		}
		X509ExtendedKeyManager keyManager = DefaultKeyManagerFactory.getKeyManager();
		X509Certificate[] chain = null;
		if (keyManager != null) {
			// Uses the key manager which was established, and cached, when the key store was
			// opened during application initialization - no additional password entry occurs
			String alias = keyManager.chooseClientAlias(CLIENT_KEY_TYPES, null, null);
			if (alias != null) {
				chain = keyManager.getCertificateChain(alias);
			}
		}
		if (chain == null || chain.length == 0) {
			throw new GeneralSecurityException("Unable to obtain a PKI certificate from " +
				CERT_OPTION + " key store: " + certParameter);
		}
		X509Certificate cert = chain[0];
		cert.checkValidity();		// throws if expired or not yet valid
		// RFC 2253 form, which is how the server renders the subject of a presented certificate
		distinguishedName = cert.getSubjectX500Principal().getName();
		commonName = null;
		if (!useDistinguishedName) {
			// Legacy deployments used Common Name (CN) instead of Distinguished Name (DN) for users
			try {
				commonName = PKIUtils.getCommonName(distinguishedName);
			}
			catch (InvalidNameException e) {
				throw new GeneralSecurityException(
					"Failed to extract common name (CN) from certificate", e);
			}
			if (commonName == null) {
				throw new GeneralSecurityException(
					"Certificate DN does not contain common name (CN): " + distinguishedName);
			}
		}
		verifyIssuedByCertAuthority(cert);
		System.out.println(
			"Using certificate for " + connectingUserName + " (admin): " + distinguishedName);
	}

	/**
	 * Verify that the specified client certificate will be accepted by the PostgreSQL server, which
	 * authenticates it (under {@code clientcert=verify-full}) using only those certificate
	 * authorities contained within its {@value #POSTGRES_ROOTCA} ({@code ssl_ca_file}) - the set
	 * established and validated by {@link #checkCertAuthorityFile()}.
	 * <p>
	 * Only that set is considered: a certificate authority which happens to be embedded within the
	 * {@code --cert} key store's own certificate chain is unknown to the server, so accepting it
	 * here would report a certificate as usable which the server will subsequently reject.
	 * @param cert the client certificate to be verified
	 * @throws GeneralSecurityException if the certificate would not be accepted by the server
	 */
	private void verifyIssuedByCertAuthority(X509Certificate cert)
			throws GeneralSecurityException {

		String reject = "Certificate for " + connectingUserName + " (" +
			cert.getSubjectX500Principal().getName() + ") will not be accepted by the server: ";

		// Trace the chain as the server will, using only the authorities it has been given.  This
		// is done ahead of the PKIX validation below to identify precisely where the chain breaks.
		List<X509Certificate> chain;
		try {
			chain = traceChainOfTrust(cert, certAuthorities);
		}
		catch (CertificateException e) {
			throw new CertificateException(reject + e.getMessage());
		}
		if (chain.isEmpty() && !certAuthorities.contains(cert)) {
			throw new CertificateException(reject + "certificate is self-signed and is not one of " +
				"the authorities within " + activeCertAuthorityFile.getAbsolutePath());
		}

		// Full PKIX validation against the same authorities, which additionally applies those
		// constraints the server's own verification imposes (client authentication key usage,
		// authority path length, ...)
		try {
			PKIUtils.getTrustManager(activeCertAuthorityFile)
					.checkClientTrusted(new X509Certificate[] { cert },
						cert.getPublicKey().getAlgorithm());
		}
		catch (IOException e) {
			throw new GeneralSecurityException("Failed to read certificate authority file: " +
				activeCertAuthorityFile.getAbsolutePath(), e);
		}
		catch (CertificateException e) {
			throw new CertificateException(reject + e.getMessage());
		}

		// An expired authority within the chain is reported here as well as by the file validation,
		// since it is this certificate which the server will refuse once the authority lapses
		Date now = new Date();
		for (X509Certificate caCert : chain) {
			if (now.after(caCert.getNotAfter())) {
				System.out.println("Warning: the certificate of " + connectingUserName +
					" depends upon an EXPIRED certificate authority: " + certName(caCert));
			}
		}
	}

	/**
	 * Establish, and fully validate, the set of certificate authorities which the PostgreSQL server
	 * will use to authenticate client certificates.  The authorities are read from the file given
	 * by {@code --cafile} or, when that option is omitted, from the {@value #POSTGRES_ROOTCA}
	 * previously installed within the data directory by {@code init} or {@code configure}.
	 * <p>
	 * PostgreSQL requires this file to be an unencrypted concatenation of PEM encoded certificates
	 * which itself provides a complete chain of trust for every authority it contains, since the
	 * server does not look beyond the file when building the chain for a presented client
	 * certificate.  It is validated accordingly, and re-validated each time it is used since a
	 * chain which was complete when installed can become stale: an expired (or not yet valid)
	 * authority produces a warning, whereas a certificate which is not a certificate authority, or
	 * an authority whose chain cannot be traced to a root within the same file, is an error.
	 * @throws IOException if no certificate authority file is available or it cannot be read
	 * @throws GeneralSecurityException if the file does not provide a usable set of authorities
	 */
	private void checkCertAuthorityFile() throws IOException, GeneralSecurityException {
		if (certAuthorities != null) {
			return;			// already established and validated
		}
		activeCertAuthorityFile = certAuthorityFile;
		if (activeCertAuthorityFile == null) {
			// The option may be omitted when reconfiguring a deployment which already has one
			File rootCA = dataDirectory != null ? new File(dataDirectory, POSTGRES_ROOTCA) : null;
			if (rootCA == null || !rootCA.isFile()) {
				throw new IOException("PKI authentication requires a certificate authority file: " +
					CAFILE_OPTION + " </cacert-path>");
			}
			activeCertAuthorityFile = rootCA;
		}
		else if (!activeCertAuthorityFile.isFile()) {
			throw new IOException("Certificate authority file not found: " +
				activeCertAuthorityFile.getAbsolutePath());
		}
		System.out.println(
			"Certificate authority file: " + activeCertAuthorityFile.getAbsolutePath());
		List<X509Certificate> certs =
			PKIUtils.loadX509PemCertificates(activeCertAuthorityFile);
		if (certs.isEmpty()) {
			// A DER encoded certificate, a keystore, or an encrypted file lands here, none of which
			// the server is able to read
			throw new CertificateException("File does not contain any PEM encoded certificate " +
				"(an unencrypted PEM certificate file is required): " +
				activeCertAuthorityFile.getAbsolutePath());
		}
		certAuthorities = validateCertAuthorities(certs);
	}

	/**
	 * Validate the certificates read from the certificate authority file, reporting the trust
	 * status of each, and reduce them to the set of authorities the PostgreSQL server will use.
	 * All defects are reported together so that a single run identifies everything which must be
	 * corrected within the file.
	 * @param certs all certificates read from the certificate authority file
	 * @return the certificate authorities, each with a complete chain of trust within the file
	 * @throws GeneralSecurityException if the file contains a certificate which is not a
	 *   certificate authority, or an authority whose chain of trust is incomplete
	 */
	private List<X509Certificate> validateCertAuthorities(List<X509Certificate> certs)
			throws GeneralSecurityException {

		List<String> errors = new ArrayList<>();
		List<X509Certificate> caCerts = new ArrayList<>();
		for (X509Certificate cert : certs) {
			// The basicConstraints CA indication is required of every certificate within the file;
			// the server will not build a chain through any other certificate, and a client
			// certificate placed here in error would be silently ignored
			if (cert.getBasicConstraints() == -1) {
				errors.add("Not a certificate authority (CA): " + certName(cert));
			}
			else {
				caCerts.add(cert);
			}
		}
		for (X509Certificate caCert : caCerts) {
			boolean selfSigned = isSelfSigned(caCert);
			try {
				traceChainOfTrust(caCert, caCerts);
				reportCertificate(selfSigned ? "Root certificate authority"
						: "Intermediate certificate authority", caCert);
			}
			catch (CertificateException e) {
				errors.add(e.getMessage());
			}
			boolean[] keyUsage = caCert.getKeyUsage();
			if (keyUsage != null && keyUsage.length > 5 && !keyUsage[5]) {	// keyCertSign
				System.out.println("Warning: certificate authority is not permitted to sign " +
					"certificates (keyCertSign key usage is absent): " + certName(caCert));
			}
		}
		if (!errors.isEmpty()) {
			StringBuilder buffer = new StringBuilder("Invalid certificate authority file: ");
			buffer.append(activeCertAuthorityFile.getAbsolutePath());
			for (String error : errors) {
				buffer.append("\n   ").append(error);
			}
			throw new CertificateException(buffer.toString());
		}
		return caCerts;
	}

	/**
	 * Trace the chain of trust for the specified certificate through the given set of certificate
	 * authorities, verifying the signature of each certificate against its issuer.
	 * @param cert the certificate whose chain of trust is to be traced (need not itself be a
	 *   certificate authority)
	 * @param caCerts the certificate authorities available for building the chain
	 * @return the issuing authorities, ordered from the immediate issuer of cert through to the
	 *   self-signed root; empty if cert is itself self-signed
	 * @throws CertificateException if the chain cannot be traced to a self-signed root within
	 *   caCerts
	 */
	private List<X509Certificate> traceChainOfTrust(X509Certificate cert,
			List<X509Certificate> caCerts) throws CertificateException {

		List<X509Certificate> chain = new ArrayList<>();
		X509Certificate current = cert;
		while (!isSelfSigned(current)) {
			X509Certificate issuer = findIssuer(current, caCerts);
			if (issuer == null) {
				throw new CertificateException("Incomplete chain of trust for " + certName(cert) +
					": issuing authority is not within " + activeCertAuthorityFile.getName() +
					": " + current.getIssuerX500Principal().getName());
			}
			if (issuer.equals(cert) || chain.contains(issuer)) {
				throw new CertificateException("Circular chain of trust for " + certName(cert) +
					" at authority: " + certName(issuer));
			}
			chain.add(issuer);
			current = issuer;
		}
		return chain;
	}

	/**
	 * Locate the certificate authority which issued the specified certificate.
	 * @param cert the issued certificate
	 * @param caCerts the certificate authorities to be searched
	 * @return the issuing authority, or null if none of them signed cert
	 */
	private static X509Certificate findIssuer(X509Certificate cert,
			List<X509Certificate> caCerts) {
		for (X509Certificate caCert : caCerts) {
			if (!cert.getIssuerX500Principal().equals(caCert.getSubjectX500Principal())) {
				continue;
			}
			try {
				cert.verify(caCert.getPublicKey());
				return caCert;
			}
			catch (GeneralSecurityException e) {
				// Keep looking: more than one authority may carry this name (e.g., a renewed
				// authority issued with a new key pair)
			}
		}
		return null;
	}

	/**
	 * @param cert a certificate
	 * @return true if the certificate was issued, and signed, by itself (a root)
	 */
	private static boolean isSelfSigned(X509Certificate cert) {
		if (!cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) {
			return false;
		}
		try {
			cert.verify(cert.getPublicKey());
			return true;
		}
		catch (GeneralSecurityException e) {
			return false;
		}
	}

	/**
	 * Report a certificate and its validity period on the console, as a warning if it is not
	 * currently within that period.
	 * @param label description of the certificate's role
	 * @param cert the certificate to be reported
	 */
	private static void reportCertificate(String label, X509Certificate cert) {
		Date now = new Date();
		String detail = label + ": " + certName(cert);
		if (now.after(cert.getNotAfter())) {
			System.out.println("Warning: " + detail + " EXPIRED " + cert.getNotAfter());
		}
		else if (now.before(cert.getNotBefore())) {
			System.out.println(
				"Warning: " + detail + " is not valid until " + cert.getNotBefore());
		}
		else {
			System.out.println("   " + detail + ", expires " + cert.getNotAfter());
		}
	}

	/**
	 * @param cert a certificate
	 * @return the certificate's subject name and serial number, for reporting purposes
	 */
	private static String certName(X509Certificate cert) {
		return cert.getSubjectX500Principal().getName() + " [S/N " +
			cert.getSerialNumber().toString(16) + "]";
	}

	/**
	 * Load configuration parameters from an already-initialized data directory.
	 * @throws IOException if the data directory has not been initialized
	 */
	private void loadConfiguration() throws IOException {
		File configFile = new File(dataDirectory, POSTGRES_CONFIGFILE);
		File hbaFile = new File(dataDirectory, POSTGRES_CONNECTFILE);
		if (!configFile.exists()) {
			throw new IOException("Data directory not initialized: run \"bsim_ctl " + COMMAND_INIT +
				" " + dataDirectory.getAbsolutePath() + "\" first");
		}
		recoverConfigurationParameters(configFile, hbaFile);
	}

	/**
	 * Initialize a new (uninitialized) data directory: run PostgreSQL's init command, tailor the
	 * configuration files based on BSimControl's command-line options and the Ghidra specific
	 * configuration options, and generate the server SSL certificate.  The data directory must not
	 * already be initialized.
	 * @returns server certificate used for deployment
	 * @throws IOException if the data directory is already initialized or a file operation fails
	 * @throws InterruptedException if the postgres command is interrupted
	 * @throws SAXException if tuneConfig fails
	 * @throws GeneralSecurityException if the cert file cannot be processed
	 */
	private File initializeNewDataDirectory()
			throws IOException, InterruptedException, SAXException, GeneralSecurityException {
		File configFile = new File(dataDirectory, POSTGRES_CONFIGFILE);
		File hbaFile = new File(dataDirectory, POSTGRES_CONNECTFILE);
		if (configFile.exists()) {
			throw new IOException(
				"Data directory already exists: " + dataDirectory.getAbsolutePath());
		}
		
		System.out.println("Initializing data directory: " + dataDirectory.getAbsolutePath());
		
		File serverConfigFile = Application.getModuleDataFile("serverconfig.xml").getFile(false);
		if (hostAuthentication == AUTHENTICATION_PKI) {
			// NOTE: the certificate authority and the admin user's distinguished name were both
			// established/validated by establishPkiIdentity
			System.out.println("PostgreSQL host authentication mode: pki");
			System.out.println("Adding " + connectingUserName + "(admin) with certificate " +
				certificateNameLabel() + ": " + certificateSystemName());
		}
		else if (hostAuthentication == AUTHENTICATION_PASSWORD) {
			System.out.println("PostgreSQL host authentication mode: password");
			establishAdminPassword();
			if (dropPrivileges) {
				chownToOwner(passwordFile, false);		// initdb runs as OWNER and must read pwfile
			}
		}
		else {
			System.out.println("PostgreSQL host authentication mode: trust (no authentication)");
		}
		
		List<String> command = new ArrayList<String>();
		command.add(postgresControl.getAbsolutePath());
		command.add("init");
		command.add("-o");
		command.add("-A " + PASSWORD_METHOD); // specified during init to avoid warnings
		command.add("-o");
		command.add("'--username=" + connectingUserName + '\'');
		if (hostAuthentication == AUTHENTICATION_PASSWORD) {
			command.add("-o");
			command.add("'--pwfile=" + passwordFile.getAbsolutePath() + '\'');
		}
		command.add("-D");
		command.add(dataDirectory.getAbsolutePath());
		int res = runPostgresCommand(command);
		if (res != 0) {
			throw new IOException("Error initializing postgres database");
		}
		File configCopy = new File(dataDirectory, POSTGRES_CONFIGFILE + ".orig");

		if (hostAuthentication == AUTHENTICATION_PKI || localAuthentication == AUTHENTICATION_PKI) {
			// The authority file was established, and validated, by establishPkiIdentity
			File rootCA = new File(dataDirectory, POSTGRES_ROOTCA);
			FileUtilities.copyFile(activeCertAuthorityFile, rootCA, false, null);
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
		// Patch the configuration; interface binding and cert source follow key store presence.
		boolean keystorePresent = (keystoreFile != null);
		tuneConfig(configCopy, configFile, hbaCopy, hbaFile, serverConfigFile, keystorePresent, true);
		File serverCert = new File(dataDirectory, POSTGRES_CERTFILE);
		File serverKey = new File(dataDirectory, POSTGRES_KEYFILE);
		if (keystorePresent) {
			System.out.println("Importing PostgreSQL server certificate from key store");
			importServerCertificate(keystoreFile, serverCert, serverKey);
		}
		else {
			System.out.println("Generating self-signed (loopback-only) PostgreSQL server certificate");
			generateSelfSignedCertificate(serverCert, serverKey);
			System.out.println(
				"NOTE: BSim clients should add server certificate as trusted certificate:\n   " +
				serverCert.getAbsolutePath());
		}
		saveDeploymentConfig();		// record the --auth mode for subsequent invocations
		normalizeOwnership();		// re-own any root-created files to OWNER
		return serverCert;
	}

	/**
	 * Scan the PostgreSQL data directory from the command-line
	 * Make sure the directory exists and establish the File object -dataDirectory-
	 * @param params are the command-line arguments
	 * @param slot is the position to retrieve the data directory argument
	 * @throws IllegalArgumentException if the data directory is invalid
	 * @throws IOException if the canonical file cannot be retrieved
	 */
	private void scanDataDirectory(String[] params, int slot, boolean mustExist)
			throws IllegalArgumentException, IOException {
		if (params.length <= slot) {
			throw new IllegalArgumentException("Missing data directory");
		}
		dataDirectory = new File(params[slot]);
		if (mustExist) {
			if (!dataDirectory.isDirectory()) {
				throw new IllegalArgumentException(
					"Data directory " + dataDirectory.getAbsolutePath() + " does not exist");
			}
			dataDirectory = dataDirectory.getCanonicalFile();
		}
		else if (dataDirectory.exists()) {
			throw new IllegalArgumentException(
				"New data directory " + dataDirectory.getAbsolutePath() + " must not exist");
		}
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
	 * Initialize a new PostgreSQL data directory configured for BSim, then briefly start the
	 * server to enable the BSim (lshvector) extension before leaving it stopped.  The data
	 * directory must not already be initialized (use {@link #configureCommand()} to change an
	 * existing configuration).
	 * @throws IOException if initialization fails
	 * @throws InterruptedException if a postgres command is interrupted
	 * @throws SAXException if the configuration cannot be tuned
	 * @throws GeneralSecurityException if authentication/certificate handling fails
	 */
	private void initCommand()
			throws IOException, InterruptedException, SAXException, GeneralSecurityException {
		resolveDeployment(true, false);
		discoverPostgresInstall();
		File configFile = new File(dataDirectory, POSTGRES_CONFIGFILE);
		if (configFile.exists()) {
			throw new IOException("Data directory already initialized: use \"" + COMMAND_CONFIGURE +
				"\" to change settings or \"" + COMMAND_START + "\" to run the server");
		}
		
		if (hostAuthentication == AUTHENTICATION_PKI || localAuthentication == AUTHENTICATION_PKI) {
			// The admin user's certificate establishes both their DN/CN identity mapping and the
			// credential used for the local connection which enables the BSim extension below
			establishPkiIdentity();
		}
		else {
			warnUnusedCertAuthorityOption();
		}
		
		createDataDirectory();
		File serverCrt = initializeNewDataDirectory();

		// Briefly start the server to enable the BSim extension, then leave it stopped.
		pgCtlStart();
		
		// Trust server certificate to ensure the connection to enable BSim LSHExtension succeeds
		System.setProperty(DefaultTrustManagerFactory.GHIDRA_CACERTS_PATH_PROPERTY, serverCrt.getAbsolutePath());
		DefaultSSLContextInitializer.initialize(true);
		
		boolean extensionEnabled = true;
		try {
			enableLSHExtension();
			System.out.println("BSim extension enabled");
		}
		catch (SQLException | IOException e) {
			System.out.println(e.getMessage());
			extensionEnabled = false;
		}

		pgCtlStop(!extensionEnabled); // Force a shutdown if extension isn't enabled

		if (!extensionEnabled) {
			throw new IOException("Initialization failed: BSim extension could not be enabled");
		}

		System.out.println("Initialization complete; run \"bsim_ctl " + COMMAND_START + " " +
			dataDirectory.getAbsolutePath() + "\" to start the server");
	}

	/**
	 * Start a previously-initialized PostgreSQL server on the local host.  No configuration is
	 * performed; the data directory must already have been initialized with {@code bsim_ctl init}.
	 * @throws IOException if the data directory is not initialized or the server cannot be started
	 * @throws InterruptedException if the process fails during the run
	 */
	private void startCommand() throws IOException, InterruptedException {
		resolveDeployment(false, false);
		discoverPostgresInstall();
		if (isServiceInstalled()) {
			systemctlLifecycle("start");
			return;
		}
		loadConfiguration();
		pgCtlStart();
		System.out.println("Server started");
	}

	/**
	 * Run "pg_ctl start" for the current data directory, waiting for the server to be ready.
	 * @throws IOException if the server cannot be started
	 * @throws InterruptedException if the process is interrupted
	 */
	private void pgCtlStart() throws IOException, InterruptedException {
		File logFile = new File(dataDirectory, "logfile");
		List<String> command = new ArrayList<String>();
		command.add(postgresControl.getAbsolutePath());
		command.add("start");
		command.add("-w");
		command.add("-D");
		command.add(dataDirectory.getAbsolutePath());
		command.add("-l");
		command.add(logFile.getAbsolutePath());
		int res = runPostgresCommand(command);
		if (res != 0) {
			throw new IOException("Could not start postgres server process");
		}
	}

	/**
	 * Restart a previously-initialized PostgreSQL server on the local host.  No configuration is
	 * performed.
	 * @throws IOException if the data directory is not initialized or the server cannot be restarted
	 * @throws InterruptedException if the process fails during the run
	 */
	private void restartCommand() throws IOException, InterruptedException {
		resolveDeployment(false, false);
		discoverPostgresInstall();
		if (isServiceInstalled()) {
			systemctlLifecycle("restart");
			return;
		}
		
		if (!isPostmasterRunning()) {
			startCommand();
			return;
		}

		loadConfiguration();
		File logFile = new File(dataDirectory, "logfile");
		List<String> command = new ArrayList<String>();
		command.add(postgresControl.getAbsolutePath());
		command.add("restart");
		command.add("-w");
		command.add("-D");
		command.add(dataDirectory.getAbsolutePath());
		command.add("-l");
		command.add(logFile.getAbsolutePath());
		if (forceShutdown) {
			command.add("-m");
			command.add("fast");
		}
		int res = runPostgresCommand(command);
		if (res != 0) {
			throw new IOException("Could not restart postgres server process");
		}
		System.out.println("Server restarted");
	}

	/**
	 * Stop the running PostgreSQL processes on the local host. No authentication is required to shutdown
	 * the server.  User must be the process owner.
	 * @throws IOException if postgres cannot be discovered or stopped
	 * @throws InterruptedException if the stop command is interrupted
	 */
	private void stopCommand() throws IOException, InterruptedException {
		resolveDeployment(false, false);
		discoverPostgresInstall();
		if (isServiceInstalled()) {
			systemctlLifecycle("stop");
			return;
		}
		if (!isPostmasterRunning()) {
			System.out.println("Server has not been started");
		}
		else {
			pgCtlStop(forceShutdown);
			System.out.println("Server shutdown complete");
		}
	}

	/**
	 * Run "pg_ctl stop" for the current data directory.
	 * @param fast if true use "fast" shutdown mode (does not wait for clients to disconnect,
	 *   all active transactions are rolled back)
	 * @throws IOException if the server cannot be stopped
	 * @throws InterruptedException if the process is interrupted
	 */
	private void pgCtlStop(boolean fast) throws IOException, InterruptedException {
		List<String> command = new ArrayList<String>();
		command.add(postgresControl.getAbsolutePath());
		command.add("stop");
		command.add("-D");
		command.add(dataDirectory.getAbsolutePath());
		if (fast) {
			command.add("-m");
			command.add("fast");		// Does not wait for clients to disconnect, all active transactions rolled back
		}
		int res = runPostgresCommand(command);
		if (res != 0) {
			throw new IOException("Error shutting down postgres server process");
		}
	}

	/**
	 * Retrieve the status of a PostgreSQL server.
	 * @throws IOException if server status can not be retrieved
	 * @throws InterruptedException if the status command is interrupted
	 */
	private void statusCommand() throws IOException, InterruptedException {
		resolveDeployment(false, false);
		discoverPostgresInstall();
		loadConfiguration();
		
		System.out.println("BSim PostgreSQL status: " + dataDirectory.getAbsolutePath());
		System.out.println("  Owner          : " + ownerName);
		System.out.println("  Port           : " + port);
		
		String authMode = authModeName(hostAuthentication);
		System.out.println("  Authentication : " + authMode + "   (local connections: " +
			authModeName(localAuthentication) + ")");
		if (hostAuthentication == AUTHENTICATION_PKI || localAuthentication == AUTHENTICATION_PKI) {
			System.out.println("  Certificate ID : " + certificateNameLabel());
		}
		System.out.println("  Remote access  : " +
			(remoteAccessConfigured ? "ENABLED" : "DISABLED (loopback only)"));

		boolean running = isPostmasterRunning();
		Properties marker = readServiceMarker();
		if (marker != null) {
			String unit = marker.getProperty("unitName");
			String enabled = isLinux() ? systemctlQuery("is-enabled", unit) : "unknown";
			System.out.println(
				"  Service        : INSTALLED  unit=" + unit + "  scope=system  " + enabled);
			String svcUser = marker.getProperty("user");
			if (svcUser != null && !svcUser.equals(ownerName)) {
				System.out.println("  WARNING        : data directory owner (" + ownerName +
					") != service user (" + svcUser + ")");
			}
			String active = isLinux() ? systemctlQuery("is-active", unit) : "unknown";
			
			System.out.println("  Status         : " +
				(running ? "RUNNING (via service)" : "STOPPED") + "  [systemctl status: " +
				active + "]");
		}
		else {
			System.out.println("  Service        : NOT INSTALLED");
			System.out.println("  Status         : " +
				(running ? "RUNNING (standalone)" : "STOPPED"));
		}
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
		int res = runPostgresCommand(command);
		if (res != 0) {
			throw new IOException("Error creating new user");
		}
	}

	/**
	 * Update the PostgreSQL identity map (pg_ident.conf) adding a map from the currently active
	 * certificate name - the full {@code codistinguishedName}, or only its {@code commonName} for a deployment
	 * which registers that instead (see {@link #recoverCertificateNameMode(ServerConfig)}) - to
	 * {@code username}.
	 * @param username the user name to add
	 * @throws IOException if the postgres ident file is invalid
	 */
	private void addCertificateName(String username) throws IOException {
		File identFile = new File(dataDirectory, POSTGRES_IDENTFILE);
		File copyFile = new File(dataDirectory, POSTGRES_IDENTFILE + ".copy");
		if (!identFile.isFile()) {
			throw new IOException("Missing ident file: " + identFile.getAbsolutePath());
		}
		ServerConfig.patchIdent(identFile, copyFile, POSTGRES_MAP_IDENTIFIER,
			certificateSystemName(), username, true);
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
		resolveDeployment(false, false);
		discoverPostgresInstall();
		loadConfiguration();			// Needed to pick up authentication settings
		boolean pkiAuthentication = (hostAuthentication == AUTHENTICATION_PKI
				|| localAuthentication == AUTHENTICATION_PKI);
		if (pkiAuthentication) {
			if (distinguishedName == null) {
				throw new GeneralSecurityException("The distinguished name (" + DN_OPTION +
					") of the user's certificate is required");
			}
			// Only a legacy deployment which registers the common name alone requires the distinguished
			// name to carry one
			if (!useDistinguishedName && commonName == null) {
				throw new GeneralSecurityException(
					"The distinguished name (" + DN_OPTION +
						") does not have a required common name (CN): " + distinguishedName);
			}
		}

		boolean resetPassword = (hostAuthentication == AUTHENTICATION_PASSWORD
				|| localAuthentication == AUTHENTICATION_PASSWORD);
		adminPasswordData = null;
		
		localConnection = getOrCreateLocalConnection();

		StringBuilder buffer = new StringBuilder();
		buffer.append("CREATE ROLE ");
		Utils.escapeIdentifier(buffer, specifiedUserName);
		buffer.append(" WITH LOGIN");

		try (Statement st = localConnection.createStatement()) {
			st.executeUpdate(buffer.toString());
			System.out.println("Added user '" + specifiedUserName + "'");
		}
		catch (SQLException err) {
			if (!err.getMessage().contains("already exists")) {		// Suppress already exists exception
				throw err;
			}
			resetPassword = false;
			System.err.println("User '" + specifiedUserName + "' already exists");
		}
		finally {
			if (resetPassword) {
				resetPassword(localConnection, specifiedUserName);
			}
			localConnection.close();
		}

		if (pkiAuthentication) {
			addCertificateName(specifiedUserName);
			normalizeOwnership();		// pg_ident.conf rewritten in-process; re-own to OWNER
			reloadIdent();
			System.out.println("Linking certificate " + certificateNameLabel() + " '" +
				certificateSystemName() + "' to user: " + specifiedUserName);
			return;
		}
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
			System.out.println("Error creating connection to local Postgres database");
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
		resolveDeployment(false, false);
		discoverPostgresInstall();
		loadConfiguration();
		boolean userDoesNotExist = false;
		localConnection = getOrCreateLocalConnection();
		StringBuilder buffer = new StringBuilder();
		buffer.append("DROP ROLE ");
		Utils.escapeIdentifier(buffer, specifiedUserName);

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
			// An entry is removed by the role it maps to, so the certificate name it was registered
			// with is neither needed nor available here
			ServerConfig.patchIdent(identFile, copyFile, POSTGRES_MAP_IDENTIFIER, null,
				specifiedUserName, false);
			FileUtilities.copyFile(copyFile, identFile, false, null);
			normalizeOwnership();		// pg_ident.conf rewritten in-process; re-own to OWNER
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
	 * List all defined PostgreSQL users (login roles) on the currently running server along with
	 * their role.  A local connection is established and {@code pg_roles} is queried; each login
	 * role is reported as "admin" if it has superuser privileges (as granted by
	 * {@link #changePrivilegeCommand()}), otherwise "user".
	 * <p>
	 * When the deployment is configured for PKI authentication the certificate name registered for
	 * each user within the identity map ({@value #POSTGRES_IDENTFILE}) is reported as well: their
	 * full distinguished name, or only its common name for a deployment which registers that
	 * instead (see {@link #recoverCertificateNameMode(ServerConfig)}).  A user with no registered
	 * name is unable to authenticate and is reported as such.
	 * @throws Exception if there's a problem getting a connection to the Postgres database
	 */
	private void listUsersCommand() throws Exception {
		resolveDeployment(false, false);
		loadConfiguration();			// Needed to pick up the configured port and authentication
		boolean pkiAuthentication = (hostAuthentication == AUTHENTICATION_PKI
				|| localAuthentication == AUTHENTICATION_PKI);
		Map<String, List<String>> certificateNames =
			pkiAuthentication ? readCertificateNames() : Map.of();
		localConnection = getOrCreateLocalConnection();
		String query =
			"SELECT rolname, rolsuper FROM pg_roles WHERE rolcanlogin ORDER BY rolname";
		try (Statement st = localConnection.createStatement();
				ResultSet rs = st.executeQuery(query)) {
			System.out.println("Defined users: " + dataDirectory.getAbsolutePath());
			if (!pkiAuthentication) {
				System.out.println(String.format("  %-32s %s", "USER", "ROLE"));
			}
			else {
				System.out.println(String.format("  %-32s %-6s %s", "USER", "ROLE",
					useDistinguishedName ? "CERTIFICATE DN" : "CERTIFICATE CN"));
			}
			while (rs.next()) {
				String rolname = rs.getString("rolname");
				String role = rs.getBoolean("rolsuper") ? "admin" : "user";
				if (!pkiAuthentication) {
					System.out.println(String.format("  %-32s %s", rolname, role));
					continue;
				}
				List<String> names = certificateNames.getOrDefault(rolname, List.of());
				System.out.println(String.format("  %-32s %-6s %s", rolname, role,
					names.isEmpty() ? "<none registered>" : names.get(0)));
				for (int i = 1; i < names.size(); i++) {	// user registered with more than one
					System.out.println(String.format("  %-32s %-6s %s", "", "", names.get(i)));
				}
			}
		}
		finally {
			localConnection.close();
		}
	}

	/**
	 * Read the certificate identity mappings which are registered within the PostgreSQL identity
	 * file ({@value #POSTGRES_IDENTFILE}) of the current data directory.
	 * @return the certificate names registered for each database user (role)
	 * @throws IOException if the identity file is missing or cannot be parsed
	 */
	private Map<String, List<String>> readCertificateNames() throws IOException {
		File identFile = new File(dataDirectory, POSTGRES_IDENTFILE);
		if (!identFile.isFile()) {
			throw new IOException("Missing ident file: " + identFile.getAbsolutePath());
		}
		return ServerConfig.scanIdent(identFile, POSTGRES_MAP_IDENTIFIER);
	}

	/**
	 * The data directory for a server (which must be running) is reconfigured with new local and
	 * remote authentication options, and the port may be reconfigured as well.  Database records
	 * are unaltered.  The user submits the {@code --auth}, {@code --noLocalAuth},
	 * {@code --cafile}, {@code --keystore} and {@code --port} options on the command line: among
	 * those submitted, any option that doesn't match the current configuration is changed.
	 * <p>
	 * The server must be running so that the invoking user can be authenticated with the admin role
	 * before any authentication change is permitted, and so that any credential the change requires
	 * (a password, or a certificate identity mapping) is put in place first.  The configuration
	 * files are only consumed by the server when it starts, so the server is left running and the
	 * changes take effect when it is next restarted.
	 * @throws IOException if the server is not running or a file operation fails
	 * @throws SAXException if the {@link #tuneConfig(File, File, File, File, File, boolean, boolean)} call fails
	 * @throws GeneralSecurityException if certificate or distinguished name handling fails
	 * @throws Exception if the admin connection cannot be established
	 */
	private void configureCommand() throws Exception {
		resolveDeployment(false, false);
		discoverPostgresInstall();
		File configFile = new File(dataDirectory, POSTGRES_CONFIGFILE);
		File hbaFile = new File(dataDirectory, POSTGRES_CONNECTFILE);
		if (!configFile.exists()) {
			throw new IOException("Data directory not initialized: run \"bsim_ctl " + COMMAND_INIT +
				" " + dataDirectory.getAbsolutePath() + "\" first");
		}
		int requestedLocalAuth = localAuthentication;
		int requestedHostAuth = hostAuthentication;
		int requestedPort = port;
		port = -1;
		recoverConfigurationParameters(configFile, hbaFile);
		if (!isServerRunning()) {
			throw new IOException("Server must be running to change its configuration: run " +
				"\"bsim_ctl " + COMMAND_START + " " + dataDirectory.getAbsolutePath() + "\" first");
		}

		// The --auth option establishes both the host and local authentication, whereas
		// --noLocalAuth on its own only downgrades local authentication and must leave the
		// configured authentication mode as-is
		boolean hostAuthChange = authOptionPresent && (requestedHostAuth != hostAuthentication);
		boolean localAuthChange = authConfigPresent && (requestedLocalAuth != localAuthentication);
		int newLocalAuth = localAuthChange ? requestedLocalAuth : localAuthentication;
		int newHostAuth = hostAuthChange ? requestedHostAuth : hostAuthentication;

		// A key store establishes the server certificate and enables remote access; one already
		// installed by a previous configuration remains in place, which is what a recovered
		// non-loopback binding indicates.
		boolean keystorePresent = (keystoreFile != null) || remoteAccessConfigured;

		boolean newLocalPki = localAuthChange && (newLocalAuth == AUTHENTICATION_PKI);
		boolean newRemotePki = hostAuthChange && (newHostAuth == AUTHENTICATION_PKI);
		boolean pkiInEffect =
			(newLocalAuth == AUTHENTICATION_PKI) || (newHostAuth == AUTHENTICATION_PKI);

		// A newly specified certificate authority file replaces the authorities the server trusts
		// (root.crt) and is therefore a change in its own right, provided pki is in effect
		boolean certAuthorityChange = (certAuthorityFile != null) && pkiInEffect;
		if (!pkiInEffect) {
			warnUnusedCertAuthorityOption();
		}
		if (!hostAuthChange && !localAuthChange && !certAuthorityChange &&
			(requestedPort == -1 || requestedPort == port) && keystoreFile == null) {
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
		boolean newPasswordAuth = (localAuthChange && newLocalAuth == AUTHENTICATION_PASSWORD) ||
			(hostAuthChange && newHostAuth == AUTHENTICATION_PASSWORD);

		// A transition to pki requires the admin user's certificate identity, so that their
		// PostgreSQL identity mapping is established for the new authentication mode.  Replacing
		// the certificate authorities of a deployment which already uses pki requires it as well:
		// their certificate must be issued by the incoming authority, and the mapping must match
		// the certificate they will present, or the change would lock them out of the server.
		if (newLocalPki || newRemotePki || certAuthorityChange) {
			establishPkiIdentity();
		}

		// Any authentication change requires that the invoking user prove they hold the admin role,
		// unless authentication is being removed entirely - which is also the means of recovering
		// from a lost password or certificate
		if ((hostAuthChange || localAuthChange || certAuthorityChange) &&
			(newLocalAuth != AUTHENTICATION_NONE || newHostAuth != AUTHENTICATION_NONE)) {
			localConnection = verifyAdminAuthentication();
			try {
				// A transition to password authentication when the admin user has no password
				// established would leave them unable to connect once the change takes effect
				if (newPasswordAuth) {
					if (!hasPassword(localConnection)) {
						establishNewPassword(localConnection);
					}
					else {
						System.out.println("Existing DB password for user '" + connectingUserName +
							"' remains in effect");
					}
				}
			}
			finally {
				localConnection.close();
			}
		}

		// Beyond this point the configuration is modified; the running server is unaffected since
		// it only consumes these files when started
		if (requestedPort != -1 && requestedPort != port) {
			port = requestedPort;
			System.out.println("Server will now listen on port " + Integer.toString(port));
		}
		if (localAuthChange) {
			localAuthentication = newLocalAuth;
			System.out.println("New local authentication: " + authModeName(localAuthentication));
		}
		if (hostAuthChange) {
			hostAuthentication = newHostAuth;
			System.out.println("New host authentication: " + authModeName(hostAuthentication));
		}
		if (newLocalPki || newRemotePki || certAuthorityChange) {
			if (certAuthorityChange) {
				// Install the newly specified authorities; without the option the authorities
				// already installed (and re-validated above) remain in place
				File rootCA = new File(dataDirectory, POSTGRES_ROOTCA);
				FileUtilities.copyFile(certAuthorityFile, rootCA, false, null);
				System.out.println("Installed certificate authority file: " + POSTGRES_ROOTCA);
			}
			addCertificateName(connectingUserName);
			System.out.println("Linking certificate " + certificateNameLabel() + " '" +
				certificateSystemName() + "' to user: " + connectingUserName);
		}

		tuneConfig(configCopy, configFile, hbaCopy, hbaFile, serverConfigFile, keystorePresent, false);
		
		File certFile = new File(dataDirectory, POSTGRES_CERTFILE);
		File keyFile = new File(dataDirectory, POSTGRES_KEYFILE);
		if (keystoreFile != null) {
			System.out.println("Importing server certificate from key store");
			importServerCertificate(keystoreFile, certFile,	keyFile);
		}
		saveDeploymentConfig();		// record the --auth mode for subsequent invocations
		normalizeOwnership();		// re-own any root-created files to OWNER

		if (newPasswordAuth) {
			System.out.println("NOTE: any other existing user may not have a DB password; after " +
				"restarting use the " + COMMAND_RESET_PASSWORD + " command for each");
		}
		if (newLocalPki || newRemotePki) {
			System.out.println("NOTE: any other existing user requires a certificate identity " +
				"mapping; after restarting use the " + COMMAND_ADDUSER + " command with the " +
				DN_OPTION + " option for each");
		}
		else if (certAuthorityChange) {
			System.out.println("NOTE: after restarting, every other user must present a certificate " +
				"issued by an authority within the installed " + POSTGRES_ROOTCA);
		}
		System.out.println("Configuration updated; changes take effect when the server is " +
			"restarted: bsim_ctl " + COMMAND_RESTART + " " + dataDirectory.getAbsolutePath());
	}

	/**
	 * Reset the password for -username- to DEFAULT_PASSWORD
	 * @param pdb is the connection over which to issue the command
	 * @param username is the user name to reset
	 * @throws SQLException if the sql query fails
	 */
	private void resetPassword(Connection pdb, String username) throws SQLException {
		StringBuilder buffer = new StringBuilder();
		buffer.append("ALTER ROLE ");
		Utils.escapeIdentifier(buffer, username);
		buffer.append(" WITH PASSWORD '");
		buffer.append(DEFAULT_PASSWORD);
		buffer.append('\'');
		executeSQLStatement(pdb, buffer.toString());
		System.out.println("DB password for user '" + username + "' reset to '" + DEFAULT_PASSWORD + "'");
	}

	/**
	 * Verify that the invoking user is able to authenticate with the running server, using the
	 * authentication currently configured, and holds the admin role.  This is required before any
	 * authentication change is made so that an administrator cannot lock themself, or others, out
	 * of a server they are unable to access.
	 * @return the established admin connection which the caller must close
	 * @throws IOException if the user cannot be authenticated or lacks the admin role
	 * @throws Exception if the connection cannot be established
	 */
	private Connection verifyAdminAuthentication() throws Exception {
		Connection pdb = getOrCreateLocalConnection();
		boolean verified = false;
		try (Statement st = pdb.createStatement();
				ResultSet rs = st.executeQuery(
					"SELECT rolsuper FROM pg_roles WHERE rolname = CURRENT_USER")) {
			if (!rs.next()) {
				throw new IOException(
					"Unable to determine role privilege for user: " + connectingUserName);
			}
			if (!rs.getBoolean(1)) {
				throw new IOException("User '" + connectingUserName +
					"' does not have the admin role required to change the configuration");
			}
			verified = true;
		}
		finally {
			if (!verified) {
				pdb.close();
			}
		}
		System.out.println("Authenticated '" + connectingUserName + "' (admin)");
		return pdb;
	}

	/**
	 * Determine if the connected user has a database password established.  Used when transitioning
	 * to password authentication to detect the case where they would otherwise be unable to
	 * authenticate after the change takes effect.
	 * @param pdb is the connection over which to issue the query
	 * @return true if a password is established, false if not (or if it cannot be determined)
	 */
	private boolean hasPassword(Connection pdb) {
		try (Statement st = pdb.createStatement();
				ResultSet rs = st.executeQuery(
					"SELECT rolpassword IS NOT NULL FROM pg_authid WHERE rolname = CURRENT_USER")) {
			return rs.next() && rs.getBoolean(1);
		}
		catch (SQLException e) {
			Msg.warn(this, "Unable to determine if a password is established for " +
				connectingUserName + ": " + e.getMessage());
			return false;		// assume not established so a new password is requested
		}
	}

	/**
	 * Prompt for, and establish, a new database password for the connected admin user.  The
	 * password must be in place before the transition to password authentication takes effect,
	 * which occurs when the server is next restarted.
	 * @param pdb is the connection over which to issue the command
	 * @throws IOException if a new password cannot be obtained
	 * @throws SQLException if the password cannot be established
	 */
	private void establishNewPassword(Connection pdb) throws IOException, SQLException {
		char[] newPassword = requestNewPassword();
		try {
			StringBuilder buffer = new StringBuilder();
			buffer.append("ALTER ROLE ");
			Utils.escapeIdentifier(buffer, connectingUserName);
			buffer.append(" WITH PASSWORD '");
			Utils.escapeLiteral(buffer, new String(newPassword), true);
			buffer.append('\'');
			executeSQLStatement(pdb, buffer.toString());
		}
		finally {
			clearPasswordData(newPassword);
		}
		System.out.println("DB password established for user '" + connectingUserName + "'");
	}

	/**
	 * Prompt on the console for a new database password, which must be entered twice and match.
	 * @return the new password which must be cleared by the caller when done using it
	 * @throws IOException if a password entry could not be obtained
	 */
	private char[] requestNewPassword() throws IOException {
		for (;;) {
			char[] newPassword =
				requestPassword("New " + connectingUserName + " (admin) DB password:");
			if (newPassword == null) {
				throw new IOException("Failed to obtain password");
			}
			char[] repeatPassword = requestPassword("Please re-enter DB password:");
			boolean match =
				newPassword.length != 0 && comparePasswordData(newPassword, repeatPassword);
			clearPasswordData(repeatPassword);
			if (match) {
				return newPassword;
			}
			boolean blank = newPassword.length == 0;
			clearPasswordData(newPassword);
			System.out.println(blank ? "Password may not be blank" : "Passwords do not match");
		}
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
			StringBuilder buffer = new StringBuilder("ALTER ROLE ");
			Utils.escapeIdentifier(buffer, specifiedUserName);
			if (adminPrivilegeRequested) {
				System.out.println("Granting admin privileges to " + specifiedUserName);
				buffer.append(" SUPERUSER CREATEROLE CREATEDB");
			}
			else {
				System.out.println("Revoking admin privileges from " + specifiedUserName);
				buffer.append(" NOSUPERUSER NOCREATEROLE NOCREATEDB");
			}
			executeSQLStatement(localConnection, buffer.toString());
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
				case COMMAND_INIT:
					initCommand();
					break;
				case COMMAND_START:
					startCommand();
					break;
				case COMMAND_STOP:
					stopCommand();
					break;
				case COMMAND_RESTART:
					restartCommand();
					break;
				case COMMAND_STATUS:
					statusCommand();
					break;
				case COMMAND_INSTALL_SERVICE:
					installServiceCommand();
					break;
				case COMMAND_UNINSTALL_SERVICE:
					uninstallServiceCommand();
					break;
				case COMMAND_ADDUSER:
					addUserCommand();
					break;
				case COMMAND_DROPUSER:
					dropUserCommand();
					break;
				case COMMAND_LISTUSERS:
					listUsersCommand();
					break;
				case COMMAND_CONFIGURE:
					configureCommand();
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
				Msg.error(this, e.getMessage(), e);
			}
		}
	}

	private static void printUsage() {
		//@formatter:off
		System.err.println("\n" + 
			"USAGE: bsim_ctl [command]  required-args... [OPTIONS...]\n\n" +
			"                init       </datadir-path> [--keystore|-k \"</keystore-path>\"] [--auth|-a pki|password|trust] [--noLocalAuth]\n"+
			"                                           [--cafile|-ca \"</cacert-path>\"] [--port|-p <portnum>] [--os-user <account>]\n" +
			"                configure  </datadir-path> [--keystore|-k \"</keystore-path>\"] [--auth|-a pki|password|trust] [--noLocalAuth]\n" +
			"                                           [--cafile|-ca \"</cacert-path>\"] [--port|-p <portnum>]\n" +
			"                start      </datadir-path>\n" +
			"                stop       </datadir-path> [--force|-f]\n" +
			"                restart    </datadir-path> [--force|-f]\n" +
			"                status     </datadir-path>\n" +
			"                install-service   </datadir-path>   (root only)\n" +
			"                uninstall-service </datadir-path>   (root only)\n" +
			"                adduser    </datadir-path> <username> [--dn|-dn \"<distinguished-name>\"]\n" +
			"                dropuser   </datadir-path> <username>\n" +
			"                listusers  </datadir-path>\n" +
			"                resetpassword   <username> [--port|-p <portnum>]\n" +
			"                changeprivilege <username> admin|user [--port|-p <portnum>]\n" +
			"\n" +
			"   Global options:\n" +
			"      --user|-u <username>\n" +
			"      --cert </certfile-path>\n" +
			"      --verbose|-v\n" +
			"\n" +
			"NOTES:\n\n" +
			"1. The server must be started for the following commands to work:\n" + 
			"   'configure', 'adduser', 'dropuser', 'listusers', 'resetpassword', 'changeprivilege'\n\n" +
			"2. Options with values may also be specified using the form: --option=value\n\n" +
			"3. If the --port option is omitted or has a negative value the default PostgreSQL port 5432 will be used.\n\n" +
			"4. A 'configure' change takes effect when the server is next restarted; the invoking user must be\n" +
			"   able to authenticate with the admin role before any authentication change is permitted.\n\n" +
			"5. The --cert option is required by 'init' and 'configure' for PKI authentication; the admin user's\n" +
			"   distinguished name (DN) and common name (CN) are obtained from that certificate and verified\n" +
			"   against the --cafile certificate authorities.  The --dn option is only used by 'adduser', where it\n" +
			"   is required when PKI authentication is used.\n\n" +
			"6. The --cafile file must be an unencrypted PEM file which provides a complete chain of trust for\n" +
			"   every certificate authority it contains.  It is required by 'init' for PKI authentication, and\n" +
			"   may be omitted by 'configure' to retain the authorities already installed.\n\n" +
			"7. A PKI server initialized by this version of Ghidra matches each user's full certificate\n" +
			"   distinguished name (DN), whereas one initialized by an earlier version continues to match only\n" +
			"   the common name (CN) which its existing user entries were registered with.  'configure' and\n" +
			"   'adduser' follow whichever the server is configured for, and 'status'/'listusers' report it.\n" +
			"   Specify --dn in RFC 2253 form, exactly as the certificate subject is rendered by the openssl command:\n" +
			"      openssl x509 -noout -subject -nameopt RFC2253 -in <certfile>\n\n"
		);
		  
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
			System.err.println("Certificate error");
			System.err.println(e.getMessage());
		}
		catch (IllegalArgumentException e) {
			System.err.println("Error in command line arguments");
			System.err.println(e.getMessage());
		}
		catch (IOException e) {
			System.err.println("Error in command processing");
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
						System.out.println(" " + line);
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
