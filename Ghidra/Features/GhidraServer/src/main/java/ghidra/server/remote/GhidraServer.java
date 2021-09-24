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
package ghidra.server.remote;

import static ghidra.server.remote.GhidraServer.AuthMode.*;

import java.io.*;
import java.net.*;
import java.rmi.NoSuchObjectException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.*;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.List;

import javax.rmi.ssl.SslRMIClientSocketFactory;
import javax.rmi.ssl.SslRMIServerSocketFactory;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.x500.X500Principal;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import generic.jar.ResourceFile;
import generic.random.SecureRandomFactory;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.remote.*;
import ghidra.net.ApplicationKeyManagerFactory;
import ghidra.net.SSLContextInitializer;
import ghidra.server.RepositoryManager;
import ghidra.server.UserManager;
import ghidra.server.security.*;
import ghidra.server.stream.BlockStreamServer;
import ghidra.server.stream.RemoteBlockStreamHandle;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.DuplicateNameException;
import utilities.util.FileUtilities;
import utility.application.ApplicationLayout;

/**
 * <code>GhidraServer</code> provides the main Ghidra server application and
 * implements GhidraServerHandle which facilitates remote access to services
 * provided by a repository manager. The single instance of GhidraServer is set
 * within the RMI Registry which is accessible on a user specified port.
 */
public class GhidraServer extends UnicastRemoteObject implements GhidraServerHandle {

	private static final String SERIAL_FILTER_FILE = "serial.filter";

	private static final String TLS_SERVER_PROTOCOLS_PROPERTY = "ghidra.tls.server.protocols";

	private static SslRMIServerSocketFactory serverSocketFactory;
	private static SslRMIClientSocketFactory clientSocketFactory;
	private static InetAddress bindAddress;

	private static Logger log;

	private static String HELP_FILE = "ServerHelp.txt";
	private static String USAGE_ARGS =
		"[-ip <hostname>] [-i #.#.#.#] [-p#] [-n] [-a#] [-d<ad_domain>] [-e<days>] [-jaas <config_file>] [-u] [-autoProvision] [-anonymous] [-ssh] <repository_path>";

	private static final String RMI_SERVER_PROPERTY = "java.rmi.server.hostname";

	enum AuthMode {

		NO_AUTH_LOGIN("None"),
		PASSWORD_FILE_LOGIN("Password File"),
		KRB5_AD_LOGIN("Active Directory via Kerberos"),
		PKI_LOGIN("PKI"),
		JAAS_LOGIN("JAAS");

		private String description;

		AuthMode(String description) {
			this.description = description;
		}

		public String getDescription() {
			return description;
		}

		public static AuthMode fromIndex(int index) {
			//@formatter:off
			switch ( index) {
				case 0: return PASSWORD_FILE_LOGIN;
				case 1: return KRB5_AD_LOGIN;
				case 2: return PKI_LOGIN;
				case 4: return JAAS_LOGIN;
				default: return null;
			}
			//@formatter:on
		}
	}

	private static GhidraServer server;

	private RepositoryManager mgr;
	private AuthenticationModule authModule;
	private SSHAuthenticationModule sshAuthModule; // only supported in conjunction with password authentication modes (0 & 1)
	private AnonymousAuthenticationModule anonymousAuthModule;
	private BlockStreamServer blockStreamServer;
	private boolean autoProvisionAuthedUsers;

	/**
	 * Server handle constructor.
	 *
	 * @param rootDir
	 *            root repositories directory for server
	 * @param authMode
	 *            authentication mode
	 * @param loginDomain
	 *            login domain or null (used for OS_PASSWORD_LOGIN mode only)
	 * @param allowUserToSpecifyName if true user name may be altered
	 * @param altSSHLoginAllowed if true SSH authentication will be permitted
	 * as an alternate form of authentication
	 * @param defaultPasswordExpirationDays number of days default password will be valid
	 * @param allowAnonymousAccess allow anonymous access if true
	 * @param autoProvisionAuthedUsers flag to turn on automatically adding successfully
	 * authenticated users to the user manager if they don't already exist
	 * @param jaasConfigFile JAAS configuration file
	 * @throws IOException if an IO error occurs
	 * @throws CertificateException if failed to parse CA certs file used for PKI authentication
	 */
	GhidraServer(File rootDir, AuthMode authMode, String loginDomain,
			boolean allowUserToSpecifyName, boolean altSSHLoginAllowed,
			int defaultPasswordExpirationDays, boolean allowAnonymousAccess,
			boolean autoProvisionAuthedUsers, File jaasConfigFile)
			throws IOException, CertificateException {

		super(ServerPortFactory.getRMISSLPort(), clientSocketFactory, serverSocketFactory);

		this.autoProvisionAuthedUsers = autoProvisionAuthedUsers;

		if (log == null) {
			// logger generally initialized by main method, however during
			// testing the main method may be bypassed
			log = LogManager.getLogger(GhidraServer.class);
		}

		if (allowAnonymousAccess) {
			anonymousAuthModule = new AnonymousAuthenticationModule();
		}

		boolean supportLocalPasswords = false;
		switch (authMode) {
			case PASSWORD_FILE_LOGIN:
				supportLocalPasswords = true;
				authModule = new PasswordFileAuthenticationModule(allowUserToSpecifyName);
				break;
			case PKI_LOGIN:
				if (altSSHLoginAllowed) {
					log.warn("SSH authentication option ignored when PKI authentication used");
					altSSHLoginAllowed = false;
				}
				SecureRandomFactory.getSecureRandom(); // incur initialization delay up-front
				authModule = new PKIAuthenticationModule(allowAnonymousAccess);
				break;
			case NO_AUTH_LOGIN:
				if (altSSHLoginAllowed) {
					log.warn("SSH authentication option ignored when no authentication used");
					altSSHLoginAllowed = false;
				}
				break;
			case JAAS_LOGIN:
				authModule =
					new JAASAuthenticationModule("auth", allowUserToSpecifyName, jaasConfigFile);
				break;
			case KRB5_AD_LOGIN:
				if (loginDomain == null || loginDomain.isBlank()) {
					throw new IllegalArgumentException("Missing login domain value -d<ad_domain>");
				}
				authModule = new Krb5ActiveDirectoryAuthenticationModule(loginDomain,
					allowUserToSpecifyName);
				break;
			default:
				throw new IllegalArgumentException("Unsupported Authentication mode: " + authMode);
		}

		if (altSSHLoginAllowed) {
			SecureRandomFactory.getSecureRandom(); // incur initialization delay up-front
			sshAuthModule = new SSHAuthenticationModule(allowUserToSpecifyName);
		}

		mgr = new RepositoryManager(rootDir, supportLocalPasswords, defaultPasswordExpirationDays,
			allowAnonymousAccess);

		GhidraServer.server = this;

		// Establish serialization filter to address deserialization vulnerabity concerns
		setGlobalSerializationFilter();

		// Start block stream server - use RMI serverSocketFactory
		blockStreamServer = BlockStreamServer.getBlockStreamServer();
		ServerSocket streamServerSocket;
		if (serverSocketFactory != null) {
			streamServerSocket =
				serverSocketFactory.createServerSocket(ServerPortFactory.getStreamPort());
		}
		else {
			streamServerSocket = new GhidraSSLServerSocket(ServerPortFactory.getStreamPort(),
				bindAddress, null, null, authMode == PKI_LOGIN);
		}
		blockStreamServer.startServer(streamServerSocket, initRemoteAccessHostname());
	}

	@Override
	public Callback[] getAuthenticationCallbacks() throws RemoteException {
		log.info("Authentication callbacks requested by " + RepositoryManager.getRMIClient());
		try {
			Callback[] callbacks =
				authModule != null ? authModule.getAuthenticationCallbacks() : null;
			if (sshAuthModule != null) {
				callbacks = sshAuthModule.addAuthenticationCallbacks(callbacks);
			}
			if (anonymousAuthModule != null &&
				(authModule == null || authModule.anonymousCallbacksAllowed())) {
				callbacks = anonymousAuthModule.addAuthenticationCallbacks(callbacks);
			}
			return callbacks;
		}
		catch (Throwable t) {
			log.error("Failed to generate authentication callbacks", t);
			throw new RemoteException("Failed to generate authentication callbacks", t);
		}
	}

	@Override
	public void checkCompatibility(int serverInterfaceVersion) throws RemoteException {
		if (serverInterfaceVersion > INTERFACE_VERSION) {
			throw new RemoteException(
				"Incompatible server interface, a newer Ghidra Server version is required.");
		}
		else if (serverInterfaceVersion < INTERFACE_VERSION) {
			throw new RemoteException(
				"Incompatible server interface, the minimum supported Ghidra version is " +
					MIN_GHIDRA_VERSION);
		}
	}

	@Override
	public RemoteRepositoryServerHandle getRepositoryServer(Subject user, Callback[] authCallbacks)
			throws LoginException, RemoteException {

		System.gc();

		GhidraPrincipal principal = GhidraPrincipal.getGhidraPrincipal(user);
		if (principal == null) {
			throw new FailedLoginException("GhidraPrincipal required");
		}

		boolean anonymousAccess = false;
		String username = principal.getName();
		if (anonymousAuthModule != null &&
			anonymousAuthModule.anonymousAccessRequested(authCallbacks)) {
			username = UserManager.ANONYMOUS_USERNAME;
			anonymousAccess = true;
			RepositoryManager.log(null, null, "Anonymous access allowed", principal.getName());
		}
		else if (authModule != null) {
			NameCallback nameCb =
				AuthenticationModule.getFirstCallbackOfType(NameCallback.class, authCallbacks);
			if (nameCb != null) {
				if (!authModule.isNameCallbackAllowed()) {
					RepositoryManager.log(null, null,
						"Illegal authentication callback: NameCallback not permitted", username);
					throw new LoginException("Illegal authentication callback");
				}
				String name = nameCb.getName();
				if (name == null) {
					RepositoryManager.log(null, null,
						"Illegal authentication callback: NameCallback must specify login name",
						username);
					throw new LoginException("Illegal authentication callback");
				}
				username = name;
			}
		}

		RepositoryManager.log(null, null, "Repository server handle requested", username);

		boolean supportPasswordChange = false;
		if (!anonymousAccess) {
			if (sshAuthModule != null && sshAuthModule.hasSignedSSHCallback(authCallbacks)) {
				// SSH is only supported in conjunction with password authentication
				try {
					username =
						sshAuthModule.authenticate(mgr.getUserManager(), user, authCallbacks);
				}
				catch (LoginException e) {
					RepositoryManager.log(null, null,
						"SSH Authentication failed (" + e.getMessage() + ")", username);
					throw e;
				}
			}
			else if (authModule != null) {
				try {
					username = authModule.authenticate(mgr.getUserManager(), user, authCallbacks);
					anonymousAccess = UserManager.ANONYMOUS_USERNAME.equals(username);
					if (!anonymousAccess) {
						if (!mgr.getUserManager().isValidUser(username)) {
							if (autoProvisionAuthedUsers) {
								try {
									mgr.getUserManager().addUser(username);
									RepositoryManager.log(null, null,
										"User '" + username + "' successful auto provision",
										username);
								}
								catch (DuplicateNameException | IOException e) {
									RepositoryManager.log(
										null, null, "User '" + username +
											"' auto provision failed.  Cause: " + e.getMessage(),
										username);
									throw new LoginException(
										"Error when trying to auto provision successfully authenticated user: " +
											username);
								}
							}
							else {
								RepositoryManager.log(null, null,
									"User successfully authenticated, but does not exist in Ghidra user list: " +
										username,
									null);
								// Throw LoginException instead of FailedLoginException to prevent
								// the user from being asked to retry the login, which might
								// lead them to try older/different passwords and get their system
								// account locked.
								throw new LoginException("Unknown user: " + username);
							}
						}
						RepositoryManager.log(null, null, "User '" + username + "' authenticated",
							principal.getName());
					}
				}
				catch (LoginException e) {
					RepositoryManager.log(null, null, "Login failed (" + e.getMessage() + ")",
						username);
					// Create new exceptions so we don't leak config info to the client.
					if (e instanceof FailedLoginException) {
						throw new FailedLoginException("User authentication failed");
					}
					throw new LoginException("User login system failure");
				}
				if (authModule instanceof PasswordFileAuthenticationModule) {
					supportPasswordChange = true;
				}
			}
			else if (!mgr.getUserManager().isValidUser(username)) {
				FailedLoginException e = new FailedLoginException("Unknown user: " + username);
				RepositoryManager.log(null, null, "Login failed (" + e.getMessage() + ")",
					username);
				throw e;
			}
		}
		if (anonymousAccess) {
			RepositoryManager.log(null, null, "Anonymous server access granted", null);
		}

		return new RepositoryServerHandleImpl(username, anonymousAccess, mgr,
			supportPasswordChange);
	}

	/**
	 * Dispose the entire server.
	 */
	public void dispose() {
		try {
			unexportObject(this, true);
		}
		catch (NoSuchObjectException e) {
			// don't care?
		}
		if (mgr != null) {
			mgr.dispose();
			mgr = null;
			log.info("Ghidra server terminated.");
		}
		if (server == this) {
			server = null;
			// RMIClassServer.stopServer();
		}
		if (blockStreamServer != null && blockStreamServer.isRunning()) {
			blockStreamServer.stopServer();
			blockStreamServer = null;
		}
	}

	/**
	 * Display an optional message followed by usage syntax.
	 *
	 * @param msg
	 */
	private static void displayUsage(String msg) {
		if (msg != null) {
			System.out.println(msg);
		}
		System.out.println("Usage: java " + GhidraServer.class.getName() + USAGE_ARGS);
	}

	private static void displayHelp() {

		try (InputStream in = GhidraServer.class.getResourceAsStream(HELP_FILE)) {
			List<String> lines = FileUtilities.getLines(in);
			lines.stream().forEach(s -> System.out.println(s));
		}
		catch (IOException e) {
			// don't care
		}
	}

	private static final int IP_INTERFACE_RETRY_TIME_SEC = 5;
	private static final int IP_INTERFACE_MAX_RETRIES = 12; // 1-minute

	private static InetAddress findHost() {

		for (int attempt = 0; attempt < IP_INTERFACE_MAX_RETRIES; ++attempt) {
			try {
				if (attempt != 0) {
					log.warn("Failed to discover IP interface - retry in " +
						IP_INTERFACE_RETRY_TIME_SEC + " seconds...");
					Thread.sleep(IP_INTERFACE_RETRY_TIME_SEC * 1000);
				}
				Enumeration<NetworkInterface> e = NetworkInterface.getNetworkInterfaces();
				while (e.hasMoreElements()) {
					NetworkInterface nic = e.nextElement();
					Enumeration<InetAddress> e2 = nic.getInetAddresses();
					while (e2.hasMoreElements()) {
						InetAddress ia = e2.nextElement();
						if (!ia.isLoopbackAddress()) {
							if (attempt != 0) {
								log.info("Discovered IP interface: " + ia.getHostAddress());
							}
							return ia;
						}
					}
				}
				log.info("No interfaces found: using loopback interface");
				return InetAddress.getLoopbackAddress();
			}
			catch (SocketException e) {
				// ignore
			}
			catch (InterruptedException e) {
				break;
			}
		}
		return null;
	}

	private static String initRemoteAccessHostname() throws UnknownHostException {
		String hostname = System.getProperty(RMI_SERVER_PROPERTY);
		if (hostname == null) {
			if (bindAddress != null) {
				hostname = bindAddress.getHostAddress();
			}
			else {
				InetAddress localhost = InetAddress.getLocalHost();
				if (localhost.isLoopbackAddress()) {
					localhost = findHost();
					if (localhost == null) {
						log.fatal("Can't find host ip address!");
						System.exit(-1);
					}
				}
				hostname = localhost.getHostAddress();
			}
			System.setProperty(RMI_SERVER_PROPERTY, hostname);
		}
		return hostname;
	}

	private static File getServerCfgFile(String cfgFileName) {
		File tmp = new File(cfgFileName);
		if (tmp.isAbsolute()) {
			return tmp;
		}

		ResourceFile serverRoot = new ResourceFile(Application.getInstallationDirectory(),
			SystemUtilities.isInDevelopmentMode() ? "ghidra/Ghidra/RuntimeScripts/Common/server"
					: "server");
		if (serverRoot == null || serverRoot.getFile(false) == null) {
			System.err.println(
				"Failed to resolve installation root directory!: " + serverRoot.getAbsolutePath());
			System.exit(-1);
		}
		return new File(serverRoot.getFile(false), cfgFileName);
	}

	/**
	 * Main method for starting the Ghidra server.
	 *
	 * @param args  command line arguments
	 */
	public static synchronized void main(String[] args) {

		if (serverSocketFactory != null) {
			throw new IllegalStateException("Server previously started within JVM");
		}

		if (args.length == 0) {
			displayHelp();
			System.exit(-1);
		}

		if (server != null) {
			throw new AssertException("Server already started");
		}

		int basePort = DEFAULT_PORT;
		AuthMode authMode = NO_AUTH_LOGIN;
		boolean nameCallbackAllowed = false;
		boolean altSSHLoginAllowed = false;
		boolean allowAnonymousAccess = false;
		String loginDomain = null;
		String rootPath = null;
		int defaultPasswordExpiration = -1;
		boolean autoProvision = false;
		File jaasConfigFile = null;

		// Network name resolution disabled by default
		InetNameLookup.setLookupEnabled(false);

		// Initialize application
		try {
			ApplicationLayout layout = new GhidraServerApplicationLayout();
			ApplicationConfiguration configuration = new ApplicationConfiguration();
			configuration.setInitializeLogging(false);
			Application.initializeApplication(layout, configuration);
		}
		catch (IOException e) {
			System.err.println("Failed to initialize the application!");
			System.exit(-1);
		}

		// Process command line options
		for (int i = 0; i < args.length; i++) {
			String s = args[i];
			if (s.startsWith("-p")) { // RMI Registry Server Port option
				try {
					basePort = Integer.parseInt(s.substring(2));
				}
				catch (NumberFormatException e1) {
					basePort = -1;
				}
				if (basePort <= 0 || basePort > 65535) {
					displayUsage("Invalid registry port specified");
					System.exit(-1);
				}
			}
			else if (s.startsWith("-a") && s.length() == 3) { // Authentication Mode
				int authModeNum = Integer.MIN_VALUE;
				try {
					authModeNum = Integer.parseInt(s.substring(2));
				}
				catch (NumberFormatException e1) {
					displayUsage("Invalid option: " + s);
					System.exit(-1);
				}

				authMode = AuthMode.fromIndex(authModeNum);

				if (authMode == null) {
					displayUsage("Invalid authentication mode: " + s);
					System.exit(-1);
				}
			}
			else if (s.startsWith("-ip")) { // setting server remote access hostname
				int nextArgIndex = i + 1;
				String hostname;
				if (s.length() == 3 && nextArgIndex < args.length) {
					hostname = args[++i];
				}
				else {
					hostname = s.substring(3);
				}
				hostname = hostname.trim();
				if (hostname.length() == 0 || hostname.startsWith("-")) {
					displayUsage("Missing -ip hostname");
					System.exit(-1);
				}
				System.setProperty(RMI_SERVER_PROPERTY, hostname);
			}
			else if (s.startsWith("-i")) {  // setting server bind address
				int nextArgIndex = i + 1;
				String bindIp;
				if (s.length() == 2 && nextArgIndex < args.length) {
					bindIp = args[++i];
				}
				else {
					bindIp = s.substring(2);
				}
				bindIp = bindIp.trim();
				if (bindIp.length() == 0 || bindIp.startsWith("-")) {
					displayUsage("Missing -i interface bind address");
					System.exit(-1);
				}
				try {
					bindAddress = InetAddress.getByName(bindIp);
				}
				catch (UnknownHostException e) {
					System.err.println("Unknown server interface bind address: " + bindIp);
					System.exit(-1);
				}
			}
			else if (s.startsWith("-d") && s.length() > 2) { // Login Domain
				loginDomain = s.substring(2);
			}
			else if (s.equals("-u")) {
				nameCallbackAllowed = true;
			}
			else if (s.equals("-n")) {
				InetNameLookup.setLookupEnabled(true);
			}
			else if (s.equals("-anonymous")) {
				allowAnonymousAccess = true;
			}
			else if (s.equals("-ssh")) {
				altSSHLoginAllowed = true;
			}
			else if (s.startsWith("-e")) { // default password expiration (days)
				try {
					defaultPasswordExpiration = Integer.parseInt(s.substring(2));
				}
				catch (NumberFormatException e1) {
					// handled by validation below
				}
				if (defaultPasswordExpiration < 0) {
					displayUsage("Invalid default password expiration");
					System.exit(-1);
				}
				else if (defaultPasswordExpiration == 0) {
					System.out.println("Default password expiration has been disbaled.");
				}
			}
			else if (s.startsWith("-jaas")) {
				String jaasConfigFileStr;
				if (s.length() == 5) {
					i++;
					jaasConfigFileStr = (i < args.length) ? args[i] : "";
				}
				else {
					jaasConfigFileStr = s.substring(5);
				}
				jaasConfigFileStr = jaasConfigFileStr.trim();
				if (jaasConfigFileStr.isEmpty()) {
					displayUsage("Missing -jaas config file path argument");
					System.exit(-1);
				}
				jaasConfigFile = getServerCfgFile(jaasConfigFileStr);
				if (!jaasConfigFile.isFile()) {
					displayUsage(
						"JAAS config file (-jaas <configfile>) does not exist or is not file: " +
							jaasConfigFile.getAbsolutePath());
					System.exit(-1);
				}
			}
			else if (s.equals("-autoProvision")) {
				autoProvision = true;
			}
			else {
				if (i < (args.length - 1)) {
					displayUsage("Invalid usage!");
					System.exit(-1);
				}
				rootPath = s;
			}
		}

		if (rootPath == null) {
			displayUsage("Repository directory must be specified!");
			System.exit(-1);
		}

		File serverRoot = new File(rootPath);
		if (!serverRoot.isAbsolute()) {
			ResourceFile installRoot = Application.getInstallationDirectory();
			if (installRoot == null || installRoot.getFile(false) == null) {
				System.err.println("Failed to resolve installation root directory!");
				System.exit(-1);
			}
			serverRoot = new File(installRoot.getFile(false), rootPath);
		}

		if (authMode == JAAS_LOGIN) {
			if (jaasConfigFile == null) {
				displayUsage("JAAS config file argument (-jaas <configfile>) not specified");
				System.exit(-1);
			}
		}

		try {
			serverRoot = serverRoot.getCanonicalFile();
		}
		catch (IOException e1) {
			System.err.println(
				"Failed to resolve repository directory: " + serverRoot.getAbsolutePath());
			System.exit(-1);
		}

		if (!serverRoot.exists() && !serverRoot.mkdirs()) {
			System.err.println(
				"Failed to create repository directory: " + serverRoot.getAbsolutePath());
			System.exit(-1);
		}

		Application.initializeLogging(new File(serverRoot, "server.log"), null);

		// In the absence of module initialization - we must invoke directly
		SSLContextInitializer.initialize();

		log = LogManager.getLogger(GhidraServer.class); // init log *after* initializing log system

		ServerPortFactory.setBasePort(basePort);

		Runtime.getRuntime().addShutdownHook(new Thread((Runnable) () -> {
			if (server != null) {
				server.dispose();
			}
		}, "Ghidra Server Disposer"));

		// Create and install a security manager
		// if (System.getSecurityManager() == null) {
		// 		System.setSecurityManager(new RMISecurityManager());
		// }

		try {
			// Ensure that remote access hostname is properly set for RMI registration
			String hostname = initRemoteAccessHostname();

			if (ApplicationKeyManagerFactory.getPreferredKeyStore() == null) {
				// keystore has not been identified - use self-signed certificate
				ApplicationKeyManagerFactory.setDefaultIdentity(
					new X500Principal("CN=GhidraServer"));
			}
			if (!ApplicationKeyManagerFactory.initialize()) {
				log.fatal("Failed to initialize PKI/SSL keystore");
				System.exit(0);
				return;
			}

			// RMIClassServer.startServer(classSvrPort);

			// String codeBaseProp = "http://" +
			// localhost.getCanonicalHostName() + ":" + classSvrPort + "/";
			// System.setProperty(RMI_CODEBASE_PROPERTY, codeBaseProp);

			log.info("Ghidra Server " + Application.getApplicationVersion());
			log.info("   Server remote access address: " + hostname);
			if (bindAddress == null) {
				log.info("   Server listening on all interfaces");
			}
			else {
				log.info("   Server listening on interface: " + bindAddress.getHostAddress());
			}
			log.info("   RMI Registry port: " + ServerPortFactory.getRMIRegistryPort());
			log.info("   RMI SSL port: " + ServerPortFactory.getRMISSLPort());
			log.info("   Block Stream port: " + ServerPortFactory.getStreamPort());
			log.info("   Block Stream compression: " +
				(RemoteBlockStreamHandle.enableCompressedSerializationOutput ? "enabled"
						: "disabled"));
//			log.info("   Class server port: " + ??);
			log.info("   Root: " + rootPath);
			log.info("   Auth: " + authMode.getDescription());
			if (authMode == PASSWORD_FILE_LOGIN && defaultPasswordExpiration >= 0) {
				log.info("   Default password expiration: " +
					(defaultPasswordExpiration == 0 ? "disabled"
							: (defaultPasswordExpiration + " days")));
			}
			if (authMode != PKI_LOGIN) {
				log.info("   Prompt for user ID: " + (nameCallbackAllowed ? "yes" : "no"));
			}
			if (altSSHLoginAllowed) {
				log.info("   SSH authentication option enabled");
			}
			log.info(
				"   Anonymous server access: " + (allowAnonymousAccess ? "enabled" : "disabled"));

			serverSocketFactory = new SslRMIServerSocketFactory(null, getEnabledTlsProtocols(),
				authMode == PKI_LOGIN) {
				@Override
				public ServerSocket createServerSocket(int port) throws IOException {
					return new GhidraSSLServerSocket(port, bindAddress, getEnabledCipherSuites(),
						getEnabledProtocols(), getNeedClientAuth());
				}

			};
			clientSocketFactory = new SslRMIClientSocketFactory();

			log.info(SystemUtilities.getUserName() + " starting Ghidra Server...");

			GhidraServer svr = new GhidraServer(serverRoot, authMode, loginDomain,
				nameCallbackAllowed, altSSHLoginAllowed, defaultPasswordExpiration,
				allowAnonymousAccess, autoProvision, jaasConfigFile);

			log.info("Registering Ghidra Server...");

			Registry registry = LocateRegistry.createRegistry(
				ServerPortFactory.getRMIRegistryPort(), clientSocketFactory, serverSocketFactory);
			registry.bind(BIND_NAME, svr);

			log.info("Registered Ghidra Server.");

		}
		catch (IOException e) {
			e.printStackTrace();
			log.error(e.getMessage());
			System.exit(-1);
		}
		catch (Throwable t) {
			log.fatal("Server error: " + t.getMessage(), t);
			System.exit(-1);
		}
	}

	private static String[] getEnabledTlsProtocols() {
		String protocolList = System.getProperty(TLS_SERVER_PROTOCOLS_PROPERTY);
		if (protocolList != null) {

			log.info("   Enabled protocols: " + protocolList);

			String[] protocols = protocolList.split(";");
			for (int i = 0; i < protocols.length; i++) {
				protocols[i] = protocols[i].trim();
			}
			return protocols;
		}
		return null;
	}

	static synchronized void stop() {
		if (server == null) {
			throw new IllegalStateException("Invalid Stop request, Server is not running");
		}
		server.dispose();
	}

	public static RMIServerSocketFactory getRMIServerSocketFactory() {
		return serverSocketFactory;
	}

	public static RMIClientSocketFactory getRMIClientSocketFactory() {
		return clientSocketFactory;
	}

	private static void setGlobalSerializationFilter() throws IOException {
		
		ObjectInputFilter patternFilter = readSerialFilterPatternFile();

		ObjectInputFilter filter = new ObjectInputFilter() {

			@Override
			public Status checkInput(FilterInfo info) {

				Class<?> clazz = info.serialClass();

				// Give serial filter patterns first shot
				Status status = patternFilter.checkInput(info);
				if (status != Status.UNDECIDED) {
					if (status == Status.REJECTED) {
						return serialReject(info, "failed by serial.filter pattern");
					}
					return status;
				}


				if (clazz == null) {
					return Status.ALLOWED;
				}
				
				Class<?> componentType = clazz.getComponentType();
				if (componentType != null && componentType.isPrimitive()) {
					return Status.ALLOWED; // allow all primitive arrays
				}

				return serialReject(info, "not allowed");
			}

			private Status serialReject(FilterInfo info, String reason) {
				String clientHost = RepositoryManager.getRMIClient();
				StringBuilder buf = new StringBuilder();
				buf.append("Rejected class serialization");
				if (clientHost != null) {
					buf.append(" from ");
					buf.append(clientHost);
				}
				buf.append("(");
				buf.append(reason);
				buf.append(")");

				Class<?> serialClass = info.serialClass();
				if (serialClass != null) {
					buf.append(": ");
					buf.append(serialClass.getCanonicalName());
					buf.append(" ");
					if (serialClass.getComponentType() != null) {
						buf.append("(");
						buf.append("array-length=");
						buf.append(info.arrayLength());
						buf.append(")");
					}
				}

				log.error(buf.toString());
				return Status.REJECTED;
			}

		};

		// Install global serial class filter
		ObjectInputFilter.Config.setSerialFilter(filter);
	}

	/**
	 * Read serial.filter file content removing any comments and newlines and generate 
	 * corresponding {@link ObjectInputFilter}.  See {@link java.io.ObjectInputFilter.Config#createFilter(String)}
	 * for filter syntax.
	 * @return serial filter content 
	 * @throws IOException if file error occurs
	 */
	private static ObjectInputFilter readSerialFilterPatternFile() throws IOException {

		File serialFilterFile = Application.getModuleDataFile(SERIAL_FILTER_FILE).getFile(false);
		if (serialFilterFile == null) {
			// jar mode not supported
			throw new FileNotFoundException(SERIAL_FILTER_FILE + " not found");
		}
		try {
			StringBuilder buf = new StringBuilder();
			try (FileReader fr = new FileReader(serialFilterFile);
					BufferedReader r = new BufferedReader(fr)) {

				for (String line = r.readLine(); line != null; line = r.readLine()) {
					int ix = line.indexOf('#');
					if (ix >= 0) {
						// strip comment
						line = line.substring(0, ix);
					}
					line = line.trim();
					if (line.length() == 0) {
						continue;
					}
					if (!line.endsWith(";")) {
						throw new IllegalArgumentException(
							"all filter statements must end with `;`");
					}
					if (line.length() != 0) {
						buf.append(line);
					}
				}
			}
			return ObjectInputFilter.Config.createFilter(buf.toString());
		}
		catch (Exception e) {
			throw new IOException("Failed to parse " + SERIAL_FILTER_FILE, e);
		}
	}

}
