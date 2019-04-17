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

import java.io.*;
import java.net.*;
import java.rmi.NoSuchObjectException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.*;
import java.security.cert.CertificateException;
import java.util.Enumeration;

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
import ghidra.framework.*;
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
import resources.ResourceManager;
import utility.application.ApplicationLayout;

/**
 * <code>GhidraServer</code> provides the main Ghidra server application and
 * implements GhidraServerHandle which facilitates remote access to services
 * provided by a repository manager. The single instance of GhidraServer is set
 * within the RMI Registry which is accessible on a user specified port.
 */
public class GhidraServer extends UnicastRemoteObject implements GhidraServerHandle {

	private static SslRMIServerSocketFactory serverSocketFactory;
	private static SslRMIClientSocketFactory clientSocketFactory;

	private static Logger log;

	private static String HELP_FILE = "/ghidra/server/remote/ServerHelp.txt";
	private static String USAGE_ARGS =
		" [-p<port>] [-a<authMode>] [-d<domain>] [-u] [-anonymous] [-ssh] [-ip<ipAddr>] [-e<expireDays>] [-n] <serverPath>";

	private static final String RMI_SERVER_PROPERTY = "java.rmi.server.hostname";
	// private static final String RMI_CODEBASE_PROPERTY = "java.rmi.server.codebase";

	private static final String[] AUTH_MODES =
		{ "None", "Password File", "OS Password", "PKI", "OS Password & Password File" };

	public static final int NO_AUTH_LOGIN = -1;
	public static final int PASSWORD_FILE_LOGIN = 0;
	public static final int OS_PASSWORD_LOGIN = 1;
	public static final int PKI_LOGIN = 2;
	public static final int ALT_OS_PASSWORD_LOGIN = 3;

	private static GhidraServer server;

	private RepositoryManager mgr;
	private AuthenticationModule authModule;
	private SSHAuthenticationModule sshAuthModule; // only supported in conjunction with password authentication modes (0 & 1)
	private AnonymousAuthenticationModule anonymousAuthModule;

	private BlockStreamServer blockStreamServer;

	/**
	 * Server handle constructor.
	 * 
	 * @param rootDir
	 *            root repositories directory for server
	 * @param authMode
	 *            authentication mode
	 * @param loginDomain
	 *            login domain or null (used for OS_PASSWORD_LOGIN mode only)
	 * @param nameCallbackAllowed if true user name may be altered 
	 * @param altSSHLoginAllowed if true SSH authentication will be permitted
	 * as an alternate form of authentication
	 * @param defaultPasswordExpirationDays number of days default password will be valid
	 * @param allowAnonymousAccess allow anonymous access if true
	 * @throws IOException
	 */
	GhidraServer(File rootDir, int authMode, final String loginDomain, boolean nameCallbackAllowed,
			boolean altSSHLoginAllowed, int defaultPasswordExpirationDays,
			boolean allowAnonymousAccess) throws IOException, CertificateException {

		super(ServerPortFactory.getRMISSLPort(), clientSocketFactory, serverSocketFactory);

		if (log == null) {
			// logger generally initialized by main method, however during
			// testing the main method may be bypassed
			log = LogManager.getLogger(GhidraServer.class);
		}

		if (allowAnonymousAccess) {
			anonymousAuthModule = new AnonymousAuthenticationModule();
		}

		boolean supportLocalPasswords = false;
		boolean requireExplicitPasswordReset = true;
		switch (authMode) {
			case PASSWORD_FILE_LOGIN:
				supportLocalPasswords = true;
				requireExplicitPasswordReset = false;
				authModule = new PasswordFileAuthenticationModule(nameCallbackAllowed);
				break;
//			case ALT_OS_PASSWORD_LOGIN:
//				supportLocalPasswords = true;
//			case OS_PASSWORD_LOGIN:
//				OperatingSystem os = OperatingSystem.CURRENT_OPERATING_SYSTEM;
//				if (os == OperatingSystem.WINDOWS) {
//					authModule = new NTPasswordAuthenticationModule(loginDomain,
//						nameCallbackAllowed, authMode == ALT_OS_PASSWORD_LOGIN);
//				}
//				else if (os == UNIX) {
//					authModule = new UnixPasswordAuthenticationModule(nameCallbackAllowed);
//				}
//				else {
//					throw new IllegalArgumentException(
//						"OS Password Authentication only supported for Microsoft Windows");
//				}
//				break;
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
			default:
				throw new IllegalArgumentException("Unsupported Authentication mode: " + authMode);
		}

		if (altSSHLoginAllowed) {
			SecureRandomFactory.getSecureRandom(); // incur initialization delay up-front
			sshAuthModule = new SSHAuthenticationModule(nameCallbackAllowed);
		}

		mgr = new RepositoryManager(rootDir, supportLocalPasswords, requireExplicitPasswordReset,
			defaultPasswordExpirationDays, allowAnonymousAccess);

		GhidraServer.server = this;

		blockStreamServer = BlockStreamServer.getBlockStreamServer();
		blockStreamServer.startServer();
	}

	/*
	 * @see ghidra.framework.remote.GhidraServerHandle#getAuthenticationCallbacks(javax.security.auth.Subject)
	 */
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

	/*
	 * @see ghidra.framework.remote.GhidraServerHandle#checkCompatibility(int)
	 */
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

	/*
	 * @see ghidra.framework.remote.GhidraServerHandle#getRepositoryServer(javax.security.auth.callback.Callback[])
	 */
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
			for (Callback cb : authCallbacks) {
				if (cb instanceof NameCallback) {
					if (!authModule.isNameCallbackAllowed()) {
						RepositoryManager.log(null, null,
							"Illegal authentictaion callback: NameCallback not permitted",
							username);
						throw new LoginException("Illegal authentictaion callback");
					}
					NameCallback nameCb = (NameCallback) cb;
					String name = nameCb.getName();
					if (name == null) {
						RepositoryManager.log(null, null,
							"Illegal authentictaion callback: NameCallback must specify login name",
							username);
						throw new LoginException("Illegal authentictaion callback");
					}
					username = name;
					break;
				}
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
						RepositoryManager.log(null, null, "User '" + username + "' authenticated",
							principal.getName());
					}
				}
				catch (LoginException e) {
					RepositoryManager.log(null, null, "Login failed (" + e.getMessage() + ")",
						username);
					throw e;
				}
				if (authModule instanceof PasswordFileAuthenticationModule) {
					supportPasswordChange = true;
				}
//				else if (authModule instanceof NTPasswordAuthenticationModule) {
//					supportPasswordChange =
//						((NTPasswordAuthenticationModule) authModule).usingLocalAuthentication(
//							authCallbacks);
//				}
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
		InputStream in = ResourceManager.getResourceAsStream(HELP_FILE);
		try {
			BufferedReader br = new BufferedReader(new InputStreamReader(in));
			while (true) {
				String line = br.readLine();
				if (line == null) {
					break;
				}
				System.out.println(line);
			}
		}
		catch (IOException e) {
			// don't care
		}
		finally {
			try {
				in.close();
			}
			catch (IOException e) {
				// we tried
			}
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
		int authMode = NO_AUTH_LOGIN;
		boolean nameCallbackAllowed = false;
		boolean altSSHLoginAllowed = false;
		boolean allowAnonymousAccess = false;
		String loginDomain = null;
		String rootPath = null;
		int defaultPasswordExpiration = -1;

		// Network name resolution disabled by default
		InetNameLookup.setLookupEnabled(false);

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
				try {
					authMode = Integer.parseInt(s.substring(2));
				}
				catch (NumberFormatException e1) {
					displayUsage("Invalid option: " + s);
					System.exit(-1);
				}
			}
			else if (s.startsWith("-ip")) { // Setting server ip address to bind to
				System.setProperty(RMI_SERVER_PROPERTY, s.substring(3));
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
			else {
				if (i < (args.length - 1)) {
					displayUsage("Invalid usage!");
					System.exit(-1);
				}
				rootPath = s;
			}
		}

		if (authMode < NO_AUTH_LOGIN || authMode > ALT_OS_PASSWORD_LOGIN) {
			displayUsage("Invalid authentication mode!");
			System.exit(-1);
		}
		if (authMode == OS_PASSWORD_LOGIN || authMode == ALT_OS_PASSWORD_LOGIN) {
			if (OperatingSystem.CURRENT_OPERATING_SYSTEM != OperatingSystem.WINDOWS) {
				displayUsage("Authentication mode (" + authMode +
					") only supported under Microsoft Windows");
				System.exit(-1);
			}
		}

		if (rootPath == null) {
			displayUsage("Repository directory must be specified!");
			System.exit(-1);
		}

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

		File serverRoot = new File(rootPath);
		if (!serverRoot.isAbsolute()) {
			ResourceFile installRoot = Application.getInstallationDirectory();
			if (installRoot == null || installRoot.getFile(false) == null) {
				System.err.println("Failed to resolve installation root directory!");
				System.exit(-1);
			}
			serverRoot = new File(installRoot.getFile(false), rootPath);
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
			// Determine IP interface to bind to
			String hostname = System.getProperty(RMI_SERVER_PROPERTY);
			if (hostname == null) {
				InetAddress localhost = InetAddress.getLocalHost();
				if (localhost.isLoopbackAddress()) {
					localhost = findHost();
					if (localhost == null) {
						log.fatal("Can't find host ip address!");
						System.exit(0);
						return;
					}
				}
				System.setProperty(RMI_SERVER_PROPERTY, localhost.getHostAddress());
				hostname = localhost.getCanonicalHostName();
			}
			else {
				log.warn("forcing server to bind to " + hostname);
			}

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

			log.info("   Server bound to " + System.getProperty(RMI_SERVER_PROPERTY));
			log.info("   RMI Registry port: " + ServerPortFactory.getRMIRegistryPort());
			log.info("   RMI SSL port: " + ServerPortFactory.getRMISSLPort());
			log.info("   Block Stream port: " + ServerPortFactory.getStreamPort());
			log.info("   Block Stream compression: " +
				(RemoteBlockStreamHandle.enableCompressedSerializationOutput ? "enabled"
						: "disabled"));
//			log.info("   Class server port: " + ??);
			log.info("   Root: " + rootPath);
			log.info("   Auth: " + AUTH_MODES[authMode + 1]);
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

			log.info(SystemUtilities.getUserName() + " starting Ghidra Server...");

			serverSocketFactory = new SslRMIServerSocketFactory(null, null, authMode == PKI_LOGIN) {
				@Override
				public ServerSocket createServerSocket(int port) throws IOException {
					return new GhidraSSLServerSocket(port, getEnabledCipherSuites(),
						getEnabledProtocols(), getNeedClientAuth());
				}
			};
			clientSocketFactory = new SslRMIClientSocketFactory();

			GhidraServer svr =
				new GhidraServer(serverRoot, authMode, loginDomain, nameCallbackAllowed,
					altSSHLoginAllowed, defaultPasswordExpiration, allowAnonymousAccess);

			log.info("Registering Ghidra Server...");

			Registry registry =
				LocateRegistry.createRegistry(ServerPortFactory.getRMIRegistryPort());
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

}
