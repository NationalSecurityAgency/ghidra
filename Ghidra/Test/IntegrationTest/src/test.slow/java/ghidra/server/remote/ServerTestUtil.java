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
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.util.ArrayList;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.rmi.ssl.SslRMIClientSocketFactory;

import org.apache.commons.lang3.RandomStringUtils;

import generic.test.*;
import ghidra.framework.client.*;
import ghidra.framework.data.ContentHandler;
import ghidra.framework.data.DomainObjectAdapter;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.framework.remote.GhidraServerHandle;
import ghidra.framework.remote.RMIServerPortFactory;
import ghidra.framework.store.FileSystem;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.framework.store.local.LocalFolderItem;
import ghidra.net.*;
import ghidra.program.model.listing.Program;
import ghidra.server.ServerAdmin;
import ghidra.server.UserManager;
import ghidra.test.ToyProgramBuilder;
import ghidra.util.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import ghidra.util.timer.GTimer;
import sun.security.x509.*;
import utilities.util.FileUtilities;

/**
 * 
 */
public class ServerTestUtil {

	public static final int GHIDRA_TEST_SERVER_PORT = 14100;
	public static final String LOCALHOST = "127.0.0.1";

	public static final String TEST_PKI_USER_PASSPHRASE = "xyzzy";
	public static final String TEST_PKI_SERVER_PASSPHRASE = "plugh";
	public static final String TEST_PKI_USER_DN = "CN=Ghidra Test Client, O=Ghidra, OU=Test, C=US";
	public static final String TEST_PKI_SERVER_DN =
		"CN=Ghidra Test Server, O=Ghidra, OU=Test, C=US";
	public static final String TEST_PKI_CA_DN = "CN=Ghidra Test CA, O=Ghidra, OU=Test, C=US";

	private static String[] AUTH_MODES =
		new String[] { "Private Password", "NT Login Password", "PKI", "NT/Private Password" };

	public static final URL TEST_REPO_URL =
		GhidraURL.makeURL(LOCALHOST, GHIDRA_TEST_SERVER_PORT, "Test");
	public static final URL TEST1_REPO_URL =
		GhidraURL.makeURL(LOCALHOST, GHIDRA_TEST_SERVER_PORT, "Test1");

	/**
	 * Default user "test" has been pre-added to server with repository admin rights to both 
	 * the "Test" and "Test1" repos
	 */
	public static final String ADMIN_USER = "test";

	/**
	 * User "userA" has read access to the "Test" repo and write access to the "Test1" repo.
	 * User must be added to server before connecting.
	 */
	public static final String USER_A = "userA";

	/**
	 * User "userB" has read access to the "Test" repo and write access to the "Test1" repo.
	 * User must be added to server before connecting.
	 */
	public static final String USER_B = "userB";

	private static final int SERVER_STARTUP_MAXWAIT_MS = 20000;

	private static IOThread cmdOut;
	private static IOThread cmdErr;
	private static Process serverProcess;
	private static String serverRepositories;

	static {
		Runtime.getRuntime().addShutdownHook(new ShutdownHook());
	}

	private static File testPkiDirectory;

	private ServerTestUtil() {
		// utils class; can't create
	}

	/** 
	 * This is our attempt to cleanup lingering server processes after testing.  This has no 
	 * effect if everything was shutdown correctly.
	 */
	private static class ShutdownHook extends Thread {
		@Override
		public void run() {
			Msg.debug(ServerTestUtil.class, "\n\n\n\n\tSHUTDOWN HOOK RUNNING");
			disposeServer();
		}
	}

	/**
	 * 
	 * Thread to read from an input stream and write it to stdout.
	 */
	private static class IOThread extends Thread {
		private BufferedReader shellOutput;
		@SuppressWarnings("unused")
		private InputStream input;
		volatile boolean isDisposed;
		volatile boolean terminated;
		volatile boolean serverStartComplete;

		public IOThread(InputStream input) {
			this.input = input;
			shellOutput = new BufferedReader(new InputStreamReader(input));
			setDaemon(true);
		}

		@Override
		public void run() {
			String line = null;
			try {
				while (!isDisposed && (line = shellOutput.readLine()) != null) {
					if (line.contains("Address already in use")) {
						throw new IllegalStateException("Server already running--could not start!");
					}
					if (line.contains("ERROR")) {
						terminateIn(1000);
					}
					if (line.contains("Registering Ghidra Server...")) {
						synchronized (this) {
							serverStartComplete = true;
							notifyAll();
						}
					}
					Msg.info(this, "SERVER " + line);
				}
			}
			catch (Exception e) {
				if (!isDisposed) { // don't care about exceptions happening as a result of disposing
					ConcurrentTestExceptionHandler.handle(this, e);
				}
			}
			finally {
				synchronized (this) {
					terminated = true;
					notifyAll();
				}
			}
		}

		/**
		 * Waits the specified time before notifying the blocking client thread to give up
		 * on the process to which this class is bound.
		 * @param millis the timeout
		 */
		private void terminateIn(int millis) {

			// let the IO thread finish processing the stack info before failing
			GTimer.scheduleRunnable(millis, () -> {
				// we have no way to interrupt a blocking IO call :(
				synchronized (this) {
					// signal to the client thread to stop waiting; this IO thread
					// is a daemon, so it will not prevent JVM shutdown
					terminated = true;
					isDisposed = true;
					notifyAll();
				}
			});
		}

		synchronized void waitForServerStartOrTermination() {
			try {
				while (!terminated && !serverStartComplete) {
					wait();
				}
			}
			catch (InterruptedException e) {
				// ignore
			}
		}

		void dispose() {
			isDisposed = true;
			interrupt();
		}
	}

	public static void main(String[] args) {

		String USER = ClientUtil.getUserName();
		File serverRoot = null;
		try {
			File parent = AbstractGenericTest.createTempDirectory("ServerTestUtil");

			// Create server instance
			serverRoot = new File(parent, "My_Server");
			FileUtilities.deleteDir(serverRoot);
			createServer(serverRoot.getAbsolutePath(), 0, new String[] { USER });
		}
		catch (Exception e) {
			e.printStackTrace();
		}

		try {
			int i = 0;
			while (true) {
				++i;
				ClientUtil.getRepositoryServer(LOCALHOST, 0, true);
				if ((i % 10) == 0) {
					Msg.info(ServerTestUtil.class, "Success: " + (++i));
				}
				Thread.sleep(100);
			}

		}
		catch (Exception e) {
			e.printStackTrace();
		}
		finally {
			try {
				if (serverRoot != null) {
					disposeServer();
				}
			}
			catch (Exception e) {
				e.printStackTrace();
			}
		}

		System.exit(0);

	}

	/**
	 * Create and start a server instance on the specified port.
	 * This server must be disposed before attempting to create another.
	 * This method will block until server starts or fails to start.
	 * @param dirPath server root directory
	 * @param port RMI registry port, 0 indicates that default port should be used
	 * @param userNames list of server users
	 * @throws IOException
	 */
	public static synchronized void createServer(String dirPath, int port, String[] userNames)
			throws IOException {

		if (serverProcess != null) {
			throw new RuntimeException("Server already running, only one allowed");
		}

		File dir = new File(dirPath);
		if (dir.exists()) {
			Msg.error(ServerTestUtil.class,
				"WARNING! Removing existing server directory: " + dirPath);
			FileUtilities.deleteDir(dir);
			if (dir.exists()) {
				throw new IOException("Failed to remove existing server directory: " + dirPath);
			}
		}
		FileUtilities.mkdirs(dir);

		// Add users to Server using UserManager
		createUsers(dirPath, userNames);

		startServer(dirPath, port, -1, false, false, false);

	}

	/**
	 * Start a server instance on the specified port.  The server repository
	 * will be populated with the contents of the specified repository archive
	 * zip file. This server must be disposed before attempting to create another.
	 * This method will block until server either starts or fails to start.
	 * @param dirPath server root directory to be created and populated
	 * @param testRepositoryArchiveZipPath zip resource path to an archive
	 * containing the contents of a server repository
	 * @param port RMI registry port, 0 indicates that default port should be used
	 * @param authMode primary authentication mode (0-3, -1=None, see GhidraServer)
	 * @param enableAltLoginName if true alternate login name will be 
	 * enabled for those modes which support it.
	 * @param enableSSHAuthentication enable SSH authentication if true
	 * @param enableAnonymousAuthentication enable anonymous logins
	 * @throws IOException
	 */
	public static synchronized void startServer(String dirPath, String testRepositoryArchiveZipPath,
			int port, int authMode, boolean enableAltLoginName, boolean enableSSHAuthentication,
			boolean enableAnonymousAuthentication) throws IOException {

		// Create server instance
		File serverRoot = new File(dirPath);
		if (serverRoot.exists()) {
			throw new DuplicateFileException("Server root directory already exists: " + dirPath);
		}

		// Unpack repository archive
		InputStream in = new FileInputStream(testRepositoryArchiveZipPath);
		try {
			ZipInputStream zip = new ZipInputStream(in);
			unpackArchive(zip, serverRoot);
		}
		finally {
			in.close();
		}

		startServer(serverRoot.getAbsolutePath(), GHIDRA_TEST_SERVER_PORT, authMode,
			enableAltLoginName, enableSSHAuthentication, enableAnonymousAuthentication);
	}

	private static void unpackArchive(ZipInputStream zip, File parentDir) throws IOException {
		ZipEntry entry = null;
		while ((entry = zip.getNextEntry()) != null) {
			String name = entry.getName();
			//System.out.println("Unpack: " + name);
			File f = new File(parentDir, name);
			if (name.endsWith("/")) {
				f.mkdirs();
				if (!f.isDirectory()) {
					throw new IOException("failed to create dir: " + f);
				}
			}
			else {
				FileUtilities.copyStreamToFile(zip, f, false, TaskMonitor.DUMMY);
			}
		}
	}

	private static synchronized File getPkiTestDirectory() {
		if (testPkiDirectory == null) {
			testPkiDirectory = new File(System.getProperty("java.io.tmpdir"), "test-pki");
			FileUtilities.deleteDir(testPkiDirectory);
			testPkiDirectory.mkdirs();

			try {
				generatePkiCerts();
			}
			catch (Exception e) {
				throw new RuntimeException("Test server PKI generation failure", e);
			}
		}
		return testPkiDirectory;
	}

	/**
	 * Get the test CA certificate used with the test server
	 * @return JKS certificate storage file path
	 */
	public static String getTestPkiCACertsPath() {
		return getPkiTestDirectory().getAbsolutePath() + File.separator + "test-cacerts.crt";
	}

	/**
	 * Get the server certificate used with the test server
	 * @return JKS test server keystore file path
	 */
	public static String getTestPkiServerKeystorePath() {
		return getPkiTestDirectory().getAbsolutePath() + File.separator + "test-server.p12";
	}

	/**
	 * Get user test keystore to be used with a test server
	 * @return test user keystore file path
	 */
	public static String getTestPkiUserKeystorePath() {
		return getPkiTestDirectory().getAbsolutePath() + File.separator + "test.p12";
	}

	/**
	 * Force client username to be used throughout Ghidra.  This may be required when testing 
	 * so that the default login name can be forced.
	 * @param username
	 * @see ClientUtil#getUserName()
	 * @see SystemUtilities#getUserName()
	 */
	public static void setLocalUser(String username) {
		TestUtils.setInstanceField("userName", SystemUtilities.class, username);
		if (!username.equals(ClientUtil.getUserName())) {
			throw new AssertException("Failed to force client username: " + username);
		}
	}

	/**
	 * Start a server instance on the specified port.
	 * This server must be disposed before attempting to create another.
	 * @param dirPath server root directory
	 * @param port RMI registry port, 0 indicates that default port should be used
	 * @param authMode authentication mode (-1 for no authentication)
	 * @param enableAltLoginName if true enable alternate login name
	 * @param enableSSHAuthentication if true SSH authentication will be enabled
	 * @param enableAnonymousAuthentication if true anonymous usage is allowed
	 * @throws IOException
	 */
	public static synchronized void startServer(String dirPath, int port, int authMode,
			boolean enableAltLoginName, boolean enableSSHAuthentication,
			boolean enableAnonymousAuthentication) throws IOException {

		if (port == 0) {
			port = GHIDRA_TEST_SERVER_PORT;
		}

		Msg.debug(ServerTestUtil.class, "--- Preparing to start Ghidra Server ---");
		Msg.debug(ServerTestUtil.class,
			"     Authentication: " + (authMode < 0 ? "None" : AUTH_MODES[authMode]));
		Msg.debug(ServerTestUtil.class, "     Enable Alternate Login Name: " + enableAltLoginName);
		Msg.debug(ServerTestUtil.class,
			"     Enable Anonymous Login: " + enableAnonymousAuthentication);

		// Force client-side use of newly generated CA certificates
		System.setProperty(ApplicationTrustManagerFactory.GHIDRA_CACERTS_PATH_PROPERTY,
			getTestPkiCACertsPath());
		SSLContextInitializer.initialize(true);

		ArrayList<String> argList = new ArrayList<>();
		String javaCommand =
			System.getProperty("java.home") + File.separator + "bin" + File.separator + "java";
		argList.add(javaCommand);

		argList.add("-cp");
		argList.add(System.getProperty("java.class.path"));

		argList.add("-Xmx512M");

		argList.add("-Xdebug");
		argList.add("-Xnoagent");
		argList.add("-Djava.compiler=NONE");
		argList.add("-D" + ApplicationTrustManagerFactory.GHIDRA_CACERTS_PATH_PROPERTY + "=" +
			getTestPkiCACertsPath());
		argList.add("-D" + ApplicationKeyManagerFactory.KEYSTORE_PATH_PROPERTY + "=" +
			getTestPkiServerKeystorePath());
		argList.add("-D" + ApplicationKeyManagerFactory.KEYSTORE_PASSWORD_PROPERTY + "=" +
			TEST_PKI_SERVER_PASSPHRASE);
		argList.add("-Xrunjdwp:transport=dt_socket,server=y,suspend=n,address=*:18202"); // *: for remote debug support
		argList.add("-DSystemUtilities.isTesting=true");

		// -Djava.security.policy=C:/policy
//		URL policy = ResourceManager.getResource("policy");
//		if (policy == null) {
//			throw new RuntimeException("Failed to find security policy resource");
//		}
//		argList.add("-Djava.security.policy=" + policy.toExternalForm());

		argList.add("ghidra.server.remote.GhidraServer");
		if (authMode >= 0) {
			argList.add("-a" + authMode);
		}
		if (enableAltLoginName) {
			argList.add("-u");
		}
		if (enableSSHAuthentication) {
			argList.add("-ssh");
		}
		if (enableAnonymousAuthentication) {
			argList.add("-anonymous");
		}

		argList.add("-ip" + LOCALHOST); // bind to loopback interface
		argList.add("-p" + port);
		argList.add(dirPath);

		String[] args = new String[argList.size()];
		argList.toArray(args);

		System.out.println();
		for (String arg : argList) {
			boolean includeQuotes = arg.indexOf(' ') != -1;
			if (includeQuotes) {
				System.out.print("'");
			}
			System.out.print(arg);
			if (includeQuotes) {
				System.out.print("'");
			}
			System.out.print(" ");
		}
		System.out.println();

		try {
			serverProcess = Runtime.getRuntime().exec(args);
			serverRepositories = dirPath;

			cmdOut = new IOThread(serverProcess.getInputStream());
			cmdErr = new IOThread(serverProcess.getErrorStream());
			cmdOut.start();
			cmdErr.start();
		}
		catch (Exception e) {
			e.printStackTrace();
			throw new AssertException("Exception starting Ghidra Server", e);
		}

		Msg.info(ServerTestUtil.class, "Waiting for Ghidra Server RMI registration to complete...");
		cmdOut.waitForServerStartOrTermination(); // based upon message output only
		if (!cmdOut.serverStartComplete) {
			throw new AssertException("Ghidra Server failed to start");
		}

		waitUntilServerAvailable(GHIDRA_TEST_SERVER_PORT);
	}

	private static void waitUntilServerAvailable(final int basePort) throws IOException {

		RMIServerPortFactory portFactory = new RMIServerPortFactory(basePort);

		int maxTries = SERVER_STARTUP_MAXWAIT_MS / 200;
		int tries = 0;
		boolean success = false;
		try {
			while (tries++ < maxTries) {
				Thread.sleep(200);
				if (isServerRegistered(portFactory.getRMIRegistryPort()) &&
					canConnect(portFactory.getRMISSLPort())) {
					Msg.info(ServerTestUtil.class,
						"Successfully verified Ghidra Server registration and SSL port availability");
					success = true;
					return;
				}
			}
		}
		catch (InterruptedException e) {
			// ignore - stop waiting
		}
		finally {
			if (!success) {
				disposeServer();
			}
		}

		throw new IOException("Timed-out waiting for Ghidra Server to start");
	}

	private static boolean isServerRegistered(int port) throws IOException {
		Registry reg = LocateRegistry.getRegistry(LOCALHOST, port, new SslRMIClientSocketFactory());
		try {
			reg.lookup(GhidraServerHandle.BIND_NAME);
			return true;
		}
		catch (Exception ce) {
			return false;
		}
	}

	private static boolean canConnect(int port) {

		Socket socket = null;
		try {
			SocketAddress sockaddr = new InetSocketAddress(LOCALHOST, port);
			socket = new Socket();
			socket.connect(sockaddr, 500);
			return true;
		}
		catch (UnknownHostException e) {
			return true; // defer error
		}
		catch (IOException e) {
			return false; // connect error?
		}
		finally {
			if (socket != null) {
				try {
					socket.close();
				}
				catch (IOException e) {
					// ignore
				}
			}
		}
	}

	/**
	 * Start new server instance and return server adapter.
	 * This method blocks until server is started and adapter is connected.  
	 * @param serverRoot root directory
	 * @param users list of server users
	 * @return server adapter
	 * @throws IOException if there are any IOExceptions starting the server
	 */
	public static RepositoryServerAdapter getServerAdapter(File serverRoot, String[] users)
			throws IOException {

		RepositoryServerAdapter rsa = null;

		boolean success = false;
		try {

			createServer(serverRoot.getAbsolutePath(), GHIDRA_TEST_SERVER_PORT, users);

			waitUntilServerAvailable(GHIDRA_TEST_SERVER_PORT);

			rsa = ClientUtil.getRepositoryServer(LOCALHOST, GHIDRA_TEST_SERVER_PORT);
			rsa.connect();
			success = true;
		}
		catch (NotConnectedException e) {
			// note: this will trigger a popup dialog
		}
		finally {
			if (!success) {
				disposeServer();
			}
		}

		return rsa;
	}

	public static synchronized void disposeServer() {

		System.setProperty(ApplicationTrustManagerFactory.GHIDRA_CACERTS_PATH_PROPERTY, "");

		Msg.debug(ServerTestUtil.class, "disposeServer() - process exist? " + serverProcess);
		if (serverProcess != null) {

			cmdOut.dispose();
			cmdErr.dispose();

			Msg.debug(ServerTestUtil.class, "*** Terminating Ghidra Server Instance... ***");

			serverProcess.destroy();

			Msg.debug(ServerTestUtil.class, "\tafter call to destroy");

			try {
				serverProcess.waitFor();
			}
			catch (InterruptedException e) {
				// don't care
			}

			if (serverProcess.isAlive()) {
				Msg.debug(ServerTestUtil.class, "Its alive...");
			}

			dumpServerLog();

			serverProcess = null;
			serverRepositories = null;

			if (testPkiDirectory != null) {
				FileUtilities.deleteDir(testPkiDirectory);
				testPkiDirectory = null;
			}
		}
	}

	private static void dumpServerLog() {

		File serverLogFile = new File(serverRepositories, "server.log");
		if (!serverLogFile.exists()) {
			Msg.error(ServerTestUtil.class, "Ghidra Server log not found: " + serverLogFile);
			return;
		}

		Msg.debug(ServerTestUtil.class, ">>> START Ghidra Server Log Dump >>>");

		try (BufferedReader r = new BufferedReader(new FileReader(serverLogFile))) {
			String s;
			while ((s = r.readLine()) != null) {
				System.out.println("    SERVER: " + s);
			}
		}
		catch (IOException e) {
			Msg.error(ServerTestUtil.class, "Error dumping file: " + serverLogFile, e);
		}

		Msg.debug(ServerTestUtil.class, "<<< END Ghidra Server Log Dump <<<");
	}

	/**
	 * Create KnownUsers file containing the specified list of users.
	 * @param dirPath server root directory
	 * @param userNames list of user names
	 * @throws IOException if there are any exceptions creating users
	 */
	public static void createUsers(String dirPath, String... userNames) throws IOException {

		File rootDir = new File(dirPath);
		File userFile = new File(rootDir, UserManager.USER_PASSWORD_FILE);

		String[] entries = new String[userNames.length];
		for (int i = 0; i < userNames.length; i++) {
			char[] hash = HashUtilities.getSaltedHash(HashUtilities.SHA256_ALGORITHM,
				"changeme".toCharArray());
			entries[i] = userNames[i] + ":" + (new String(hash)) + ":*";
		}

		writeFile(userFile, entries);
	}

	private static void writeFile(File file, String... lines) throws IOException {

		file.delete();

		BufferedWriter bw = new BufferedWriter(new FileWriter(file));
		try {
			for (String line : lines) {
				bw.write(line);
				bw.newLine();
			}
		}
		finally {
			try {
				bw.close();
			}
			catch (IOException e) {
				// we tried
			}
		}
	}

	private static void addSSHKeys(String dirPath, String privateKey, String privateKeyFilename,
			String publicKey, String publicKeyFilename) throws IOException {

		File rootDir = new File(dirPath);
		File sshDir = new File(rootDir, "~ssh");
		FileUtilities.mkdirs(sshDir);

		FileUtilities.writeStringToFile(new File(sshDir, privateKeyFilename), privateKey);
		FileUtilities.writeStringToFile(new File(sshDir, publicKeyFilename), publicKey);
	}

	/**
	 * Creates a versioned server repository filesystem prior to starting a Ghidra Server.
	 * The following test user permissions are granted:
	 * <pre>
	 * 	test=ADMIN
	 *  userA=READ_ONLY
	 *  userB=WRITE
	 * </pre>
	 * @param dirPath the location for the server to be created
	 * @param repoName the name of the repository
	 * @param userAccessLines the permissions for the set of users being created (see above)
	 * @return newly created versioned filesystem (caller is responsible for invoking the
	 * dispose method on the returned object.
	 * @throws IOException 
	 */
	public static LocalFileSystem createRepository(String dirPath, String repoName,
			String... userAccessLines) throws IOException {

		File repoDir = new File(dirPath, NamingUtilities.mangle(repoName));
		FileUtilities.mkdirs(repoDir);

		LocalFileSystem repoFileSystem =
			LocalFileSystem.getLocalFileSystem(repoDir.getAbsolutePath(), true, true, false, false);

		File userAccessFile = new File(repoDir, "userAccess.acl");
		writeFile(userAccessFile, userAccessLines);

		return repoFileSystem;
	}

	public static void createRepositoryItem(LocalFileSystem repoFilesystem, String name,
			String folderPath, int numFunctions) throws Exception {

		ToyProgramBuilder builder = new ToyProgramBuilder(name, true);

		try {
			Program program = builder.getProgram();

			int funcAddr = 0;
			for (int i = 0; i < numFunctions; i++) {
				String funcAddrStr = String.valueOf(funcAddr);
				builder.createMemory("func" + i, funcAddrStr, 2);
				builder.addBytesReturn(funcAddrStr);
				builder.disassemble(funcAddrStr, 2);
				builder.createFunction(funcAddrStr);
				funcAddr += 2;
			}

			setProgramHashes(program);

			ContentHandler contentHandler = DomainObjectAdapter.getContentHandler(program);
			long checkoutId = contentHandler.createFile(repoFilesystem, null, folderPath, name,
				program, TaskMonitor.DUMMY);
			LocalFolderItem item = repoFilesystem.getItem(folderPath, name);
			if (item == null) {
				throw new IOException("Item not found: " + FileSystem.SEPARATOR + name);
			}
			item.terminateCheckout(checkoutId, false);
		}
		catch (CancelledException e) {
			throw new RuntimeException(e); // unexpected
		}
		catch (InvalidNameException e) {
			throw new IOException(e);
		}
		finally {
			builder.dispose();
		}
	}

	/**
	 * Create and populate server test repositories "Test" and "Test1" with the specified 
	 * users added.  The ADMIN_USER "test" is added by default. 
	 * @param dirPath server root
	 * @param users optional inclusion of USER_A and/or USER_B to be added with no authentication required
	 * @throws Exception
	 */
	public static void createPopulatedTestServer(String dirPath, String... users) throws Exception {

		Msg.info(ServerTestUtil.class, "Constructing Ghidra Server for testing: " + dirPath);

		File rootDir = new File(dirPath);
		FileUtilities.deleteDir(rootDir);
		FileUtilities.mkdirs(rootDir);

		String[] userArray = new String[users.length + 1];
		userArray[0] = ADMIN_USER;
		System.arraycopy(users, 0, userArray, 1, users.length);
		createUsers(dirPath, userArray);

		String keys[] = SSHKeyUtil.generateSSHKeys();
		addSSHKeys(dirPath, keys[0], "test.key", keys[1], "test.pub");

		LocalFileSystem repoFilesystem = createRepository(dirPath, "Test", ADMIN_USER + "=ADMIN",
			USER_A + "=READ_ONLY", USER_B + "=WRITE");
		try {
			createRepositoryItem(repoFilesystem, "foo", "/", 0);
			createRepositoryItem(repoFilesystem, "notepad", "/", 0);
			createRepositoryItem(repoFilesystem, "bash", "/f1", 0);
		}
		finally {
			repoFilesystem.dispose();
		}

		repoFilesystem = createRepository(dirPath, "Test1", "=ANONYMOUS_ALLOWED",
			ADMIN_USER + "=ADMIN", USER_A + "=WRITE");
		try {
			createRepositoryItem(repoFilesystem, "foo1", "/", 0);
			createRepositoryItem(repoFilesystem, "notepad1", "/", 0);
			createRepositoryItem(repoFilesystem, "bash1", "/f2", 0);
			createRepositoryItem(repoFilesystem, "foo2", "/", 2);
		}
		finally {
			repoFilesystem.dispose();
		}
	}

	/**
	 * Sets dummy hash values for the given program.
	 *
	 * @param program the current program
	 */
	private static void setProgramHashes(Program program) {
		int id = program.startTransaction("sethashes");
		try {
			String md5 = RandomStringUtils.randomNumeric(32);
			program.setExecutableMD5(md5);
			String sha256 = RandomStringUtils.randomNumeric(64);
			program.setExecutableSHA256(sha256);
		}
		finally {
			program.endTransaction(id, true);
		}
	}

	/**
	 * Generate self-signed test-CA key/certificate and a test user key/certificate
	 */
	private static void generatePkiCerts() throws Exception {

		String caPath = getTestPkiCACertsPath(); // CA certs keystore is .jks file
		File caFile = new File(caPath);
		if (caFile.exists() && !caFile.delete()) {
			throw new RuntimeException("Failed to generate new test-CA key file: " + caPath);
		}

		String userKeystorePath = getTestPkiUserKeystorePath(); // user keystore is .p12 file
		File userKeystoreFile = new File(userKeystorePath);
		if (userKeystoreFile.exists() && !userKeystoreFile.delete()) {
			throw new RuntimeException(
				"Failed to generate new test-user key file: " + userKeystorePath);
		}

		String serverKeystorePath = getTestPkiServerKeystorePath(); // server keystore is .p12 file
		File serverKeystoreFile = new File(serverKeystorePath);
		if (serverKeystoreFile.exists() && !serverKeystoreFile.delete()) {
			throw new RuntimeException(
				"Failed to generate new test-server key file: " + serverKeystorePath);
		}

		// Generate CA certificate and keystore
		Msg.info(ServerTestUtil.class, "Generating self-signed CA cert: " + caPath);

		CertificateExtensions caCertExtensions = new CertificateExtensions();
		BasicConstraintsExtension caBasicConstraints = new BasicConstraintsExtension(true, true, 1);
		caCertExtensions.set(PKIXExtensions.BasicConstraints_Id.toString(), caBasicConstraints);

		KeyUsageExtension caKeyUsage = new KeyUsageExtension();
		caKeyUsage.set(KeyUsageExtension.KEY_CERTSIGN, true);
		caCertExtensions.set(PKIXExtensions.KeyUsage_Id.toString(), caKeyUsage);

		KeyStore caKeystore = ApplicationKeyManagerUtils.createKeyStore(null, "PKCS12",
			ApplicationKeyManagerFactory.DEFAULT_PASSWORD.toCharArray(), "test-CA",
			caCertExtensions, TEST_PKI_CA_DN, null, 2);
		ApplicationKeyManagerUtils.exportX509Certificates(caKeystore, caFile);

		PasswordProtection caPass =
			new PasswordProtection(ApplicationKeyManagerFactory.DEFAULT_PASSWORD.toCharArray());
		PrivateKeyEntry caPrivateKeyEntry =
			(PrivateKeyEntry) caKeystore.getEntry("test-CA", caPass);

		// Generate User/Client certificate and keystore
		Msg.info(ServerTestUtil.class, "Generating test user key/cert (signed by test-CA, pwd: " +
			TEST_PKI_USER_PASSPHRASE + "): " + userKeystorePath);
		ApplicationKeyManagerUtils.createKeyStore(userKeystoreFile, "PKCS12",
			TEST_PKI_USER_PASSPHRASE.toCharArray(), "test-sig", null, TEST_PKI_USER_DN,
			caPrivateKeyEntry, 2);

		// Generate Server certificate and keystore
		Msg.info(ServerTestUtil.class, "Generating test server key/cert (signed by test-CA, pwd: " +
			TEST_PKI_SERVER_PASSPHRASE + "): " + serverKeystorePath);
		ApplicationKeyManagerUtils.createKeyStore(serverKeystoreFile, "PKCS12",
			TEST_PKI_SERVER_PASSPHRASE.toCharArray(), "test-sig", null, TEST_PKI_SERVER_DN,
			caPrivateKeyEntry, 2);
	}

	/**
	 * Add PKI user to server
	 * @param serverRoot
	 * @param userName
	 * @param dn
	 * @throws Exception
	 */
	public static void addPKIUser(File serverRoot, String userName, String dn) throws Exception {
		ServerAdmin serverAdmin = new ServerAdmin();
		if (dn != null) {
			serverAdmin.execute(new String[] { serverRoot.getAbsolutePath(), "-dn", userName, dn });
		}
		else {
			serverAdmin.execute(new String[] { serverRoot.getAbsolutePath(), "-add", userName });
		}
	}

}
