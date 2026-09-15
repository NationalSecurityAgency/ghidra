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
package ghidra.net;

import java.io.FileNotFoundException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import javax.net.ssl.*;
import javax.rmi.ssl.SslRMIClientSocketFactory;
import javax.security.auth.x500.X500Principal;

import org.apache.commons.lang3.StringUtils;

import ghidra.framework.OperatingSystem;
import ghidra.util.Msg;

/**
 * <code>DefaultTrustManagerFactory</code> provides the ability to establish
 * acceptable certificate authorities to be used with the default SSLContext
 * as established by {@link DefaultSSLContextInitializer}. 
 * <p>
 * All SSL connections which leverage this factory will perform peer authentication against
 * the established certificate authorities.  If an error occurs while reading a specified CA
 * certs file, a "closed" trust policy is adopted and all peer authentication will fail.
 * <p>
 * An application X.509 CA certificates file path may optionally be specified via the system
 * property <i>ghidra.cacerts</i>.  The file may be in a standard form (*.pem, *.crt,
 * *.cer, *.der) or may be in a Java JKS form (*.jks). The application may choose to set this
 * property automatically based upon the presence of a <i>cacerts</i> file at a predetermined
 * location prior to trust manager initialization.
 * <p>
 * When the <i>ghidra.cacerts</i> property has been specified that trust store is used
 * exclusively and the OS and Java default trust stores are ignored.  This applies to both
 * client and server use, allowing a deployment to restrict trust to its own authorities.  When
 * the property has not been specified the OS trust store and the Java default trust store are
 * used.
 * <p>
 * A server reached over a loopback connection is authenticated in the same way as any other.
 * Setting the client property <i>ghidra.disable.loopback.server.authentication</i> to
 * {@code true} waives that authentication for loopback connections only, which permits such a
 * server to present a self-signed certificate.  It should be used only where every local account
 * is trusted: a loopback connection is not inherently authentic, and any local process able to
 * bind the port ahead of the intended server would be accepted in its place - along with any
 * credential subsequently sent to it.
 * <p>
 * NOTE: Since {@link SslRMIClientSocketFactory} and {@link SSLServerSocketFactory} employ a
 * static cache of a default {@link SSLSocketFactory}, with its default {@link SSLContext}, we
 * must utilize a wrapped implementation of the associated {@link X509TrustManager} so that any
 * changes are used by the existing default {@link SSLSocketFactory}.
 */
public class DefaultTrustManagerFactory {

	/**
	 * The VM property name to be used when specifying the application trust store
	 * X509 'cacerts' file path.
	 */
	public static final String GHIDRA_CACERTS_PATH_PROPERTY = "ghidra.cacerts";
	
	/**
	 * The VM property name which may be used to disable authentication of a server certificate
	 * presented over a loopback connection.  Loopback server authentication is performed by
	 * default; specifying this property as {@code true} waives it, permitting a server reached
	 * over loopback to present a self-signed (or otherwise untrusted) certificate.
	 */
	public static final String GHIDRA_DISABLE_LOOPBACK_SERVER_AUTH_PROPERTY =
			"ghidra.disable.loopback.server.authentication";

	// Must default to false so that authentication is performed until the property has actually
	// been read by init(); a true initial value would waive it for any connection established
	// beforehand.  The effective value is established by init().
	private static boolean disableLoopbackServerAuth = false;

	/**
	 * Use a singleton wrappedTrustManager so we can alter the true trustManager
	 * as needed.  Once the installed trust manager is consumed by the SSL Engine,
	 * we are unable to get it to use a new one.  Use of a wrapper solves this
	 * issue which occurs during testing.
	 */
	private static final WrappedTrustManager wrappedTrustManager = new WrappedTrustManager();

	/**
	 * <code>ApplicationTrustManagerFactory</code> constructor
	 */
	private DefaultTrustManagerFactory() {
		// no instantiation - static methods only
	}

	/**
	 * Initialize trust managers.  The OS and Java default trust stores are loaded unless a
	 * trust store has been specified with the <i>ghidra.cacerts</i> property, in which case
	 * that trust store is used exclusively.  If an error occurs processing a specified
	 * cacerts file, a "closed" trust policy will be adopted.
	 */
	private static void init() {
		
		// Loopback server authentication is enabled by default, although it can be disabled 
		// via a property setting
		disableLoopbackServerAuth = Boolean.parseBoolean(
				System.getProperty(GHIDRA_DISABLE_LOOPBACK_SERVER_AUTH_PROPERTY, "false"));
		if (disableLoopbackServerAuth) {
			Msg.warn(DefaultTrustManagerFactory.class, "Loopback server authentication has been disabled.");
		}

		String cacertsPath = System.getProperty(GHIDRA_CACERTS_PATH_PROPERTY);
		if (StringUtils.isBlank(cacertsPath)) {
			cacertsPath = null;
		}

		// A specified cacerts trust store is used exclusively, for both client and server use,
		// so that a deployment is able to restrict trust to its own certificate authorities.
		// The OS and Java default trust stores are only used in its absence.
		boolean loadDefaultTrustStores = (cacertsPath == null);
		wrappedTrustManager.initialize(loadDefaultTrustStores);

		if (cacertsPath != null) {
			try {
				KeyStore trustStore = FlexibleTrustStoreLoader.getTrustStore(cacertsPath);
				X509TrustManager trustManager = getTrustManager(trustStore);
				wrappedTrustManager.addTrustManager(trustManager);

				Msg.info(DefaultTrustManagerFactory.class,
					"Loaded " + trustManager.getAcceptedIssuers().length +
						" trusted CA certificates from: " + cacertsPath);
			}
			catch (FileNotFoundException | KeyStoreException | NoSuchAlgorithmException e) {
				wrappedTrustManager.setTrustManagerError(e);
				String msg = e.getMessage();
				if (msg == null) {
					msg = e.toString();
				}
				Msg.error(DefaultTrustManagerFactory.class,
					"Failed to process cacerts (" + cacertsPath + "): " + msg, e);
			}
		}

	}

	/**
	 * Get trust manager after performing any necessary initialization.
	 * 
	 * @return trust managers
	 */
	public static synchronized TrustManager[] getTrustManagers() {
		if (!wrappedTrustManager.isReady()) {
			init(); // lazy initialization to allow password prompt when needed
		}
		return new TrustManager[] { wrappedTrustManager };
	}

	/**
	 * Invalidate the active keystore and key manager.
	 * 
	 * NOTE: This should only be invoked by {@link DefaultSSLContextInitializer}.
	 */
	static synchronized void invalidateTrustManagers() {
		wrappedTrustManager.invalidate();
	}

	/**
	 * Returns a list of trusted issuers (i.e., CA certificates) as established
	 * by the {@link DefaultTrustManagerFactory}.
	 * 
	 * @return array of trusted Certificate Authorities
	 * @throws CertificateException if failed to properly initialize trust manager
	 * due to CA certificate error(s).
	 */
	public static X500Principal[] getTrustedIssuers() throws CertificateException {
		return wrappedTrustManager.getTrustedIssuers();
	}

	/**
	 * Validate a client certificate ensuring that it is not expired and is
	 * trusted based upon the active trust managers.
	 * @param certChain X509 certificate chain
	 * @param authType authentication type (i.e., "RSA")
	 * @throws CertificateException if certificate validation fails
	 */
	public static void validateClient(X509Certificate[] certChain, String authType)
			throws CertificateException {
		wrappedTrustManager.checkClientTrusted(certChain, authType);
	}

	private static class WrappedTrustManager extends X509ExtendedTrustManager {

		private List<X509TrustManager> trustManagers;
		private Exception caError;
		private X509Certificate[] trustedIssuers;

		synchronized boolean isReady() {
			return trustManagers != null;
		}

		synchronized void invalidate() {
			trustManagers = null;
			caError = null;
			trustedIssuers = null;
		}

		synchronized void initialize(boolean loadDefaultTrustStores) {
			trustManagers = new ArrayList<>();
			caError = null;
			if (loadDefaultTrustStores) {
				addOSTrustManager(trustManagers);
				addDefaultTrustManager(trustManagers);
			}
			trustedIssuers = null;
		}

		synchronized void addTrustManager(X509TrustManager trustManager) {
			if (trustManager != null) {
				trustManagers.add(trustManager);
				trustedIssuers = null;
			}
		}

		synchronized void setTrustManagerError(Exception caError) {
			this.caError = caError;
		}

		@Override
		public synchronized void checkClientTrusted(X509Certificate[] chain, String authType)
				throws CertificateException {
			checkTrustManager();
			CertificateException exc = null;
			for (X509TrustManager trustManager : trustManagers) {
				try {
					trustManager.checkClientTrusted(chain, authType);
					return;
				}
				catch (CertificateException e) {
					exc = keepPreferredException(exc, e);
				}
			}
			if (exc != null) {
				throw exc;
			}
		}

		@Override
		public synchronized void checkClientTrusted(X509Certificate[] chain, String authType,
				Socket socket)
				throws CertificateException {
			checkTrustManager();
			CertificateException exc = null;
			for (X509TrustManager trustManager : trustManagers) {
				try {
					if (trustManager instanceof X509ExtendedTrustManager extTrustManager) {
						extTrustManager.checkClientTrusted(chain, authType, socket);
					}
					else {
						trustManager.checkClientTrusted(chain, authType);
					}
					return;
				}
				catch (CertificateException e) {
					exc = keepPreferredException(exc, e);
				}
			}
			if (exc != null) {
				throw exc;
			}
		}

		@Override
		public synchronized void checkClientTrusted(X509Certificate[] chain, String authType,
				SSLEngine engine)
				throws CertificateException {
			checkTrustManager();
			CertificateException exc = null;
			for (X509TrustManager trustManager : trustManagers) {
				try {
					if (trustManager instanceof X509ExtendedTrustManager extTrustManager) {
						extTrustManager.checkClientTrusted(chain, authType, engine);
					}
					else {
						trustManager.checkClientTrusted(chain, authType);
					}
					return;
				}
				catch (CertificateException e) {
					exc = keepPreferredException(exc, e);
				}
			}
			if (exc != null) {
				throw exc;
			}
		}

		@Override
		public synchronized void checkServerTrusted(X509Certificate[] chain, String authType)
				throws CertificateException {
			checkTrustManager();
			CertificateException exc = null;
			for (X509TrustManager trustManager : trustManagers) {
				try {
					trustManager.checkServerTrusted(chain, authType);
					return;
				}
				catch (CertificateException e) {
					exc = keepPreferredException(exc, e);
				}
			}
			if (exc != null) {
				throw new ServerCertificateException(chain, exc);
			}
		}

		@Override
		public synchronized void checkServerTrusted(X509Certificate[] chain, String authType,
				Socket socket)
				throws CertificateException {
			if (disableLoopbackServerAuth && isLoopback(socket)) {
				return;
			}
			checkTrustManager();
			CertificateException exc = null;
			for (X509TrustManager trustManager : trustManagers) {
				try {
					if (trustManager instanceof X509ExtendedTrustManager extTrustManager) {
						extTrustManager.checkServerTrusted(chain, authType, socket);
					}
					else {
						trustManager.checkServerTrusted(chain, authType);
					}
					return;
				}
				catch (CertificateException e) {
					exc = keepPreferredException(exc, e);
				}
			}
			if (exc != null) {
				throw new ServerCertificateException(chain, exc);
			}
		}

		@Override
		public synchronized void checkServerTrusted(X509Certificate[] chain, String authType,
				SSLEngine engine)
				throws CertificateException {
			if (disableLoopbackServerAuth && isLoopback(engine)) {
				return;
			}
			checkTrustManager();
			CertificateException exc = null;
			for (X509TrustManager trustManager : trustManagers) {
				try {
					if (trustManager instanceof X509ExtendedTrustManager extTrustManager) {
						extTrustManager.checkServerTrusted(chain, authType, engine);
					}
					else {
						trustManager.checkServerTrusted(chain, authType);
					}
					return;
				}
				catch (CertificateException e) {
					exc = keepPreferredException(exc, e);
				}
			}
			if (exc != null) {
				throw new ServerCertificateException(chain, exc);
			}
		}

		private CertificateException keepPreferredException(CertificateException exc1,
				CertificateException exc2) {
			// Since we may be checking with multiple trust managers, where one may have the 
			// correct certification path, we would prefer to keep an exception that was produced
			// in that case (i.e., general CertificateException) instead of a validator exception
			// where a trust path was not found.
			if (exc1 != null && exc1.getClass() == CertificateException.class) {
				if (exc1.getCause() == null) {
					return exc1;
				}
				if (exc2 != null && exc2.getClass() != CertificateException.class) {
					return exc1;
				}
			}
			return exc2;
		}

		private boolean isLoopback(Socket socket) {
			if (socket != null) {
				InetAddress address = socket.getInetAddress();
				if (address != null && address.isLoopbackAddress()) {
					return true;
				}
			}
			return false;
		}

		private boolean isLoopback(SSLEngine engine) {
			if (engine != null) {
				String peerHost = engine.getPeerHost();
				if (peerHost != null) {
					return isLoopbackHost(peerHost);
				}
			}
			return false;
		}

		/**
		 * Determine if a peer host is one of the standard loopback names or addresses.
		 * <p>
		 * Only these literal forms are recognized; no name resolution is performed.  A resolver
		 * lookup here would occur while this trust manager's monitor is held, where a slow or
		 * unresponsive resolver would stall every TLS handshake within this JVM.  Restricting the
		 * check to the standard forms also keeps it independent of name resolution, which a
		 * {@code hosts} entry or DNS record could otherwise influence.
		 *
		 * @param peerHost peer host name or literal address
		 * @return true if the peer host is a standard loopback name or address
		 */
		private boolean isLoopbackHost(String peerHost) {
			String host = peerHost.trim();
			if (host.startsWith("[") && host.endsWith("]")) {
				host = host.substring(1, host.length() - 1);	// IPv6 literal in URI form
			}
			return NetworkUtils.isLoopbackAddress(host);
		}

		@Override
		public synchronized X509Certificate[] getAcceptedIssuers() {
			if (trustedIssuers != null) {
				return trustedIssuers;
			}

			Set<CertIdentity> seen = new HashSet<>();
			List<X509Certificate> deduped = new ArrayList<>();

			for (X509TrustManager tm : trustManagers) {
				for (X509Certificate cert : tm.getAcceptedIssuers()) {
					CertIdentity id = new CertIdentity(cert);
					if (seen.add(id)) {
						deduped.add(cert);
					}
				}
			}
			trustedIssuers = deduped.toArray(new X509Certificate[deduped.size()]);
			return trustedIssuers;
		}

		synchronized X500Principal[] getTrustedIssuers() throws CertificateException {

			WrappedTrustManager trustMgr = wrappedTrustManager;
			trustMgr.checkTrustManager();

			X509Certificate[] acceptedIssuers = trustMgr.getAcceptedIssuers();
			if (acceptedIssuers == null || acceptedIssuers.length == 0) {
				return null; // trust all authorities
			}

			Set<X500Principal> set = new HashSet<>();
			for (X509Certificate trustedCert : acceptedIssuers) {
				set.add(trustedCert.getSubjectX500Principal());
			}
			X500Principal[] principals = new X500Principal[set.size()];
			return set.toArray(principals);
		}

		private void checkTrustManager() throws CertificateException {
			if (caError != null) {
				throw new CertificateException("Failed to load CA certs", caError);
			}
			if (trustManagers != null && !trustManagers.isEmpty()) {
				return; // OK to proceed with at least one trust manager installed
			}
			throw new CertificateException("Trust manager not properly initialized");
		}

	}
	
	private static final class CertIdentity {
		private final String subject;
		private final String serial;
		private final byte[] publicKey;

		public CertIdentity(X509Certificate cert) {
			this.subject = cert.getSubjectX500Principal().getName();
			this.serial = cert.getSerialNumber().toString();
			this.publicKey = cert.getPublicKey().getEncoded();
		}

		@Override
		public boolean equals(Object o) {
			if (!(o instanceof CertIdentity))
				return false;
			CertIdentity other = (CertIdentity) o;
			return subject.equals(other.subject) && serial.equals(other.serial) &&
				java.util.Arrays.equals(publicKey, other.publicKey);
		}

		@Override
		public int hashCode() {
			return subject.hashCode() ^ serial.hashCode() ^ java.util.Arrays.hashCode(publicKey);
		}
	}

	private static void addOSTrustManager(List<X509TrustManager> trustManagers) {
		try {
			KeyStore ks;
			if (OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.WINDOWS) {
				ks = KeyStore.getInstance("Windows-ROOT");
				ks.load(null, null); // populate from OS trust store
			}
			else if (OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.MAC_OS_X) {
				ks = KeyStore.getInstance("KeychainStore");
				ks.load(null, null); // populate from OS trust store
			}
			else {
				ks = UnixSystemTrustKeyStoreUtil.loadSystemCaKeyStore();
			}
			if (ks != null) {
				X509TrustManager trustManager = getTrustManager(ks);
				trustManagers.add(trustManager);

				Msg.info(DefaultTrustManagerFactory.class,
					"Loaded " + trustManager.getAcceptedIssuers().length +
						" trusted CA certificates from the OS trust store.");
			}
		}
		catch (Exception e) {
			wrappedTrustManager.caError = e;
			Msg.error(DefaultTrustManagerFactory.class,
				"OS trust store load failed: " + e.getMessage());
		}
	}

	private static void addDefaultTrustManager(List<X509TrustManager> trustManagers) {
		String defaultCACertsPath = System.getProperty("java.home") + "/lib/security/cacerts";
		try {
			KeyStore ks = FlexibleTrustStoreLoader.getTrustStore(defaultCACertsPath);
			X509TrustManager trustManager = getTrustManager(ks);
			trustManagers.add(trustManager);

			Msg.info(DefaultTrustManagerFactory.class,
				"Loaded " + trustManager.getAcceptedIssuers().length +
					" trusted CA certificates from the Java default trust store.");
		}
		catch (Exception e) {
			if (wrappedTrustManager.caError == null) { // don't overwrite addOSTrustManager error
				wrappedTrustManager.caError = e;
			}
			Msg.error(DefaultTrustManagerFactory.class,
				"Default Java Truststore load failed: " + e.getMessage());
		}
	}

	private static X509TrustManager getTrustManager(KeyStore trustStore)
			throws NoSuchAlgorithmException, KeyStoreException {
		TrustManagerFactory tmf = TrustManagerFactory.getInstance(
			TrustManagerFactory.getDefaultAlgorithm());
		tmf.init(trustStore);
		for (TrustManager tm : tmf.getTrustManagers()) {
			if (tm instanceof X509TrustManager x509Tm) {
				if (x509Tm.getAcceptedIssuers().length != 0) {
					return x509Tm;
				}
			}
		}
		throw new KeyStoreException("X509 CA certificates not found");
	}

}
