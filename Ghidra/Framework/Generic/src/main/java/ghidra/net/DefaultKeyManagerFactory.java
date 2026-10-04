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

import java.net.Socket;
import java.net.SocketAddress;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import javax.net.ssl.*;
import javax.rmi.ssl.SslRMIClientSocketFactory;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.x500.X500Principal;

import org.apache.commons.lang3.StringUtils;

import ghidra.framework.Application;
import ghidra.framework.preferences.Preferences;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;

/**
 * {@link DefaultKeyManagerFactory} provides access to the default application key manager
 * associated with the preferred keystore file specified by the {@link #KEYSTORE_PATH_PROPERTY}
 * system property or set with {@link #setDefaultKeyStore(String, boolean)}.
 * <p>
 * Keystore selection depends on the role established via {@link #initialize(boolean)}
 * (client mode is the default for all lazy initialization paths):
 * <ul>
 * <li><b>Explicit keystore</b> (client or server) - a keystore file specified via the
 * {@link #KEYSTORE_PATH_PROPERTY} system property, user preference, or
 * {@link #setDefaultKeyStore(String, boolean)} is always used when set.  The
 * {@link #KEYSTORE_PASSWORD_PROPERTY} applies to such file-based keystores only.  This is 
 * treated as a default password to access the default keystore file if specified.  In the 
 * absence of a configured password provider (e.g., server) it must be specified.
 * </li>
 * <li><b>Server</b> - without an explicit keystore, a self-signed certificate is generated
 * using the identity established with {@link #setDefaultIdentity(X500Principal)}, otherwise
 * a default name is used.  The server may impose use restrictions when an automatic self-signed
 * certificate is used and will cause client-side server-authentication issues if accessed
 * remotely.  The OS-managed keystore is never used by the Ghidra Server.</li>
 * <li><b>Client</b> - without an explicit keystore, the OS-managed user keystore is used
 * when available (<code>Windows-MY</code> on Windows, Apple <code>KeychainStore</code> on
 * macOS).</li>
 * </ul>
 * <p>
 * NOTE: Since {@link SslRMIClientSocketFactory} and {@link SSLServerSocketFactory} employ a
 * static cache of a default {@link SSLSocketFactory}, with its default {@link SSLContext}, we
 * must utilize a wrapped implementation of the associated {@link X509ExtendedKeyManager} so that
 * an updated keystore is used by the existing default {@link SSLSocketFactory}.
 */
public class DefaultKeyManagerFactory {

	/**
	 * Keystore path system property or user preference.  Setting the system
	 * property will take precedence over the user preference.
	 */
	public static final String KEYSTORE_PATH_PROPERTY = "ghidra.keystore";

	/**
	 * Password system property may be set.  If set, this password will be used
	 * when accessing the keystore before attempting to use <code>customPasswordProvider</code>
	 * if it has been set.
	 */
	public static final String KEYSTORE_PASSWORD_PROPERTY = "ghidra.password";

	public static final String DEFAULT_PASSWORD = "changeme";

	private static final int SELF_SIGNED_DURATION_DAYS = 2 * 365; // 2-years

	// Certificate info when self-signed cert is used
	private static X500Principal defaultIdentity;
	private static List<String> defaultSubjectAlternativeNames;

	// True if this JVM is acting as the Ghidra Server (see initialize(boolean)).
	// Factory-level state so it survives key manager invalidation/re-init cycles.
	private static boolean serverMode = false;

	// Factory maintains a single X509 key manager
	private static final DefaultX509KeyManager keyManagerWrapper = new DefaultX509KeyManager();

	/**
	 * Prune path to trim leading and trailing white space. A null will be
	 * returned if the pruned path is null or the empty string.
	 *
	 * @param path file path to be pruned (may be null)
	 * @return pruned path or null if path was null or pruned path was the empty
	 *         string
	 */
	private static String prunePath(String path) {
		if (path != null) {
			path = path.trim();
			if (path.length() == 0) {
				path = null;
			}
		}
		return path;
	}

	/**
	 * Set default user keystore file path (e.g., certificate file with private key).
	 * This method will have no effect if the keystore had been set via the system
	 * property and an error will be displayed.  Otherwise, the keystore will
	 * be updated and the key manager re-initialized.  The user preference will be
	 * updated unless a failure occurred while attempting to open the keystore.
	 * This change will take immediate effect for the current executing application,
	 * however, it may still be superseded by a system property setting when running
	 * the application in the future. See {@link #getKeyStore()}.
	 * 
	 * @param path keystore file path or null to clear current key store and preference.
	 * @param savePreference if true will be saved as user preference
	 * @return true if successful else false if error occurred (see log).
	 */
	public static synchronized boolean setDefaultKeyStore(String path, boolean savePreference) {

		// NOTE: Should consider throwing exception instead of returning boolean

		if (System.getProperty(KEYSTORE_PATH_PROPERTY) != null) {
			Msg.showError(DefaultKeyManagerFactory.class, null, "Set KeyStore Failed",
				"PKI KeyStore was set via system property and can not be changed");
			return false;
		}

		path = prunePath(path);

		try {
			keyManagerWrapper.init(path);
			if (savePreference) {
				Preferences.setProperty(KEYSTORE_PATH_PROPERTY, path);
				Preferences.store();
			}
			return true;
		}
		catch (CancelledException e) {
			// ignore
		}
		catch (GeneralSecurityException e) {
			Msg.showError(DefaultKeyManagerFactory.class, null, "Set KeyStore Failed",
				"Failed to create PKI key manager: " + e.getMessage());
		}
		return false; // keystore left unchanged
	}

	/**
	 * Determine if active key manager is utilizing a generated self-signed certificate (server only)
	 * client certificate.
	 *
	 * @return true if using self-signed certificate.
	 */
	public static boolean usingGeneratedSelfSignedCertificate() {
		return keyManagerWrapper.usingGeneratedSelfSignedCertificate();
	}

	/**
	 * Determine if active key manager is utilizing the OS-managed user keystore
	 * (<code>Windows-MY</code> on Windows, Apple <code>KeychainStore</code> on macOS).
	 *
	 * @return true if using the OS-managed keystore.
	 */
	public static boolean usingOSManagedKeyStore() {
		return keyManagerWrapper.usingOSManagedKeyStore();
	}

	/**
	 * Determine if active key manager is utilizing the file-based user keystore.
	 * @return true if using the file-based user keystore.
	 */
	public static boolean usingFileKeyStore() {
		return keyManagerWrapper.usingFileKeyStore();
	}

	/**
	 * Set the default self-signed principal identity to be used during initialization
	 * if no keystore defined.  Current application key manager will be invalidated.
	 * (NOTE: this is intended for server use only when client will not be performing
	 * CA validation).
	 *
	 * @param identity if not null and a KeyStore path has not be set, this
	 * identity will be used to generate a self-signed certificate and private key
	 */
	public synchronized static void setDefaultIdentity(X500Principal identity) {
		defaultIdentity = identity;
		keyManagerWrapper.invalidateKey();
	}

	/**
	 * Add the optional self-signed subject alternative name to be used during initialization
	 * if no keystore defined.  Current application key manager will be invalidated.
	 * (NOTE: this is intended for server use only when client will not be performing
	 * CA validation).
	 * @param subjectAltName name to be added to the current list of alternative subject names.
	 * A null value will clear all names currently set.  
	 * name will be used to generate a self-signed certificate and private key
	 */
	public synchronized static void addSubjectAlternativeName(String subjectAltName) {
		if (subjectAltName == null) {
			defaultSubjectAlternativeNames = null;
		}
		else {
			if (defaultSubjectAlternativeNames == null) {
				defaultSubjectAlternativeNames = new ArrayList<>();
			}
			defaultSubjectAlternativeNames.add(subjectAltName);
		}
		keyManagerWrapper.invalidateKey();
	}

	/**
	 * Initialize key manager if needed.  Doing this explicitly independent of an SSL connection
	 * allows application to bail before initiating connection.  This will get handshake failure
	 * if user forgets keystore password or other keystore problem.
	 * <p>
	 * The current role is retained (client mode unless {@link #initialize(boolean)} was
	 * previously invoked with <code>true</code>).  In client mode, when no keystore has been
	 * specified, the OS-managed keystore will be used if available.  Otherwise no keystore
	 * is used.
	 *
	 * @return true if key manager initialized, otherwise false
	 */
	public static boolean initialize() {
		try {
			keyManagerWrapper.init();
			return true;
		}
		catch (CancelledException e) {
			// ignore
		}
		catch (Exception e) {
			logInitError(e);
		}
		return false; // keystore left unchanged
	}

	/**
	 * Initialize key manager if needed, indicating whether this JVM is acting as a server
	 * or client.  In server mode the OS-managed keystore is never used.  If server mode and
	 * without an explicit keystore path, a self-signed certificate keystore will be generated 
	 * using the specified {@link #setDefaultIdentity(X500Principal) identity} or a default identity.
	 * If the role differs from the current mode any existing key manager will be invalidated and 
	 * re-initialized.
	 *
	 * @param isServer true if initializing for the Ghidra Server, false for client use.
	 * @return true if key manager initialized, otherwise false
	 */
	public synchronized static boolean initialize(boolean isServer) {
		if (serverMode != isServer) {
			serverMode = isServer;
			keyManagerWrapper.invalidateKey();
		}
		return initialize();
	}

	/**
	 * {@return true if key manager factory has been initialized for dedicated server use}
	 */
	public static boolean isServerMode() {
		return serverMode;
	}
	
	/**
	 * Invalidate the existing default key manager.
	 */
	public synchronized static void invalidateKeyManager() {
		keyManagerWrapper.invalidateKey();
	}

	/**
	 * If the system property <i>ghidra.keystore</i> takes precedence in establishing 
	 * the keystore.  If using a GUI and the system property has not been set, the 
	 * user preference with the same name will be used.
	 * @return active keystore path or null if currently not running with a keystore or
	 * one has not been set.
	 */
	public static String getPreferredKeyStore() {
		String path = prunePath(System.getProperty(KEYSTORE_PATH_PROPERTY));
		if (path == null && !SystemUtilities.isInHeadlessMode()) {
			path = prunePath(Preferences.getProperty(KEYSTORE_PATH_PROPERTY));
		}
		return path;
	}

	/**
	 * Get the default/preferred key store file path.
	 * @return default key store file path or null if not set
	 */
	public static String getKeyStore() {
		return keyManagerWrapper.getKeyStore();
	}

	/**
	 * Get the lazy default key manager associated with the preferred key store.
	 * @return default key manager or null if not initialized
	 */
	public static X509ExtendedKeyManager getKeyManager() {
		return keyManagerWrapper;
	}

	private static void logInitError(Exception e) {
		Msg.showError(DefaultKeyManagerFactory.class, null, "Key Manager Initialization Failure",
			"Failed to create PKI key manager: " + e.getMessage());
	}

	/**
	 * <code>DefaultKeyManager</code> provides a wrapper for the X509 wrappedKeyManager whose
	 * instantiation is delayed until needed.  When a wrapper method is first invoked, the
	 * {@link DefaultX509KeyManager#init()} method is called to open the keystore
	 * (which may require a password prompt) and establish the underlying X509KeyManager.
	 */
	private static class DefaultX509KeyManager extends X509ExtendedKeyManager {

		private record KeyManagerRecord(X509KeyManager wrappedKeyManager, String keystorePath,
				boolean isSelfSigned, boolean isOSManaged) {}

		private static final KeyManagerRecord UNINITIALIZED =
			new KeyManagerRecord(null, null, false, false);

		// Data record is used to allow atomic switching of keystore data
		private volatile KeyManagerRecord keyManagerRecord = UNINITIALIZED;

		private DefaultX509KeyManager() {
			invalidateKey();
		}

		@Override
		public String chooseEngineServerAlias(String keyType, Principal[] issuers,
				SSLEngine engine) {
			try {
				KeyManagerRecord keyMgrRec = init();
				String alias = null;
				if (keyMgrRec.wrappedKeyManager instanceof X509ExtendedKeyManager extKeyMgr) {
					alias = extKeyMgr.chooseEngineServerAlias(keyType, issuers, engine);
				}
				else if (keyMgrRec.wrappedKeyManager != null) {
					alias = keyMgrRec.wrappedKeyManager.chooseServerAlias(keyType, issuers, null);
				}
				return alias;
			}
			catch (CancelledException e) {
				// ignore
			}
			catch (Exception e) {
				logInitError(e);
			}
			return null;
		}

		@Override
		public String chooseEngineClientAlias(String[] keyType, Principal[] issuers,
				SSLEngine engine) {
			try {
				KeyManagerRecord keyMgrRec = init();
				String alias = null;
				if (keyMgrRec.wrappedKeyManager instanceof X509ExtendedKeyManager extKeyMgr) {
					alias = extKeyMgr.chooseEngineClientAlias(keyType, issuers, engine);
				}
				else if (keyMgrRec.wrappedKeyManager != null) {
					alias = keyMgrRec.wrappedKeyManager.chooseClientAlias(keyType, issuers, null);
				}
				if (alias == null) {
					warnNoClientCert(engine);
				}
				return alias;
			}
			catch (CancelledException e) {
				// ignore
			}
			catch (Exception e) {
				logInitError(e);
			}
			return null;
		}

		@Override
		public String chooseClientAlias(String[] keyType, Principal[] issuers,
				Socket socket) {
			try {
				KeyManagerRecord keyMgrRec = init();
				String alias = null;
				if (keyMgrRec.wrappedKeyManager != null) {
					alias = keyMgrRec.wrappedKeyManager.chooseClientAlias(keyType, issuers, socket);
				}
				if (alias == null) {
					warnNoClientCert(socket);
				}
				return alias;
			}
			catch (CancelledException e) {
				// ignore
			}
			catch (Exception e) {
				logInitError(e);
			}
			return null;
		}

		@Override
		public String chooseServerAlias(String keyType, Principal[] issuers,
				Socket socket) {
			try {
				KeyManagerRecord keyMgrRec = init();
				String alias = null;
				if (keyMgrRec.wrappedKeyManager != null) {
					alias = keyMgrRec.wrappedKeyManager.chooseServerAlias(keyType, issuers, socket);
				}
				return alias;
			}
			catch (CancelledException e) {
				// ignore
			}
			catch (Exception e) {
				logInitError(e);
			}
			return null;
		}

		private void warnNoClientCert(Socket socket) {
			if (socket != null) {
				Msg.warn(this,
					"No suitable user PKI certificate available for authentication to server: " +
						getPeerEndpoint(socket));
			}
		}

		private void warnNoClientCert(SSLEngine engine) {
			if (engine != null) {
				Msg.warn(this,
					"No suitable user PKI certificate available for authentication to server: " +
						getPeerEndpoint(engine));
			}
		}

		/**
		 * Get remote endpoint description for the specified connected socket.
		 * @param socket connection socket
		 * @return remote endpoint description
		 */
		private static String getPeerEndpoint(Socket socket) {
			SocketAddress addr = socket.getRemoteSocketAddress();
			return addr != null ? addr.toString() : "<unknown>";
		}

		/**
		 * Get remote endpoint description for the specified SSL engine.
		 * @param engine SSL engine
		 * @return remote endpoint description
		 */
		private static String getPeerEndpoint(SSLEngine engine) {
			String host = engine.getPeerHost();
			return host != null ? (host + ":" + engine.getPeerPort()) : "<unknown>";
		}

		@Override
		public String[] getClientAliases(String keyType, Principal[] issuers) {
			try {
				KeyManagerRecord keyMgrRec = init();
				if (keyMgrRec.wrappedKeyManager != null) {
					return keyMgrRec.wrappedKeyManager.getClientAliases(keyType, issuers);
				}
			}
			catch (CancelledException e) {
				// ignore
			}
			catch (Exception e) {
				logInitError(e);
			}
			return null;
		}

		@Override
		public String[] getServerAliases(String keyType, Principal[] issuers) {
			try {
				KeyManagerRecord keyMgrRec = init();
				if (keyMgrRec.wrappedKeyManager != null) {
					return keyMgrRec.wrappedKeyManager.getServerAliases(keyType, issuers);
				}
			}
			catch (CancelledException e) {
				// ignore
			}
			catch (Exception e) {
				logInitError(e);
			}
			return null;
		}

		@Override
		public X509Certificate[] getCertificateChain(String alias) {
			try {
				KeyManagerRecord keyMgrRec = init();
				if (keyMgrRec.wrappedKeyManager != null) {
					return keyMgrRec.wrappedKeyManager.getCertificateChain(alias);
				}
			}
			catch (CancelledException e) {
				// ignore
			}
			catch (Exception e) {
				logInitError(e);
			}
			return null;
		}

		@Override
		public PrivateKey getPrivateKey(String alias) {
			try {
				KeyManagerRecord keyMgrRec = init();
				if (keyMgrRec.wrappedKeyManager != null) {
					return keyMgrRec.wrappedKeyManager.getPrivateKey(alias);
				}
			}
			catch (CancelledException e) {
				// ignore
			}
			catch (Exception e) {
				logInitError(e);
			}
			return null;
		}

		/**
		 * Invalidate the active keystore and key manager
		 */
		private void invalidateKey() {
			keyManagerRecord = UNINITIALIZED;
		}

		/**
		 * Return active keystore path or preferred keystore path if not yet initialized.
		 * @return active keystore path or preferred keystore path if not yet initialized.
		 */
		private String getKeyStore() {
			String path = keyManagerRecord.keystorePath;
			return path != null ? path : getPreferredKeyStore();
		}

		/**
		 * Determine if active key manager is utilizing a generated self-signed certificate.
		 * @return true if using self-signed certificate.
		 */
		private boolean usingGeneratedSelfSignedCertificate() {
			return keyManagerRecord.isSelfSigned();
		}

		/**
		 * Determine if active key manager is utilizing the OS-managed user keystore.
		 * @return true if using the OS-managed keystore.
		 */
		private boolean usingOSManagedKeyStore() {
			return keyManagerRecord.isOSManaged();
		}

		/**
		 * Determine if active key manager is utilizing the file-based user keystore.
		 * @return true if using the file-based user keystore.
		 */
		private boolean usingFileKeyStore() {
			return keyManagerRecord.keystorePath() != null;
		}

		/**
		 * Initialize the default x509KeyManager singleton wrappedKeyManager associated with the 
		 * preferred keystore path.
		 * If the <code>x509KeyManager</code> already exists, this method has no affect.  If the
		 * <code>keystorePath</code> has not already been set, the <code>getPreferredKeyStore()</code>
		 * method will be invoked to obtain the keystore which should be used in establishing the
		 * <code>wrappedKeyManager</code>.  If no keystore has been identified, keystore selection
		 * is based upon the current role (see {@link #init(String)}).  If an error occurs it
		 * will be logged and key managers will remain uninitialized.
		 * @return KeyManagerRecord key manager initialized successfully or was previously initialized
		 * @throws CancelledException user cancelled keystore password entry request
		 * @throws GeneralSecurityException if key manager initialization failed
		 */
		private KeyManagerRecord init() throws GeneralSecurityException, CancelledException {
			KeyManagerRecord keyMgrRec = keyManagerRecord;
			if (keyMgrRec != UNINITIALIZED) {
				return keyMgrRec;
			}
			return init(getPreferredKeyStore());
		}

		/**
		 * Initialize the default x509KeyManager singleton wrappedKeyManager using the specified path.
		 * If the <code>x509KeyManager</code> already exists for the specified keystore path,
		 * this method has no affect.  If no keystore has been identified, keystore selection
		 * is based upon the current role:
		 * <ul>
		 * <li>Server mode: if the Default Identity has been set, a self-signed certificate
		 * will be generated, otherwise the wrappedKeyManager will remain null and false will
		 * be returned.</li>
		 * <li>Client mode: the OS-managed user keystore (Windows/macOS) will be used if supported,
		 * otherwise the default Java behavior will apply without a keystore.</li>
		 * </ul>
		 * If an error occurs it will be logged and key managers will remain uninitialized.
		 * @param newKeystorePath specifies the keystore to be opened or null for no keystore
		 * @return KeyManagerRecord key manager initialized successfully or was previously initialized
		 * @throws CancelledException user cancelled keystore password entry request
		 * @throws GeneralSecurityException if key manager initialization failed
		 */
		private synchronized KeyManagerRecord init(String newKeystorePath)
				throws CancelledException, GeneralSecurityException {

			if (newKeystorePath != null) {
				// Specified keystore is already being used
				if (keyManagerRecord.wrappedKeyManager != null &&
					Objects.equals(keyManagerRecord.keystorePath, newKeystorePath)) {
					return keyManagerRecord;
				}
			}
			else if (keyManagerRecord != UNINITIALIZED && keyManagerRecord.keystorePath == null) {
				// Assume we have already initialized using OS or default
				return keyManagerRecord;
			}
			
			KeyManagerRecord newKeyManagerRecord = null;
			boolean failed = false;
			try {
				// Always use keystorePath is specified
				if (!StringUtils.isBlank(newKeystorePath)) {
					Msg.info(DefaultKeyManagerFactory.class,
						"Using certificate keystore: " + newKeystorePath);
					// Password optionally specified via property
					String keystorePwd = System.getProperty(KEYSTORE_PASSWORD_PROPERTY);
					newKeyManagerRecord = new KeyManagerRecord(
						ApplicationKeyManagerFactory.getKeyManager(newKeystorePath, keystorePwd),
						newKeystorePath, false, false);
					return newKeyManagerRecord;
				}

				if (serverMode) {
					// Server mode without a specified key store file will use self-signed certificate.
					// A server should generally specify a default identify 
					// Server may impose limitations.
					if (defaultIdentity == null) {
						defaultIdentity = getDefaultServerCertificateName();
					}
					Msg.info(this, "Using self-signed certificate: " + defaultIdentity.getName());
					char[] pwd = DEFAULT_PASSWORD.toCharArray();
					KeyStore selfSignedKeyStore = PKIUtils.createKeyStore("defaultSigKey",
						defaultIdentity.getName(), SELF_SIGNED_DURATION_DAYS, null, false, null,
						"JKS", defaultSubjectAlternativeNames, pwd);
					newKeyManagerRecord = new KeyManagerRecord(ApplicationKeyManagerFactory
							.getKeyManagerFromKeyStore(selfSignedKeyStore, pwd),
						null, true, false);
					return newKeyManagerRecord;
				}

				// Client without a keystore: attempt to load OS-managed keystore 
				X509KeyManager osKeyManager = ApplicationKeyManagerFactory.getOSKeyManager();
				if (osKeyManager != null) {
					newKeyManagerRecord = new KeyManagerRecord(osKeyManager, null, false, true);
					return newKeyManagerRecord;
				}
				
				// Rely on Java's default behavior - no need to use self-signed certificate for client.
				// If PKI Client Authentication is used a real User Certification will be needed. 
				newKeyManagerRecord = new KeyManagerRecord(null, null, false, false);
				return newKeyManagerRecord;
			}
			catch (CancelledException e) {
				failed = true;
				throw e;
			}
			catch (GeneralSecurityException e) {
				throw e;
			}
			catch (Throwable t) {
				failed = true;
				throw new KeyStoreException("Failed to create PKI key manager", t);
			}
			finally {
				if (!failed) {
					keyManagerRecord = newKeyManagerRecord;
				}
			}
		}

		/**
		 * Get name to be used for the auto-generated self-signed server certificate
		 * (e.g., "Ghidra_Server").
		 * @return server certificate name
		 */
		private X500Principal getDefaultServerCertificateName() {
			return new X500Principal("CN=" + (Application.isInitialized() ? Application.getName() : "Ghidra_Server"));
		}
	}

	/**
	 * Sign the supplied token byte array using an installed certificate from
	 * one of the specified authorities
	 * @param authorities trusted certificate authorities used to constrain client certificate
	 *   (may be null or empty array if CA constraint does not matter).
	 * @param token token byte array
	 * @return signed token object
	 * @throws NoSuchAlgorithmException algorithm associated within signing certificate not found
	 * @throws SignatureException failed to generate SignedToken
	 * @throws CertificateException error associated with signing certificate
	 */
	public static SignedToken getSignedToken(Principal[] authorities, byte[] token)
			throws NoSuchAlgorithmException, SignatureException, CertificateException {

		PrivateKey privateKey = null;
		X509Certificate[] certificateChain = null;
		try {
			X509ExtendedKeyManager x509KeyManager = getKeyManager();
			if (x509KeyManager != null) {
				String alias = x509KeyManager.chooseClientAlias(new String[] { PKIUtils.RSA_TYPE },
					authorities, null);
				if (alias != null) {
					privateKey = x509KeyManager.getPrivateKey(alias);
					certificateChain = x509KeyManager.getCertificateChain(alias);
				}
			}
			if (privateKey == null || certificateChain == null) {
				CertificateException e =
					new CertificateException("suitable PKI certificate not found");
				throw e;
			}

			//
			// See JAVA Examples in a Nutshell (p.358) for use of Signer and
			// IdentityScope classes
			//

			String algorithm = certificateChain[0].getSigAlgName();
			Signature sig = Signature.getInstance(algorithm);
			try {
				sig.initSign(privateKey);
			}
			catch (InvalidKeyException e) {
				throw new CertificateException("suitable PKI certificate not found", e);
			}
			sig.update(token);

			return new SignedToken(token, sig.sign(), certificateChain, algorithm);
		}
		finally {
			if (privateKey != null) {
				// Note: Keystore destroy only supported in Java 1.8
				try {
					privateKey.destroy();
				}
				catch (DestroyFailedException e) {
					// ignore - may not be supported by all keystores
				}
			}
		}
	}

	/**
	 * Verify that the specified sigBytes reflect my signature of the specified token.
	 * @param authorities trusted certificate authorities used to constrain client certificate
	 *   (may be null or empty array if CA constraint does not matter).
	 * @param token byte array token
	 * @param signature token signature
	 * @return true if signature is my signature
	 * @throws NoSuchAlgorithmException algorithym associated within signing certificate not found
	 * @throws SignatureException failed to generate SignedToken
	 * @throws CertificateException error associated with signing certificate
	 */
	public static boolean isMySignature(Principal[] authorities, byte[] token, byte[] signature)
			throws NoSuchAlgorithmException, SignatureException, CertificateException {
		SignedToken signedToken = getSignedToken(authorities, token);
		return Arrays.equals(signature, signedToken.signature);
	}
}
