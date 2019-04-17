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
import java.io.IOException;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.net.ssl.*;
import javax.security.auth.x500.X500Principal;

import org.apache.commons.lang3.StringUtils;

import ghidra.framework.preferences.Preferences;
import ghidra.security.KeyStorePasswordProvider;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.filechooser.ExtensionFileFilter;
import ghidra.util.filechooser.GhidraFileFilter;

/**
 * <code>ApplicationKeyManagerFactory</code> provides application keystore management
 * functionality and the ability to generate X509KeyManager's for use with an SSLContext
 * or other PKI related operations.  Access to keystore data (other than keystore path)
 * is restricted to package access.  Certain public operations are exposed via the
 * {@link ApplicationKeyManagerUtils} class.
 */
public class ApplicationKeyManagerFactory {

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

	/**
	 * PKCS Private Key/Certificate File Filter
	 */
	public static final GhidraFileFilter CERTIFICATE_FILE_FILTER =
		new ExtensionFileFilter(ApplicationKeyStore.PKCS_FILE_EXTENSIONS, "PKCS Key File");

	public static final String DEFAULT_PASSWORD = "changeme";

	private static final int SELF_SIGNED_DURATION_DAYS = 2 * 365; // 2-years

	private static KeyStorePasswordProvider customPasswordProvider;
	private static X500Principal defaultIdentity;

	private static ApplicationKeyManagerFactory instance;

	/**
	 * Get ApplicationKeyManager singleton
	 * @return application X509KeyManager
	 */
	static synchronized ApplicationKeyManagerFactory getInstance() {
		if (instance == null) {
			instance = new ApplicationKeyManagerFactory();
		}
		return instance;
	}

	/**
	 * get the single key manager instance associated with the factory.
	 * @return key manager instance
	 */
	private static ApplicationKeyManager getKeyManagerWrapper() {
		return getInstance().keyManagerWrapper;
	}

	/**
	 * Set the active keystore password provider
	 * @param provider keystore password provider
	 */
	public static synchronized void setKeyStorePasswordProvider(KeyStorePasswordProvider provider) {
		customPasswordProvider = provider;
	}

	/**
	 * Prune path to trim leading and trailing white space. A null will be
	 * returned if the pruned path is null or the empty string.
	 *
	 * @param path
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
	 * Set user keystore file path (e.g., certificate file with private key).
	 * This method will have no effect if the keystore had been set via the system
	 * property and an error will be displayed.  Otherwise, the keystore will
	 * be updated and the key manager re-initialized.  The user preference will be
	 * updated unless a failure occurred while attempting to open the keystore.
	 * This change will take immediate effect for the current executing application,
	 * however, it may still be superseded by a system property setting when running
	 * the application in the future. See {@link #getKeyStore()}.
	 * @param path keystore file path
	 * @param savePreference if true will be saved as user preference
	 * @throws IOException if file or certificate error occurs
	 */
	public static synchronized void setKeyStore(String path, boolean savePreference)
			throws IOException {

		if (System.getProperty(KEYSTORE_PATH_PROPERTY) != null) {
			Msg.showError(ApplicationKeyManagerFactory.class, null, "Set KeyStore Failed",
				"KeyStore was set via system property and can not be changed");
			return;
		}

		path = prunePath(path);

		try {
			boolean keyInitialized = getKeyManagerWrapper().init(path);

			if (savePreference && (path == null || keyInitialized)) {
				Preferences.setProperty(KEYSTORE_PATH_PROPERTY, path);
				Preferences.store();
			}
		}
		catch (CancelledException e) {
			// ignore - keystore left unchanged
		}
	}

	/**
	 * Get the keystore path associated with the active key manager or the
	 * preferred keystore path if not yet initialized.
	 */
	public static synchronized String getKeyStore() {
		return getKeyManagerWrapper().getKeyStore();
	}

	/**
	 * If the system property <i>ghidra.keystore</i> takes precedence in establishing 
	 * the ketsore.  If using a GUI and the system property has not been set, the 
	 * user preference with the same name will be used.
	 * @return active keystore path or null if currently not running with a keystore or
	 * one has not been set.
	 */
	public static synchronized String getPreferredKeyStore() {
		String path = prunePath(System.getProperty(KEYSTORE_PATH_PROPERTY));
		if (path == null && !SystemUtilities.isInHeadlessMode()) {
			path = prunePath(Preferences.getProperty(KEYSTORE_PATH_PROPERTY));
		}
		return path;
	}

	/**
	 * Determine if active key manager is utilizing a generated self-signed certificate.
	 * @return true if using self-signed certificate.
	 */
	public static synchronized boolean usingGeneratedSelfSignedCertificate() {
		return getKeyManagerWrapper().usingGeneratedSelfSignedCertificate();
	}

	/**
	 * Set the default self-signed principal identity to be used during initialization
	 * if no keystore defined.  Current application key manager will be invalidated.
	 * @param identity if not null and a KeyStore path has not be set, this
	 * identity will be used to generate a self-signed certificate and private key
	 * (NOTE: this is intended for server use only when client will not be performing
	 * CA validation).
	 */
	public synchronized static void setDefaultIdentity(X500Principal identity) {
		defaultIdentity = identity;
		getKeyManagerWrapper().invalidateKey();
	}

	/**
	 * Initialize key manager if needed.  Doing this explicitly independent of an SSL connection
	 * allows application to bail before initiating connection.  This will get handshake failure
	 * if user forgets keystore password or other keystore problem.
	 * @return true if key manager initialized, otherwise false
	 */
	public synchronized static boolean initialize() {
		try {
			return getKeyManagerWrapper().init();
		}
		catch (CancelledException e) {
			return false;
		}
	}

	/**
	 * Invalidate the key managers associated with this factory
	 */
	public synchronized static void invalidateKeyManagers() {
		getKeyManagerWrapper().invalidateKey();
	}

	// Factory maintains a single X509 key manager
	private ApplicationKeyManager keyManagerWrapper = new ApplicationKeyManager();

	/**
	 * <code>ApplicationKeyManagerFactory</code> constructor
	 */
	private ApplicationKeyManagerFactory() {
	}

	/**
	 * Get key managers
	 * @return key managers
	 */
	KeyManager[] getKeyManagers() {
		return new KeyManager[] { keyManagerWrapper };
	}

	/**
	 * <code>ProtectedKeyStoreData</code> provides a container for a keystore
	 * which has been successfully accessed using the specified password.
	 */
	private static class ProtectedKeyStoreData {
		KeyStore keyStore;
		char[] password;

		ProtectedKeyStoreData(KeyStore keyStore, char[] password) {
			this.keyStore = keyStore;
			this.password = password != null ? password.clone() : null;
		}

		/**
		 * Dispose this keystore data wrapper and the retained password
		 */
		void dispose() {
			if (password != null) {
				Arrays.fill(password, ' ');
			}
			keyStore = null;
		}

		@Override
		protected void finalize() throws Throwable {
			dispose();
			super.finalize();
		}
	}

	/**
	 * Get protected keystore data for specified keystorePath.  Caller is responsible for
	 * properly disposing returned object.
	 * @param keystorePath protected keystore path
	 * @return protected keystore data
	 * @throws CancelledException password entry was cancelled by user
	 * @throws KeyStoreException error occurred opening/processing keystore
	 */
	private static ProtectedKeyStoreData getProtectedKeyStoreData(String keystorePath)
			throws CancelledException, KeyStoreException {

		Msg.info(ApplicationKeyManagerFactory.class, "Using certificate keystore: " + keystorePath);

		String keystorePwd = System.getProperty(KEYSTORE_PASSWORD_PROPERTY);

		int tryCount = 0;

		while (true) {
			char[] password = new char[0];
			char[] oldPassword = null;
			try {
				if (tryCount == 0) {
					// try no password first
				}
				else if (tryCount == 1) {
					// try default password
					Msg.debug(ApplicationKeyManagerFactory.class,
						"Attempting to load keystore without password...");
					password = DEFAULT_PASSWORD.toCharArray();
				}
				else if (tryCount == 2) {
					// try specified password
					if (keystorePwd != null) {
						Msg.debug(ApplicationKeyManagerFactory.class,
							"Attempting to load keystore with property-based password...");
						password = keystorePwd.toCharArray();
					}
					else {
						// no system property password provided
						++tryCount;
						continue;
					}
				}
				else if (customPasswordProvider != null) {
					disposePassword(oldPassword);
					oldPassword = password;
					password =
						customPasswordProvider.getKeyStorePassword(keystorePath, tryCount != 3);
					if (password == null) {
						throw new CancelledException();
					}
					if (Arrays.equals(password, oldPassword)) {
						// Give-up if same password specified twice to avoid infinite loop
						// just in case password provider only supplies one password
						break;
					}
					Msg.debug(ApplicationKeyManagerFactory.class,
						"Attempting to open keystore with user-supplied password...");
				}
				else {
					break; // give-up
				}
				++tryCount;

				// we only support a single password for both keystore and private key
				KeyStore keyStore = ApplicationKeyStore.getKeyStoreInstance(keystorePath, password);
				return new ProtectedKeyStoreData(keyStore, password);
			}
			catch (NoSuchAlgorithmException | CertificateException | FileNotFoundException e) {
				throw new KeyStoreException("Failed to process keystore: " + keystorePath, e);
			}
			catch (KeyStoreException | IOException e) {
				// Java Bug: JDK-6974037 : PKCS12 Keystore load with invalid passwords generates different exceptions
				Exception ioException = getIOException(e);
				if (ioException != null) {
					// Assume all IOExceptions are the result of improperly decrypted keystore
					// since arbitrary and inconsistent errors are produced when attempting to 
					// load an encrypted keystore without a password or with the wrong password.
					continue;
				}
				throw new KeyStoreException(
					"Failed to process keystore (" + tryCount + "): " + keystorePath, e);
			}
			finally {
				disposePassword(oldPassword);
				disposePassword(password);
			}
		}
		throw new KeyStoreException("Failed to unlock key storage: " + keystorePath);
	}

	private static void disposePassword(char[] password) {
		if (password != null) {
			Arrays.fill(password, (char) 0);
			password = null;
		}
	}

	private static IOException getIOException(Exception e) {
		Throwable cause = e;
		while (cause != null) {
			if (cause instanceof IOException) {
				return (IOException) cause;
			}
			cause = cause.getCause();
		}
		return null;
	}

	/**
	 * <code>ApplicationKeyManager</code> provides a wrapper for the X509 wrappedKeyManager whose
	 * instantiation is delayed until needed.  When a wrapper method is first invoked, the
	 * {@link ApplicationKeyManagerFactory#init()} method is called to open the keystore
	 * (which may require a password prompt) and establish the underlying X509KeyManager.
	 */
	private class ApplicationKeyManager extends X509ExtendedKeyManager {

		private X509KeyManager wrappedKeyManager;
		private String keystorePath;
		private boolean isSelfSigned = false;

		@Override
		public String chooseEngineServerAlias(String keyType, Principal[] issuers,
				SSLEngine engine) {
			return super.chooseEngineServerAlias(keyType, issuers, engine);
		}

		@Override
		public String chooseEngineClientAlias(String[] keyType, Principal[] issuers,
				SSLEngine engine) {
			return super.chooseEngineClientAlias(keyType, issuers, engine);
		}

		@Override
		public synchronized String chooseClientAlias(String[] keyType, Principal[] issuers,
				Socket socket) {
			try {
				init();
			}
			catch (CancelledException e) {
				// ignore
			}
			if (wrappedKeyManager == null) {
				return null;
			}
			return wrappedKeyManager.chooseClientAlias(keyType, issuers, socket);
		}

		@Override
		public synchronized String chooseServerAlias(String keyType, Principal[] issuers,
				Socket socket) {
			try {
				init();
			}
			catch (CancelledException e) {
				// ignore
			}
			if (wrappedKeyManager == null) {
				return null;
			}
			return wrappedKeyManager.chooseServerAlias(keyType, issuers, socket);
		}

		@Override
		public String[] getClientAliases(String keyType, Principal[] issuers) {
			try {
				init();
			}
			catch (CancelledException e) {
				// ignore
			}
			if (wrappedKeyManager == null) {
				return null;
			}
			return wrappedKeyManager.getClientAliases(keyType, issuers);
		}

		@Override
		public String[] getServerAliases(String keyType, Principal[] issuers) {
			try {
				init();
			}
			catch (CancelledException e) {
				// ignore
			}
			if (wrappedKeyManager == null) {
				return null;
			}
			return wrappedKeyManager.getServerAliases(keyType, issuers);
		}

		@Override
		public X509Certificate[] getCertificateChain(String alias) {
			if (wrappedKeyManager == null) {
				return null;
			}
			return wrappedKeyManager.getCertificateChain(alias);
		}

		@Override
		public PrivateKey getPrivateKey(String alias) {
			if (wrappedKeyManager == null) {
				return null;
			}
			return wrappedKeyManager.getPrivateKey(alias);
		}

		/**
		 * Invalidate the active keystore and key manager
		 */
		private synchronized void invalidateKey() {
			wrappedKeyManager = null;
			keystorePath = null;
			isSelfSigned = false;
		}

		/**
		 * Return active keystore path or preferred keystore path if not yet initialized.
		 * @return active keystore path or preferred keystore path if not yet initialized.
		 */
		private synchronized String getKeyStore() {
			return wrappedKeyManager != null ? keystorePath : getPreferredKeyStore();
		}

		/**
		 * Determine if active key manager is utilizing a generated self-signed certificate.
		 * @return true if using self-signed certificate.
		 */
		private synchronized boolean usingGeneratedSelfSignedCertificate() {
			return wrappedKeyManager != null && isSelfSigned;
		}

		/**
		 * Initialize the x509KeyManager associated with the active keystore setting.
		 * If the <code>x509KeyManager</code> already exists, this method has no affect.  If the
		 * <code>keystorePath</code> has not already been set, the <code>getPreferredKeyStore()</code>
		 * method will be invoked to obtain the keystore which should be used in establishing the
		 * <code>wrappedKeyManager</code>.  If no keystore has been identified and the Default Identity
		 * has been set, a self-signed certificate will be generated.  If nothing has been set, the
		 * wrappedKeyManager will remain null and false will be returned.  If an error occurs it
		 * will be logged and key managers will remain uninitialized.
		 * @return true if key manager initialized successfully or was previously initialized.
		 * @throws CancelledException user cancelled keystore password entry request
		 */
		private synchronized boolean init() throws CancelledException {
			if (wrappedKeyManager != null) {
				return true;
			}
			return init(getPreferredKeyStore());
		}

		/**
		 * Initialize the x509KeyManager.
		 * If the <code>x509KeyManager</code> already exists for the specified keystore path,
		 * this method has no affect.  If no keystore has been identified and the Default Identity
		 * has been set, a self-signed certificate will be generated.  If nothing has been set, the
		 * wrappedKeyManager will remain null and false will be returned.  If an error occurs it
		 * will be logged and key managers will remain uninitialized.
		 * @param newKeystorePath specifies the keystore to be opened or null for no keystore
		 * @return true if key manager initialized successfully or was previously initialized
		 * @throws CancelledException user cancelled keystore password entry request
		 */
		private synchronized boolean init(String newKeystorePath) throws CancelledException {

			if (wrappedKeyManager != null) {
				if (StringUtils.equals(keystorePath, newKeystorePath)) {
					return true;
				}
				invalidateKey();
			}

			ProtectedKeyStoreData keystoreData = null;
			try {
				if (newKeystorePath != null && newKeystorePath.length() != 0) {
					keystoreData = getProtectedKeyStoreData(newKeystorePath);
				}
				else if (defaultIdentity != null) {
					// use self-signed keystore as fallback (intended for server use only)
					Msg.info(this, "Using self-signed certificate: " + defaultIdentity.getName());
					char[] pwd = DEFAULT_PASSWORD.toCharArray();
					KeyStore selfSignedKeyStore =
						ApplicationKeyManagerUtils.createKeyStore(null, "JKS", pwd, "defaultSigKey",
							null, defaultIdentity.getName(), null, SELF_SIGNED_DURATION_DAYS);
					keystoreData = new ProtectedKeyStoreData(selfSignedKeyStore, pwd);
					isSelfSigned = true;
				}
				else {
					return false;
				}

				ApplicationKeyStore.logCerts(keystoreData.keyStore);

				KeyManagerFactory kmf =
					KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
				kmf.init(keystoreData.keyStore, keystoreData.password);

				// Assume that one keystore will produce at most one KeyManager
				KeyManager[] keyManagers = kmf.getKeyManagers();
				if (keyManagers.length == 1 && (keyManagers[0] instanceof X509KeyManager)) {
					wrappedKeyManager = (X509KeyManager) keyManagers[0];
					keystorePath = newKeystorePath; // update current keystore path
					return true;
				}

				isSelfSigned = false;

				if (keyManagers.length == 0) {
					Msg.showError(this, null, "Keystore Failure",
						"Failed to create key manager: failed to process keystore (no keys processed)");
				}
				else if (keyManagers.length == 1) {
					Msg.showError(this, null, "Keystore Failure",
						"Failed to create key manager: failed to process keystore (expected X.509)");
				}
				else {
					// Unexpected condition
					Msg.showError(this, null, "Keystore Failure",
						"Failed to create key manager: unsupported keystore produced multiple KeyManagers");
				}
			}
			catch (CancelledException e) {
				throw e;
			}
			catch (Exception e) {
				Msg.showError(this, null, "Keystore Failure",
					"Failed to create key manager: " + e.getMessage(), e);
			}
			finally {
				if (keystoreData != null) {
					keystoreData.dispose();
					keystoreData = null;
				}
			}
			return false;
		}
	}

}
