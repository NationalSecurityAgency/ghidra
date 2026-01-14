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
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import javax.net.ssl.*;
import javax.rmi.ssl.SslRMIClientSocketFactory;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.x500.X500Principal;

import org.apache.commons.lang3.StringUtils;

import ghidra.framework.preferences.Preferences;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;

/**
 * {@link DefaultKeyManagerFactory} provides access to the default application key manager
 * associated with the preferred keystore file specified by the {@link #KEYSTORE_PATH_PROPERTY}
 * system property or set with {@link #setDefaultKeyStore(String, boolean)}.  
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
	 * @return true if successful else false if error occured (see log).
	 */
	public static synchronized boolean setDefaultKeyStore(String path, boolean savePreference) {

		if (System.getProperty(KEYSTORE_PATH_PROPERTY) != null) {
			Msg.showError(DefaultKeyManagerFactory.class, null, "Set KeyStore Failed",
				"PKI KeyStore was set via system property and can not be changed");
			return false;
		}

		path = prunePath(path);

		try {
			boolean keyInitialized = keyManagerWrapper.init(path);

			if (savePreference && (path == null || keyInitialized)) {
				Preferences.setProperty(KEYSTORE_PATH_PROPERTY, path);
				Preferences.store();
			}
			return keyInitialized;
		}
		catch (CancelledException e) {
			// ignore - keystore left unchanged
			return false;
		}
	}

	/**
	 * Determine if active key manager is utilizing a generated self-signed certificate.
	 * 
	 * @return true if using self-signed certificate.
	 */
	public static synchronized boolean usingGeneratedSelfSignedCertificate() {
		return keyManagerWrapper.usingGeneratedSelfSignedCertificate();
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
	 * @return true if key manager initialized, otherwise false
	 */
	public synchronized static boolean initialize() {
		try {
			return keyManagerWrapper.init();
		}
		catch (CancelledException e) {
			return false;
		}
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
	public static synchronized String getPreferredKeyStore() {
		String path = prunePath(System.getProperty(KEYSTORE_PATH_PROPERTY));
		if (path == null && !SystemUtilities.isInHeadlessMode()) {
			path = prunePath(Preferences.getProperty(KEYSTORE_PATH_PROPERTY));
		}
		return path;
	}

	/**
	 * Get the default/preferred key store path.
	 * @return default key store path or null if not set
	 */
	public static synchronized String getKeyStore() {
		return keyManagerWrapper.getKeyStore();
	}

	/**
	 * Get the lazy default key manager associated with the preferred key store.
	 * @return default key manager or null if not initialized
	 */
	public static synchronized X509ExtendedKeyManager getKeyManager() {
		return keyManagerWrapper;
	}

	/**
	 * <code>DefaultKeyManager</code> provides a wrapper for the X509 wrappedKeyManager whose
	 * instantiation is delayed until needed.  When a wrapper method is first invoked, the
	 * {@link DefaultX509KeyManager#init()} method is called to open the keystore
	 * (which may require a password prompt) and establish the underlying X509KeyManager.
	 */
	private static class DefaultX509KeyManager extends X509ExtendedKeyManager {

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
			return keystorePath != null ? keystorePath : getPreferredKeyStore();
		}

		/**
		 * Determine if active key manager is utilizing a generated self-signed certificate.
		 * @return true if using self-signed certificate.
		 */
		private synchronized boolean usingGeneratedSelfSignedCertificate() {
			return wrappedKeyManager != null && isSelfSigned;
		}

		/**
		 * Initialize the default x509KeyManager singleton wrappedKeyManager associated with the 
		 * preferred keystore path.
		 * If the <code>x509KeyManager</code> already exists, this method has no affect.  If the
		 * <code>keystorePath</code> has not already been set, the <code>getPreferredKeyStore()</code>
		 * method will be invoked to obtain the keystore which should be used in establishing the
		 * <code>wrappedKeyManager</code>.  If no keystore has been identified and the Default Identity
		 * has been set, a self-signed certificate will be generated.  If nothing has been set, the
		 * wrappedKeyManager will remain null and false will be returned.  If an error occurs it
		 * will be logged and key managers will remain uninitialized.
		 * @return true if key manager initialized successfully or was previously initialized, else
		 * false if keystore path has not been set and default identity for self-signed certificate
		 * has not be established (see {@link DefaultKeyManagerFactory#setDefaultIdentity(X500Principal)}).
		 * @throws CancelledException user cancelled keystore password entry request
		 */
		private synchronized boolean init() throws CancelledException {
			if (wrappedKeyManager != null) {
				return true;
			}
			return init(getPreferredKeyStore());
		}

		/**
		 * Initialize the default x509KeyManager singleton wrappedKeyManager using the specified path.
		 * If the <code>x509KeyManager</code> already exists for the specified keystore path,
		 * this method has no affect.  If no keystore has been identified and the Default Identity
		 * has been set, a self-signed certificate will be generated.  If nothing has been set, the
		 * wrappedKeyManager will remain null and false will be returned.  If an error occurs it
		 * will be logged and key managers will remain uninitialized.
		 * @param newKeystorePath specifies the keystore to be opened or null for no keystore
		 * @return true if key manager initialized successfully or was previously initialized, else
		 * false if new keystore path was not specified and default identity for self-signed certificate
		 * has not be established (see {@link DefaultKeyManagerFactory#setDefaultIdentity(X500Principal)}).
		 * @throws CancelledException user cancelled keystore password entry request
		 */
		private synchronized boolean init(String newKeystorePath) throws CancelledException {

			if (wrappedKeyManager != null) {
				if (StringUtils.equals(keystorePath, newKeystorePath)) {
					return true;
				}
				invalidateKey();
			}

			isSelfSigned = false;
			try {
				if (newKeystorePath != null && newKeystorePath.length() != 0) {
					Msg.info(DefaultKeyManagerFactory.class,
						"Using certificate keystore: " + newKeystorePath);
					// Password optionally specified via property
					String keystorePwd = System.getProperty(KEYSTORE_PASSWORD_PROPERTY);
					wrappedKeyManager =
						ApplicationKeyManagerFactory.getKeyManager(newKeystorePath, keystorePwd);
					keystorePath = newKeystorePath; // update current keystore path
				}
				else if (defaultIdentity != null) {
					// use self-signed keystore as fallback (intended for server use only)
					Msg.info(this, "Using self-signed certificate: " + defaultIdentity.getName());
					char[] pwd = DEFAULT_PASSWORD.toCharArray();
					KeyStore selfSignedKeyStore = PKIUtils.createKeyStore("defaultSigKey",
						defaultIdentity.getName(), SELF_SIGNED_DURATION_DAYS, null, null, "JKS",
						defaultSubjectAlternativeNames, pwd);
					wrappedKeyManager = ApplicationKeyManagerFactory
							.getKeyManagerFromKeyStore(selfSignedKeyStore, pwd);
					isSelfSigned = true;
				}
				else {
					return false;
				}
				return true;
			}
			catch (CancelledException e) {
				throw e;
			}
			catch (Exception e) {
				Msg.showError(this, null, "PKI Keystore Failure",
					"Failed to create PKI key manager: " + e.getMessage(), e);
			}
			return false;
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
				e.printStackTrace();
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
