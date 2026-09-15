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

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import javax.net.ssl.*;

import generic.hash.HashUtilities;
import ghidra.framework.OperatingSystem;
import ghidra.security.KeyStorePasswordProvider;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;

/**
 * {@link ApplicationKeyManagerFactory} provides a factory for using and caching X509 keystores.
 */
public class ApplicationKeyManagerFactory {

	private static KeyStorePasswordProvider customPasswordProvider;

	// X509KeyManager cached keyed by file hash concatenated with its canonical path
	private static HashMap<String, X509KeyManager> keyStoreCache = new HashMap<>();

	private ApplicationKeyManagerFactory() {
		// no construct
	}

	/**
	 * Set the active keystore password provider
	 * @param provider keystore password provider
	 */
	public static synchronized void setKeyStorePasswordProvider(KeyStorePasswordProvider provider) {
		customPasswordProvider = provider;
	}

	/**
	 * Clear all cached key managers.
	 * NOTE: This is primarily intended for test use only.
	 */
	public static synchronized void clearKeyManagerCache() {
		keyStoreCache.clear();
	}

	/**
	 * Get key manager for specified JKS or PKCS12 keystore file path.  The user may be prompted
	 * for a password if required which will block the invocation of this synchronized method.  
	 * If successfully opened, the resulting key manager instance will be cached for subsequent 
	 * re-use of the same keystore.
	 * 
	 * @param keystorePath protected keystore path
	 * @param defaultPasswd default password (e.g., supplied by property) or null
	 * @return key manager
	 * @throws CancelledException password entry was cancelled by user
	 * @throws KeyStoreException error occurred opening/processing keystore
	 */
	public synchronized static X509KeyManager getKeyManager(String keystorePath,
			String defaultPasswd) throws CancelledException, KeyStoreException {

		String hashKey;

		try {
			if (PKIUtils.detectKeyStoreType(keystorePath) == null) {
				throw new KeyStoreException("Unsupported PKI key store file type: " + keystorePath);
			}
			// Obtain canonical path for cache use
			File keystoreFile = new File(keystorePath);
			keystorePath = (keystoreFile).getCanonicalPath();

			hashKey = HashUtilities.getHash(HashUtilities.MD5_ALGORITHM, keystoreFile) + "_" +
				keystorePath;

			X509KeyManager keyManager = keyStoreCache.get(hashKey);
			if (keyManager != null) {
				return keyManager;
			}
		}
		catch (IOException e) {
			throw new KeyStoreException("Failed to open keystore: " + keystorePath, e);
		}

		int tryCount = 0;

		while (true) {
			char[] password = new char[0];
			char[] oldPassword = null;
			try {
				if (tryCount == 0) {
					// try no password first
				}
				else if (tryCount == 1) {
					// try specified password
					if (defaultPasswd != null) {
						password = defaultPasswd.toCharArray();
					}
					else {
						// no default password was provided
						++tryCount;
						continue;
					}
				}
				else if (customPasswordProvider != null) {
					disposePassword(oldPassword);
					oldPassword = password;
					password =
						customPasswordProvider.getKeyStorePassword(keystorePath, tryCount != 2);
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

				// NOTE: we only support a single password for both keystore and private key
				KeyStore keyStore = PKIUtils.getKeyStoreInstance(keystorePath, password);
				X509KeyManager keyManager = getKeyManagerFromKeyStore(keyStore, password);
				keyStoreCache.put(hashKey, keyManager);
				return keyManager;
			}
			catch (UnrecoverableKeyException | NoSuchAlgorithmException | CertificateException
					| FileNotFoundException e) {
				throw new KeyStoreException("Failed to process keystore: " + keystorePath, e);
			}
			catch (KeyStoreException | IOException e) {
				// Java Bug: JDK-6974037 : PKCS12 Keystore load with invalid passwords generates different exceptions
				Exception ioException = getIOException(e);
				if (ioException != null &&
					ioException.getCause() instanceof UnrecoverableKeyException) {
					continue; // Assume incorrect password was specified
				}
				throw new KeyStoreException("Failed to open keystore: " + keystorePath, e);
			}
			finally {
				disposePassword(oldPassword);
				disposePassword(password);
			}
		}
		throw new KeyStoreException("Failed to unlock key storage: " + keystorePath);
	}

	/**
	 * Get key manager for specified JKS or PKCS12 keystore. The keystore must only contain a 
	 * single X509 certificate and corresponding private key which has a usage of digital signing.
	 * @param keyStore JKS or PKCS12 keystore file
	 * @param password password for accessing keystore and private key.
	 * @return X509 key manager instance
	 * @throws NoSuchAlgorithmException if the specified algorithm is not available from the 
	 * 			specified provider.
	 * @throws UnrecoverableKeyException if the key cannot be recovered
	 *          (e.g. the given password is wrong).
	 * @throws KeyStoreException if a general failure occurs while accessing keystore
	 */
	static X509KeyManager getKeyManagerFromKeyStore(KeyStore keyStore, char[] password)
			throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {

		// Assume cert of interest is the first one
		Enumeration<String> aliases = keyStore.aliases();
		if (!aliases.hasMoreElements()) {
			throw new KeyStoreException("PKI key store is empty");
		}
		Certificate certificate = keyStore.getCertificate(aliases.nextElement());
		if (!(certificate instanceof X509Certificate x509Cert)) {
			throw new KeyStoreException("PKI X509 Certificate not found");
		}
		boolean[] keyUsage = x509Cert.getKeyUsage();
		if (keyUsage != null && !keyUsage[0]) {
			throw new KeyStoreException("PKI key store must contain Digital Signing certificate");
		}

		KeyManagerFactory kmf =
			KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		kmf.init(keyStore, password);

		// Assume that one keystore will produce at most one KeyManager
		KeyManager[] keyManagers = kmf.getKeyManagers();
		if (keyManagers.length == 1 && (keyManagers[0] instanceof X509KeyManager)) {
			return (X509KeyManager) keyManagers[0];
		}
		throw new KeyStoreException("Unsupported keystore");
	}

	/**
	 * Get a key manager backed by the OS-managed user keystore for the current platform
	 * (<code>Windows-MY</code> on Windows, Apple <code>KeychainStore</code> on macOS).
	 * Private key access is guarded by the OS, so no keystore password is used.
	 * Alias selection from a multi-entry store is deferred to the platform
	 * {@link X509KeyManager} which will filter by key type and requested CA issuers.
	 * <p>
	 * NOTE: The resulting key manager is intentionally not cached since OS keystore
	 * contents may be changed externally; a fresh instance is produced on each call.
	 *
	 * @return X509 key manager, or null if the current platform has no OS-managed keystore
	 *         or the store contains no usable private-key entry (i.e., no X509 certificate
	 *         key entry whose keyUsage extension, if present, permits digitalSignature).
	 * @throws KeyStoreException if a failure occurs while accessing the OS keystore
	 */
	static X509KeyManager getOSKeyManager() throws KeyStoreException {

		KeyStore keyStore;
		String storeName;
		try {
			if (OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.WINDOWS) {
				storeName = "Windows-MY";
				keyStore = KeyStore.getInstance(storeName);
			}
			else if (OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.MAC_OS_X) {
				storeName = "KeychainStore";
				keyStore = KeyStore.getInstance(storeName, "Apple");
			}
			else {
				return null; // no OS-managed keystore for platform
			}
			keyStore.load(null, null); // populate from OS key store
		}
		catch (GeneralSecurityException | IOException e) {
			throw new KeyStoreException("Failed to open OS key store", e);
		}

		if (!hasUsableKeyEntry(keyStore)) {
			return null;
		}

		try {
			KeyManagerFactory kmf =
				KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
			try {
				kmf.init(keyStore, null); // OS guards key access; no password
			}
			catch (GeneralSecurityException e) {
				// some KeychainStore implementations reject a null password
				kmf.init(keyStore, new char[0]);
			}
			for (KeyManager keyManager : kmf.getKeyManagers()) {
				if (keyManager instanceof X509KeyManager x509KeyManager) {
					Msg.info(ApplicationKeyManagerFactory.class,
						"Using OS-managed key store: " + storeName);
					return x509KeyManager;
				}
			}
		}
		catch (GeneralSecurityException e) {
			throw new KeyStoreException("Failed to process OS key store: " + storeName, e);
		}
		return null;
	}

	/**
	 * Determine if the specified keystore contains at least one usable identity:
	 * a private-key entry whose X509 certificate keyUsage extension, if present,
	 * permits digitalSignature.
	 *
	 * @param keyStore loaded keystore to be examined
	 * @return true if a usable private-key entry was found
	 * @throws KeyStoreException if a failure occurs while accessing the keystore
	 */
	private static boolean hasUsableKeyEntry(KeyStore keyStore) throws KeyStoreException {
		Enumeration<String> aliases = keyStore.aliases();
		while (aliases.hasMoreElements()) {
			String alias = aliases.nextElement();
			if (!keyStore.isKeyEntry(alias)) {
				continue;
			}
			if (keyStore.getCertificate(alias) instanceof X509Certificate x509Cert) {
				boolean[] keyUsage = x509Cert.getKeyUsage();
				if (keyUsage == null || keyUsage[0]) {
					return true;
				}
			}
		}
		return false;
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

}
