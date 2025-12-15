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

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import javax.net.ssl.*;
import javax.rmi.ssl.SslRMIClientSocketFactory;
import javax.security.auth.x500.X500Principal;

import ghidra.framework.preferences.Preferences;
import ghidra.util.Msg;

/**
 * <code>DefaultTrustManagerFactory</code> provides the ability to establish
 * acceptable certificate authorities to be used with the default SSLContext
 * as established by {@link DefaultSSLContextInitializer}. 
 * <p>
 * The default behavior is for no trust authority to be established, in which case 
 * SSL peers will not be authenticated.  If CA certificates have been set, all SSL
 * connections which leverage this factory will perform peer authentication.  If an error
 * occurs while reading the CA certs file, all peer authentication will fail based upon the 
 * inability to choose a suitable client/server certificate.
 * <p>
 * The application X.509 CA certificates file may be in the standard form (*.pem, *.crt, 
 * *.cer, *.der) or may be in a Java JKS form (*.jks). The path to this file may be 
 * established in one of two ways using the absolute file path:
 * <ol>
 * <li>setting the system property <i>ghidra.cacerts</i> (takes precedence)</li> 
 * <li>setting the user preference <i>ghidra.cacerts</i></li>
 * </ol>
 * <p>
 * The application may choose to set the file path automatically based upon the presence of
 * a <i>cacerts</i> file at a predetermined location.
 * <p>
 * NOTE: Since {@link SslRMIClientSocketFactory} and {@link SSLServerSocketFactory} employ a
 * static cache of a default {@link SSLSocketFactory}, with its default {@link SSLContext}, we
 * must utilize a wrapped implementation of the associated {@link X509TrustManager} so that any
 * changes are used by the existing default {@link SSLSocketFactory}.
 */
public class DefaultTrustManagerFactory {

	/**
	 * The X509 cacerts file to be used when authenticating remote 
	 * certificates is identified by either a system property or user
	 * preference <i>ghidra.cacerts</i>.  The system property takes precedence.
	 */
	public static final String GHIDRA_CACERTS_PATH_PROPERTY = "ghidra.cacerts";

	private static final X509Certificate[] NO_CERTS = new X509Certificate[0];

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
	 * Initialize trustManagers if <i>ghidra.cacerts</i> property or preference was specified, 
	 * otherwise an "open" trust manager will be established.  If an error occurs processing
	 * a specified cacerts file, a "closed" trust policy will be adopted.
	 */
	private static void init() {

		String cacertsPath = System.getProperty(GHIDRA_CACERTS_PATH_PROPERTY);
		if (cacertsPath == null || cacertsPath.length() == 0) {
			// check user preferences if cacerts not set via system property
			cacertsPath = Preferences.getProperty(GHIDRA_CACERTS_PATH_PROPERTY);
			if (cacertsPath == null || cacertsPath.length() == 0) {
				Msg.info(DefaultTrustManagerFactory.class,
					"Trust manager disabled, cacerts have not been set");
				wrappedTrustManager.setTrustManager(new OpenTrustManager());
				return;
			}
		}

		try {
			Msg.info(DefaultTrustManagerFactory.class,
				"Trust manager initializing with cacerts: " + cacertsPath);
			KeyStore keyStore = PKIUtils.loadCertificateStore(cacertsPath);
			TrustManagerFactory tmf =
				TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			tmf.init(keyStore);
			X509TrustManager x509TrustMgr = null;
			TrustManager[] trustManagers = tmf.getTrustManagers();
			for (TrustManager trustMgr : trustManagers) {
				if (trustMgr instanceof X509TrustManager) {
					x509TrustMgr = (X509TrustManager) trustMgr;
					wrappedTrustManager.setTrustManager(x509TrustMgr);
					PKIUtils.logCerts(x509TrustMgr.getAcceptedIssuers());
					break;
				}
			}
			if (x509TrustMgr == null) {
				throw new CertificateException("Failed to load any X509 certificates");
			}
		}
		catch (GeneralSecurityException | IOException e) {
			wrappedTrustManager.setTrustManagerError(e);
			String msg = e.getMessage();
			if (msg == null) {
				msg = e.toString();
			}
			Msg.error(DefaultTrustManagerFactory.class,
				"Failed to process cacerts (" + cacertsPath + "): " + msg, e);
		}
	}

	/**
	 * Get trust manager after performing any necessary initialization.
	 * 
	 * @return trust managers
	 */
	public static synchronized TrustManager[] getTrustManagers() {
		if (wrappedTrustManager.trustManager == null) {
			init();
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

	private static class WrappedTrustManager implements X509TrustManager {

		private X509TrustManager trustManager;
		private Exception caError;

		WrappedTrustManager() {
			invalidate();
		}

		void invalidate() {
			this.trustManager = null;
			this.caError = null;
		}

		synchronized void setTrustManager(X509TrustManager trustManager) {
			this.trustManager = trustManager;
			this.caError = null;
		}

		synchronized void setTrustManagerError(Exception caError) {
			this.trustManager = null;
			this.caError = caError;
		}

		@Override
		public synchronized void checkClientTrusted(X509Certificate[] chain, String authType)
				throws CertificateException {
			checkTrustManager();
			trustManager.checkClientTrusted(chain, authType);
		}

		@Override
		public synchronized void checkServerTrusted(X509Certificate[] chain, String authType)
				throws CertificateException {
			checkTrustManager();
			trustManager.checkServerTrusted(chain, authType);
		}

		@Override
		public synchronized X509Certificate[] getAcceptedIssuers() {
			if (trustManager == null) {
				return NO_CERTS;
			}
			return trustManager.getAcceptedIssuers();
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
			if (trustManager != null) {
				return;
			}
			if (caError != null) {
				throw new CertificateException("Failed to load CA certs", caError);
			}
			throw new CertificateException("Trust manager not properly initialized");
		}

	}

	/**
	 * <code>OpenTrustManager</code> provides a means of adopting an "open" trust policy
	 * where any peer certificate will be considered acceptable.
	 */
	private static class OpenTrustManager implements X509TrustManager {

		/*
		 * @see javax.net.ssl.X509TrustManager#checkClientTrusted(java.security.cert.X509Certificate[], java.lang.String)
		 */
		@Override
		public void checkClientTrusted(X509Certificate[] chain, String authType)
				throws CertificateException {
			// trust all certs
		}

		/*
		 * @see javax.net.ssl.X509TrustManager#checkServerTrusted(java.security.cert.X509Certificate[], java.lang.String)
		 */
		@Override
		public void checkServerTrusted(X509Certificate[] chain, String authType)
				throws CertificateException {
			// trust all certs
		}

		/*
		 * @see javax.net.ssl.X509TrustManager#getAcceptedIssuers()
		 */
		@Override
		public X509Certificate[] getAcceptedIssuers() {
			return NO_CERTS; // no CA's have been stipulated
		}

	}

}
