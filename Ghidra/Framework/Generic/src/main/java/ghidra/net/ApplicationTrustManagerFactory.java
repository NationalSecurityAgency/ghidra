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

import javax.net.ssl.*;

import ghidra.framework.preferences.Preferences;
import ghidra.util.Msg;

/**
 * <code>ApplicationTrustManagerFactory</code> provides the ability to establish
 * acceptable certificate authorities to be used with SSL connections and PKI 
 * authentication.  
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
 */
public class ApplicationTrustManagerFactory {

	/**
	 * The X509 cacerts file to be used when authenticating remote 
	 * certificates is identified by either a system property or user
	 * preference <i>ghidra.cacerts</i>.  The system property takes precedence.
	 */
	public static final String GHIDRA_CACERTS_PATH_PROPERTY = "ghidra.cacerts";

	/**
	 * Use a singleton wrappedTrustManager so we can alter the true trustManager
	 * as needed.  Once the installed trust manager is consumed by the SSL Engine,
	 * we are unable to get it to use a new one.  Use of a wrapper solves this
	 * issue which occurs during testing.
	 */
	private static X509TrustManager trustManager;
	private static TrustManager[] wrappedTrustManagers;

	private static boolean hasCAs;
	private static Exception caError;

	/**
	 * <code>ApplicationTrustManagerFactory</code> constructor
	 */
	private ApplicationTrustManagerFactory() {
		// no instantiation - static methods only
	}

	/**
	 * Initialize trustManagers if <i>ghidra.cacerts</i> property or preference was specified, 
	 * otherwise an "open" trust manager will be established.  If an error occurs processing
	 * a specified cacerts file, a "closed" trust policy will be adopted.
	 */
	private static void init() {

		if (wrappedTrustManagers == null) {
			wrappedTrustManagers = new WrappedTrustManager[] { new WrappedTrustManager() };
		}

		String cacertsPath = System.getProperty(GHIDRA_CACERTS_PATH_PROPERTY);
		if (cacertsPath == null || cacertsPath.length() == 0) {
			// check user preferences if cacerts not set via system property
			cacertsPath = Preferences.getProperty(GHIDRA_CACERTS_PATH_PROPERTY);
			if (cacertsPath == null || cacertsPath.length() == 0) {
				Msg.info(ApplicationTrustManagerFactory.class,
					"Trust manager disabled, cacerts have not been set");
				trustManager = new OpenTrustManager();
				return;
			}
		}

		try {
			Msg.info(ApplicationTrustManagerFactory.class,
				"Trust manager initializing with cacerts: " + cacertsPath);
			KeyStore keyStore = ApplicationKeyStore.getCertificateStoreInstance(cacertsPath);
			TrustManagerFactory tmf =
				TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			tmf.init(keyStore);
			TrustManager[] trustManagers = tmf.getTrustManagers();
			for (TrustManager trustManager2 : trustManagers) {
				if (trustManager2 instanceof X509TrustManager) {
					X509TrustManager mgr = (X509TrustManager) trustManager2;
					ApplicationKeyStore.logCerts(mgr.getAcceptedIssuers());
					trustManager = mgr;
					break;
				}
			}
			hasCAs = true;
		}
		catch (GeneralSecurityException | IOException e) {
			caError = e;
			String msg = e.getMessage();
			if (msg == null) {
				msg = e.toString();
			}
			Msg.error(ApplicationTrustManagerFactory.class,
				"Failed to process cacerts (" + cacertsPath + "): " + msg, e);
		}
	}

	/**
	 * Determine if certificate authorities are in place.  If no certificate authorities
	 * have been specified via the "ghidra.cacerts" property, all certificates will be 
	 * trusted. 
	 * @return true if certificate authorities are in place, else false.
	 */
	public static boolean hasCertificateAuthorities() {
		return hasCAs;
	}

	/**
	 * Determine if a CA cert initialization error occurred
	 * @return true if error occurred (see {@link #getCertError()})
	 */
	static boolean hasCertError() {
		return caError != null;
	}

	/**
	 * Get the CA cert initialization error which occurred
	 * during initialization 
	 * @return error object or null if not applicable
	 */
	static Exception getCertError() {
		return caError;
	}

	/**
	 * Get trust managers after performing any necessary initialization.
	 * @return trust managers
	 */
	static synchronized TrustManager[] getTrustManagers() {
		if (trustManager == null) {
			init();
		}
		return wrappedTrustManagers.clone();
	}

	/**
	 * Invalidate the active keystore and key manager 
	 */
	static synchronized void invalidateTrustManagers() {
		trustManager = null;
		caError = null;
	}

	private static final X509Certificate[] NO_CERTS = new X509Certificate[0];

	private static class WrappedTrustManager implements X509TrustManager {

		@Override
		public void checkClientTrusted(X509Certificate[] chain, String authType)
				throws CertificateException {
			if (trustManager == null) {
				throw new CertificateException("Trust manager not properly initialized");
			}
			trustManager.checkClientTrusted(chain, authType);
		}

		@Override
		public void checkServerTrusted(X509Certificate[] chain, String authType)
				throws CertificateException {
			if (trustManager == null) {
				throw new CertificateException("Trust manager not properly initialized");
			}
			trustManager.checkServerTrusted(chain, authType);
		}

		@Override
		public X509Certificate[] getAcceptedIssuers() {
			if (trustManager == null) {
				return NO_CERTS;
			}
			return trustManager.getAcceptedIssuers();
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
			return null; // no CA's have been stipulated
		}

	}

}
