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

import java.security.SecureRandom;

import javax.net.ssl.*;

import generic.random.SecureRandomFactory;
import ghidra.framework.ModuleInitializer;
import ghidra.util.Msg;

/**
 * Initialize the default SSLContext for use by SSL connections (e.g., https).
 * It is the responsibility of the Application to properly invoke this initializer 
 * so that the default SSLContext may be established. While HTTPS URL connections
 * will make use of this default SSLContext, other SSL connections may need to 
 * specify the {@link ApplicationSSLSocketFactory} to leverage the applications
 * default SSLContext.
 * @see ApplicationTrustManagerFactory
 * @see ApplicationKeyManagerFactory
 * @see ApplicationKeyManagerUtils
 */
public class SSLContextInitializer implements ModuleInitializer {

	// NOTE: specifying a default protocol of "TLS" will defer the default 
	// protocol selection to the underlying protocol implementation.
	// The protocol may be specified as a comma-separated list of protocol
	// versions where the leftmost takes precendence during the initial 
	// negotiation.  The Java security policy may be modified to disable
	// the use of specific protocols via the jdk.tls.disabledAlgorithms
	// property.  The security property file is located within the
	// java installation at jre/lib/security/java.security

	// Default list of allowed TLS protocols for outbound connections
	private static final String DEFAULT_TLS_PROTOCOL = "TLS";

	private static final String PROTOCOL_PROPERTY = "ghidra.net.ssl.protocol";

	private static SSLContext sslContext;

	/**
	 * Initialize default SSLContext with optional reset.
	 * This method is primarily intended for testing.
	 * @param reset if true a complete reset will be done to force use of
	 * any new certificate or keystores previously used.
	 * @return true if successful, else false (see logged error)
	 */
	public static synchronized boolean initialize(boolean reset) {
		if (reset) {
			sslContext = null;
			ApplicationTrustManagerFactory.invalidateTrustManagers();
			ApplicationKeyManagerFactory.invalidateKeyManagers();
		}
		return initialize();
	}

	private static String getSSLProtocol() {
		String value = System.getProperty(PROTOCOL_PROPERTY);
		if (value != null) {
			value = value.trim();
			if (value.length() != 0) {
				return value;
			}
		}
		return DEFAULT_TLS_PROTOCOL;
	}

	/**
	 * Initialize default SSLContext
	 * @return true if successful, else false (see logged error)
	 */
	public static synchronized boolean initialize() {

		if (sslContext != null) {
			SSLContext.setDefault(sslContext);
			return true;
		}

		Msg.info(SSLContextInitializer.class, "Initializing SSL Context");

		KeyManager[] keyManagers = ApplicationKeyManagerFactory.getInstance().getKeyManagers();

		try {

			sslContext = SSLContext.getInstance(getSSLProtocol());
			SecureRandom random = SecureRandomFactory.getSecureRandom();
			sslContext.init(keyManagers, ApplicationTrustManagerFactory.getTrustManagers(), random);
			SSLContext.setDefault(sslContext);

			// Must install default HostnameVerifier - otherwise all traffic will fail
			HostnameVerifier originalVerifier = HttpsURLConnection.getDefaultHostnameVerifier();
			if (!(originalVerifier instanceof HttpsHostnameVerifier)) {
				HttpsURLConnection.setDefaultHostnameVerifier(new HttpsHostnameVerifier());
			}

			// Establish default HTTPS socket factory
			HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());

			// Force the HttpClient to be re-created by the next request to
			// HttpClients.getHttpClient() so that the new SSLContext is used
			HttpClients.clearHttpClient();

			return true;

		}
		catch (Exception e) {
			Msg.error(SSLContextInitializer.class,
				"SSL Context initialization failed: " + e.getMessage(), e);
		}
		return false;
	}

	@Override
	public void run() {
		initialize();
	}

	@Override
	public String getName() {
		return "SSL Context";
	}

	/**
	 * <code>HttpsHostnameVerifier</code> is required by HttpsURLConnection even
	 * if it does nothing.  The verify method will only be invoked if the default 
	 * behavior fails the connection attempt due to a hostname mismatch.
	 * @see HttpsURLConnection#setHostnameVerifier(HostnameVerifier)
	 */
	public static class HttpsHostnameVerifier implements HostnameVerifier {
		@Override
		public boolean verify(String hostname, SSLSession session) {
			return false;
		}
	}

}
