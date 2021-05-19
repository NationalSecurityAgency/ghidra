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
import java.net.http.HttpClient;
import java.net.http.HttpClient.Redirect;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.SSLContext;

public class HttpClients {
	/**
	 * Note: java.net.http.HttpClient instances can allocate system resources (file handles),
	 * and frequently creating a new HttpClient could exhaust system resources.
	 * <p>
	 * There is no "close()" on a HttpClient to release resources.  The system resources 
	 * allocated by HttpClient instances will be released when the instance is gc'd.
	 * However, since the resources in question (filehandles) are not tied to memory pressure,
	 * its possible a gc() won't happen before running out of file handles if a few hundred
	 * HttpClient instances have been created / discarded.  
	 * <p>
	 * Also note, there is no per-connection ability to disable hostname verification in a
	 * SSL/TLS connection.  There is a global flag:
	 * -Djdk.internal.httpclient.disableHostnameVerification
	 * 
	 */
	private static HttpClient client;

	/**
	 * Creates a HttpClient Builder using Ghidra SSL/TLS context info.
	 * 
	 * @return a new HttpClient Builder
	 * @throws IOException if error in PKI settings or crypto configuration 
	 */
	public static HttpClient.Builder newHttpClientBuilder() throws IOException {
		if (!ApplicationKeyManagerFactory.initialize()) {
			if (ApplicationKeyManagerFactory.getKeyStore() != null) {
				throw new IOException("Failed to initialize PKI certificate keystore");
			}
		}

		try {
			return HttpClient.newBuilder()
					.sslContext(SSLContext.getDefault())
					.followRedirects(Redirect.NORMAL);
		}
		catch (NoSuchAlgorithmException nsae) {
			throw new IOException("Missing algorithm", nsae);
		}
	}

	/**
	 * Returns a shared, plain (no special options) {@link HttpClient}.
	 * 
	 * @return a {@link HttpClient}
	 * @throws IOException if error in PKI settings or crypto configuration 
	 */
	public static synchronized HttpClient getHttpClient() throws IOException {
		if (client == null) {
			client = newHttpClientBuilder().build();
		}

		return client;
	}

	/**
	 * Clears the currently cached {@link HttpClient}, forcing it to be
	 * rebuilt during the next call to {@link #getHttpClient()}.
	 */
	public static synchronized void clearHttpClient() {
		client = null;
	}

}
