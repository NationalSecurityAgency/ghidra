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

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

/**
 * {@link ServerCertificateException} is thrown when TLS/SSL server
 * certificate validation fails during an attempted server connection.
 */
public class ServerCertificateException extends CertificateException {

	private X509Certificate[] serverCertChain;

	/**
	 * Constructor
	 * @param serverCertChain server certificate chain
	 * @param cause underlying validation cause
	 */
	public ServerCertificateException(X509Certificate[] serverCertChain, CertificateException cause) {
		super("Server authentication failed: " + getReason(cause) + getServerInfo(serverCertChain),
			cause);
		this.serverCertChain = serverCertChain;
	}

	private static String getReason(CertificateException cause) {
		Throwable originalCause = cause.getCause();
		if (originalCause != null) {
			return originalCause.getMessage();
		}
		return cause.getMessage();
	}

	private static String getServerInfo(X509Certificate[] serverCertChain) {

		X500Principal subject = serverCertChain[0].getSubjectX500Principal();
		X500Principal issuer = serverCertChain[0].getIssuerX500Principal();

		StringBuilder buf = new StringBuilder(": ");
		buf.append(subject.getName());
		buf.append(" [");
		if (issuer.equals(subject)) {
			buf.append("self-signed");
		}
		else {
			buf.append("issued by: ");
			buf.append(issuer.getName());
		}
		buf.append("]");
		return buf.toString();
	}

	/**
	 * {@return server certificate chain}
	 */
	public X509Certificate[] getServerCertChain() {
		return serverCertChain;
	}
}
