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
package ghidra.framework.remote;

import java.io.Serializable;
import java.security.Principal;
import java.security.cert.X509Certificate;

import javax.security.auth.callback.Callback;
import javax.security.auth.x500.X500Principal;

/**
 * <code>SignatureCallback</code> provides a Callback implementation used
 * to perform PKI authentication.  This callback is instantiated
 * by the server with a random token which must be signed using the 
 * user's certificate which contains one of the recognizedAuthorities
 * within it certificate chain.
 * <p>
 * It is the responsibility of the callback handler to invoke the 
 * sign(X509Certificate[], byte[]) and return this object in response
 * to the callback.
 * <p>
 * The supplied token is validated by the server during authentication as one that it had issued
 * but is primarily intended as the basis for the client's signature.  This callback must be 
 * signed and returned to the server in a short period of time or the authentication will fail.
 */
public class SignatureCallback implements Callback, Serializable {

	public static final long serialVersionUID = 1L;

	private X500Principal[] recognizedAuthorities;
	private final byte[] token;
	private final byte[] serverSignature;

	private byte[] signature;
	private X509Certificate[] certChain;

	/**
	 * Construct callback with a random token to be signed by the client. 
	 * @param recognizedAuthorities list of CA's from which one must occur
	 * within the certificate chain of the signing certificate.
	 * @param token random bytes to be signed
	 * @param serverSignature servers signature of token at time of generation
	 */
	public SignatureCallback(X500Principal[] recognizedAuthorities, byte[] token,
			byte[] serverSignature) {
		this.token = token;
		this.serverSignature = serverSignature;
		this.recognizedAuthorities = recognizedAuthorities;
	}

	/**
	 * {@return list of approved certificate authorities which constrains which user certificate is
	 * used to authenticate.}
	 */
	public Principal[] getRecognizedAuthorities() {
		return recognizedAuthorities;
	}

	/**
	 * {@return token to be signed using user certificate}
	 */
	public byte[] getToken() {
		return token;
	}

	/**
	 * {@return signed token bytes set by callback handler}
	 */
	public byte[] getSignature() {
		return signature;
	}

	/**
	 * {@return the server's signature of the token bytes}
	 */
	public byte[] getServerSignature() {
		return serverSignature;
	}

	/**
	 * {@return certificate chain used to sign token}
	 */
	public X509Certificate[] getCertificateChain() {
		return certChain;
	}

	/**
	 * Set token signature data.  Method must be invoked by 
	 * callback handler.
	 * @param sigCertChain certificate chain used to sign token.
	 * @param certSignature token signature
	 */
	public void sign(X509Certificate[] sigCertChain, byte[] certSignature) {
		this.certChain = sigCertChain;
		this.signature = certSignature;
	}

}
