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

import java.io.IOException;
import java.io.Serializable;
import java.security.SecureRandom;

import javax.security.auth.callback.Callback;

import ch.ethz.ssh2.signature.*;
import generic.random.SecureRandomFactory;

/**
 * <code>SSHSignatureCallback</code> provides a Callback implementation used
 * to perform SSH authentication.  This callback is instantiated
 * by the server with a random token which must be signed using the 
 * user's SSH private key.
 * <p>
 * It is the responsibility of the callback handler to invoke the 
 * sign method and return this object in response
 * to the callback.
 */
public class SSHSignatureCallback implements Callback, Serializable {

	public static final long serialVersionUID = 1L;

	private final byte[] token;
	private final byte[] serverSignature;
	private byte[] signature;

	/**
	 * Construct callback with a random token to be signed by the client. 
	 * @param token random bytes to be signed
	 */
	public SSHSignatureCallback(byte[] token, byte[] serverSignature) {
		this.token = token;
		this.serverSignature = serverSignature;
	}

	/**
	 * @return token to be signed using user certificate.
	 */
	public byte[] getToken() {
		return (token == null ? null : (byte[]) token.clone());
	}

	/**
	 * @return signed token bytes set by callback handler.
	 */
	public byte[] getSignature() {
		return (signature == null ? null : (byte[]) signature.clone());
	}

	/**
	 * @return the server's signature of the token bytes.
	 */
	public byte[] getServerSignature() {
		return serverSignature;
	}

	/**
	 * @return true if callback has been signed
	 */
	public boolean isSigned() {
		return signature != null;
	}

	/**
	 * Sign this challenge with the specified SSH private key.
	 * @param sshPrivateKey RSAPrivateKey or DSAPrivateKey
	 * @throws IOException if signature generation failed
	 * @see RSAPrivateKey
	 * @see DSAPrivateKey
	 */
	public void sign(Object sshPrivateKey) throws IOException {
		if (sshPrivateKey instanceof RSAPrivateKey) {
			RSAPrivateKey key = (RSAPrivateKey) sshPrivateKey;
			// TODO: verify correct key by using accepted public key fingerprint
			RSASignature rsaSignature = RSASHA1Verify.generateSignature(token, key);
			signature = RSASHA1Verify.encodeSSHRSASignature(rsaSignature);
		}
		else if (sshPrivateKey instanceof DSAPrivateKey) {
			DSAPrivateKey key = (DSAPrivateKey) sshPrivateKey;
			// TODO: verify correct key by using accepted public key fingerprint
			SecureRandom random = SecureRandomFactory.getSecureRandom();
			DSASignature dsaSignature = DSASHA1Verify.generateSignature(token, key, random);
			signature = DSASHA1Verify.encodeSSHDSASignature(dsaSignature);
		}
		else {
			throw new IllegalArgumentException("Unsupported SSH private key");
		}
	}

}
