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

import java.io.*;

import javax.security.auth.callback.Callback;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.params.DSAKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.*;
import org.bouncycastle.util.Strings;

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
	 * @param serverSignature server signature of token (using server PKI)
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
	 * Get the server signature of token (using server PKI)
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
	 * Write UInt32 to an SSH-encoded buffer.
	 * (modeled after org.bouncycastle.crypto.util.SSHBuilder.u32(int))
	 * @param value integer value
	 * @param out data output stream
	 */
	private static void sshBuilderWriteUInt32(int value, ByteArrayOutputStream out) {
		byte[] tmp = new byte[4];
		tmp[0] = (byte) ((value >>> 24) & 0xff);
		tmp[1] = (byte) ((value >>> 16) & 0xff);
		tmp[2] = (byte) ((value >>> 8) & 0xff);
		tmp[3] = (byte) (value & 0xff);
		out.writeBytes(tmp);
	}

	/**
	 * Write byte array to an SSH-encoded buffer.
	 * (modeled after org.bouncycastle.crypto.util.SSHBuilder.writeBlock(byte[])
	 * @param value byte array
	 * @param out data output stream
	 */
	private static void sshBuilderWriteBlock(byte[] value, ByteArrayOutputStream out) {
		sshBuilderWriteUInt32(value.length, out);
		out.writeBytes(value);
	}

	/**
	 * Write string to an SSH-encoded buffer.
	 * (modeled after org.bouncycastle.crypto.util.SSHBuilder.writeString(String)
	 * @param str string data
	 * @param out data output stream
	 */
	private static void sshBuilderWriteString(String str, ByteArrayOutputStream out) {
		sshBuilderWriteBlock(Strings.toByteArray(str), out);
	}

	/**
	 * Sign this challenge with the specified SSH private key.
	 * @param privateKeyParameters SSH private key parameters 
	 *        ({@link RSAKeyParameters} or {@link RSAKeyParameters})
	 * @throws IOException if signature generation failed
	 */
	public void sign(Object privateKeyParameters) throws IOException {
		try {
			// NOTE: Signature is formatted consistent with legacy implementation
			// for backward compatibility
			if (privateKeyParameters instanceof RSAKeyParameters) {
				RSAKeyParameters cipherParams = (RSAKeyParameters) privateKeyParameters;
				RSADigestSigner signer = new RSADigestSigner(new SHA1Digest());
				signer.init(true, cipherParams);
				signer.update(token, 0, token.length);
				ByteArrayOutputStream out = new ByteArrayOutputStream();
				sshBuilderWriteString("ssh-rsa", out);
				sshBuilderWriteBlock(signer.generateSignature(), out);
				signature = out.toByteArray();
			}
			else if (privateKeyParameters instanceof DSAKeyParameters) {
				DSAKeyParameters cipherParams = (DSAKeyParameters) privateKeyParameters;
				DSADigestSigner signer = new DSADigestSigner(new DSASigner(), new SHA1Digest());
				signer.init(true, cipherParams);
				signer.update(token, 0, token.length);
				ByteArrayOutputStream out = new ByteArrayOutputStream();
				sshBuilderWriteString("ssh-dss", out);
				sshBuilderWriteBlock(signer.generateSignature(), out);
				signature = out.toByteArray();
			}
			else {
				throw new IllegalArgumentException("Unsupported SSH private key");
			}
		}
		catch (DataLengthException | CryptoException e) {
			throw new IOException("Cannot generate SSH signature: " + e.getMessage(), e);
		}
	}

}
