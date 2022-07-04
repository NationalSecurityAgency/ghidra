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
package ghidra.server.security;

import java.io.*;
import java.util.*;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.params.DSAKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.*;
import org.bouncycastle.util.Strings;

import ghidra.framework.remote.GhidraPrincipal;
import ghidra.framework.remote.SSHSignatureCallback;
import ghidra.framework.remote.security.SSHKeyManager;
import ghidra.net.*;
import ghidra.server.UserManager;

/**
 * <code>SSHAuthenticationModule</code> provides SHA1-RSA and SHA1-DSA signature-based authentication
 * support using SSH public/private keys where user public keys are made available to the server.
 * Module makes use of a {@link SSHSignatureCallback} object to convey the signature request to a
 * client.
 */
public class SSHAuthenticationModule {

	private static final long MAX_TOKEN_TIME = 10000;
	private static final int TOKEN_SIZE = 64;

	private final boolean nameCallbackAllowed;

	public SSHAuthenticationModule(boolean nameCallbackAllowed) {
		this.nameCallbackAllowed = nameCallbackAllowed;
	}

	public Callback[] addAuthenticationCallbacks(Callback[] primaryAuthCallbacks) {
		boolean addNameCallback = nameCallbackAllowed;
		if (nameCallbackAllowed && primaryAuthCallbacks != null) {
			for (Callback cb : primaryAuthCallbacks) {
				if (cb instanceof NameCallback) {
					// no need to add another one
					addNameCallback = false;
					break;
				}
			}
		}
		List<Callback> list = new ArrayList<Callback>();
		if (primaryAuthCallbacks != null) {
			list.addAll(Arrays.asList(primaryAuthCallbacks));
		}
		if (addNameCallback) {
			list.add(new NameCallback("User ID:"));
		}
		byte[] token = TokenGenerator.getNewToken(TOKEN_SIZE);
		try {
			boolean usingSelfSignedCert =
				ApplicationKeyManagerFactory.usingGeneratedSelfSignedCertificate();
			SignedToken signedToken = ApplicationKeyManagerUtils.getSignedToken(
				usingSelfSignedCert ? null : ApplicationKeyManagerUtils.getTrustedIssuers(), token);
			list.add(new SSHSignatureCallback(token, signedToken.signature));
		}
		catch (Exception e) {
			throw new RuntimeException("Unable to generate signed token", e);
		}
		return list.toArray(new Callback[list.size()]);
	}

	public boolean hasSignedSSHCallback(Callback[] callbacks) {
		if (callbacks != null) {
			for (int i = 0; i < callbacks.length; i++) {
				if (callbacks[i] instanceof SSHSignatureCallback) {
					SSHSignatureCallback sshCb = (SSHSignatureCallback) callbacks[i];
					return sshCb.isSigned();
				}
			}
		}
		return false;
	}

	/**
	 * Read UInt32 from SSH-encoded buffer.
	 * (modeled after org.bouncycastle.crypto.util.SSHBuffer.readU32())
	 * @param in data input stream
	 * @return integer value
	 * @throws IOException if IO error occurs reading input stream or inadequate 
	 * bytes are available.
	 */
	private static int sshBufferReadUInt32(ByteArrayInputStream in) throws IOException {
		byte[] tmp = in.readNBytes(4);
		if (tmp.length != 4) {
			throw new IOException("insufficient data");
		}
		int value = (tmp[0] & 0xff) << 24;
		value |= (tmp[1] & 0xff) << 16;
		value |= (tmp[2] & 0xff) << 8;
		value |= (tmp[3] & 0xff);
		return value;
	}

	/**
	 * Read block of data from SSH-encoded buffer.
	 * (modeled after org.bouncycastle.crypto.util.SSHBuffer.readBlock())
	 * @param in data input stream
	 * @return byte array
	 * @throws IOException if IO error occurs reading input stream or inadequate 
	 * bytes are available.
	 */
	private static byte[] sshBufferReadBlock(ByteArrayInputStream in) throws IOException {
		int len = sshBufferReadUInt32(in);
		if (len <= 0 || len > in.available()) {
			throw new IOException("insufficient data");
		}
		return in.readNBytes(len);
	}

	/**
	 * Complete the authentication process
	 * @param userMgr Ghidra server user manager
	 * @param subject unauthenticated user ID (must be used if name callback not provided/allowed)
	 * @param callbacks authentication callbacks
	 * @return authenticated user ID (may come from callbacks)
	 * @throws LoginException if authentication failure occurs
	 */
	public String authenticate(UserManager userMgr, Subject subject, Callback[] callbacks)
			throws LoginException {

		GhidraPrincipal user = GhidraPrincipal.getGhidraPrincipal(subject);
		if (user == null) {
			throw new FailedLoginException("GhidraPrincipal required");
		}
		String username = user.getName();

		NameCallback nameCb = null;
		SSHSignatureCallback sshCb = null;
		if (callbacks != null) {
			for (int i = 0; i < callbacks.length; i++) {
				if (callbacks[i] instanceof NameCallback) {
					nameCb = (NameCallback) callbacks[i];
				}
				if (callbacks[i] instanceof SSHSignatureCallback) {
					sshCb = (SSHSignatureCallback) callbacks[i];
				}
			}
		}

		if (nameCallbackAllowed && nameCb != null) {
			username = nameCb.getName();
		}
		if (username == null || username.length() == 0) {
			throw new FailedLoginException("User ID must be specified");
		}
		if (!userMgr.isValidUser(username)) {
			throw new FailedLoginException("Unknown user: " + username);
		}

		if (sshCb == null) {
			throw new FailedLoginException(
				"SSH Signature callback not found for user: " + username);
		}

		File sshPublicKeyFile = userMgr.getSSHPubKeyFile(username);
		if (sshPublicKeyFile == null) {
			throw new FailedLoginException("SSH public key file not found for user: " + username);
		}

		byte[] sigBytes = sshCb.getSignature();
		if (sigBytes == null) {
			throw new FailedLoginException("SSH Signature missing");
		}

		byte[] token = sshCb.getToken();
		if (!TokenGenerator.isRecentToken(token, MAX_TOKEN_TIME)) {
			throw new FailedLoginException("Stale SSH Signature callback");
		}

		boolean isValid = false;
		try {
			boolean usingSelfSignedCert =
				ApplicationKeyManagerFactory.usingGeneratedSelfSignedCertificate();
			isValid = ApplicationKeyManagerUtils.isMySignature(
				usingSelfSignedCert ? null : ApplicationKeyManagerUtils.getTrustedIssuers(), token,
				sshCb.getServerSignature());
		}
		catch (Exception e) {
			throw new RuntimeException("Unable to verify signed token", e);
		}
		if (!isValid) {
			throw new FailedLoginException("Invalid SSH Signature callback");
		}

		try {
			ByteArrayInputStream in = new ByteArrayInputStream(sigBytes);
			String keyAlgorithm = Strings.fromByteArray(sshBufferReadBlock(in));
			byte[] sig = sshBufferReadBlock(in);
			if (in.available() != 0) {
				throw new FailedLoginException("SSH Signature contained extra bytes");
			}

			CipherParameters cipherParams = SSHKeyManager.getSSHPublicKey(sshPublicKeyFile);

			if (cipherParams instanceof RSAKeyParameters) {
				if (!"ssh-rsa".equals(keyAlgorithm)) {
					throw new FailedLoginException("Invalid SSH RSA Signature");
				}
				RSADigestSigner signer = new RSADigestSigner(new SHA1Digest());
				signer.init(false, cipherParams);
				signer.update(token, 0, token.length);
				if (!signer.verifySignature(sig)) {
					throw new FailedLoginException("Incorrect signature");
				}
			}
			else if (cipherParams instanceof DSAKeyParameters) {
				if (!"ssh-dss".equals(keyAlgorithm)) {
					throw new FailedLoginException("Invalid SSH DSA Signature");
				}
				DSADigestSigner signer = new DSADigestSigner(new DSASigner(), new SHA1Digest());
				signer.init(false, cipherParams);
				signer.update(token, 0, token.length);
				if (!signer.verifySignature(sig)) {
					throw new FailedLoginException("Incorrect signature");
				}
			}
			else {
				throw new FailedLoginException("Unsupported public key");
			}

		}
		catch (LoginException e) {
			throw e;
		}
		catch (Throwable t) {
			String msg = t.getMessage();
			if (msg == null) {
				msg = t.toString();
			}
			throw new FailedLoginException(msg);
		}
		return username;
	}

	public boolean allowsNameCallback() {
		return nameCallbackAllowed;
	}

}
