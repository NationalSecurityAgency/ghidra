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

import java.io.IOException;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.x500.X500Principal;

import org.apache.logging.log4j.*;

import ghidra.framework.remote.GhidraPrincipal;
import ghidra.framework.remote.SignatureCallback;
import ghidra.net.*;
import ghidra.server.RepositoryManager;
import ghidra.server.UserManager;

/**
 * <code>PKIAuthenticationModule</code> performs client authentication through the 
 * use of a dual-signed token.  
 */
public class PKIAuthenticationModule implements AuthenticationModule {
	static final Logger log = LogManager.getLogger(PKIAuthenticationModule.class);

	private static final long MAX_TOKEN_TIME = 5 * 60000; // 5-minutes
	private static final int TOKEN_SIZE = 64;

	private X500Principal[] authorities; // imposed on client certificate
	private boolean anonymousAllowed;

	public PKIAuthenticationModule(boolean anonymousAllowed)
			throws IOException, CertificateException {
		this.anonymousAllowed = anonymousAllowed;
		authorities = ApplicationKeyManagerUtils.getTrustedIssuers();
		if (authorities == null) {
			throw new IOException("trusted PKI Certificate Authorities have not been configured");
		}
	}

	@Override
	public boolean anonymousCallbacksAllowed() {
		// PKI anonymous login handled internally
		// Valid PKI still required
		return false;
	}

	/*
	 * @see ghidra.server.security.AuthenticationModule#getAuthenticationCallbacks()
	 */
	@Override
	public Callback[] getAuthenticationCallbacks() {
		SignatureCallback sigCb;
		try {
			byte[] token = TokenGenerator.getNewToken(TOKEN_SIZE);
			boolean usingSelfSignedCert =
				ApplicationKeyManagerFactory.usingGeneratedSelfSignedCertificate();
			SignedToken signedToken = ApplicationKeyManagerUtils.getSignedToken(
				usingSelfSignedCert ? null : authorities, token);
			sigCb = new SignatureCallback(authorities, token, signedToken.signature);
		}
		catch (Throwable t) {
			throw new RuntimeException("Unable to generate signed token", t);
		}
		return new Callback[] { sigCb };
	}

	@Override
	public boolean isNameCallbackAllowed() {
		return false;
	}

	/*
	 * @see ghidra.server.security.AuthenticationModule#authenticate(ghidra.server.UserManager, javax.security.auth.Subject, javax.security.auth.callback.Callback[])
	 */
	@Override
	public String authenticate(UserManager userMgr, Subject subject, Callback[] callbacks)
			throws LoginException {

		// assume we are operating over a secure authenticated socket -
		// unfortunately, there appears no way to obtain PKI credentials
		// used when authenticating SSL connection with client

		GhidraPrincipal user = GhidraPrincipal.getGhidraPrincipal(subject);
		if (user == null) {
			throw new FailedLoginException("GhidraPrincipal required");
		}
		String username = user.getName();

		SignatureCallback sigCb = null;
		if (callbacks != null) {
			for (int i = 0; i < callbacks.length; i++) {
				if (callbacks[i] instanceof SignatureCallback) {
					sigCb = (SignatureCallback) callbacks[i];
					break;
				}
			}
		}
		if (sigCb == null) {
			throw new FailedLoginException("PKI Signature callback required");
		}

		try {

			byte[] token = sigCb.getToken();

			if (!TokenGenerator.isRecentToken(token, MAX_TOKEN_TIME)) {
				throw new FailedLoginException("Stale Signature callback");
			}

			boolean usingSelfSignedCert =
				ApplicationKeyManagerFactory.usingGeneratedSelfSignedCertificate();
			if (!ApplicationKeyManagerUtils.isMySignature(usingSelfSignedCert ? null : authorities,
				token, sigCb.getServerSignature())) {
				throw new FailedLoginException("Invalid Signature callback");
			}

			X509Certificate[] certChain = sigCb.getCertificateChain();
			if (certChain == null || certChain.length == 0) {
				throw new FailedLoginException("user certificate not provided");
			}

			ApplicationKeyManagerUtils.validateClient(certChain,
				ApplicationKeyManagerUtils.RSA_TYPE);

			byte[] sigBytes = sigCb.getSignature();
			if (sigBytes != null) {

				Signature sig = Signature.getInstance(certChain[0].getSigAlgName());
				sig.initVerify(certChain[0]);
				sig.update(token);
				if (!sig.verify(sigBytes)) {
					throw new FailedLoginException("Incorrect signature");
				}
			}

			String dnUsername =
				userMgr.getUserByDistinguishedName(certChain[0].getSubjectX500Principal());
			if (dnUsername != null) {
				return dnUsername;
			}

			if (userMgr.isValidUser(username)) {
				X500Principal x500User = userMgr.getDistinguishedName(username);
				if (x500User == null) {
					userMgr.logUnknownDN(username, certChain[0].getSubjectX500Principal());
					if (!anonymousAllowed) {
						throw new FailedLoginException("Distinguished name is unknown");
					}
					log.log(Level.WARN, "Know user's DN not found (" + username + ") ");
					username = UserManager.ANONYMOUS_USERNAME;
				}
				else { // if (!certChain[0].getSubjectX500Principal().equals(dn.asX500Principal())) {
					userMgr.logUnknownDN(username, certChain[0].getSubjectX500Principal());
					if (!anonymousAllowed) {
						throw new FailedLoginException(
							"Expected distinguished name: " + x500User.getName());
					}
					username = UserManager.ANONYMOUS_USERNAME;
				}
			}
			else {
				if (!anonymousAllowed) {
					throw new FailedLoginException("Unknown user: " + username);
				}
				username = UserManager.ANONYMOUS_USERNAME;
			}

			if (UserManager.ANONYMOUS_USERNAME.equals(username)) {
				RepositoryManager.log(null, null, "Anonymous access allowed for: " +
					certChain[0].getSubjectX500Principal().toString(), user.getName());
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
}
