/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.framework.remote.GhidraPrincipal;
import ghidra.server.UserManager;

import java.io.IOException;
import java.util.Arrays;

import javax.security.auth.Subject;
import javax.security.auth.callback.*;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;

public class PasswordFileAuthenticationModule implements AuthenticationModule {

	private final boolean nameCallbackAllowed;

	public PasswordFileAuthenticationModule(boolean nameCallbackAllowed) {
		this.nameCallbackAllowed = nameCallbackAllowed;
	}

	@Override
	public boolean anonymousCallbacksAllowed() {
		return true;
	}

	/*
	 * @see ghidra.server.security.AuthenticationModule#getAuthenticationCallbacks()
	 */
	public Callback[] getAuthenticationCallbacks() {
		PasswordCallback passCb = new PasswordCallback("Password:", false);
		if (nameCallbackAllowed) {
			NameCallback nameCb = new NameCallback("User ID:");
			return new Callback[] { nameCb, passCb };
		}
		return new Callback[] { passCb };
	}

	@Override
	public boolean isNameCallbackAllowed() {
		return nameCallbackAllowed;
	}

	/*
	 * @see ghidra.server.security.AuthenticationModule#authenticate(ghidra.server.UserManager, javax.security.auth.Subject, javax.security.auth.callback.Callback[])
	 */
	public String authenticate(UserManager userMgr, Subject subject, Callback[] callbacks)
			throws LoginException {
		GhidraPrincipal user = GhidraPrincipal.getGhidraPrincipal(subject);
		if (user == null) {
			throw new FailedLoginException("GhidraPrincipal required");
		}
		String username = user.getName();

		NameCallback nameCb = null;
		PasswordCallback passCb = null;
		if (callbacks != null) {
			for (int i = 0; i < callbacks.length; i++) {
				if (callbacks[i] instanceof NameCallback) {
					nameCb = (NameCallback) callbacks[i];
				}
				else if (callbacks[i] instanceof PasswordCallback) {
					passCb = (PasswordCallback) callbacks[i];
				}
			}
		}

		if (nameCallbackAllowed && nameCb != null) {
			username = nameCb.getName();
		}
		if (username == null || username.length() == 0) {
			throw new FailedLoginException("User ID must be specified");
		}

		if (passCb == null) {
			throw new FailedLoginException("Password callback required");
		}

		char[] pass = null;
		try {
			pass = passCb.getPassword();
			passCb.clearPassword();
			userMgr.authenticateUser(username, pass);
		}
		catch (IOException e) {
			String msg = e.getMessage();
			if (msg == null) {
				msg = e.toString();
			}
			throw new FailedLoginException(msg);
		}
		finally {
			if (pass != null) {
				Arrays.fill(pass, ' ');
			}
		}
		return username;
	}

}
