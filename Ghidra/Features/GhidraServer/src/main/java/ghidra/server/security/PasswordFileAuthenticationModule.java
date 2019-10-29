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
import java.util.Arrays;

import javax.security.auth.Subject;
import javax.security.auth.callback.*;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;

import org.apache.commons.lang3.StringUtils;

import ghidra.framework.remote.GhidraPrincipal;
import ghidra.server.UserManager;

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
	@Override
	public Callback[] getAuthenticationCallbacks() {
		return AuthenticationModule.createSimpleNamePasswordCallbacks(nameCallbackAllowed);
	}

	@Override
	public boolean isNameCallbackAllowed() {
		return nameCallbackAllowed;
	}

	/*
	 * @see ghidra.server.security.AuthenticationModule#authenticate(ghidra.server.UserManager, javax.security.auth.Subject, javax.security.auth.callback.Callback[])
	 */
	@Override
	public String authenticate(UserManager userMgr, Subject subject, Callback[] callbacks)
			throws LoginException {
		GhidraPrincipal user = GhidraPrincipal.getGhidraPrincipal(subject);
		if (user == null) {
			throw new FailedLoginException("GhidraPrincipal required");
		}
		String username = user.getName();

		NameCallback nameCb =
			AuthenticationModule.getFirstCallbackOfType(NameCallback.class, callbacks);
		PasswordCallback passCb =
			AuthenticationModule.getFirstCallbackOfType(PasswordCallback.class, callbacks);

		if (nameCallbackAllowed && nameCb != null) {
			username = nameCb.getName();
		}
		if (StringUtils.isBlank(username)) {
			throw new FailedLoginException("User ID must be specified");
		}

		if (passCb == null) {
			throw new FailedLoginException("Password callback required");
		}

		char[] pass = passCb.getPassword();
		passCb.clearPassword();

		try {
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
