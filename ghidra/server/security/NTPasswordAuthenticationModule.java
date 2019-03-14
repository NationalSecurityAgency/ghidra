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
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;

import javax.security.auth.Subject;
import javax.security.auth.callback.*;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;

import com.tagish.auth.win32.NTSystem;

public class NTPasswordAuthenticationModule implements AuthenticationModule {

	private final NTSystem ntSystem;
	private final String domainName;
	private final String namePrompt; // if not null, name callback is allowed
	private final String passPrompt;
	private final boolean localAuthOK;
	private final String[] authChoices;

	/**
	 * Authentication module constructor.
	 * @param domainName NT authentication domain
	 * @param nameCallbackAllowed if true user may be prompted for domain user-ID
	 */
	public NTPasswordAuthenticationModule(String domainName, boolean nameCallbackAllowed,
			boolean localAuthOK) {
		this.localAuthOK = localAuthOK;
		this.domainName = domainName;
		ntSystem = new NTSystem();
		ntSystem.checkVersion();
		String hostName = null;
		try {
			hostName = InetAddress.getLocalHost().getHostName();
		}
		catch (UnknownHostException e) {
		}
		if (hostName == null) {
			hostName = ntSystem.getName();
		}
		if (localAuthOK) {
			String osAuth = (domainName != null) ? "Domain: " + domainName : "Host: " + hostName;
			authChoices = new String[] { osAuth, "Ghidra Server" };
		}
		else {
			authChoices = null;
		}

		if (nameCallbackAllowed) {
			if (localAuthOK) {
				namePrompt = "User ID:";
			}
			else if (domainName == null) {
				namePrompt = "User ID (" + hostName + "):";
			}
			else {
				namePrompt = "User ID (" + domainName + "):";
			}
		}
		else {
			namePrompt = null;
		}

		if (!localAuthOK && !nameCallbackAllowed) {
			if (domainName == null) {
				passPrompt = "Password (" + hostName + "):";
			}
			else {
				passPrompt = "Password (" + domainName + "):";
			}
		}
		else {
			passPrompt = "Password:";
		}
	}

	@Override
	public boolean isNameCallbackAllowed() {
		return namePrompt != null;
	}

	@Override
	public boolean anonymousCallbacksAllowed() {
		return true;
	}

	/*
	 * @see ghidra.server.security.AuthenticationModule#getAuthenticationCallbacks(javax.security.auth.Subject)
	 */
	public Callback[] getAuthenticationCallbacks() {
		ArrayList<Callback> list = new ArrayList<Callback>();
		if (namePrompt != null) {
			list.add(new NameCallback(namePrompt));
		}
		list.add(new PasswordCallback(passPrompt, false));
		if (localAuthOK) {
			list.add(new ChoiceCallback("Authenticator:", authChoices, 0, false));
		}
		Callback[] callbacks = new Callback[list.size()];
		list.toArray(callbacks);
		return callbacks;
	}

	private boolean useOSAuthentication(ChoiceCallback choiceCb) {
		if (choiceCb != null) {
			int[] selectedIndexes = choiceCb.getSelectedIndexes();
			if (selectedIndexes.length == 1 && selectedIndexes[0] == 1) {
				return false; // 2nd choice corresponds to local password file (Ghidra Server)
			}
		}
		return true;
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
		ChoiceCallback choiceCb = null;
		if (callbacks != null) {
			for (int i = 0; i < callbacks.length; i++) {
				if (callbacks[i] instanceof NameCallback) {
					nameCb = (NameCallback) callbacks[i];
				}
				else if (callbacks[i] instanceof PasswordCallback) {
					passCb = (PasswordCallback) callbacks[i];
				}
				else if (callbacks[i] instanceof ChoiceCallback) {
					choiceCb = (ChoiceCallback) callbacks[i];
				}
			}
		}

		if (namePrompt != null && nameCb != null) {
			username = nameCb.getName();
		}
		if (username == null || username.length() == 0) {
			throw new FailedLoginException("User ID must be specified");
		}

		if (passCb == null) {
			throw new FailedLoginException("Password callback required");
		}

		if (!userMgr.isValidUser(username)) {
			throw new FailedLoginException("Unknown user: " + username);
		}

		boolean osAuth = useOSAuthentication(choiceCb);

		char[] pass = null;
		try {

			pass = passCb.getPassword();
			passCb.clearPassword();

			if (osAuth) {
				// Authenticate only - do not stay logged-in
				ntSystem.logon(username, pass, domainName);
				ntSystem.logoff();
			}
			else {
				userMgr.authenticateUser(username, pass);
			}

		}
		catch (FailedLoginException e) {
			String msg = e.getMessage();
			if (domainName == null && msg != null &&
				msg.indexOf("storage control block address is invalid") > 0) {
				throw new FailedLoginException(
					"NT Domain is unknown (see server startup option -d)");
			}
			throw e;
		}
		catch (IOException e) {
			String msg = e.getMessage();
			if (msg == null) {
				msg = e.toString();
			}
			throw new FailedLoginException(msg);
		}
		catch (Throwable t) {
//Err.error(this, null, "Error", "Unexpected Exception: " + e.getMessage(), e);
			String msg = t.getMessage();
			if (msg == null) {
				msg = t.toString();
			}
			throw new FailedLoginException("server error: " + msg);
		}
		finally {
			if (pass != null) {
				Arrays.fill(pass, ' ');
			}
		}
		return username;
	}

	public boolean usingLocalAuthentication(Callback[] callbacks) {
		if (callbacks != null) {
			for (int i = 0; i < callbacks.length; i++) {
				if (callbacks[i] instanceof ChoiceCallback) {
					return !useOSAuthentication((ChoiceCallback) callbacks[i]);
				}
			}
		}
		return false;
	}

}
