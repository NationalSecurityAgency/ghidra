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
import java.util.concurrent.atomic.AtomicReference;

import javax.security.auth.Subject;
import javax.security.auth.callback.*;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import ghidra.framework.remote.GhidraPrincipal;
import ghidra.server.UserManager;

/**
 * Adapter between Ghidra {@link AuthenticationModule}s and simple JAAS {@link LoginModule}s.
 * <p>
 * JAAS is typically configured via an external file that specifies the stack of LoginModules
 * per login context configuration "name".
 * <p>
 * This implementation only supports JAAS LoginModules that use Name and Password callbacks,
 * and ignores any customization in the name and password callbacks in favor of its own
 * callbacks.
 * <p>
 *
 */
public class JAASAuthenticationModule implements AuthenticationModule {

	private boolean allowUserToSpecifyName;
	private String loginContextName;

	public JAASAuthenticationModule(String loginContextName, boolean allowUserToSpecifyName) {
		this.loginContextName = loginContextName;
		this.allowUserToSpecifyName = allowUserToSpecifyName;
	}

	@Override
	public String authenticate(UserManager userMgr, Subject subject, Callback[] callbacks)
			throws LoginException {
		GhidraPrincipal principal = GhidraPrincipal.getGhidraPrincipal(subject);
		AtomicReference<String> loginName = new AtomicReference<>();
		LoginContext loginCtx = new LoginContext(loginContextName, loginModuleCallbacks -> {
			loginName.set(copyCallbackValues(callbacks, loginModuleCallbacks, principal));
		});

		// this is where the callback is triggered
		loginCtx.login();

		String loginNameResult = loginName.get();
		return (loginNameResult != null) ? loginNameResult : principal.getName();
	}

	@Override
	public Callback[] getAuthenticationCallbacks() {
		// We don't know for sure what callbacks the JAAS LoginModule is going to throw at us
		// during the login() method.  Therefore, to keep things simple, we are going to limit
		// the supported JAAS LoginModules to ones that only use Name and Password callbacks.
		return AuthenticationModule.createSimpleNamePasswordCallbacks(allowUserToSpecifyName);
	}

	@Override
	public boolean anonymousCallbacksAllowed() {
		return false;
	}

	@Override
	public boolean isNameCallbackAllowed() {
		return allowUserToSpecifyName;
	}

	/**
	 * Copies the callback values from the callback instances in the src list to the
	 * corresponding instances (matched by callback class type) in the dest list, and
	 * then returns the user name.
	 *
	 * @param srcInstances array of callback instances to copy from
	 * @param destInstances array of callback instances to copy to
	 * @param principal the user principal (ie. default) name, used when no
	 * name callback is found
	 * @return the effective user name, either the principal or value from name callback.
	 * @throws IOException if missing password callback
	 */
	private String copyCallbackValues(Callback[] srcInstances, Callback[] destInstances,
			GhidraPrincipal principal) throws IOException {
		PasswordCallback srcPcb =
			AuthenticationModule.getFirstCallbackOfType(PasswordCallback.class, srcInstances);
		NameCallback srcNcb =
			AuthenticationModule.getFirstCallbackOfType(NameCallback.class, srcInstances);

		String userName = null;
		NameCallback destNcb =
			AuthenticationModule.getFirstCallbackOfType(NameCallback.class, destInstances);
		if (destNcb != null) {
			userName =
				(allowUserToSpecifyName && srcNcb != null) ? srcNcb.getName() : principal.getName();
			destNcb.setName(userName);
		}

		PasswordCallback destPcb =
			AuthenticationModule.getFirstCallbackOfType(PasswordCallback.class, destInstances);
		if (destPcb != null) {
			if (srcPcb == null) {
				throw new IOException("Missing password callback value");
			}
			destPcb.setPassword(srcPcb.getPassword());
		}
		return userName;
	}

}
