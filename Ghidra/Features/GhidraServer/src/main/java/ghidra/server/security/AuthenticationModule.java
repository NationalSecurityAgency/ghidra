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

import javax.security.auth.Subject;
import javax.security.auth.callback.*;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;

import ghidra.server.UserManager;

public interface AuthenticationModule {

	public static final String USERNAME_CALLBACK_PROMPT = "User ID";
	public static final String PASSWORD_CALLBACK_PROMPT = "Password";

	/**
	 * Complete the authentication process.
	 * <p>
	 * Note to AuthenticationModule implementors:
	 * <ul>
	 * <li>The authentication callback objects are not guaranteed to be the same
	 * instances as those returned by the {@link #getAuthenticationCallbacks()}.<br>
	 * (they may have been cloned or duplicated or copied in some manner)</li>
	 * <li>The authentication callback array may contain callback instances other than
	 * the ones your module specified in its {@link #getAuthenticationCallbacks()}</li>
	 * </ul>
	 * <p>
	 * @param userMgr Ghidra server user manager
	 * @param subject unauthenticated user ID (must be used if name callback not provided/allowed)
	 * @param callbacks authentication callbacks
	 * @return authenticated user ID (may come from callbacks)
	 * @throws LoginException if error during login.  Client should not retry authentication
	 * @throws FailedLoginException if authentication was unsuccessful.  Client may
	 * retry authentication
	 */
	String authenticate(UserManager userMgr, Subject subject, Callback[] callbacks)
			throws LoginException;

	/**
	 * Returns authentication callbacks needed to authenticate a user.
	 */
	Callback[] getAuthenticationCallbacks();

	/**
	 * Allows this AuthenticationModule to deny default anonymous login steps.
	 * <p>
	 * @return true if a separate AnonymousCallback is allowed and may be
	 * added to the array returned by getAuthenticationCallbacks.
	 * @see #getAuthenticationCallbacks()
	 */
	boolean anonymousCallbacksAllowed();

	/**
	 * @return true if NameCallback is allowed
	 */
	boolean isNameCallbackAllowed();

	/**
	 * Creates a standard pair of name and password callback instances.
	 *
	 * @param allowUserToSpecifyName boolean flag, if false, a name callback is not added to the results
	 * @return an array of callbacks
	 */
	static Callback[] createSimpleNamePasswordCallbacks(boolean allowUserToSpecifyName) {
		PasswordCallback passCb = new PasswordCallback(PASSWORD_CALLBACK_PROMPT + ":", false);
		if (allowUserToSpecifyName) {
			NameCallback nameCb = new NameCallback(USERNAME_CALLBACK_PROMPT + ":");
			return new Callback[] { nameCb, passCb };
		}
		return new Callback[] { passCb };
	}

	/**
	 * Find the first callback of a specific type in the list and returns it.
	 *
	 * @param <T> the type of callback
	 * @param callbackClass the callback class (ie. Namecallback.class)
	 * @param callbackArray array of callbacks to search
	 * @return callback instance that is of type T, or null if not found
	 */
	static <T extends Callback> T getFirstCallbackOfType(Class<T> callbackClass,
			Callback[] callbackArray) {
		if (callbackArray == null) {
			return null;
		}

		for (Callback cb : callbackArray) {
			if (callbackClass == cb.getClass()) {
				return callbackClass.cast(cb);
			}
		}
		return null;
	}
}
