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

import ghidra.server.UserManager;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.login.LoginException;

public interface AuthenticationModule {

	/**
	 * Complete the authentication process
	 * @param userMgr Ghidra server user manager
	 * @param subject unauthenticated user ID (must be used if name callback not provided/allowed)
	 * @param callbacks authentication callbacks
	 * @return authenticated user ID (may come from callbacks)
	 * @throws LoginException
	 */
	String authenticate(UserManager userMgr, Subject subject, Callback[] callbacks)
			throws LoginException;

	/**
	 * Returns authentication callbacks needed to authenticate a user.
	 */
	Callback[] getAuthenticationCallbacks();

	/**
	 * @return true if a separate AnonymousCallback is allowed and may be
	 * added to the array returned by getAuthenticationCallbacks.
	 * @see #getAuthenticationCallbacks()
	 */
	boolean anonymousCallbacksAllowed();

	/**
	 * @return true if NameCallback is allowed
	 */
	boolean isNameCallbackAllowed();

}
