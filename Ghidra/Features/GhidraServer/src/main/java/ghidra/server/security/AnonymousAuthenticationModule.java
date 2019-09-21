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

import java.util.*;

import javax.security.auth.callback.Callback;

import ghidra.framework.remote.AnonymousCallback;

public class AnonymousAuthenticationModule {

	public Callback[] addAuthenticationCallbacks(Callback[] primaryAuthCallbacks) {
		List<Callback> list = new ArrayList<Callback>();
		if (primaryAuthCallbacks != null) {
			list.addAll(Arrays.asList(primaryAuthCallbacks));
		}
		list.add(new AnonymousCallback());
		return list.toArray(new Callback[list.size()]);
	}

	public boolean anonymousAccessRequested(Callback[] callbacks) {
		AnonymousCallback anonCb =
			AuthenticationModule.getFirstCallbackOfType(AnonymousCallback.class, callbacks);
		return anonCb != null && anonCb.anonymousAccessRequested();
	}

}
