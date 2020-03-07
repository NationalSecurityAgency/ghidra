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

import java.io.Serializable;

import javax.security.auth.callback.Callback;

public class AnonymousCallback implements Callback, Serializable {

	public static final long serialVersionUID = 1L;

	private boolean anonymousAccessRequested = false;

	/**
	 * If state set to true anonymous read-only access will be requested
	 * @param state true to request anonymous access
	 */
	public void setAnonymousAccessRequested(boolean state) {
		anonymousAccessRequested = state;
	}

	/**
	 * @return true if anonymous access requested
	 */
	public boolean anonymousAccessRequested() {
		return anonymousAccessRequested;
	}

}
