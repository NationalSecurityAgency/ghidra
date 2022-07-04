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
package agent.frida.manager.evt;

import agent.frida.frida.FridaClient;
import agent.frida.manager.FridaSession;

public class FridaSessionSelectedEvent extends AbstractFridaEvent<String> {
	private final String id;
	private FridaSession session;

	/**
	 * The selected session ID must be specified by Frida.
	 * 
	 * @param session Frida-defined session
	 */
	public FridaSessionSelectedEvent(FridaSession session) {
		super(FridaClient.getId(session));
		this.session = session;
		this.id = FridaClient.getId(session);
	}

	/**
	 * Get the selected session ID
	 * 
	 * @return the session ID
	 */
	public String getSessionId() {
		return id;
	}

	public FridaSession getSession() {
		return session;
	}

}
