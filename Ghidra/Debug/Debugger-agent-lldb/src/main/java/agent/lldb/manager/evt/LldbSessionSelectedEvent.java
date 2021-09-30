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
package agent.lldb.manager.evt;

import SWIG.SBTarget;
import agent.lldb.lldb.DebugClient;

public class LldbSessionSelectedEvent extends AbstractLldbEvent<String> {
	private final String id;
	private SBTarget session;

	/**
	 * The selected session ID must be specified by lldb.
	 * 
	 * @param session lldb-defined session
	 */
	public LldbSessionSelectedEvent(SBTarget session) {
		super(DebugClient.getId(session));
		this.session = session;
		this.id = DebugClient.getId(session);
	}

	/**
	 * Get the selected session ID
	 * 
	 * @return the session ID
	 */
	public String getSessionId() {
		return id;
	}

	public SBTarget getSession() {
		return session;
	}

}
