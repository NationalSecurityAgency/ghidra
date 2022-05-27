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

import agent.frida.manager.FridaState;

public class FridaRunningEvent extends AbstractFridaEvent<String> {
	private final String id;

	/**
	 * Construct a new event, parsing the tail for information
	 * 
	 * A thread ID must be specified by frida.
	 * 
	 * @param id the event info
	 */
	public FridaRunningEvent(String id) {
		super(id);
		this.id = id;
	}

	/**
	 * Get the ID of the thread causing the event
	 * 
	 * @return the thread ID
	 */
	public String getThreadId() {
		return id;
	}

	@Override
	public FridaState newState() {
		return FridaState.FRIDA_THREAD_RUNNING;
	}

}
