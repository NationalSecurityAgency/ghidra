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
import agent.frida.frida.FridaThreadInfo;
import agent.frida.manager.*;

/**
 * The event corresponding with FridaThread.eBroadcastBitThreadSelected
 */
public class FridaThreadSelectedEvent extends AbstractFridaEvent<String> {
	private final String id;
	private FridaState state;
	private FridaThread thread;
	private FridaFrame frame;

	/**
	 * @param info thread info
	 */
	public FridaThreadSelectedEvent(FridaThreadInfo info) {
		super(FridaClient.getId(info.thread));
		this.id = FridaClient.getId(info.thread);
		this.state = info.thread.getState();
		this.thread = info.thread;
	}

	/**
	 * Get the selected thread ID
	 * 
	 * @return the thread ID
	 */
	public String getThreadId() {
		return id;
	}

	public FridaState getState() {
		return state;
	}

	public FridaThread getThread() {
		return thread;
	}

	public FridaFrame getFrame() {
		return frame;
	}

}
