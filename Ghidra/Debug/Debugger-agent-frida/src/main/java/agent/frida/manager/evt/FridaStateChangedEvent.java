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
import agent.frida.manager.*;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;

/**
 * The event corresponding with FridaProcess.eBroadcastBitStateChanged
 */
public class FridaStateChangedEvent extends AbstractFridaEvent<TargetExecutionState> {

	private FridaState state = null;
	private String id;

	public FridaStateChangedEvent(Object obj, TargetExecutionState state) {
		super(state);
		this.state = FridaClient.convertState(state);
		this.id = FridaClient.getId(obj);
	}

	public FridaFrame getFrame(FridaThread thread) {
		return null;
	}

	@Override
	public FridaState newState() {
		return state;
	}

	public void setState(FridaState state) {
		this.state = state;
	}
	
	public String getId() {
		return id;
	}

}
