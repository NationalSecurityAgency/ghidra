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

import agent.frida.manager.FridaCause;
import agent.frida.manager.FridaCause.Causes;
import agent.frida.manager.FridaEvent;
import agent.frida.manager.FridaReason;
import agent.frida.manager.FridaState;
import agent.frida.manager.cmd.FridaPendingCommand;

/**
 * A base class for frida events
 *
 * @param <T> the type of information detailing the event
 */
public abstract class AbstractFridaEvent<T> implements FridaEvent<T> {
	private final T info;
	protected FridaCause cause = Causes.UNCLAIMED;
	protected boolean stolen = false;
	//protected DebugStatus status = DebugStatus.NO_CHANGE;

	/**
	 * Construct a new event with the given information
	 * 
	 * @param info the information
	 */
	protected AbstractFridaEvent(T info) {
		this.info = info;
	}

	@Override
	public T getInfo() {
		return info;
	}

	@Override
	public void claim(FridaPendingCommand<?> cmd) {
		cause = cmd;
	}

	@Override
	public FridaCause getCause() {
		return cause;
	}

	public FridaReason getReason() {
		return FridaReason.getReason(null);
	}

	@Override
	public void steal() {
		stolen = true;
	}

	@Override
	public boolean isStolen() {
		return stolen;
	}

	@Override
	public String toString() {
		return "<" + getClass().getSimpleName() + " " + info + " >";
	}

	@Override
	public FridaState newState() {
		return null;
	}

}
