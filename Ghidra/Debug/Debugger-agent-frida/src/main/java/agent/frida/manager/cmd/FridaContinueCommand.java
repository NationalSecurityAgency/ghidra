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
package agent.frida.manager.cmd;

import agent.frida.manager.*;
import agent.frida.manager.evt.*;
import agent.frida.manager.impl.FridaManagerImpl;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.util.Msg;

/**
 * Implementation of {@link FridaManager#continue()}
 */
public class FridaContinueCommand extends AbstractFridaCommand<Void> {

	private FridaProcess process;

	public FridaContinueCommand(FridaManagerImpl manager, FridaProcess process) {
		super(manager);
		this.process = process;
	}

	public FridaContinueCommand(FridaManagerImpl manager) {
		super(manager);
		this.process = null;
	}

	@Override
	public boolean handle(FridaEvent<?> evt, FridaPendingCommand<?> pending) {
		if (evt instanceof AbstractFridaCompletedCommandEvent && pending.getCommand().equals(this)) {
			pending.claim(evt);
			boolean b = evt instanceof FridaCommandErrorEvent ||
				!pending.findAllOf(FridaRunningEvent.class).isEmpty();
			return b;
		}
		else if (evt instanceof FridaRunningEvent) {
			// Event happens no matter which interpreter received the command
			pending.claim(evt);
			boolean b = !pending.findAllOf(AbstractFridaCompletedCommandEvent.class).isEmpty();
			return b;
		}
		return false;
	}

	@Override
	public Void complete(FridaPendingCommand<?> pending) {
		return null;
	}
	
	@Override
	public void invoke() {
		FridaError res = process == null ? manager.getCurrentSession().resume() : process.resume();
		if (!res.success()) {
			Msg.error(this, res.getDescription());
		}
		TargetExecutionState state = TargetExecutionState.RUNNING;
		manager.getClient().processEvent(new FridaStateChangedEvent(process, state));
	}
}
