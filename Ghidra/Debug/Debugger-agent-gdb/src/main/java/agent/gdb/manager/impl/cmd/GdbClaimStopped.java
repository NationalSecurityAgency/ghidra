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
package agent.gdb.manager.impl.cmd;

import agent.gdb.manager.GdbManager;
import agent.gdb.manager.GdbState;
import agent.gdb.manager.evt.GdbStoppedEvent;
import agent.gdb.manager.impl.*;

/**
 * Implementation of {@link GdbManager#claimStopped()}
 */
public class GdbClaimStopped extends AbstractGdbCommand<Void> {
	public GdbClaimStopped(GdbManagerImpl manager) {
		super(manager);
	}

	@Override
	public boolean validInState(GdbState state) {
		return state == GdbState.RUNNING;
	}

	@Override
	public String encode() {
		// This is not really a command, it just claims *stopped
		// The executor will also wait for (gdb). Good.
		return null;
	}

	@Override
	public boolean handle(GdbEvent<?> evt, GdbPendingCommand<?> pending) {
		if (evt instanceof GdbStoppedEvent) {
			pending.claim(evt);
			return true;
		}
		return false;
	}

	@Override
	public Void complete(GdbPendingCommand<?> pending) {
		pending.findSingleOf(GdbStoppedEvent.class);
		return null;
	}
}
