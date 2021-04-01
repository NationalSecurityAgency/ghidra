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
import agent.gdb.manager.evt.AbstractGdbCompletedCommandEvent;
import agent.gdb.manager.evt.GdbStoppedEvent;
import agent.gdb.manager.impl.*;
import agent.gdb.manager.impl.GdbManagerImpl.Interpreter;
import ghidra.util.Msg;

/**
 * Implementation of {@link GdbManager#interrupt()} when we start GDB
 */
public class GdbInterruptCommand extends AbstractGdbCommand<Void> {
	public GdbInterruptCommand(GdbManagerImpl manager) {
		super(manager);
	}

	@Override
	public boolean validInState(GdbState state) {
		//return state == GdbState.RUNNING;
		return true;
	}

	@Override
	public String encode() {
		Interpreter i = getInterpreter();
		if (i == manager.getRunningInterpreter()) {
			Msg.debug(this, "Using ^C to interrupt");
			return "\u0003";
		}
		switch (i) {
			case CLI:
				Msg.debug(this, "Interrupting via CLI");
				return "interrupt";
			case MI2:
				Msg.debug(this, "Interrupting via MI2");
				return "-exec-interrupt";
			default:
				throw new AssertionError();
		}
	}

	@Override
	public boolean handle(GdbEvent<?> evt, GdbPendingCommand<?> pending) {
		if (evt instanceof AbstractGdbCompletedCommandEvent) {
			pending.claim(evt);
			return true;
		}
		else if (evt instanceof GdbStoppedEvent) {
			pending.claim(evt);
			return true;
		}
		return false;
	}

	@Override
	public Void complete(GdbPendingCommand<?> pending) {
		// When using -exec-interrupt, ^done will come before *stopped
		//pending.findSingleOf(GdbStoppedEvent.class);
		return null;
	}

	@Override
	public Interpreter getInterpreter() {
		if (manager.hasCli() && manager.getRunningInterpreter() == Interpreter.MI2) {
			return Interpreter.CLI;
		}
		return Interpreter.MI2;
	}
}
