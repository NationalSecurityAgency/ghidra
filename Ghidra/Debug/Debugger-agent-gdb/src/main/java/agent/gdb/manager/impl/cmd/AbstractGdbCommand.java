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

import agent.gdb.manager.GdbState;
import agent.gdb.manager.evt.*;
import agent.gdb.manager.impl.*;
import agent.gdb.manager.impl.GdbManagerImpl.Interpreter;
import agent.gdb.manager.parsing.GdbParsingUtils.GdbParseError;
import ghidra.util.Msg;

/**
 * A base class for interacting with specific GDB commands
 *
 * @param <T> the type of object "returned" by the command
 */
public abstract class AbstractGdbCommand<T> implements GdbCommand<T> {
	protected final GdbManagerImpl manager;

	/**
	 * Construct a new command to be executed by the given manager
	 * 
	 * @param manager the manager to execute the command
	 */
	protected AbstractGdbCommand(GdbManagerImpl manager) {
		this.manager = manager;
	}

	@Override
	public boolean validInState(GdbState state) {
		//return state == GdbState.STOPPED;
		return true; // With dual interpreters, shouldn't have to worry.
	}

	@Override
	public void preCheck(GdbPendingCommand<? super T> pending) {
	}

	@Override
	public String toString() {
		return "<GDB/" + getInterpreter() + " " + encode() + ">";
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Selects mi2 by default. Check {@link GdbManagerImpl#hasCli()} before selecting the
	 * command-line (console) interface.
	 */
	@Override
	public Interpreter getInterpreter() {
		return Interpreter.MI2;
	}

	@Override
	public boolean handle(GdbEvent<?> evt, GdbPendingCommand<?> pending) {
		/**
		 * Unfortunately, GDB prints {@code ^running} even if the command causing that result is
		 * issued from the CLI. This is a problem when "using an existing session," because the user
		 * will likely type "start" into the existing CLI. Thus, we have to be careful not to let
		 * spurious {@code ^running} command-completion events actually complete any command, except
		 * ones where we expect that result. This seems a bug in GDB to me.
		 * 
		 * UPDATE: It looks like this will be fixed in gdb-14. Despite the fix we leave this
		 * workaround in place while we still support older gdb versions.
		 */
		if (evt instanceof GdbCommandRunningEvent) {
			return false;
		}
		if (evt instanceof AbstractGdbCompletedCommandEvent) {
			pending.claim(evt);
			return true;
		}
		return false;
	}

	@Override
	public Integer impliesCurrentThreadId() {
		return null;
	}

	@Override
	public Integer impliesCurrentFrameId() {
		return null;
	}

	@Override
	public boolean isFocusInternallyDriven() {
		return true;
	}
}
