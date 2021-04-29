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
import agent.gdb.manager.evt.GdbCommandErrorEvent;
import agent.gdb.manager.evt.GdbConsoleOutputEvent;
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
	 * Selects mi2 by default. Check {@link GdbManagerImpl#hasCli()} before selecting the
	 * command-line (console) interface.
	 */
	@Override
	public Interpreter getInterpreter() {
		return Interpreter.MI2;
	}

	/**
	 * Check for an error reported in MI2 syntax via the CLI
	 * 
	 * <p>
	 * This must be used in the {@link #handle(GdbEvent, GdbPendingCommand)} callback when the
	 * command is encoded as a MI2 command (using {@code interpreter-exec mi2}) but issued via the
	 * CLI. Depending on the GDB version and the outcome of the command, the result may be reported
	 * via the CLI, but in MI2 syntax. As of yet, this has only been observed for {@code ^error}
	 * results.
	 * 
	 * @param evt the event to check
	 * @return the decoded error event, if applicable, or the original unmodified event.
	 */
	protected GdbEvent<?> checkErrorViaCli(GdbEvent<?> evt) {
		if (evt instanceof GdbConsoleOutputEvent) {
			GdbConsoleOutputEvent outEvt = (GdbConsoleOutputEvent) evt;
			// This is quirky in 8.0.1.
			// I don't know to what other version(s) it applies.
			String out = outEvt.getOutput();
			if (out.startsWith("^error")) {
				try {
					return GdbCommandErrorEvent.fromMi2(out.split(",", 2)[1].trim());
				}
				catch (GdbParseError e) {
					Msg.error(this, "Could not parse error result", e);
				}
			}
		}
		return evt;
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
