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
import agent.gdb.manager.impl.GdbCommand;
import agent.gdb.manager.impl.GdbManagerImpl;
import agent.gdb.manager.impl.GdbManagerImpl.Interpreter;

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
}
