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
package agent.dbgeng.manager.evt;

import agent.dbgeng.dbgeng.DebugClient.ChangeDebuggeeState;
import ghidra.comm.util.BitmaskSet;

/**
 * The event corresponding with ChangedDebuggeeState
 */
public class DbgDebuggeeStateChangeEvent extends AbstractDbgEvent<Integer> {
	private final BitmaskSet<ChangeDebuggeeState> flags;
	private final long argument;

	/**
	 * The selected flags must be specified by dbgeng.
	 * 
	 * @param flags dbgeng-provided id
	 * @param argument event-specific argument
	 */
	public DbgDebuggeeStateChangeEvent(BitmaskSet<ChangeDebuggeeState> flags, long argument) {
		super((int) flags.getBitmask());
		this.flags = flags;
		this.argument = argument;
	}

	public BitmaskSet<ChangeDebuggeeState> getFlags() {
		return flags;
	}

	public long getArgument() {
		return argument;
	}

}
