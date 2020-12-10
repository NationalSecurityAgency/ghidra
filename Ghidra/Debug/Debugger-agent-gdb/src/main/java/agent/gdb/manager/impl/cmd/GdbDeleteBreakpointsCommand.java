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

import org.apache.commons.lang3.StringUtils;

import agent.gdb.manager.GdbInferior;
import agent.gdb.manager.evt.AbstractGdbCompletedCommandEvent;
import agent.gdb.manager.evt.GdbCommandDoneEvent;
import agent.gdb.manager.impl.*;

/**
 * Implementation of {@link GdbInferior#deleteBreakpoint(long)}
 */
public class GdbDeleteBreakpointsCommand extends AbstractGdbCommand<Void> {

	private final long[] numbers;

	public GdbDeleteBreakpointsCommand(GdbManagerImpl manager, long... numbers) {
		super(manager);
		this.numbers = numbers;
	}

	@Override
	public String encode() {
		return "-break-delete " + StringUtils.join(numbers, ' ');
	}

	@Override
	public boolean handle(GdbEvent<?> evt, GdbPendingCommand<?> pending) {
		if (evt instanceof AbstractGdbCompletedCommandEvent) {
			pending.claim(evt);
			return true;
		}
		return false;
	}

	@Override
	public Void complete(GdbPendingCommand<?> pending) {
		pending.checkCompletion(GdbCommandDoneEvent.class);
		// GDB does not give notification for breakpoints removed by GDB/MI commands
		for (long number : numbers) {
			manager.doBreakpointDeleted(number, pending);
		}
		return null;
	}
}
