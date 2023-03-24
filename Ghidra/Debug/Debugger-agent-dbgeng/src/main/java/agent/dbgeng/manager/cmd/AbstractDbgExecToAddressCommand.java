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
package agent.dbgeng.manager.cmd;

import agent.dbgeng.dbgeng.DebugControl;
import agent.dbgeng.dbgeng.DebugThreadId;
import agent.dbgeng.manager.DbgEvent;
import agent.dbgeng.manager.evt.*;
import agent.dbgeng.manager.impl.DbgManagerImpl;
import agent.dbgeng.manager.impl.DbgThreadImpl;
import ghidra.util.Msg;

public abstract class AbstractDbgExecToAddressCommand extends AbstractDbgCommand<Void> {

	private final DebugThreadId id;
	private final String address;

	public AbstractDbgExecToAddressCommand(DbgManagerImpl manager, DebugThreadId id,
			String address) {
		super(manager);
		this.id = id;
		this.address = address;
	}

	@Override
	public boolean handle(DbgEvent<?> evt, DbgPendingCommand<?> pending) {
		if (evt instanceof AbstractDbgCompletedCommandEvent && pending.getCommand().equals(this)) {
			return evt instanceof DbgCommandErrorEvent ||
				!pending.findAllOf(DbgRunningEvent.class).isEmpty();
		}
		else if (evt instanceof DbgRunningEvent) {
			// Event happens no matter which interpreter received the command
			pending.claim(evt);
			return !pending.findAllOf(AbstractDbgCompletedCommandEvent.class).isEmpty();
		}
		return false;
	}

	protected abstract String generateCommand(String address);

	@Override
	public void invoke() {
		String cmd = generateCommand(address);
		String prefix = id == null ? "" : "~" + id.id() + " ";
		DebugControl control = manager.getControl();
		DbgThreadImpl eventThread = manager.getEventThread();
		if (eventThread != null && eventThread.getId().equals(id)) {
			control.execute(cmd);
		}
		else {
			if (manager.isKernelMode()) {
				Msg.info(this, "Thread-specific steppign is ignored in kernel-mode");
				control.execute(cmd);
			}
			else {
				control.execute(prefix + cmd);
			}
		}
	}
}
