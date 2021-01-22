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

import java.util.Map;

import agent.dbgeng.dbgeng.DebugControl;
import agent.dbgeng.dbgeng.DebugThreadId;
import agent.dbgeng.manager.DbgEvent;
import agent.dbgeng.manager.DbgManager.ExecSuffix;
import agent.dbgeng.manager.DbgThread;
import agent.dbgeng.manager.evt.*;
import agent.dbgeng.manager.impl.DbgManagerImpl;
import agent.dbgeng.manager.impl.DbgThreadImpl;
import ghidra.util.Msg;

/**
 * Implementation of {@link DbgThread#stepInstruction()}
 */
public class DbgStepCommand extends AbstractDbgCommand<Void> {

	private DebugThreadId id;
	protected final ExecSuffix suffix;
	private String lastCommand = "tct";

	public DbgStepCommand(DbgManagerImpl manager, DebugThreadId id, ExecSuffix suffix) {
		super(manager);
		this.id = id;
		this.suffix = suffix;
	}

	public DbgStepCommand(DbgManagerImpl manager, DebugThreadId id, Map<String, ?> args) {
		super(manager);
		this.id = id;
		this.suffix = ExecSuffix.EXTENDED;
		this.lastCommand = (String) args.get("Command");
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

	// NB:  Would really prefer to do this through the API, but the API does
	//  not appear to support freeze/unfreeze and suspend/resume thread.  These appear
	//  to be applied via the kernel32 API.  Worse, the Windbg/KD API appears to lack
	//  commands to query the freeze/suspend count for a given thread.  Rather than 
	//  wrestle with the underlying API, we're going to just use the WIndbg commands.
	//  Note that the thread-restricted form is used iff we're stepping a thread other
	//  then the event thread.
	@Override
	public void invoke() {
		String cmd = "";
		String prefix = id == null ? "" : "~" + id.id + " ";
		DebugControl control = manager.getControl();
		if (suffix.equals(ExecSuffix.STEP_INSTRUCTION)) {
			cmd = "t";
			//control.setExecutionStatus(DebugStatus.STEP_INTO);
		}
		else if (suffix.equals(ExecSuffix.NEXT_INSTRUCTION)) {
			cmd = "p";
			//control.setExecutionStatus(DebugStatus.STEP_OVER);
		}
		else if (suffix.equals(ExecSuffix.FINISH)) {
			cmd = "gu";
			//control.setExecutionStatus(DebugStatus.STEP_BRANCH);
		}
		else if (suffix.equals(ExecSuffix.EXTENDED)) {
			cmd = getLastCommand();
		}
		DbgThreadImpl eventThread = manager.getEventThread();
		if (eventThread != null && eventThread.getId().equals(id)) {
			control.execute(cmd);
		}
		else {
			if (manager.isKernelMode()) {
				Msg.info(this, "Thread-specific stepping ignored in kernel-mode");
				control.execute(cmd);
			}
			else {
				control.execute(prefix + cmd);
			}
		}
	}

	public String getLastCommand() {
		return lastCommand;
	}

	public void setLastCommand(String lastCommand) {
		this.lastCommand = lastCommand;
	}
}
