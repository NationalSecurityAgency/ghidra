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
import agent.dbgeng.dbgeng.DebugProcessId;
import agent.dbgeng.dbgeng.DebugSystemObjects;
import agent.dbgeng.dbgeng.DebugThreadId;
import agent.dbgeng.manager.DbgEvent;
import agent.dbgeng.manager.DbgThread;
import agent.dbgeng.manager.evt.AbstractDbgCompletedCommandEvent;
import agent.dbgeng.manager.evt.DbgConsoleOutputEvent;
import agent.dbgeng.manager.impl.DbgManagerImpl;
import agent.dbgeng.manager.impl.DbgProcessImpl;
import agent.dbgeng.manager.impl.DbgThreadImpl;
import ghidra.util.Msg;

public class DbgSetCurrentState extends AbstractDbgCommand<DbgThread> {

	private long pid;
	private long tid;
	private DebugProcessId pID;
	private DebugThreadId tID;

	public DbgSetCurrentState(DbgManagerImpl manager) {
		super(manager);
	}

	@Override
	public boolean handle(DbgEvent<?> evt, DbgPendingCommand<?> pending) {
		if (evt instanceof AbstractDbgCompletedCommandEvent && pending.getCommand().equals(this)) {
			return true;
		}
		else if (evt instanceof DbgConsoleOutputEvent) {
			pending.steal(evt);
		}
		return false;
	}

	@Override
	public DbgThread complete(DbgPendingCommand<?> pending) {
		StringBuilder builder = new StringBuilder();
		for (DbgConsoleOutputEvent out : pending.findAllOf(DbgConsoleOutputEvent.class)) {
			builder.append(out.getOutput());
		}
		parse(builder.toString());

		if (pID == null) {
			return null;
		}
		DbgProcessImpl proc = manager.getProcessComputeIfAbsent(pID, pid, true);
		DbgThreadImpl thread = manager.getThreadComputeIfAbsent(tID, proc, tid, true);
		try {
			DebugSystemObjects so = manager.getSystemObjects();
			proc.setOffset(so.getCurrentProcessDataOffset());
			thread.setOffset(so.getCurrentThreadDataOffset());
		} catch (Exception e) {
			Msg.error(this, e.getMessage());
		}
		return thread;
	}

	private void parse(String result) {
		String[] lines = result.split("\n");
		for (int i = 0; i < lines.length; i++) {
			String line = lines[i];
			if (line.contains("THREAD")) {
				String[] fields = line.trim().split("\\s+");
				if (fields.length > 3 && fields[2].equals("Cid")) {
					String[] split = fields[3].split("\\.");
					if (split.length == 2) {
						pid = Long.parseLong(split[0], 16);
						tid = Long.parseLong(split[1], 16);
						pID = new DebugProcessId(pid);
						tID = new DebugThreadId(tid);
					}
				}
				break;
			}
		}		
	}

	@Override
	public void invoke() {
		DebugControl control = manager.getControl();
		control.execute("!thread");
	}

}
