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

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import agent.dbgeng.dbgeng.DebugControl;
import agent.dbgeng.dbgeng.DebugThreadId;
import agent.dbgeng.dbgeng.DebugThreadRecord;
import agent.dbgeng.manager.DbgEvent;
import agent.dbgeng.manager.DbgThread;
import agent.dbgeng.manager.evt.AbstractDbgCompletedCommandEvent;
import agent.dbgeng.manager.evt.DbgConsoleOutputEvent;
import agent.dbgeng.manager.impl.DbgManagerImpl;
import agent.dbgeng.manager.impl.DbgProcessImpl;
import agent.dbgeng.manager.impl.DbgThreadImpl;
import ghidra.util.Msg;

public class DbgListOSThreadsCommand extends AbstractDbgCommand<Map<DebugThreadId, DbgThread>> {
	protected final DbgProcessImpl process;
	private List<DebugThreadId> updatedThreadIds = new ArrayList<>();;

	public DbgListOSThreadsCommand(DbgManagerImpl manager, DbgProcessImpl process) {
		super(manager);
		this.process = process;
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
	public Map<DebugThreadId, DbgThread> complete(DbgPendingCommand<?> pending) {
		StringBuilder builder = new StringBuilder();
		for (DbgConsoleOutputEvent out : pending.findAllOf(DbgConsoleOutputEvent.class)) {
			builder.append(out.getOutput());
		}
		parse(builder.toString());
		Msg.warn(this, "Completed OS thread list for pid="+Long.toHexString(process.getPid()));
		Map<DebugThreadId, DbgThread> threads = process.getKnownThreads();
		return threads;
	}

	private void parse(String result) {
		String[] lines = result.split("\n");
		Long offset = null;
		for (int i = 0; i < lines.length; i++) {
			String line = lines[i];
			if (line.contains("THREAD")) {
				String[] fields = line.trim().split("\\s+");
				if (fields.length > 4 && fields[0].equals("THREAD")) {
					BigInteger val = new BigInteger(fields[1], 16);
					offset = val.longValue();
					String[] split = fields[3].split("\\.");
					if (split.length == 2) {
						Long tid = Long.parseLong(split[1], 16);
						DbgThreadImpl mirror = manager.getThreadComputeIfAbsent(new DebugThreadRecord(tid), process, tid, false);
						if (offset != null) {
							mirror.setOffset(offset);
							updatedThreadIds.add(mirror.getId());
						}
					}
				}
			}		
		}		
	}

	@Override
	public void invoke() {
		Msg.warn(this, "Retrieving OS thread list for pid="+Long.toHexString(process.getPid()));
		DebugControl control = manager.getControl();
		control.execute("!process "+Long.toHexString(process.getOffset())+" 2");		
	}

}
