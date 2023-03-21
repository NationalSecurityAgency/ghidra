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
import agent.dbgeng.dbgeng.DebugProcessId;
import agent.dbgeng.dbgeng.DebugProcessRecord;
import agent.dbgeng.manager.DbgEvent;
import agent.dbgeng.manager.DbgManager;
import agent.dbgeng.manager.DbgProcess;
import agent.dbgeng.manager.evt.AbstractDbgCompletedCommandEvent;
import agent.dbgeng.manager.evt.DbgConsoleOutputEvent;
import agent.dbgeng.manager.impl.DbgManagerImpl;
import agent.dbgeng.manager.impl.DbgProcessImpl;
import ghidra.util.Msg;

/**
 * Implementation of {@link DbgManager#listProcesses()}
 */
public class DbgListOSProcessesCommand extends AbstractDbgCommand<Map<DebugProcessId, DbgProcess>> {
	private List<DebugProcessId> updatedProcessIds = new ArrayList<>();

	public DbgListOSProcessesCommand(DbgManagerImpl manager) {
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
	public Map<DebugProcessId, DbgProcess> complete(DbgPendingCommand<?> pending) {
		StringBuilder builder = new StringBuilder();
		for (DbgConsoleOutputEvent out : pending.findAllOf(DbgConsoleOutputEvent.class)) {
			builder.append(out.getOutput());
		}
		parse(builder.toString());
		Msg.warn(this, "Completed OS process list");
		return manager.getKnownProcesses();
	}

	private void parse(String result) {
		String[] lines = result.split("\n");
		Long offset = null;
		for (int i = 0; i < lines.length; i++) {
			String line = lines[i];
			if (line.contains("PROCESS")) {
				offset = null;			
				String[] fields = line.trim().split("\\s+");
				if (fields.length > 1 && fields[0].equals("PROCESS")) {
					BigInteger val = new BigInteger(fields[1], 16);
					offset = val.longValue();
				}
			}
			if (line.contains("Cid:")) {
				String[] fields = line.trim().split("\\s+");
				if (fields.length > 3 && fields[2].equals("Cid:")) {
					Long pid = Long.parseLong(fields[3], 16);
					DbgProcessImpl mirror = manager.getProcessComputeIfAbsent(new DebugProcessRecord(pid), pid, false);
					if (offset != null) {
						mirror.setOffset(offset);
						updatedProcessIds.add(mirror.getId());
					}
				}
			}		
		}		
	}

	@Override
	public void invoke() {
		Msg.warn(this, "Retrieving OS process list");
		DebugControl control = manager.getControl();
		control.execute("!process 0 0");		
	}
}
