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

import agent.dbgeng.dbgeng.DebugControl;
import agent.dbgeng.dbgeng.DebugProcessId;
import agent.dbgeng.dbgeng.DebugSystemObjects;
import agent.dbgeng.manager.DbgEvent;
import agent.dbgeng.manager.DbgProcess;
import agent.dbgeng.manager.evt.AbstractDbgCompletedCommandEvent;
import agent.dbgeng.manager.evt.DbgConsoleOutputEvent;
import agent.dbgeng.manager.impl.DbgManagerImpl;
import agent.dbgeng.manager.impl.DbgProcessImpl;

public class DbgSetActiveProcessCommand extends AbstractDbgCommand<Void> {

	private DbgProcessImpl process;
	private Long offset;

	/**
	 * Set the active process
	 * 
	 * @param manager the manager to execute the command
	 * @param process the desired process
	 */
	public DbgSetActiveProcessCommand(DbgManagerImpl manager, DbgProcess process) {
		super(manager);
		this.process = (DbgProcessImpl) process;
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
	public Void complete(DbgPendingCommand<?> pending) {
		StringBuilder builder = new StringBuilder();
		for (DbgConsoleOutputEvent out : pending.findAllOf(DbgConsoleOutputEvent.class)) {
			builder.append(out.getOutput());
		}
		parse(builder.toString());
		if (offset != null) {
			manager.getSystemObjects().setImplicitThreadDataOffset(offset);
		}
		return null;
	}

	private void parse(String result) {
		String[] lines = result.split("\n");
		for (int i = 0; i < lines.length; i++) {
			String line = lines[i];
			if (line.contains("PROCESS")) {
				String[] fields = line.trim().split("\\s+");
				if (fields.length > 1 && fields[0].equals("PROCESS")) {
					BigInteger val = new BigInteger(fields[1], 16);
					offset = val.longValue();
					process.setOffset(offset);
				}
				break;
			}
		}		
	}

	@Override
	public void invoke() {
		if (process != null) {
			DebugProcessId id = process.getId();
			if (id != null) {
				DebugSystemObjects so = manager.getSystemObjects();
				if (manager.isKernelMode()) {
					offset = process.getOffset();
					if (offset == null || offset == 0L) {
						DebugControl control = manager.getControl();
						control.execute("!process "+Long.toHexString(process.getPid())+" 0");		
					}
				} else {
					so.setCurrentProcessId(id);
					DebugProcessId currentProcessId = so.getCurrentProcessId();
					if (!id.id().equals(currentProcessId.id())) {
						so.setCurrentProcessId(id);
					}
				}
			}
		}
	}
}
