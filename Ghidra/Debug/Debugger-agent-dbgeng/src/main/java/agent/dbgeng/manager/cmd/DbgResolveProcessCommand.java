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
import agent.dbgeng.manager.DbgEvent;
import agent.dbgeng.manager.DbgProcess;
import agent.dbgeng.manager.evt.AbstractDbgCompletedCommandEvent;
import agent.dbgeng.manager.evt.DbgConsoleOutputEvent;
import agent.dbgeng.manager.impl.DbgManagerImpl;
import agent.dbgeng.manager.impl.DbgProcessImpl;
import ghidra.util.Msg;

public class DbgResolveProcessCommand extends AbstractDbgCommand<DbgProcess> {

	private DbgProcessImpl process;
	private Long offset;

	/**
	 * Adjust the process contents to include both pid and offset  
	 * NB: should only be used in kernel-mode against the current process (i.e. id==offset)
	 * 
	 * @param manager the manager to execute the command
	 * @param process the desired process
	 */
	public DbgResolveProcessCommand(DbgManagerImpl manager, DbgProcess process) {
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
	public DbgProcess complete(DbgPendingCommand<?> pending) {
		StringBuilder builder = new StringBuilder();
		for (DbgConsoleOutputEvent out : pending.findAllOf(DbgConsoleOutputEvent.class)) {
			builder.append(out.getOutput());
		}
		parse(builder.toString());
		return process;
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
			}
			if (line.contains("Cid:")) {
				String[] fields = line.trim().split("\\s+");
				if (fields.length > 3 && fields[2].equals("Cid:")) {
					Long pid = Long.parseLong(fields[3], 16);
					process.setPid(pid);
				}
				break;
			}		
		}		
		if (offset == null) {
			Msg.error(this, result);
		}
	}

	@Override
	public void invoke() {
		if (process != null) {
			DebugControl control = manager.getControl();
			Long key = process.getOffset() != null ? process.getOffset() : process.getPid();
			control.execute("!process "+Long.toHexString(key)+" 0");		
		}
	}
}
