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
import agent.dbgeng.dbgeng.DebugThreadId;
import agent.dbgeng.manager.DbgEvent;
import agent.dbgeng.manager.DbgThread;
import agent.dbgeng.manager.evt.AbstractDbgCompletedCommandEvent;
import agent.dbgeng.manager.evt.DbgConsoleOutputEvent;
import agent.dbgeng.manager.impl.DbgManagerImpl;
import agent.dbgeng.manager.impl.DbgThreadImpl;
import ghidra.util.Msg;

public class DbgResolveThreadCommand extends AbstractDbgCommand<DbgThread> {

	private DbgThreadImpl thread;
	private Long offset;

	/**
	 * Adjust the thread contents to include both tid and offset  
	 * NB: should only be used in kernel-mode against the current thread (i.e. id==offset)
	 * 
	 * @param manager the manager to execute the command
	 * @param thread the desired thread
	 * @param frameId the desired frame level
	 */
	public DbgResolveThreadCommand(DbgManagerImpl manager, DbgThread thread) {
		super(manager);
		this.thread = (DbgThreadImpl) thread;
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
		return thread;
	}

	private void parse(String result) {
		String[] lines = result.split("\n");
		for (int i = 0; i < lines.length; i++) {
			String line = lines[i];
			if (line.contains("THREAD")) {
				String[] fields = line.trim().split("\\s+");
				if (fields.length > 4 && fields[0].equals("THREAD")) {
					BigInteger val = new BigInteger(fields[1], 16);
					offset = val.longValue();
					thread.setOffset(offset);
					String[] split = fields[3].split("\\.");
					if (split.length == 2) {
						//Long pid = Long.parseLong(split[0], 16);
						Long tid = Long.parseLong(split[1], 16);
						thread.setTid(tid);
					}
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
		DebugControl control = manager.getControl();
		Long key = thread.getOffset() != null ? thread.getOffset() : thread.getTid();
		control.execute("!thread "+Long.toHexString(key)+" 0");		
	}
}
