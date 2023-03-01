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

public class DbgSetActiveThreadCommand extends AbstractDbgCommand<Void> {

	private DbgThreadImpl thread;
	private Integer frameId;
	private Long offset;

	/**
	 * Set the active thread
	 * 
	 * @param manager the manager to execute the command
	 * @param thread the desired thread
	 * @param frameId the desired frame level
	 */
	public DbgSetActiveThreadCommand(DbgManagerImpl manager, DbgThread thread, Integer frameId) {
		super(manager);
		this.thread = (DbgThreadImpl) thread;
		this.frameId = frameId;
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
			if (line.contains("THREAD")) {
				String[] fields = line.trim().split("\\s+");
				if (fields.length > 1 && fields[0].equals("THREAD")) {
					BigInteger val = new BigInteger(fields[1], 16);
					offset = val.longValue();
					thread.setOffset(offset);
				}
				break;
			}
		}		
	}

	@Override
	public void invoke() {
		DebugThreadId id = thread.getId();
		if (id != null) {
			if (!manager.isKernelMode()) {
				manager.getSystemObjects().setCurrentThreadId(id);
			} else {
				offset = thread.getOffset();
				if (offset == null || offset == 0L) {
					DebugControl control = manager.getControl();
					control.execute("!thread -t "+Long.toHexString(thread.getTid())+" 0");		
				}
			}
			if (frameId != null) {
				manager.getSymbols().setCurrentScopeFrameIndex(frameId);
			}
		}
	}
}
