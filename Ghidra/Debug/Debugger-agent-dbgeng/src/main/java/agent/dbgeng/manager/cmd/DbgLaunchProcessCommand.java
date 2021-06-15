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

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;

import agent.dbgeng.dbgeng.*;
import agent.dbgeng.dbgeng.DebugClient.DebugCreateFlags;
import agent.dbgeng.manager.*;
import agent.dbgeng.manager.evt.AbstractDbgCompletedCommandEvent;
import agent.dbgeng.manager.evt.DbgProcessCreatedEvent;
import agent.dbgeng.manager.impl.DbgManagerImpl;
import ghidra.comm.util.BitmaskSet;

/**
 * Implementation of {@link DbgProcess#fileExecAndSymbols(String)}
 */
public class DbgLaunchProcessCommand extends AbstractDbgCommand<DbgThread> {

	private DbgProcessCreatedEvent created = null;
	private boolean completed = false;
	private List<String> args;

	public DbgLaunchProcessCommand(DbgManagerImpl manager, List<String> args) {
		super(manager);
		this.args = args;
	}

	@Override
	public boolean handle(DbgEvent<?> evt, DbgPendingCommand<?> pending) {
		if (evt instanceof AbstractDbgCompletedCommandEvent && pending.getCommand().equals(this)) {
			completed = true;
		}
		else if (evt instanceof DbgProcessCreatedEvent) {
			created = (DbgProcessCreatedEvent) evt;
		}
		return completed && (created != null);
	}

	@Override
	public DbgThread complete(DbgPendingCommand<?> pending) {
		DebugProcessInfo info = created.getInfo();
		DebugThreadInfo tinfo = info.initialThreadInfo;
		DebugSystemObjects so = manager.getSystemObjects();
		DebugThreadId tid = so.getThreadIdByHandle(tinfo.handle);
		return manager.getThread(tid);
	}

	@Override
	public void invoke() {
		DebugClient dbgeng = manager.getClient();
		//DebugControl control = dbgeng.getControl();

		List<String> newArgs = new ArrayList<>();
		for (String arg : args) {
			String na = arg;
			if (arg.startsWith("/")) {
				na = na.substring(1);
			}
			na = na.replace("/", "\\");
			newArgs.add(na);
		}
		dbgeng.createProcess(dbgeng.getLocalServer(), StringUtils.join(newArgs, " "),
			BitmaskSet.of(DebugCreateFlags.DEBUG_PROCESS));
		manager.waitForEventEx();
	}
}
