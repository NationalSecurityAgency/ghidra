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

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import agent.dbgeng.jna.dbgeng.Kernel32Extra.PROCESSENTRY32W;
import agent.dbgeng.jna.dbgeng.ToolhelpUtil;
import agent.dbgeng.jna.dbgeng.ToolhelpUtil.Snapshot;
import agent.dbgeng.jna.dbgeng.ToolhelpUtil.SnapshotFlags;
import agent.dbgeng.manager.impl.DbgManagerImpl;
import ghidra.comm.util.BitmaskSet;

public class DbgListAvailableProcessesCommand
		extends AbstractDbgCommand<List<Pair<Integer, String>>> {

	private Snapshot snap;

	public DbgListAvailableProcessesCommand(DbgManagerImpl manager) {
		super(manager);
	}

	@Override
	public List<Pair<Integer, String>> complete(DbgPendingCommand<?> pending) {
		List<Pair<Integer, String>> result = new ArrayList<>();
		for (PROCESSENTRY32W proc : snap.getProcesses()) {
			int pid = proc.th32ProcessID.intValue();
			char[] name = proc.szExeFile;
			String exe = new String(name);
			result.add(new ImmutablePair<>(pid, exe));
		}
		return result;
	}

	@Override
	public void invoke() {
		snap = ToolhelpUtil
				.createSnapshot(BitmaskSet.of(SnapshotFlags.PROCESS, SnapshotFlags.THREAD), 0);
	}

}
