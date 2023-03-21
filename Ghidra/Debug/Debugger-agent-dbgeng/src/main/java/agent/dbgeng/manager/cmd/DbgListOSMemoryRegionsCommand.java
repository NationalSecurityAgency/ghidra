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

import java.util.*;
import java.util.Map.Entry;

import agent.dbgeng.dbgeng.DebugControl;
import agent.dbgeng.dbgeng.DebugDataSpaces.PageState;
import agent.dbgeng.manager.DbgEvent;
import agent.dbgeng.manager.DbgModuleMemory;
import agent.dbgeng.manager.evt.AbstractDbgCompletedCommandEvent;
import agent.dbgeng.manager.evt.DbgConsoleOutputEvent;
import agent.dbgeng.manager.impl.DbgManagerImpl;
import agent.dbgeng.manager.impl.DbgModuleMemoryImpl;
import ghidra.util.Msg;

public class DbgListOSMemoryRegionsCommand extends AbstractDbgCommand<List<DbgModuleMemory>> {

	private List<DbgModuleMemory> memoryRegions = new ArrayList<>();

	public DbgListOSMemoryRegionsCommand(DbgManagerImpl manager) {
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
	public List<DbgModuleMemory> complete(DbgPendingCommand<?> pending) {
		StringBuilder builder = new StringBuilder();
		for (DbgConsoleOutputEvent out : pending.findAllOf(DbgConsoleOutputEvent.class)) {
			builder.append(out.getOutput());
		}
		parse(builder.toString());

		Map<Long, DbgModuleMemory> memory = manager.getKnownMemoryRegions();
		for (DbgModuleMemory region : memoryRegions) {
			if (memory.containsValue(region)) {
				continue; // Do nothing, we're in sync
			}
			if (!memory.isEmpty()) {
				Msg.warn(this, "Resync: Was missing memory: " + Long.toHexString(region.getId()));
			}
			manager.addMemory(region);
		}
		List<Long> toRemove = new ArrayList<>();
		for (Entry<Long, DbgModuleMemory> entry : memory.entrySet()) {
			if (memoryRegions.contains(entry.getValue())) {
				continue; // Do nothing, we're in sync
			}
			toRemove.add(entry.getKey());
		}
		for (Long key : toRemove) {
			manager.removeMemory(key);
		}
		return memoryRegions;
	}

	private void parse(String result) {
		String[] lines = result.split("\n");
		for (String line : lines) {
			if (line.startsWith("Mapping")) {
				continue;
			}
			String[] fields = line.trim().split("\\s+");
			if (fields.length < 4) {
				continue;
			}
			String start = fields[0].replaceAll("`", "");
			String end = fields[1].replaceAll("`", "");
			long startVal, endVal;
			try {
				startVal = Long.parseUnsignedLong(start, 16);
				endVal = Long.parseUnsignedLong(end, 16);
			}
			catch (Exception e) {
				continue;
			}
			String name = fields[3];
			ArrayList<String> protect = new ArrayList<String>();
			DbgModuleMemoryImpl region = new DbgModuleMemoryImpl(start, startVal, endVal, startVal,
				protect, protect, PageState.COMMIT, name, true, true, true);
			memoryRegions.add(region);
		}
	}

	@Override
	public void invoke() {
		DebugControl control = manager.getControl();
		control.execute("!address");
	}

}
