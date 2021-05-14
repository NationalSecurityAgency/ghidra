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

import com.sun.jna.platform.win32.COM.COMException;

import agent.dbgeng.dbgeng.DebugDataSpaces;
import agent.dbgeng.dbgeng.DebugDataSpaces.*;
import agent.dbgeng.dbgeng.DebugModule;
import agent.dbgeng.dbgeng.DebugModule.DebugModuleName;
import agent.dbgeng.manager.DbgModuleMemory;
import agent.dbgeng.manager.impl.DbgManagerImpl;
import agent.dbgeng.manager.impl.DbgModuleMemoryImpl;
import ghidra.util.Msg;

public class DbgListMemoryRegionsCommand extends AbstractDbgCommand<List<DbgModuleMemory>> {

	private List<DbgModuleMemory> memoryRegions = new ArrayList<>();

	public DbgListMemoryRegionsCommand(DbgManagerImpl manager) {
		super(manager);
	}

	@Override
	public List<DbgModuleMemory> complete(DbgPendingCommand<?> pending) {
		Map<Long, DbgModuleMemory> memory = manager.getKnownMemoryRegions();
		for (DbgModuleMemory region : memoryRegions) {
			if (memory.containsValue(region)) {
				continue; // Do nothing, we're in sync
			}
			// Need to create the thread as if we receive =thread-created
			if (!memory.isEmpty()) {
				Msg.warn(this, "Resync: Was missing memory: " + region.getId());
			}
			manager.addMemory(region);
		}
		for (Entry<Long, DbgModuleMemory> entry : memory.entrySet()) {
			if (memoryRegions.contains(entry.getValue())) {
				continue; // Do nothing, we're in sync
			}
			manager.removeMemory(entry.getKey());
		}
		return memoryRegions;
	}

	@Override
	public void invoke() {
		DebugDataSpaces dataSpaces = manager.getDataSpaces();
		for (DebugMemoryBasicInformation info : dataSpaces.iterateVirtual(0)) {
			if (info.state == PageState.FREE) {
				continue;
			}
			String type = "[" + info.type + "]";
			if (info.type == PageType.IMAGE) {
				try {
					DebugModule mod = manager.getSymbols().getModuleByOffset(info.baseAddress, 0);
					if (mod != null) {
						type = mod.getName(DebugModuleName.IMAGE);
					}
				}
				catch (COMException e) {
					type = "[IMAGE UNKNOWN]";
				}
			}
			else if (info.type == PageType.MAPPED) {
				// TODO: Figure out the file name
			}
			long vmaStart = info.baseAddress;
			long vmaEnd = info.baseAddress + info.regionSize;

			boolean isRead = false;
			boolean isWrite = false;
			boolean isExec = false;
			List<String> ap = new ArrayList<>();
			for (PageProtection protect : info.allocationProtect) {
				ap.add(protect.toString());
				isRead |= protect.isRead();
				isWrite |= protect.isWrite();
				isExec |= protect.isExecute();
			}
			List<String> ip = new ArrayList<>();
			for (PageProtection protect : info.protect) {
				ip.add(protect.toString());
				isRead |= protect.isRead();
				isWrite |= protect.isWrite();
				isExec |= protect.isExecute();
			}
			DbgModuleMemoryImpl region =
				new DbgModuleMemoryImpl(Long.toHexString(vmaStart), vmaStart, vmaEnd,
					info.allocationBase, ap, ip, info.state, type, isRead, isWrite, isExec);
			memoryRegions.add(region);
		}
	}

}
