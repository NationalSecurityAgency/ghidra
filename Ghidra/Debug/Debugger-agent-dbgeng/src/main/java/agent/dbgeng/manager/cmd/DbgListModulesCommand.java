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

import agent.dbgeng.dbgeng.*;
import agent.dbgeng.dbgeng.DebugModule.DebugModuleName;
import agent.dbgeng.manager.DbgModule;
import agent.dbgeng.manager.impl.*;
import ghidra.util.Msg;

public class DbgListModulesCommand extends AbstractDbgCommand<Map<String, DbgModule>> {
	protected final DbgProcessImpl process;
	private Map<String, DebugModule> updatedModules = new HashMap<>();
	private Map<DebugModule, DebugModuleInfo> moduleInfo = new HashMap<>();

	public DbgListModulesCommand(DbgManagerImpl manager, DbgProcessImpl process) {
		super(manager);
		this.process = process;
	}

	@Override
	public Map<String, DbgModule> complete(DbgPendingCommand<?> pending) {
		Map<String, DbgModule> modules = process.getKnownModules();
		Set<String> cur = modules.keySet();
		for (String id : updatedModules.keySet()) {
			if (cur.contains(id)) {
				continue; // Do nothing, we're in sync
			}
			// Need to create the thread as if we receive =thread-created
			Msg.warn(this, "Resync: Was missing module: " + id);
			DebugModuleInfo info = moduleInfo.get(updatedModules.get(id));
			DbgModuleImpl module = new DbgModuleImpl(manager, process, info);
			module.add();
		}
		for (String id : new ArrayList<>(cur)) {
			if (updatedModules.containsKey(id)) {
				continue; // Do nothing, we're in sync
			}
			process.removeModule(id);
		}
		return process.getKnownModules();
	}

	@Override
	public void invoke() {
		DebugSystemObjects so = manager.getSystemObjects();
		so.setCurrentProcessId(process.getId());
		DebugSymbols symbols = manager.getSymbols();
		for (DebugModule module : symbols.iterateModules(0)) {
			DebugModuleInfo info = symbols.getModuleParameters(1, module.getIndex());
			String imageName = module.getName(DebugModuleName.IMAGE);
			String moduleName = module.getName(DebugModuleName.MODULE);
			info.setImageName(imageName);
			info.setModuleName(moduleName);
			updatedModules.put(info.toString(), module);
			moduleInfo.put(module, info);
		}
	}

}
