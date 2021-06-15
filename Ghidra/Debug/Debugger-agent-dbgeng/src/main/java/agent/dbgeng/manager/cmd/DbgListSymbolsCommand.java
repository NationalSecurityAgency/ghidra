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

import agent.dbgeng.dbgeng.*;
import agent.dbgeng.manager.impl.*;

public class DbgListSymbolsCommand extends AbstractDbgCommand<Map<String, DbgMinimalSymbol>> {
	protected final DbgProcessImpl process;
	protected final DbgModuleImpl module;

	private Map<DebugSymbolId, DebugSymbolEntry> symbolEntries = new HashMap<>();

	public DbgListSymbolsCommand(DbgManagerImpl manager, DbgProcessImpl process,
			DbgModuleImpl module) {
		super(manager);
		this.process = process;
		this.module = module;
	}

	@Override
	public Map<String, DbgMinimalSymbol> complete(DbgPendingCommand<?> pending) {
		Map<String, DbgMinimalSymbol> symbolMap = new HashMap<>();
		for (Entry<DebugSymbolId, DebugSymbolEntry> entry : symbolEntries.entrySet()) {
			DebugSymbolEntry value = entry.getValue();
			DbgMinimalSymbol minSymbol = new DbgMinimalSymbol(entry.getKey().symbolIndex,
				value.typeId, value.name, value.offset, value.size, value.tag, value.moduleBase);
			symbolMap.put(entry.getKey().toString(), minSymbol);
		}
		return symbolMap;
	}

	@Override
	public void invoke() {
		DebugSystemObjects so = manager.getSystemObjects();
		so.setCurrentProcessId(process.getId());
		DebugSymbols symbols = manager.getSymbols();

		for (DebugSymbolName symbol : symbols.iterateSymbolMatches(module.getName() + "!*")) {
			List<DebugSymbolId> symbolIdsByName = symbols.getSymbolIdsByName(symbol.name);
			for (DebugSymbolId symbolId : symbolIdsByName) {
				DebugSymbolEntry symbolEntry = symbols.getSymbolEntry(symbolId);
				symbolEntries.put(symbolId, symbolEntry);
			}
		}
	}
}
