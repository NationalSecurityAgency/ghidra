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
package agent.dbgmodel.jna.cmd;

import java.util.*;

import agent.dbgeng.dbgeng.DebugValue;
import agent.dbgeng.manager.cmd.AbstractDbgCommand;
import agent.dbgeng.manager.cmd.DbgPendingCommand;
import agent.dbgeng.manager.impl.DbgRegister;
import agent.dbgmodel.dbgmodel.main.ModelObject;
import agent.dbgmodel.gadp.impl.WrappedDbgModel;
import agent.dbgmodel.manager.DbgManager2Impl;

public class DbgGetRegisterMapCommand extends AbstractDbgCommand<Map<String, ?>> {

	private Map<String, DbgRegister> map = new HashMap<>();

	private WrappedDbgModel access;
	private List<String> path;

	public DbgGetRegisterMapCommand(DbgManager2Impl manager, List<String> path) {
		super(manager);
		this.access = manager.getAccess();
		this.path = path;
	}

	@Override
	public Map<String, ?> complete(DbgPendingCommand<?> pending) {
		return map;
	}

	@Override
	public void invoke() {
		List<String> npath = new ArrayList<String>();
		npath.add("Debugger");
		npath.addAll(path);
		Map<String, ModelObject> attributes = access.getAttributes(npath);
		int i = 0;
		for (String key : attributes.keySet()) {
			ModelObject modelObject = attributes.get(key);
			DebugValue debugValue = access.getDebugValue(modelObject);
			if (debugValue != null) {
				DbgRegister register =
					new DbgRegister(key, i++, debugValue.getValueType().byteLength);
				map.put(key, register);
			}
		}
	}
}
