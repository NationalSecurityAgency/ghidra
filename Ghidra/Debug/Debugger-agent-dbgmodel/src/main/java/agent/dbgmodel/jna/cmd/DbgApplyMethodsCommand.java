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

import java.util.List;

import agent.dbgeng.manager.cmd.AbstractDbgCommand;
import agent.dbgeng.manager.cmd.DbgPendingCommand;
import agent.dbgeng.model.iface2.DbgModelTargetObject;
import agent.dbgmodel.dbgmodel.main.ModelObject;
import agent.dbgmodel.gadp.impl.WrappedDbgModel;
import agent.dbgmodel.manager.DbgManager2Impl;
import agent.dbgmodel.model.impl.DbgModel2TargetObjectImpl;
import agent.dbgmodel.model.impl.DelegateDbgModel2TargetObject;
import ghidra.dbg.target.TargetObject;

public class DbgApplyMethodsCommand extends AbstractDbgCommand<TargetObject> {

	private WrappedDbgModel access;
	private List<String> path;
	private DbgModel2TargetObjectImpl targetObject;
	private DbgModelTargetObject result;

	public DbgApplyMethodsCommand(DbgManager2Impl manager, List<String> path,
			DbgModel2TargetObjectImpl targetObject) {
		super(manager);
		this.access = manager.getAccess();
		this.path = path;
		this.targetObject = targetObject;
	}

	@Override
	public TargetObject complete(DbgPendingCommand<?> pending) {
		return result;
	}

	@Override
	public void invoke() {
		ModelObject obj = access.getMethod(path);
		obj.setSearchKey(path.get(path.size() - 1));
		result = DelegateDbgModel2TargetObject.makeProxy(targetObject.getModel(), targetObject,
			obj.getSearchKey(), obj);
	}
}
