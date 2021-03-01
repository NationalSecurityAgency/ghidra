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

import agent.dbgeng.manager.impl.DbgManagerImpl;
import agent.dbgeng.model.iface1.DbgModelTargetFocusScope;
import ghidra.dbg.target.TargetObject;

public class DbgRequestFocusCommand extends AbstractDbgCommand<Void> {

	private DbgModelTargetFocusScope scope;
	private TargetObject obj;

	/**
	 * Set focus for the current ref
	 * 
	 * @param manager the manager to execute the command
	 * @param scope in most cases the root object (must be an ancestor for the ref)
	 * @param obj the desired focus
	 */
	public DbgRequestFocusCommand(DbgManagerImpl manager, DbgModelTargetFocusScope scope,
			TargetObject obj) {
		super(manager);
		this.scope = scope;
		this.obj = obj;
	}

	@Override
	public void invoke() {
		scope.doRequestFocus(obj);
	}
}
