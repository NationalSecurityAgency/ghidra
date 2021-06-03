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

import agent.dbgeng.manager.cmd.AbstractDbgCommand;
import agent.dbgeng.manager.cmd.DbgPendingCommand;
import agent.dbgmodel.dbgmodel.main.ModelObject;
import agent.dbgmodel.gadp.impl.WrappedDbgModel;
import agent.dbgmodel.manager.DbgManager2Impl;
import agent.dbgmodel.model.impl.*;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.util.PathUtils;

public class DbgListElementsCommand extends AbstractDbgCommand<List<TargetObject>> {

	private List<TargetObject> updatedElements;

	private WrappedDbgModel access;
	private List<String> path;
	private DbgModel2TargetObjectImpl targetObject;

	public DbgListElementsCommand(DbgManager2Impl manager, List<String> path,
			DbgModel2TargetObjectImpl targetObject) {
		super(manager);
		this.access = manager.getAccess();
		this.path = path;
		this.targetObject = targetObject;
	}

	@Override
	public List<TargetObject> complete(DbgPendingCommand<?> pending) {
		return updatedElements;
	}

	@Override
	public void invoke() {
		synchronized (access) {
			updatedElements = new ArrayList<>();
			List<ModelObject> list = access.getElements(path);
			Map<String, ? extends TargetObject> existingElements =
				targetObject.getCachedElements();

			for (ModelObject obj : list) {
				DbgModel2TargetProxy proxyElement;
				String searchKey = obj.getSearchKey();
				String elKey = PathUtils.makeKey(searchKey);
				if (existingElements.containsKey(searchKey)) {
					proxyElement = (DbgModel2TargetProxy) existingElements.get(searchKey);
					DelegateDbgModel2TargetObject delegate = proxyElement.getDelegate();
					delegate.setModelObject(obj);
				}
				else {
					proxyElement = (DbgModel2TargetProxy) DelegateDbgModel2TargetObject
							.makeProxy(targetObject.getModel(), targetObject, elKey, obj);
				}
				updatedElements.add(proxyElement);
			}
		}
	}
}
