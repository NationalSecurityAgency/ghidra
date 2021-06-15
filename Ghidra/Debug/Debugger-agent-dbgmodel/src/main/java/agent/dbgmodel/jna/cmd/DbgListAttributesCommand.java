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
import agent.dbgeng.model.iface2.DbgModelTargetObject;
import agent.dbgmodel.dbgmodel.main.ModelObject;
import agent.dbgmodel.gadp.impl.WrappedDbgModel;
import agent.dbgmodel.manager.DbgManager2Impl;
import agent.dbgmodel.model.impl.*;
import ghidra.dbg.util.PathUtils.TargetObjectKeyComparator;

public class DbgListAttributesCommand extends AbstractDbgCommand<Map<String, ?>> {

	private Map<String, Object> updatedAttributes;

	private WrappedDbgModel access;
	private List<String> path;
	private DbgModel2TargetObjectImpl targetObject;

	public DbgListAttributesCommand(DbgManager2Impl manager, List<String> path,
			DbgModel2TargetObjectImpl targetObject) {
		super(manager);
		this.access = manager.getAccess();
		this.path = path;
		this.targetObject = targetObject;
	}

	@Override
	public Map<String, ?> complete(DbgPendingCommand<?> pending) {
		return updatedAttributes;
	}

	@Override
	public void invoke() {
		try {
			updatedAttributes = new TreeMap<>(TargetObjectKeyComparator.ATTRIBUTE);
			Map<String, ModelObject> map = access.getAttributes(path);
			Map<String, ?> existingAttributes = targetObject.getCachedAttributes();
			for (String key : map.keySet()) {
				DbgModel2TargetProxy proxyAttribute;
				ModelObject obj = map.get(key);
				String atKey = obj.getSearchKey();
				Object object = existingAttributes.get(atKey);
				if (object != null && (object instanceof DbgModelTargetObject)) {
					proxyAttribute = (DbgModel2TargetProxy) object;
					DelegateDbgModel2TargetObject delegate = proxyAttribute.getDelegate();
					delegate.setModelObject(obj);
					updatedAttributes.put(key, proxyAttribute);
				}
				else {
					proxyAttribute = (DbgModel2TargetProxy) DelegateDbgModel2TargetObject
							.makeProxy(targetObject.getModel(), targetObject, atKey, obj);
					updatedAttributes.put(key, proxyAttribute);
				}
			}
			updatedAttributes.putAll(targetObject.getIntrinsics());
		}
		catch (Exception e) {
			System.err.println("Failure in ListAttributes " + targetObject);
			e.printStackTrace();
		}
	}
}
