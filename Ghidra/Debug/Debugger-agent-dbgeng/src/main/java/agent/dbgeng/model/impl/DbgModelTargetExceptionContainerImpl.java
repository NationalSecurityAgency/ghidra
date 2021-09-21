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
package agent.dbgeng.model.impl;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import agent.dbgeng.manager.DbgExceptionFilter;
import agent.dbgeng.manager.impl.DbgManagerImpl;
import agent.dbgeng.model.iface2.*;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.*;

@TargetObjectSchemaInfo(
	name = "ExceptionContainer",
	elements = { //
		@TargetElementType(type = DbgModelTargetEvent.class) //
	},
	attributes = { //
		@TargetAttributeType(type = Void.class) //
	},
	canonicalContainer = true)
public class DbgModelTargetExceptionContainerImpl extends DbgModelTargetObjectImpl
		implements DbgModelTargetEventContainer {

	public DbgModelTargetExceptionContainerImpl(DbgModelTargetDebugContainer debug) {
		super(debug.getModel(), debug, "Exceptions", "ExceptionContainer");
	}

	public DbgModelTargetException getTargetException(DbgExceptionFilter info) {
		DbgModelImpl impl = (DbgModelImpl) model;
		TargetObject modelObject = impl.getModelObject(info);
		if (modelObject != null) {
			return (DbgModelTargetException) modelObject;
		}
		return new DbgModelTargetExceptionImpl(this, info);
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		DbgManagerImpl manager = getManager();
		return manager.listExceptionFilters().thenAccept(byName -> {
			List<TargetObject> filters;
			synchronized (this) {
				filters = byName.values()
						.stream()
						.map(this::getTargetException)
						.collect(Collectors.toList());
			}
			setElements(filters, Map.of(), "Refreshed");
		});
	}
}
