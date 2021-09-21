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
import agent.dbgeng.manager.cmd.DbgListExceptionFiltersCommand;
import agent.dbgeng.manager.impl.DbgManagerImpl;
import agent.dbgeng.model.iface2.*;
import ghidra.async.AsyncUtils;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.*;
import ghidra.util.datastruct.WeakValueHashMap;

@TargetObjectSchemaInfo(
	name = "ExceptionContainer",
	elements = {
		@TargetElementType(type = DbgModelTargetExceptionImpl.class) },
	attributes = {
		@TargetAttributeType(type = Void.class) },
	canonicalContainer = true)
public class DbgModelTargetExceptionContainerImpl extends DbgModelTargetObjectImpl
		implements DbgModelTargetExceptionContainer {

	protected final DbgModelTargetDebugContainer debug;

	protected final Map<String, DbgModelTargetExceptionImpl> exceptions =
		new WeakValueHashMap<>();

	public DbgModelTargetExceptionContainerImpl(DbgModelTargetDebugContainer debug) {
		super(debug.getModel(), debug, "Exceptions", "ExceptionContainer");
		this.debug = debug;
		requestElements(true);
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		DbgModelTargetProcess targetProcess = getParentProcess();
		if (!refresh || !targetProcess.getProcess().equals(getManager().getCurrentProcess())) {
			return AsyncUtils.NIL;
		}
		return listExceptionFilters().thenAccept(byName -> {
			List<TargetObject> excObjs;
			synchronized (this) {
				excObjs =
					byName.stream().map(this::getTargetException).collect(Collectors.toList());
			}
			setElements(excObjs, Map.of(), "Refreshed");
		});
	}

	public synchronized DbgModelTargetException getTargetException(DbgExceptionFilter filter) {
		String id = filter.getName();
		DbgModelTargetExceptionImpl exc = exceptions.get(id);
		if (exc != null && exc.getFilter().getName().equals(id)) {
			return exc;
		}
		exc = new DbgModelTargetExceptionImpl(this, filter);
		exceptions.put(filter.getName(), exc);
		return exc;
	}

	public CompletableFuture<List<DbgExceptionFilter>> listExceptionFilters() {
		DbgManagerImpl manager = getManager();
		return manager.execute(new DbgListExceptionFiltersCommand(manager));
	}
}
