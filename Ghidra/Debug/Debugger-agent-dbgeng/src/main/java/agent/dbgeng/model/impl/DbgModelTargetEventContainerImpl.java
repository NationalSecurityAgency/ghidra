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

import agent.dbgeng.manager.DbgEventFilter;
import agent.dbgeng.manager.cmd.DbgListEventFiltersCommand;
import agent.dbgeng.manager.impl.DbgManagerImpl;
import agent.dbgeng.model.iface2.*;
import ghidra.async.AsyncUtils;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.*;
import ghidra.util.datastruct.WeakValueHashMap;

@TargetObjectSchemaInfo(
	name = "EventContainer",
	elements = {
		@TargetElementType(type = DbgModelTargetEventImpl.class) },
	attributes = {
		@TargetAttributeType(type = Void.class) },
	canonicalContainer = true)
public class DbgModelTargetEventContainerImpl extends DbgModelTargetObjectImpl
		implements DbgModelTargetEventContainer {

	protected final DbgModelTargetDebugContainer debug;

	protected final Map<String, DbgModelTargetEventImpl> events =
		new WeakValueHashMap<>();

	public DbgModelTargetEventContainerImpl(DbgModelTargetDebugContainer debug) {
		super(debug.getModel(), debug, "Events", "EventContainer");
		this.debug = debug;
		requestElements(true);
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		DbgModelTargetProcess targetProcess = getParentProcess();
		if (!refresh || !targetProcess.getProcess().equals(getManager().getCurrentProcess())) {
			return AsyncUtils.NIL;
		}
		return listEventFilters().thenAccept(byName -> {
			List<TargetObject> eventObjs;
			synchronized (this) {
				eventObjs = byName.stream().map(this::getTargetEvent).collect(Collectors.toList());
			}
			setElements(eventObjs, Map.of(), "Refreshed");
		});
	}

	public synchronized DbgModelTargetEvent getTargetEvent(DbgEventFilter filter) {
		String id = filter.getName();
		DbgModelTargetEventImpl event = events.get(id);
		if (event != null && event.getFilter().getName().equals(id)) {
			return event;
		}
		event = new DbgModelTargetEventImpl(this, filter);
		events.put(filter.getName(), event);
		return event;
	}

	public CompletableFuture<List<DbgEventFilter>> listEventFilters() {
		DbgManagerImpl manager = getManager();
		return manager.execute(new DbgListEventFiltersCommand(manager));
	}
}
