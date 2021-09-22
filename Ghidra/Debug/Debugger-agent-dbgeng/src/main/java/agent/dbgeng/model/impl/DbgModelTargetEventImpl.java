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

import agent.dbgeng.dbgeng.DebugControl.*;
import agent.dbgeng.manager.DbgCause;
import agent.dbgeng.manager.DbgEventFilter;
import agent.dbgeng.manager.evt.*;
import agent.dbgeng.model.iface2.*;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.PathUtils;

@TargetObjectSchemaInfo(
	name = "Event",
	elements = {
		@TargetElementType(type = Void.class) },
	attributes = {
		@TargetAttributeType(type = Object.class) })
public class DbgModelTargetEventImpl extends DbgModelTargetObjectImpl
		implements DbgModelTargetEvent {
	protected static String indexFilter(DbgEventFilter filter) {
		return filter.getName();
	}

	protected static String keyFilter(DbgEventFilter filter) {
		return PathUtils.makeKey(indexFilter(filter));
	}

	protected DbgModelTargetEventOption execOption;
	protected DbgModelTargetEventOption contOption;

	private DbgEventFilter filter;

	public DbgModelTargetEventImpl(DbgModelTargetEventContainer events, DbgEventFilter filter) {
		super(events.getModel(), events, keyFilter(filter), "EventFilter");
		this.getModel().addModelObject(filter, this);
		this.filter = filter;

		DebugFilterExecutionOption exec =
			DebugFilterExecutionOption.getByNumber(filter.getExecutionOption());
		DebugFilterContinuationOption cont =
			DebugFilterContinuationOption.getByNumber(filter.getContinueOption());
		execOption = new DbgModelTargetExecutionOptionImpl(this, exec);
		contOption = new DbgModelTargetContinuationOptionImpl(this, cont);

		changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, getIndex(), //
			"Command", filter.getCmd(), //
			"Execute", execOption, //
			"Continue", contOption //
		), "Initialized");

		getManager().addEventsListener(this);
	}

	@Override
	public DbgEventFilter getFilter() {
		return filter;
	}

	@Override
	public int getEventIndex() {
		return filter.getIndex();
	}

	@Override
	public void eventSelected(AbstractDbgEvent<?> event, DbgCause cause) {
		changeAttributes(List.of(), List.of(), Map.of( //
			MODIFIED_ATTRIBUTE_NAME, false), "Refreshed");
		if (event instanceof DbgThreadCreatedEvent &&
			getEventIndex() == DebugFilterOrdinals.DEBUG_FILTER_CREATE_THREAD.ordinal()) {
			changeAttributes(List.of(), List.of(), Map.of( //
				MODIFIED_ATTRIBUTE_NAME, true), "Refreshed");
		}
		if (event instanceof DbgThreadExitedEvent &&
			getEventIndex() == DebugFilterOrdinals.DEBUG_FILTER_EXIT_THREAD.ordinal()) {
			changeAttributes(List.of(), List.of(), Map.of( //
				MODIFIED_ATTRIBUTE_NAME, true), "Refreshed");
		}
		if (event instanceof DbgProcessCreatedEvent &&
			getEventIndex() == DebugFilterOrdinals.DEBUG_FILTER_CREATE_PROCESS.ordinal()) {
			changeAttributes(List.of(), List.of(), Map.of( //
				MODIFIED_ATTRIBUTE_NAME, true), "Refreshed");
		}
		if (event instanceof DbgProcessExitedEvent &&
			getEventIndex() == DebugFilterOrdinals.DEBUG_FILTER_EXIT_PROCESS.ordinal()) {
			changeAttributes(List.of(), List.of(), Map.of( //
				MODIFIED_ATTRIBUTE_NAME, true), "Refreshed");
		}
		if (event instanceof DbgModuleLoadedEvent &&
			getEventIndex() == DebugFilterOrdinals.DEBUG_FILTER_LOAD_MODULE.ordinal()) {
			changeAttributes(List.of(), List.of(), Map.of( //
				MODIFIED_ATTRIBUTE_NAME, true), "Refreshed");
		}
		if (event instanceof DbgModuleUnloadedEvent &&
			getEventIndex() == DebugFilterOrdinals.DEBUG_FILTER_UNLOAD_MODULE.ordinal()) {
			changeAttributes(List.of(), List.of(), Map.of( //
				MODIFIED_ATTRIBUTE_NAME, true), "Refreshed");
		}
	}
}
