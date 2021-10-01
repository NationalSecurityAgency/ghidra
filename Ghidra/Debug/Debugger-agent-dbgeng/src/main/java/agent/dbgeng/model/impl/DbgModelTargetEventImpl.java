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

import java.util.*;
import java.util.concurrent.CompletableFuture;

import agent.dbgeng.dbgeng.DebugControl.*;
import agent.dbgeng.manager.DbgCause;
import agent.dbgeng.manager.DbgEventFilter;
import agent.dbgeng.manager.cmd.DbgSetFilterArgumentCommand;
import agent.dbgeng.manager.cmd.DbgSetFilterCommandCommand;
import agent.dbgeng.manager.evt.*;
import agent.dbgeng.manager.impl.DbgManagerImpl;
import agent.dbgeng.model.iface2.*;
import ghidra.async.AsyncUtils;
import ghidra.dbg.error.DebuggerIllegalArgumentException;
import ghidra.dbg.target.TargetMethod.ParameterDescription;
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

	final String COMMAND_ATTRIBUTE_NAME = "Command";
	final String ARGUMENT_ATTRIBUTE_NAME = "Argument";
	final String CONTINUE_OPTION_ATTRIBUTE_NAME = "Continue";
	final String EXECUTE_OPTION_ATTRIBUTE_NAME = "Execute";

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
			COMMAND_ATTRIBUTE_NAME, filter.getCmd(), //
			ARGUMENT_ATTRIBUTE_NAME, filter.getArg(), //
			EXECUTE_OPTION_ATTRIBUTE_NAME, execOption, //
			CONTINUE_OPTION_ATTRIBUTE_NAME, contOption //
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
		if (event instanceof DbgInitialBreakpointEvent &&
			getEventIndex() == DebugFilterOrdinals.DEBUG_FILTER_INITIAL_BREAKPOINT.ordinal()) {
			changeAttributes(List.of(), List.of(), Map.of( //
				MODIFIED_ATTRIBUTE_NAME, true), "Refreshed");
		}
		if (event instanceof DbgInitialModuleLoadEvent &&
			getEventIndex() == DebugFilterOrdinals.DEBUG_FILTER_INITIAL_MODULE_LOAD.ordinal()) {
			changeAttributes(List.of(), List.of(), Map.of( //
				MODIFIED_ATTRIBUTE_NAME, true), "Refreshed");
		}
		if (event instanceof DbgSystemErrorEvent &&
			getEventIndex() == DebugFilterOrdinals.DEBUG_FILTER_SYSTEM_ERROR.ordinal()) {
			changeAttributes(List.of(), List.of(), Map.of( //
				MODIFIED_ATTRIBUTE_NAME, true), "Refreshed");
		}
		if (event instanceof DbgConsoleOutputEvent &&
			getEventIndex() == DebugFilterOrdinals.DEBUG_FILTER_DEBUGGEE_OUTPUT.ordinal()) {
			changeAttributes(List.of(), List.of(), Map.of( //
				MODIFIED_ATTRIBUTE_NAME, true), "Refreshed");
		}
	}

	@Override
	public Map<String, ParameterDescription<?>> getConfigurableOptions() {
		Map<String, ParameterDescription<?>> map = new HashMap<>();
		ParameterDescription<String> cmdDesc = ParameterDescription.create(String.class,
			COMMAND_ATTRIBUTE_NAME, false, "", COMMAND_ATTRIBUTE_NAME, "filter command");
		map.put(COMMAND_ATTRIBUTE_NAME, cmdDesc);
		ParameterDescription<String> argDesc =
			ParameterDescription.create(String.class, ARGUMENT_ATTRIBUTE_NAME, false, "",
				ARGUMENT_ATTRIBUTE_NAME, "filter argument");
		map.put(ARGUMENT_ATTRIBUTE_NAME, argDesc);
		ParameterDescription<Integer> execDesc =
			ParameterDescription.create(Integer.class, EXECUTE_OPTION_ATTRIBUTE_NAME, false,
				execOption.getOption(), EXECUTE_OPTION_ATTRIBUTE_NAME, "filter execution option");
		map.put(EXECUTE_OPTION_ATTRIBUTE_NAME, execDesc);
		ParameterDescription<Integer> contDesc =
			ParameterDescription.create(Integer.class, CONTINUE_OPTION_ATTRIBUTE_NAME, false,
				contOption.getOption(), CONTINUE_OPTION_ATTRIBUTE_NAME,
				"filter continuation option");
		map.put(CONTINUE_OPTION_ATTRIBUTE_NAME, contDesc);
		return map;
	}

	@Override
	public CompletableFuture<Void> writeConfigurationOption(String key, Object value) {
		DbgManagerImpl manager = getManager();
		switch (key) {
			case COMMAND_ATTRIBUTE_NAME:
				if (value instanceof String) {
					this.changeAttributes(List.of(), Map.of(COMMAND_ATTRIBUTE_NAME, value),
						"Modified");
					String cmd = (String) getCachedAttribute(COMMAND_ATTRIBUTE_NAME);
					return manager.execute(
						new DbgSetFilterCommandCommand(manager, getEventIndex(), cmd));
				}
				throw new DebuggerIllegalArgumentException("Command should be a string");
			case ARGUMENT_ATTRIBUTE_NAME:
				if (value instanceof String) {
					this.changeAttributes(List.of(), Map.of(ARGUMENT_ATTRIBUTE_NAME, value),
						"Modified");
					String cmd = (String) getCachedAttribute(ARGUMENT_ATTRIBUTE_NAME);
					return manager.execute(
						new DbgSetFilterArgumentCommand(manager, getEventIndex(), cmd));
				}
				throw new DebuggerIllegalArgumentException("Argument should be a string");
			case EXECUTE_OPTION_ATTRIBUTE_NAME:
				if (value instanceof Integer) {
					return execOption.setOption((Integer) value);
				}
				throw new DebuggerIllegalArgumentException("Option should be numeric");
			case CONTINUE_OPTION_ATTRIBUTE_NAME:
				if (value instanceof Integer) {
					return contOption.setOption((Integer) value);
				}
				throw new DebuggerIllegalArgumentException("Option should be numeric");
			default:
		}
		return AsyncUtils.NIL;
	}
}
