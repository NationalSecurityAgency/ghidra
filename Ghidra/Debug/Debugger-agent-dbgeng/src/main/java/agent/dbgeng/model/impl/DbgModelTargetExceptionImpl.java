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

import agent.dbgeng.dbgeng.DebugControl.DebugFilterContinuationOption;
import agent.dbgeng.dbgeng.DebugControl.DebugFilterExecutionOption;
import agent.dbgeng.dbgeng.DebugExceptionRecord64;
import agent.dbgeng.manager.DbgCause;
import agent.dbgeng.manager.DbgExceptionFilter;
import agent.dbgeng.manager.cmd.DbgSetFilterCommandCommand;
import agent.dbgeng.manager.cmd.DbgSetFilterSecondChanceCmdCommand;
import agent.dbgeng.manager.evt.AbstractDbgEvent;
import agent.dbgeng.manager.evt.DbgExceptionEvent;
import agent.dbgeng.manager.impl.DbgManagerImpl;
import agent.dbgeng.model.iface1.DbgModelTargetFocusScope;
import agent.dbgeng.model.iface2.*;
import ghidra.async.AsyncUtils;
import ghidra.dbg.error.DebuggerIllegalArgumentException;
import ghidra.dbg.target.TargetFocusScope;
import ghidra.dbg.target.TargetMethod.ParameterDescription;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.PathUtils;

@TargetObjectSchemaInfo(
	name = "Exception",
	elements = {
		@TargetElementType(type = Void.class) },
	attributes = {
		@TargetAttributeType(type = Object.class) })
public class DbgModelTargetExceptionImpl extends DbgModelTargetObjectImpl
		implements DbgModelTargetException {

	final String COMMAND_ATTRIBUTE_NAME = "Command";
	final String COMMAND2_ATTRIBUTE_NAME = "SecondCmd";
	final String CONTINUE_OPTION_ATTRIBUTE_NAME = "Continue";
	final String EXECUTE_OPTION_ATTRIBUTE_NAME = "Execute";
	final String EXCEPTION_CODE_ATTRIBUTE_NAME = "Exception";

	protected static String indexFilter(DbgExceptionFilter filter) {
		return filter.getName();
	}

	protected static String keyFilter(DbgExceptionFilter filter) {
		return PathUtils.makeKey(indexFilter(filter));
	}

	protected DbgModelTargetEventOption execOption;
	protected DbgModelTargetEventOption contOption;

	private DbgExceptionFilter filter;

	public DbgModelTargetExceptionImpl(DbgModelTargetExceptionContainer exceptions,
			DbgExceptionFilter filter) {
		super(exceptions.getModel(), exceptions, keyFilter(filter), "ExceptionFilter");
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
			COMMAND2_ATTRIBUTE_NAME, filter.getCmd(), //
			EXECUTE_OPTION_ATTRIBUTE_NAME, execOption, //
			CONTINUE_OPTION_ATTRIBUTE_NAME, contOption, //
			EXCEPTION_CODE_ATTRIBUTE_NAME, filter.getExceptionCode() //
		), "Initialized");

		getManager().addEventsListener(this);
	}

	@Override
	public DbgExceptionFilter getFilter() {
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
		if (event instanceof DbgExceptionEvent) {
			DebugExceptionRecord64 info = (DebugExceptionRecord64) event.getInfo();
			if (info.code == Long.parseLong(filter.getExceptionCode(), 16)) {
				((DbgModelTargetFocusScope) searchForSuitable(TargetFocusScope.class))
						.setFocus(this);
				changeAttributes(List.of(), List.of(), Map.of( //
					MODIFIED_ATTRIBUTE_NAME, true), "Refreshed");
			}
		}
	}

	@Override
	public Map<String, ParameterDescription<?>> getConfigurableOptions() {
		Map<String, ParameterDescription<?>> map = new HashMap<>();
		ParameterDescription<String> cmdDesc = ParameterDescription.create(String.class,
			COMMAND_ATTRIBUTE_NAME, false, "", COMMAND_ATTRIBUTE_NAME, "filter command");
		map.put(COMMAND_ATTRIBUTE_NAME, cmdDesc);
		ParameterDescription<String> cmdDesc2 =
			ParameterDescription.create(String.class, COMMAND2_ATTRIBUTE_NAME, false, "",
				COMMAND2_ATTRIBUTE_NAME, "filter 2nd-chance command");
		map.put(COMMAND2_ATTRIBUTE_NAME, cmdDesc2);
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
			case COMMAND2_ATTRIBUTE_NAME:
				if (value instanceof String) {
					this.changeAttributes(List.of(), Map.of(COMMAND2_ATTRIBUTE_NAME, value),
						"Modified");
					String cmd = (String) getCachedAttribute(COMMAND2_ATTRIBUTE_NAME);
					return manager.execute(
						new DbgSetFilterSecondChanceCmdCommand(manager, getEventIndex(), cmd));
				}
				throw new DebuggerIllegalArgumentException("Command should be a string");
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
