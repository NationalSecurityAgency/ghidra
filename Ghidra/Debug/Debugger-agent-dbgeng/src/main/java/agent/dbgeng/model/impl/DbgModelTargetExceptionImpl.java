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

import agent.dbgeng.dbgeng.DebugControl.DebugFilterContinuationOption;
import agent.dbgeng.dbgeng.DebugControl.DebugFilterExecutionOption;
import agent.dbgeng.dbgeng.DebugExceptionRecord64;
import agent.dbgeng.manager.DbgCause;
import agent.dbgeng.manager.DbgExceptionFilter;
import agent.dbgeng.manager.evt.AbstractDbgEvent;
import agent.dbgeng.manager.evt.DbgExceptionEvent;
import agent.dbgeng.model.iface1.DbgModelTargetFocusScope;
import agent.dbgeng.model.iface2.*;
import ghidra.dbg.target.TargetFocusScope;
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
			"Command", filter.getCmd(), //
			"SecondCmd", filter.getCmd(), //
			"Execute", execOption, //
			"Continue", contOption, //
			"Exception", filter.getExceptionCode() //
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
}
