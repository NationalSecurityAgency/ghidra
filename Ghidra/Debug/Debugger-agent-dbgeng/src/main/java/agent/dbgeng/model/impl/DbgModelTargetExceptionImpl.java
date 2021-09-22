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
import agent.dbgeng.manager.DbgExceptionFilter;
import agent.dbgeng.model.iface2.*;
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
		execOption = new DbgModelTargetEventOptionImpl(this, exec);
		contOption = new DbgModelTargetEventOptionImpl(this, cont);

		changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, getIndex(), //
			"Command", filter.getCmd(), //
			"SecondCmd", filter.getCmd(), //
			"Execute", execOption, //
			"Continue", contOption, //
			"Exception", filter.getExceptionCode() //
		), "Initialized");
	}

	@Override
	public DbgExceptionFilter getFilter() {
		return filter;
	}

}
