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

import agent.dbgeng.dbgeng.DebugControl.DebugFilterExecutionOption;
import agent.dbgeng.manager.cmd.DbgToggleExecutionCommand;
import agent.dbgeng.manager.impl.DbgManagerImpl;
import agent.dbgeng.model.iface2.*;
import ghidra.dbg.target.schema.*;

@TargetObjectSchemaInfo(
	name = "ExecutionOption",
	elements = {
		@TargetElementType(type = Void.class) },
	attributes = {
		@TargetAttributeType(type = Object.class) })
public class DbgModelTargetExecutionOptionImpl extends DbgModelTargetObjectImpl
		implements DbgModelTargetEventOption {

	private DbgModelTargetEvent event;
	private DebugFilterExecutionOption optionExc;

	public DbgModelTargetExecutionOptionImpl(DbgModelTargetEvent event,
			DebugFilterExecutionOption option) {
		super(event.getModel(), event, "Execute", "ExecutionOption");
		this.event = event;
		this.getModel().addModelObject(option, this);
		this.optionExc = option;
		setAttributes();
	}

	public DbgModelTargetExecutionOptionImpl(DbgModelTargetException exc,
			DebugFilterExecutionOption option) {
		super(exc.getModel(), exc, "Execute", "ExecutionOption");
		this.event = exc;
		this.getModel().addModelObject(option, this);
		this.optionExc = option;
		setAttributes();
	}

	@Override
	public CompletableFuture<Void> disable() {
		return enable();
	}

	@Override
	public CompletableFuture<Void> enable() {
		int ordinal = (optionExc.ordinal() + 1) % (DebugFilterExecutionOption.values().length - 1);
		return setOption(ordinal);
	}

	@Override
	public Integer getOption() {
		return optionExc.ordinal();
	}

	@Override
	public CompletableFuture<Void> setOption(int ordinal) {
		DbgManagerImpl manager = getManager();
		optionExc = DebugFilterExecutionOption.getByNumber(ordinal);
		setAttributes();
		return manager.execute(
			new DbgToggleExecutionCommand(manager, event.getEventIndex(), optionExc));
	}

	public void setAttributes() {
		changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, getName() + " : " + optionExc.description, //
			VALUE_ATTRIBUTE_NAME, optionExc, //
			ENABLED_ATTRIBUTE_NAME,
			optionExc.equals(DebugFilterExecutionOption.DEBUG_FILTER_BREAK)), "Refreshed");
	}

}
