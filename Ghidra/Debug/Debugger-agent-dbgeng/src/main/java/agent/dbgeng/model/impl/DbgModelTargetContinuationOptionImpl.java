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

import agent.dbgeng.dbgeng.DebugControl.DebugFilterContinuationOption;
import agent.dbgeng.manager.cmd.DbgToggleContinuationCommand;
import agent.dbgeng.manager.impl.DbgManagerImpl;
import agent.dbgeng.model.iface2.*;
import ghidra.dbg.target.schema.*;

@TargetObjectSchemaInfo(
	name = "ContinuationFilter",
	elements = {
		@TargetElementType(type = Void.class) },
	attributes = {
		@TargetAttributeType(type = Object.class) })
public class DbgModelTargetContinuationOptionImpl extends DbgModelTargetObjectImpl
		implements DbgModelTargetEventOption {

	private DbgModelTargetEvent event;
	private DebugFilterContinuationOption optionCont;

	public DbgModelTargetContinuationOptionImpl(DbgModelTargetEvent event,
			DebugFilterContinuationOption option) {
		super(event.getModel(), event, "Continue", "ContinuationFilter");
		this.getModel().addModelObject(option, this);
		this.event = event;
		this.optionCont = option;
		setAttributes();
	}

	public DbgModelTargetContinuationOptionImpl(DbgModelTargetException exc,
			DebugFilterContinuationOption option) {
		super(exc.getModel(), exc, "Continue", "ContinuationFilter");
		this.event = exc;
		this.getModel().addModelObject(option, this);
		this.optionCont = option;
		setAttributes();
	}

	@Override
	public CompletableFuture<Void> disable() {
		return setOption(DebugFilterContinuationOption.DEBUG_FILTER_GO_NOT_HANDLED.ordinal());
	}

	@Override
	public CompletableFuture<Void> enable() {
		return setOption(DebugFilterContinuationOption.DEBUG_FILTER_GO_HANDLED.ordinal());
	}

	@Override
	public Integer getOption() {
		return optionCont.ordinal();
	}

	@Override
	public CompletableFuture<Void> setOption(int ordinal) {
		DbgManagerImpl manager = getManager();
		optionCont = DebugFilterContinuationOption.getByNumber(ordinal);
		setAttributes();
		return manager.execute(
			new DbgToggleContinuationCommand(manager, event.getEventIndex(), optionCont));
	}

	public void setAttributes() {
		changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, getName() + " : " + optionCont.description, //
			VALUE_ATTRIBUTE_NAME, optionCont, //
			ENABLED_ATTRIBUTE_NAME,
			optionCont.equals(DebugFilterContinuationOption.DEBUG_FILTER_GO_HANDLED)),
			"Refreshed");
	}

}
