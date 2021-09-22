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
import agent.dbgeng.dbgeng.DebugControl.DebugFilterExecutionOption;
import agent.dbgeng.model.iface2.*;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.PathUtils;

@TargetObjectSchemaInfo(
	name = "Event",
	elements = {
		@TargetElementType(type = Void.class) },
	attributes = {
		@TargetAttributeType(type = Object.class) })
public class DbgModelTargetEventOptionImpl extends DbgModelTargetObjectImpl
		implements DbgModelTargetEventOption {

	protected static String keyFilter(DebugFilterExecutionOption option) {
		return PathUtils.makeKey(option.description);
	}

	protected static String keyFilter(DebugFilterContinuationOption option) {
		return PathUtils.makeKey(option.description);
	}

	private DebugFilterExecutionOption optionEx;
	private DebugFilterContinuationOption optionCont;

	public DbgModelTargetEventOptionImpl(DbgModelTargetEvent event,
			DebugFilterExecutionOption option) {
		super(event.getModel(), event, keyFilter(option), "EventFilter");
		this.getModel().addModelObject(option, this);
		this.optionEx = option;
	}

	public DbgModelTargetEventOptionImpl(DbgModelTargetEvent event,
			DebugFilterContinuationOption option) {
		super(event.getModel(), event, keyFilter(option), "EventFilter");
		this.getModel().addModelObject(option, this);
		this.optionCont = option;
	}

	public DbgModelTargetEventOptionImpl(DbgModelTargetException exc,
			DebugFilterExecutionOption option) {
		super(exc.getModel(), exc, keyFilter(option), "EventFilter");
		this.getModel().addModelObject(option, this);
		this.optionEx = option;
	}

	public DbgModelTargetEventOptionImpl(DbgModelTargetException exc,
			DebugFilterContinuationOption option) {
		super(exc.getModel(), exc, keyFilter(option), "EventFilter");
		this.getModel().addModelObject(option, this);
		this.optionCont = option;
	}

	@Override
	public CompletableFuture<Void> disable() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public CompletableFuture<Void> enable() {
		// TODO Auto-generated method stub
		return null;
	}

	public void setAttributes() {
		changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, getName() //
		), "Initialized");
	}

}
