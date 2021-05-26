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

import agent.dbgeng.manager.DbgCause;
import agent.dbgeng.manager.breakpoint.DbgBreakpointInfo;
import agent.dbgeng.manager.impl.DbgManagerImpl;
import agent.dbgeng.model.iface2.*;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.*;

@TargetObjectSchemaInfo(
	name = "BreakpointContainer",
	elements = { //
		@TargetElementType(type = DbgModelTargetBreakpointSpecImpl.class) //
	},
	attributes = { //
		@TargetAttributeType(type = Void.class) //
	},
	canonicalContainer = true)
public class DbgModelTargetBreakpointContainerImpl extends DbgModelTargetObjectImpl
		implements DbgModelTargetBreakpointContainer {

	protected static final TargetBreakpointKindSet SUPPORTED_KINDS =
		TargetBreakpointKindSet.of(TargetBreakpointKind.values());

	public DbgModelTargetBreakpointContainerImpl(DbgModelTargetDebugContainer debug) {
		super(debug.getModel(), debug, "Breakpoints", "BreakpointContainer");

		getManager().addEventsListener(this);

		changeAttributes(List.of(), List.of(), Map.of(  //
			// TODO: Seems terrible to duplicate this static attribute on each instance
			SUPPORTED_BREAK_KINDS_ATTRIBUTE_NAME, SUPPORTED_KINDS //
		), "Initialized");
	}

	@Override
	public void breakpointCreated(DbgBreakpointInfo info, DbgCause cause) {
		changeElements(List.of(), List.of(getTargetBreakpointSpec(info)), Map.of(), "Created");
	}

	@Override
	public void breakpointModified(DbgBreakpointInfo newInfo, DbgBreakpointInfo oldInfo,
			DbgCause cause) {
		getTargetBreakpointSpec(oldInfo).updateInfo(oldInfo, newInfo, "Modified");
	}

	@Override
	public void breakpointDeleted(DbgBreakpointInfo info, DbgCause cause) {
		DbgModelImpl impl = (DbgModelImpl) model;
		impl.deleteModelObject(info.getDebugBreakpoint());
		changeElements(List.of( //
			DbgModelTargetBreakpointSpecImpl.indexBreakpoint(info) //
		), List.of(), Map.of(), "Deleted");
	}

	@Override
	public void breakpointHit(DbgBreakpointInfo info, DbgCause cause) {
		DbgModelTargetThread targetThread =
			getParentProcess().getThreads().getTargetThread(getManager().getEventThread());
		DbgModelTargetBreakpointSpec spec = getTargetBreakpointSpec(info);
		listeners.fire.breakpointHit(getProxy(), targetThread, null, spec, spec);
		spec.breakpointHit();
	}

	public DbgModelTargetBreakpointSpec getTargetBreakpointSpec(DbgBreakpointInfo info) {
		DbgModelImpl impl = (DbgModelImpl) model;
		TargetObject modelObject = impl.getModelObject(info.getDebugBreakpoint());
		if (modelObject != null) {
			return (DbgModelTargetBreakpointSpec) modelObject;
		}
		return new DbgModelTargetBreakpointSpecImpl(this, info);
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		DbgManagerImpl manager = getManager();
		return manager.listBreakpoints().thenAccept(byNumber -> {
			List<TargetObject> specs;
			synchronized (this) {
				specs = byNumber.values()
						.stream()
						.map(this::getTargetBreakpointSpec)
						.collect(Collectors.toList());
			}
			setElements(specs, Map.of(), "Refreshed");
		});
	}
}
