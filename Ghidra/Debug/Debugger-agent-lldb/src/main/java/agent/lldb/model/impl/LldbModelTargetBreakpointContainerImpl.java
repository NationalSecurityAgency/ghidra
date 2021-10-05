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
package agent.lldb.model.impl;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import SWIG.*;
import agent.lldb.lldb.DebugClient;
import agent.lldb.manager.LldbCause;
import agent.lldb.model.iface2.*;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.*;
import ghidra.util.Msg;

@TargetObjectSchemaInfo(
	name = "BreakpointContainer",
	elements = { //
		@TargetElementType(type = LldbModelTargetAbstractXpointSpec.class) //
	},
	attributes = { //
		@TargetAttributeType(type = Void.class) //
	},
	canonicalContainer = true)
public class LldbModelTargetBreakpointContainerImpl extends LldbModelTargetObjectImpl
		implements LldbModelTargetBreakpointContainer {

	protected static final TargetBreakpointKindSet SUPPORTED_KINDS =
		TargetBreakpointKindSet.of(
			TargetBreakpointKind.SW_EXECUTE,
			//TargetBreakpointKind.HW_EXECUTE,
			TargetBreakpointKind.READ,
			TargetBreakpointKind.WRITE
		);

	private final SBTarget session;

	public LldbModelTargetBreakpointContainerImpl(LldbModelTargetDebugContainer debug,
			SBTarget session) {
		super(debug.getModel(), debug, "Breakpoints", "BreakpointContainer");
		this.session = session;

		getManager().addEventsListener(this);

		changeAttributes(List.of(), List.of(), Map.of(  //
			// TODO: Seems terrible to duplicate this static attribute on each instance
			SUPPORTED_BREAK_KINDS_ATTRIBUTE_NAME, SUPPORTED_KINDS //
		), "Initialized");
	}

	@Override
	public void breakpointCreated(Object info, LldbCause cause) {
		LldbModelTargetBreakpointSpec spec = getTargetBreakpointSpec(info);
		spec.updateInfo(info, "Created");
		changeElements(List.of(), List.of(getTargetBreakpointSpec(info)), Map.of(), "Created");
	}

	@Override
	public void breakpointModified(Object info, LldbCause cause) {
		getTargetBreakpointSpec(info).updateInfo(info, "Modified");
	}

	@Override
	public void breakpointDeleted(Object info, LldbCause cause) {
		LldbModelImpl impl = (LldbModelImpl) model;
		impl.deleteModelObject(info);
		changeElements(List.of( //
			DebugClient.getId(getModelObject()) //
		), List.of(), Map.of(), "Deleted");
	}

	@Override
	public void breakpointHit(Object obj, LldbCause cause) {
		SBBreakpoint bpt = (SBBreakpoint) obj;
		SBProcess eventProcess = getManager().getEventProcess();
		long nthreads = eventProcess.GetNumThreads();
		for (int i = 0; i < nthreads; i++) {
			SBThread t = eventProcess.GetThreadAtIndex(i);
			StopReason reason = t.GetStopReason();
			if (reason.equals(StopReason.eStopReasonBreakpoint)) {
				BigInteger bptId = t.GetStopReasonDataAtIndex(0);
				BigInteger locId = t.GetStopReasonDataAtIndex(1);
				if (bpt.GetID() == bptId.intValue()) {
					LldbModelTargetProcess targetProcess = (LldbModelTargetProcess) getModel().getModelObject(eventProcess);
					LldbModelTargetThread targetThread =
							targetProcess.getThreads().getTargetThread(t);
					LldbModelTargetBreakpointSpec spec = getTargetBreakpointSpec(bpt);
					if (spec == null) {
						Msg.error(this, "Stopped for breakpoint unknown to the agent: " + bpt + " (pc=" +
							targetThread + ")");
						return;
					}

					LldbModelTargetBreakpointLocation loc = spec.findLocation(locId);
					if (loc == null) {
						Msg.warn(this,
							"Stopped for a breakpoint whose location is unknown to the agent: " + spec);
					}
					listeners.fire.breakpointHit(this, targetThread, null, spec, loc);					
				}
			}
		}
	}

	public LldbModelTargetBreakpointSpec getTargetBreakpointSpec(Object bpt) {
		TargetObject targetObject = getMapObject(bpt);
		if (targetObject != null) {
			LldbModelTargetBreakpointSpec spec = (LldbModelTargetBreakpointSpec) targetObject;
			spec.setModelObject(bpt);
			return spec;
		}
		if (bpt instanceof SBBreakpoint) {
			return new LldbModelTargetBreakpointSpecImpl(this, bpt);
		}
		else {
			return new LldbModelTargetWatchpointSpecImpl(this, bpt);
		}
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		return getManager().listBreakpoints(getSession()).thenAccept(byNumber -> {
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

	public SBTarget getSession() {
		return session;
	}
}
