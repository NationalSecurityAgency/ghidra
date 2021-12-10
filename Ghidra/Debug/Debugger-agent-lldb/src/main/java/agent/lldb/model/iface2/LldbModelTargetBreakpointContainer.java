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
package agent.lldb.model.iface2;

import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;

import SWIG.SBTarget;
import agent.lldb.manager.LldbCause;
import agent.lldb.manager.LldbEventsListenerAdapter;
import agent.lldb.manager.breakpoint.LldbBreakpointType;
import agent.lldb.manager.impl.LldbManagerImpl;
import agent.lldb.model.impl.LldbModelTargetAbstractXpointSpec;
import ghidra.async.AsyncFence;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.TargetBreakpointSpecContainer;
import ghidra.dbg.target.schema.*;
import ghidra.program.model.address.AddressRange;

@TargetObjectSchemaInfo(
	name = "BreakpointContainer",
	elements = {
		@TargetElementType(type = LldbModelTargetAbstractXpointSpec.class) },
	attributes = {
		@TargetAttributeType(type = Void.class) },
	canonicalContainer = true)
public interface LldbModelTargetBreakpointContainer extends LldbModelTargetObject, //
		TargetBreakpointSpecContainer, //
		LldbEventsListenerAdapter {

	@Override
	public void breakpointCreated(Object info, LldbCause cause);

	@Override
	public void breakpointModified(Object info, LldbCause cause);

	@Override
	public void breakpointDeleted(Object info, LldbCause cause);

	@Override
	public void breakpointHit(Object info, LldbCause cause);

	public default CompletableFuture<Void> doPlaceBreakpoint(Set<TargetBreakpointKind> kinds,
			Function<LldbBreakpointType, CompletableFuture<?>> placer) {
		AsyncFence fence = new AsyncFence();
		if (kinds.contains(TargetBreakpointKind.READ) &&
			kinds.contains(TargetBreakpointKind.WRITE)) {
			fence.include(placer.apply(LldbBreakpointType.ACCESS_WATCHPOINT));
		}
		else if (kinds.contains(TargetBreakpointKind.READ)) {
			fence.include(placer.apply(LldbBreakpointType.READ_WATCHPOINT));
		}
		else if (kinds.contains(TargetBreakpointKind.WRITE)) {
			fence.include(placer.apply(LldbBreakpointType.WRITE_WATCHPOINT));
		}
		if (kinds.contains(TargetBreakpointKind.HW_EXECUTE)) {
			fence.include(placer.apply(LldbBreakpointType.HW_BREAKPOINT));
		}
		if (kinds.contains(TargetBreakpointKind.SW_EXECUTE)) {
			fence.include(placer.apply(LldbBreakpointType.BREAKPOINT));
		}
		return getModel().gateFuture(fence.ready());
	}

	@Override
	public default CompletableFuture<Void> placeBreakpoint(String expression,
			Set<TargetBreakpointKind> kinds) {
		LldbManagerImpl manager = getManager();
		return doPlaceBreakpoint(kinds, t -> manager.insertBreakpoint(expression, t));
	}

	@Override
	public default CompletableFuture<Void> placeBreakpoint(AddressRange range,
			Set<TargetBreakpointKind> kinds) {
		LldbManagerImpl manager = getManager();
		long offset = range.getMinAddress().getOffset();
		int len = (int) range.getLength();
		return doPlaceBreakpoint(kinds, t -> manager.insertBreakpoint(offset, len, t));
	}

	public SBTarget getSession();

}
