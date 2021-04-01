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
package agent.dbgeng.model.iface2;

import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;

import agent.dbgeng.manager.DbgEventsListenerAdapter;
import agent.dbgeng.manager.breakpoint.DbgBreakpointType;
import ghidra.async.AsyncFence;
import ghidra.dbg.target.TargetBreakpointLocationContainer;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.TargetBreakpointSpecContainer;
import ghidra.dbg.target.schema.*;
import ghidra.program.model.address.AddressRange;

@TargetObjectSchemaInfo(
	name = "BreakpointContainer",
	elements = {
		@TargetElementType(type = DbgModelTargetBreakpointSpec.class) },
	attributes = {
		@TargetAttributeType(type = Void.class) },
	canonicalContainer = true)
public interface DbgModelTargetBreakpointContainer extends DbgModelTargetObject, //
		TargetBreakpointSpecContainer, //
		TargetBreakpointLocationContainer, //
		DbgEventsListenerAdapter {

	/*
	@Override
	public void breakpointCreated(DbgBreakpointInfo info, DbgCause cause);
	
	@Override
	public void breakpointModified(DbgBreakpointInfo newInfo, DbgBreakpointInfo oldInfo,
			DbgCause cause);
	
	@Override
	public void breakpointDeleted(DbgBreakpointInfo info, DbgCause cause);
	
	@Override
	public void breakpointHit(DbgBreakpointInfo info, DbgCause cause);
	*/

	public default CompletableFuture<Void> doPlaceBreakpoint(Set<TargetBreakpointKind> kinds,
			Function<DbgBreakpointType, CompletableFuture<?>> placer) {
		AsyncFence fence = new AsyncFence();
		if (kinds.contains(TargetBreakpointKind.READ) &&
			kinds.contains(TargetBreakpointKind.WRITE)) {
			fence.include(placer.apply(DbgBreakpointType.ACCESS_WATCHPOINT));
		}
		else if (kinds.contains(TargetBreakpointKind.READ)) {
			fence.include(placer.apply(DbgBreakpointType.READ_WATCHPOINT));
		}
		else if (kinds.contains(TargetBreakpointKind.WRITE)) {
			fence.include(placer.apply(DbgBreakpointType.HW_WATCHPOINT));
		}
		if (kinds.contains(TargetBreakpointKind.HW_EXECUTE)) {
			fence.include(placer.apply(DbgBreakpointType.HW_BREAKPOINT));
		}
		if (kinds.contains(TargetBreakpointKind.SW_EXECUTE)) {
			fence.include(placer.apply(DbgBreakpointType.BREAKPOINT));
		}
		return getModel().gateFuture(fence.ready());
	}

	@Override
	public default CompletableFuture<Void> placeBreakpoint(String expression,
			Set<TargetBreakpointKind> kinds) {
		return doPlaceBreakpoint(kinds, t -> getManager().insertBreakpoint(expression, t));
	}

	@Override
	public default CompletableFuture<Void> placeBreakpoint(AddressRange range,
			Set<TargetBreakpointKind> kinds) {
		// TODO: Consider how to translate address spaces
		long offset = range.getMinAddress().getOffset();
		int len = (int) range.getLength();
		return doPlaceBreakpoint(kinds, t -> getManager().insertBreakpoint(offset, len, t));
	}

}
