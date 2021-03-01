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
package ghidra.dbg.model;

import java.util.*;
import java.util.concurrent.CompletableFuture;

import ghidra.dbg.attributes.TargetObjectList;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetBreakpointContainer.TargetBreakpointKindSet;
import ghidra.dbg.util.CollectionUtils.Delta;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.Address;

public class TestTargetBreakpoint
		extends DefaultTestTargetObject<TestTargetBreakpoint, TestTargetBreakpointContainer>
		implements TargetBreakpointSpec, TargetBreakpointLocation, TargetDeletable {

	public TestTargetBreakpoint(TestTargetBreakpointContainer parent, int num, Address address,
			int length, Set<TargetBreakpointKind> kinds) {
		super(parent, PathUtils.makeKey(PathUtils.makeIndex(num)), "Breakpoint");

		changeAttributes(List.of(), Map.of(
			SPEC_ATTRIBUTE_NAME, this,
			ADDRESS_ATTRIBUTE_NAME, address,
			AFFECTS_ATTRIBUTE_NAME, TargetObjectList.of(parent.getParent()),
			ENABLED_ATTRIBUTE_NAME, true,
			EXPRESSION_ATTRIBUTE_NAME, address.toString(),
			KINDS_ATTRIBUTE_NAME, TargetBreakpointKindSet.copyOf(kinds),
			LENGTH_ATTRIBUTE_NAME, length //
		), "Initialized");
	}

	@Override
	public void addAction(TargetBreakpointAction action) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeAction(TargetBreakpointAction action) {
		throw new UnsupportedOperationException();
	}

	@Override
	public CompletableFuture<Void> disable() {
		Delta<?, ?> delta = changeAttributes(List.of(), Map.of(
			ENABLED_ATTRIBUTE_NAME, false //
		), "Disabled Breakpoint");
		if (delta.added.containsKey(ENABLED_ATTRIBUTE_NAME)) {
			listeners.fire(TargetBreakpointSpecListener.class).breakpointToggled(this, false);
		}
		return getModel().future(null);
	}

	@Override
	public CompletableFuture<Void> enable() {
		Delta<?, ?> delta = changeAttributes(List.of(), Map.of(
			ENABLED_ATTRIBUTE_NAME, true //
		), "Enabled Breakpoint");
		if (delta.added.containsKey(ENABLED_ATTRIBUTE_NAME)) {
			listeners.fire(TargetBreakpointSpecListener.class).breakpointToggled(this, true);
		}
		return getModel().future(null);
	}

	@Override
	public CompletableFuture<Void> delete() {
		return parent.deleteBreakpoint(this);
	}
}
