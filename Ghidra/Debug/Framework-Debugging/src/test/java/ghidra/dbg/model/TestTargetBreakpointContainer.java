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
import java.util.concurrent.atomic.AtomicInteger;

import ghidra.dbg.target.TargetBreakpointLocationContainer;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.TargetBreakpointSpecContainer;
import ghidra.program.model.address.AddressRange;

// TODO: Test some other breakpoint conventions:
//   A1) 1-1 spec-effective, where spec is effective is breakpoint (DONE)
//   A2) 1-n spec-effective, where effective are children of spec
//   B1) container per process (DONE)
//   B2) container per session

public class TestTargetBreakpointContainer
		extends DefaultTestTargetObject<TestTargetBreakpoint, TestTargetProcess>
		implements TargetBreakpointSpecContainer, TargetBreakpointLocationContainer {

	protected static final TargetBreakpointKindSet ALL_KINDS =
		TargetBreakpointKindSet.of(TargetBreakpointKind.values());

	protected final AtomicInteger counter = new AtomicInteger();

	public TestTargetBreakpointContainer(TestTargetProcess parent) {
		super(parent, "Breakpoints", "BreakpointContainer");

		changeAttributes(List.of(), Map.of(
			SUPPORTED_BREAK_KINDS_ATTRIBUTE_NAME, ALL_KINDS //
		), "Initialized");
	}

	@Override
	public CompletableFuture<Void> placeBreakpoint(String expression,
			Set<TargetBreakpointKind> kinds) {
		throw new UnsupportedOperationException();
	}

	@Override
	public CompletableFuture<Void> placeBreakpoint(AddressRange range,
			Set<TargetBreakpointKind> kinds) {
		TestTargetBreakpoint bpt = new TestTargetBreakpoint(this, counter.getAndIncrement(),
			range.getMinAddress(), (int) range.getLength(), kinds);
		changeElements(List.of(), List.of(bpt), "Breakpoint Added");
		return getModel().future(null);
	}

	public CompletableFuture<Void> deleteBreakpoint(TestTargetBreakpoint bpt) {
		changeElements(List.of(bpt.getIndex()), List.of(), "Breakpoint Deleted");
		return getModel().future(null);
	}
}
