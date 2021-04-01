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
package agent.gdb.model;

import static org.junit.Assert.assertNotNull;

import java.util.List;

import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.TargetBreakpointSpecContainer.TargetBreakpointKindSet;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetStackFrame;
import ghidra.dbg.test.*;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.*;

public abstract class AbstractModelForGdbBreakpointsTest
		extends AbstractDebuggerModelBreakpointsTest implements ProvidesTargetViaLaunchSpecimen {

	@Override
	public AbstractDebuggerModelTest getTest() {
		return this;
	}

	@Override
	public DebuggerTestSpecimen getLaunchSpecimen() {
		return GdbLinuxSpecimen.ECHO_HW;
	}

	@Override
	public List<String> getExpectedBreakpointContainerPath(List<String> targetPath) {
		return PathUtils.parse("Breakpoints");
	}

	@Override
	public TargetBreakpointKindSet getExpectedSupportedKinds() {
		return TargetBreakpointKindSet.of(
			TargetBreakpointKind.SW_EXECUTE,
			TargetBreakpointKind.HW_EXECUTE,
			TargetBreakpointKind.READ,
			TargetBreakpointKind.WRITE);
	}

	@Override
	public AddressRange getSuitableRangeForBreakpoint(TargetObject target,
			TargetBreakpointKind kind) throws Throwable {
		TargetStackFrame frame = retry(() -> {
			TargetStackFrame f = findAnyStackFrame(target.getPath());
			assertNotNull(f);
			return f;
		}, List.of(AssertionError.class));
		waitOn(frame.fetchAttributes());
		Address pc = frame.getProgramCounter().add(16); // Avoid "main" (temporary bp)
		switch (kind) {
			case SW_EXECUTE:
			case HW_EXECUTE:
				return new AddressRangeImpl(pc, pc);
			case READ:
			case WRITE:
				return new AddressRangeImpl(pc, 4);
			default:
				throw new AssertionError();
		}
	}
}
