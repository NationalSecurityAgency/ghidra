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
package agent.dbgeng.model;

import static org.junit.Assert.*;

import java.util.List;

import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.TargetBreakpointSpecContainer.TargetBreakpointKindSet;
import ghidra.dbg.test.*;
import ghidra.dbg.util.PathPattern;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.*;

public abstract class AbstractModelForDbgengBreakpointsTest
		extends AbstractDebuggerModelBreakpointsTest implements ProvidesTargetViaLaunchSpecimen {

	protected abstract PathPattern getBreakPattern();

	private static final int BREAK_ID_POS = 1;

	@Override
	public AbstractDebuggerModelTest getTest() {
		return this;
	}

	@Override
	protected List<String> seedPath() {
		return List.of();
	}

	@Override
	public DebuggerTestSpecimen getLaunchSpecimen() {
		return WindowsSpecimen.PRINT;
	}

	@Override
	public List<String> getExpectedBreakpointContainerPath(List<String> targetPath) {
		return PathUtils.extend(targetPath, PathUtils.parse("Debug.Breakpoints"));
	}

	@Override
	public TargetBreakpointKindSet getExpectedSupportedKinds() {
		return TargetBreakpointKindSet.of( //
			TargetBreakpointKind.SW_EXECUTE, //
			TargetBreakpointKind.HW_EXECUTE, //
			TargetBreakpointKind.READ, //
			TargetBreakpointKind.WRITE); //
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
		Address pc = frame.getProgramCounter();
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

	@Override
	protected void placeBreakpointViaInterpreter(AddressRange range, TargetBreakpointKind kind,
			TargetInterpreter interpreter) throws Throwable {
		Address min = range.getMinAddress();
		if (range.getLength() == 4) {
			switch (kind) {
				case READ:
					waitOn(interpreter.execute("ba r4 " + min));
					break;
				case WRITE:
					waitOn(interpreter.execute("ba w4 " + min));
					break;
				default:
					fail();
			}
		}
		else if (range.getLength() == 1) {
			switch (kind) {
				case SW_EXECUTE:
					waitOn(interpreter.execute("bp " + min));
					break;
				case HW_EXECUTE:
					waitOn(interpreter.execute("ba e1 " + min));
					break;
				default:
					fail();
			}
		}
		else {
			fail();
		}
	}

	@Override
	protected void disableViaInterpreter(TargetTogglable t, TargetInterpreter interpreter)
			throws Throwable {
		String bpId = getBreakPattern().matchIndices(t.getPath()).get(BREAK_ID_POS);
		waitOn(interpreter.execute("bd " + bpId));
	}

	@Override
	protected void enableViaInterpreter(TargetTogglable t, TargetInterpreter interpreter)
			throws Throwable {
		String bpId = getBreakPattern().matchIndices(t.getPath()).get(BREAK_ID_POS);
		waitOn(interpreter.execute("be " + bpId));
	}

	@Override
	protected void deleteViaInterpreter(TargetDeletable d, TargetInterpreter interpreter)
			throws Throwable {
		String bpId = getBreakPattern().matchIndices(d.getPath()).get(BREAK_ID_POS);
		waitOn(interpreter.execute("bc " + bpId));
	}

	@Override
	protected void assertLocCoversViaInterpreter(AddressRange range, TargetBreakpointKind kind,
			TargetBreakpointLocation loc, TargetInterpreter interpreter) throws Throwable {
		String bpId = getBreakPattern().matchIndices(loc.getPath()).get(BREAK_ID_POS);
		String line = waitOn(interpreter.executeCapture("bl " + bpId)).trim();
		assertFalse(line.contains("\n"));
		// NB. WinDbg numbers breakpoints in base 10, by default
		assertTrue(line.startsWith(bpId));
		// TODO: Do I care to parse the details? The ID is confirmed, and details via the object...
	}

	@Override
	protected void assertEnabledViaInterpreter(TargetTogglable t, boolean enabled,
			TargetInterpreter interpreter) throws Throwable {
		String bpId = getBreakPattern().matchIndices(t.getPath()).get(BREAK_ID_POS);
		String line = waitOn(interpreter.executeCapture("bl " + bpId)).trim();
		assertFalse(line.contains("\n"));
		assertTrue(line.startsWith(bpId));
		String e = line.split("\\s+")[1];
		assertEquals(enabled ? "e" : "d", e);
	}

	@Override
	protected void assertDeletedViaInterpreter(TargetDeletable d, TargetInterpreter interpreter)
			throws Throwable {
		String bpId = getBreakPattern().matchIndices(d.getPath()).get(BREAK_ID_POS);
		String line = waitOn(interpreter.executeCapture("bl " + bpId)).trim();
		assertEquals("", line);
	}
}
