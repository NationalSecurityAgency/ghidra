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

import static org.junit.Assert.*;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import generic.Unique;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.TargetBreakpointSpecContainer.TargetBreakpointKindSet;
import ghidra.dbg.test.*;
import ghidra.dbg.util.PathPattern;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.*;

public abstract class AbstractModelForGdbBreakpointsTest
		extends AbstractDebuggerModelBreakpointsTest implements ProvidesTargetViaLaunchSpecimen {

	private static final PathPattern BREAK_PATTERN =
		new PathPattern(PathUtils.parse("Breakpoints[]"));

	@Override
	public AbstractDebuggerModelTest getTest() {
		return this;
	}

	@Override
	public DebuggerTestSpecimen getLaunchSpecimen() {
		return GdbLinuxSpecimen.PRINT;
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

	@Override
	protected void placeBreakpointViaInterpreter(AddressRange range, TargetBreakpointKind kind,
			TargetInterpreter interpreter) throws Throwable {
		Address min = range.getMinAddress();
		if (range.getLength() == 4) {
			switch (kind) {
				case READ:
					waitOn(interpreter.execute("rwatch -l *((int*) 0x" + min + ")"));
					break;
				case WRITE:
					waitOn(interpreter.execute("watch -l *((int*) 0x" + min + ")"));
					break;
				default:
					fail();
			}
		}
		else if (range.getLength() == 1) {
			switch (kind) {
				case SW_EXECUTE:
					waitOn(interpreter.execute("break *0x" + min));
					break;
				case HW_EXECUTE:
					waitOn(interpreter.execute("hbreak *0x" + min));
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
		assert t instanceof TargetBreakpointSpec; // TODO: or Location
		String index = Unique.assertOne(BREAK_PATTERN.matchIndices(t.getPath()));
		waitOn(interpreter.execute("disable " + index));
	}

	@Override
	protected void enableViaInterpreter(TargetTogglable t, TargetInterpreter interpreter)
			throws Throwable {
		assert t instanceof TargetBreakpointSpec; // TODO: or Location
		String index = Unique.assertOne(BREAK_PATTERN.matchIndices(t.getPath()));
		waitOn(interpreter.execute("enable " + index));
	}

	@Override
	protected void deleteViaInterpreter(TargetDeletable d, TargetInterpreter interpreter)
			throws Throwable {
		assert d instanceof TargetBreakpointSpec; // TODO: or Location
		String index = Unique.assertOne(BREAK_PATTERN.matchIndices(d.getPath()));
		waitOn(interpreter.execute("delete " + index));
	}

	@Override
	protected void assertLocCoversViaInterpreter(AddressRange range, TargetBreakpointKind kind,
			TargetBreakpointLocation loc, TargetInterpreter interpreter) throws Throwable {
		String index =
			Unique.assertOne(BREAK_PATTERN.matchIndices(loc.getSpecification().getPath()));
		String output = waitOn(interpreter.executeCapture("info break " + index));
		String line = Unique.assertOne(Stream.of(output.split("\n"))
				.filter(l -> !l.trim().startsWith("Num"))
				.collect(Collectors.toList())).trim();
		assertTrue(line.startsWith(index));
		// TODO: Do I care to parse the details? The ID is confirmed, and details via the object...
	}

	@Override
	protected void assertEnabledViaInterpreter(TargetTogglable t, boolean enabled,
			TargetInterpreter interpreter) throws Throwable {
		assert t instanceof TargetBreakpointSpec; // TODO: or Location
		String index = Unique.assertOne(BREAK_PATTERN.matchIndices(t.getPath()));
		String output = waitOn(interpreter.executeCapture("info break " + index));
		String line = Unique.assertOne(Stream.of(output.split("\n"))
				.filter(l -> !l.trim().startsWith("Num"))
				.collect(Collectors.toList())).trim();
		assertTrue(line.startsWith(index));
		String enb = line.split("keep")[1].trim().split("\\s+")[0];
		assertEquals(enabled ? "y" : "n", enb);
	}

	@Override
	protected void assertDeletedViaInterpreter(TargetDeletable d, TargetInterpreter interpreter)
			throws Throwable {
		assert d instanceof TargetBreakpointSpec; // TODO: or Location
		String index = Unique.assertOne(BREAK_PATTERN.matchIndices(d.getPath()));
		String output = waitOn(interpreter.executeCapture("info break " + index));
		assertTrue(output.contains("No breakpoint"));
	}
}
