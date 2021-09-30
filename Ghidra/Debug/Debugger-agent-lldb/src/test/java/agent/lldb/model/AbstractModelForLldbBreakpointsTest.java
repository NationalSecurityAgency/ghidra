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
package agent.lldb.model;

import static org.junit.Assert.*;

import java.util.List;
import java.util.Map;

import agent.lldb.model.iface2.*;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.TargetBreakpointSpecContainer.TargetBreakpointKindSet;
import ghidra.dbg.test.*;
import ghidra.dbg.util.PathPattern;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.*;

public abstract class AbstractModelForLldbBreakpointsTest
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
		return MacOSSpecimen.PRINT;
	}

	@Override
	public List<String> getExpectedBreakpointContainerPath(List<String> targetPath) {
		List<String> procsPath = PathUtils.parent(targetPath);
		List<String> sessionPath = PathUtils.parent(procsPath);
		return PathUtils.extend(sessionPath, PathUtils.parse("Debug.Breakpoints"));
	}

	@Override
	public TargetBreakpointKindSet getExpectedSupportedKinds() {
		return TargetBreakpointKindSet.of( //
			TargetBreakpointKind.SW_EXECUTE, //
			//TargetBreakpointKind.HW_EXECUTE, //
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
					waitOn(interpreter.execute("watchpoint set expression -w read -s 4 -- " + min));
					break;
				case WRITE:
					waitOn(interpreter.execute("watchpoint set expression -w write -s 4 -- " + min));
					break;
				default:
					fail();
			}
		}
		else if (range.getLength() == 1) {
			switch (kind) {
				case SW_EXECUTE:
					waitOn(interpreter.execute("breakpoint set -a " + min));
					break;
				case HW_EXECUTE:
					waitOn(interpreter.execute("breakpoint set -H -a " + min));
					break;
				default:
					fail();
			}
		}
		else {
			fail();
		}
		LldbModelTargetSession session = (LldbModelTargetSession) interpreter;
		LldbModelTargetDebugContainer dc = (LldbModelTargetDebugContainer) session.getCachedAttribute("Debug");
		LldbModelTargetBreakpointContainer bc = (LldbModelTargetBreakpointContainer) dc.getCachedAttribute("Breakpoints");
		Map<String, ? extends TargetObject> map = bc.fetchElements().get();
		for (TargetObject val : map.values()) {
			val.fetchElements();
		}
	}
	
	private String getTypeFromSpec(TargetObject t) {
		boolean isExecute = t instanceof LldbModelTargetBreakpointSpec;
		return isExecute ? "breakpoint" : "watchpoint";
		
	}
	private String getTypeFromKind(TargetBreakpointKind kind) {
		boolean isExecute = kind.equals(TargetBreakpointKind.SW_EXECUTE) || kind.equals(TargetBreakpointKind.HW_EXECUTE);
		return isExecute ? "breakpoint" : "watchpoint";		
	}
	private String getCommand(String cmd, String type, String bpId) {
		return type + " " + cmd + " " + bpId.substring(1);
	}

	@Override
	protected void disableViaInterpreter(TargetTogglable t, TargetInterpreter interpreter)
			throws Throwable {
		String bpId = getBreakPattern().matchIndices(t.getPath()).get(BREAK_ID_POS);
		String type = getTypeFromSpec(t);
		waitOn(interpreter.execute(getCommand("disable", type, bpId)));
	}

	@Override
	protected void enableViaInterpreter(TargetTogglable t, TargetInterpreter interpreter)
			throws Throwable {
		String bpId = getBreakPattern().matchIndices(t.getPath()).get(BREAK_ID_POS);
		String type = getTypeFromSpec(t);
		waitOn(interpreter.execute(getCommand("enable", type, bpId)));
	}

	@Override
	protected void deleteViaInterpreter(TargetDeletable d, TargetInterpreter interpreter)
			throws Throwable {
		String bpId = getBreakPattern().matchIndices(d.getPath()).get(BREAK_ID_POS);
		String type = getTypeFromSpec(d);
		waitOn(interpreter.execute(getCommand("delete", type, bpId)));
	}

	@Override
	protected void assertLocCoversViaInterpreter(AddressRange range, TargetBreakpointKind kind,
			TargetBreakpointLocation loc, TargetInterpreter interpreter) throws Throwable {
		List<String> matchIndices = getBreakPattern().matchIndices(loc.getSpecification().getPath());
		String bpId = matchIndices.get(BREAK_ID_POS);
		String type = getTypeFromKind(kind);
		String line = waitOn(interpreter.executeCapture(getCommand("list", type, bpId))).trim();
		if (type.equals("breakpoint"))
			assertTrue(line.startsWith(bpId.substring(1)));			
		else 
			assertTrue(line.contains("Watchpoint " + bpId.substring(1)));
	}

	@Override
	protected void assertEnabledViaInterpreter(TargetTogglable t, boolean enabled,
			TargetInterpreter interpreter) throws Throwable {
		String bpId = getBreakPattern().matchIndices(t.getPath()).get(BREAK_ID_POS);
		String type = getTypeFromSpec(t);
		String line = waitOn(interpreter.executeCapture(getCommand("list", type, bpId))).trim();
		assertTrue(line.contains(bpId.substring(1)+":"));
		assertTrue(enabled == !line.contains("disable"));
	}

	@Override
	protected void assertDeletedViaInterpreter(TargetDeletable d, TargetInterpreter interpreter)
			throws Throwable {
		String bpId = getBreakPattern().matchIndices(d.getPath()).get(BREAK_ID_POS);
		String type = getTypeFromSpec(d);
		String line = waitOn(interpreter.executeCapture(type + " list ")).trim();
		assertFalse(line.contains(bpId+":"));
	}
}
