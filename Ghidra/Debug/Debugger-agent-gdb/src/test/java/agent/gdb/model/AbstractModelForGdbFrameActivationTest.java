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
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import generic.Unique;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.test.AbstractDebuggerModelActivationTest;
import ghidra.dbg.util.PathPattern;
import ghidra.dbg.util.PathUtils;

public abstract class AbstractModelForGdbFrameActivationTest
		extends AbstractDebuggerModelActivationTest {

	private static final PathPattern STACK_PATTERN =
		new PathPattern(PathUtils.parse("Inferiors[1].Threads[1].Stack[]"));

	DebuggerTestSpecimen getSpecimen() {
		return GdbLinuxSpecimen.STACK;
	}

	@Override
	protected Set<TargetObject> getActivatableThings() throws Throwable {
		CompletableFuture<?> frame0 =
			m.getAddedWaiter().wait(PathUtils.parse("Inferiors[1].Threads[1].Stack[0]"));
		CompletableFuture<?> frame1 =
			m.getAddedWaiter().wait(PathUtils.parse("Inferiors[1].Threads[1].Stack[1]"));
		CompletableFuture<?> frame2 =
			m.getAddedWaiter().wait(PathUtils.parse("Inferiors[1].Threads[1].Stack[2]"));

		DebuggerTestSpecimen specimen = getSpecimen();
		TargetLauncher launcher = findLauncher(); // root launcher should generate new inferiors
		waitOn(launcher.launch(specimen.getLauncherArgs()));
		TargetBreakpointSpecContainer breakpoints = findBreakpointSpecContainer(List.of());
		waitOn(breakpoints.placeBreakpoint("break_here", Set.of(TargetBreakpointKind.SW_EXECUTE)));
		TargetResumable inf =
			(TargetResumable) waitOn(m.getAddedWaiter().wait(PathUtils.parse("Inferiors[1]")));
		waitOn(inf.resume());

		waitSettled(m.getModel(), 200);

		return Set.of(
			(TargetObject) waitOn(frame0),
			(TargetObject) waitOn(frame1),
			(TargetObject) waitOn(frame2));
	}

	@Override
	protected List<String> getExpectedDefaultActivePath() {
		return PathUtils.parse("Inferiors[1].Threads[1].Stack[0]");
	}

	@Override
	protected void activateViaInterpreter(TargetObject obj, TargetInterpreter interpreter)
			throws Throwable {
		String index = Unique.assertOne(STACK_PATTERN.matchIndices(obj.getPath()));
		waitOn(interpreter.execute("frame " + index));
	}

	@Override
	protected void assertActiveViaInterpreter(TargetObject expected, TargetInterpreter interpreter)
			throws Throwable {
		String line = waitOn(interpreter.executeCapture("frame")).trim();
		assertFalse(line.contains("\n"));
		assertTrue(line.startsWith("#"));
		String frameLevel = line.substring(1).split("\\s+")[0];
		assertEquals(expected.getPath(), STACK_PATTERN.applyIndices(frameLevel).getSingletonPath());
	}
}
