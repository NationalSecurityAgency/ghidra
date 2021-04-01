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

import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.test.AbstractDebuggerModelFocusTest;
import ghidra.dbg.util.PathUtils;

public abstract class AbstractModelForGdbFrameFocusTest extends AbstractDebuggerModelFocusTest {

	DebuggerTestSpecimen getSpecimen() {
		return GdbLinuxSpecimen.STACK;
	}

	@Override
	protected Set<TargetObject> getFocusableThings() throws Throwable {
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

		return Set.of(
			(TargetObject) waitOn(frame0),
			(TargetObject) waitOn(frame1),
			(TargetObject) waitOn(frame2));
	}

	@Override
	protected List<String> getExpectedDefaultFocus() {
		return PathUtils.parse("Inferiors[1].Threads[1].Stack[0]");
	}
}
