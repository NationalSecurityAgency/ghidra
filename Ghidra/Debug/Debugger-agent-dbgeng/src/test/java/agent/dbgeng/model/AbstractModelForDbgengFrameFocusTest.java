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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.*;

import ghidra.dbg.target.*;
import ghidra.dbg.test.AbstractDebuggerModelFocusTest;

public abstract class AbstractModelForDbgengFrameFocusTest
		extends AbstractDebuggerModelFocusTest {

	protected DebuggerTestSpecimen getSpecimen() {
		return WindowsSpecimen.STACK;
	}

	@Override
	protected Set<TargetObject> getFocusableThings() throws Throwable {
		DebuggerTestSpecimen specimen = getSpecimen();
		TargetLauncher launcher = findLauncher(); // root launcher should generate new inferiors
		waitOn(launcher.launch(specimen.getLauncherArgs()));

		TargetProcess process = retry(() -> {
			TargetProcess p = m.findAny(TargetProcess.class, seedPath());
			assertNotNull(p);
			return p;
		}, List.of(AssertionError.class));

		trapAt("expStack!break_here", process);

		return retry(() -> {
			Map<List<String>, TargetStackFrame> frames =
				m.findAll(TargetStackFrame.class, seedPath(), true);
			assertTrue(frames.size() >= 3);
			return Set.copyOf(frames.values());
		}, List.of(AssertionError.class));
	}
}
