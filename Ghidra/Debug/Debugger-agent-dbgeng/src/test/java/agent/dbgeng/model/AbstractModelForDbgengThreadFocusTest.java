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

import static org.junit.Assert.assertEquals;

import java.util.*;

import ghidra.dbg.target.*;
import ghidra.dbg.test.AbstractDebuggerModelFocusTest;
import ghidra.dbg.util.PathUtils;

public abstract class AbstractModelForDbgengThreadFocusTest
		extends AbstractDebuggerModelFocusTest {

	protected int getCount() {
		return 3;
	}

	protected DebuggerTestSpecimen getSpecimen() {
		return WindowsSpecimen.PRINT;
	}

	@Override
	protected Set<TargetObject> getFocusableThings() throws Throwable {
		DebuggerTestSpecimen specimen = getSpecimen();
		TargetLauncher launcher = findLauncher();
		int count = getCount();
		for (int i = 0; i < count; i++) {
			waitOn(launcher.launch(specimen.getLauncherArgs()));
		}
		return retry(() -> {
			Map<List<String>, TargetThread> found =
				m.findAll(TargetThread.class, PathUtils.parse("Sessions[0]"));
			assertEquals(count, found.size());
			return Set.copyOf(found.values());
		}, List.of(AssertionError.class));
	}
}
