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

import ghidra.dbg.target.TargetLauncher;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.test.AbstractDebuggerModelFocusTest;
import ghidra.dbg.util.PathUtils;

public abstract class AbstractModelForGdbThreadFocusTest extends AbstractDebuggerModelFocusTest {

	protected DebuggerTestSpecimen getSpecimen() {
		return GdbLinuxSpecimen.ECHO_HW;
	}

	@Override
	protected Set<TargetObject> getFocusableThings() throws Throwable {
		CompletableFuture<?> inf1 =
			m.getAddedWaiter().wait(PathUtils.parse("Inferiors[1].Threads[1]"));
		CompletableFuture<?> inf2 =
			m.getAddedWaiter().wait(PathUtils.parse("Inferiors[2].Threads[2]"));

		DebuggerTestSpecimen specimen = getSpecimen();
		TargetLauncher launcher = findLauncher(); // root launcher should generate new inferiors
		waitOn(launcher.launch(specimen.getLauncherArgs()));
		waitOn(launcher.launch(specimen.getLauncherArgs()));

		return Set.of(
			(TargetObject) waitOn(inf1),
			(TargetObject) waitOn(inf2));
	}

	@Override
	protected List<String> getExpectedDefaultFocus() {
		return PathUtils.parse("Inferiors[2].Threads[2]");
	}
}
