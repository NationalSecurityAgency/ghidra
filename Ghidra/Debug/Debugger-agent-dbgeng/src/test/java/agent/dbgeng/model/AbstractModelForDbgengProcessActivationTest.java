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

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import generic.Unique;
import ghidra.dbg.target.*;
import ghidra.dbg.test.AbstractDebuggerModelActivationTest;
import ghidra.dbg.util.PathPattern;

public abstract class AbstractModelForDbgengProcessActivationTest
		extends AbstractDebuggerModelActivationTest {

	protected abstract PathPattern getProcessPattern();

	protected int getCount() {
		return 3;
	}

	protected DebuggerTestSpecimen getSpecimen() {
		return WindowsSpecimen.PRINT;
	}

	public abstract List<String> getExpectedSessionPath();

	@Override
	protected Set<TargetObject> getActivatableThings() throws Throwable {
		DebuggerTestSpecimen specimen = getSpecimen();
		TargetLauncher launcher = findLauncher();
		int count = getCount();
		for (int i = 0; i < count; i++) {
			waitOn(launcher.launch(specimen.getLauncherArgs()));
		}

		waitSettled(m.getModel(), 200);

		return retry(() -> {
			Map<List<String>, TargetProcess> found =
				m.findAll(TargetProcess.class, getExpectedSessionPath(), true);
			assertEquals(count, found.size());
			return Set.copyOf(found.values());
		}, List.of(AssertionError.class));
	}

	@Override
	protected void activateViaInterpreter(TargetObject obj, TargetInterpreter interpreter)
			throws Throwable {
		String id = Unique.assertOne(getProcessPattern().matchIndices(obj.getPath()));
		waitOn(interpreter.execute("|" + id + " s"));
	}

	public abstract String getIdFromCapture(String line);

	@Override
	protected void assertActiveViaInterpreter(TargetObject expected, TargetInterpreter interpreter)
			throws Throwable {
		String output = waitOn(interpreter.executeCapture("|"));
		String line = Unique.assertOne(Stream.of(output.split("\n"))
				.filter(l -> l.trim().startsWith("."))
				.collect(Collectors.toList())).trim();
		String procId = getIdFromCapture(line);
		assertEquals(expected.getPath(),
			getProcessPattern().applyIndices(procId).getSingletonPath());
	}
}
