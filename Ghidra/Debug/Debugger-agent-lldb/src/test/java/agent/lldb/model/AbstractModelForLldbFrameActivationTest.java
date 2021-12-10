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

import java.util.*;

import ghidra.dbg.target.*;
import ghidra.dbg.util.PathPattern;

public abstract class AbstractModelForLldbFrameActivationTest
		extends AbstractModelForLldbActivationTest {

	protected abstract PathPattern getStackPattern();

	protected DebuggerTestSpecimen getSpecimen() {
		return MacOSSpecimen.STACK;
	}

	@Override
	protected Set<TargetObject> getActivatableThings() throws Throwable {
		DebuggerTestSpecimen specimen = getSpecimen();
		TargetLauncher launcher = findLauncher(); // root launcher should generate new inferiors
		waitOn(launcher.launch(specimen.getLauncherArgs()));

		TargetProcess process = retry(() -> {
			TargetProcess p = m.findAny(TargetProcess.class, seedPath());
			assertNotNull(p);
			return p;
		}, List.of(AssertionError.class));

		trapAt("break_here", process);

		waitSettled(m.getModel(), 200);

		return retry(() -> {
			Map<List<String>, TargetStackFrame> frames =
				m.findAll(TargetStackFrame.class, seedPath(), true);
			assertTrue(frames.size() >= 3);
			return Set.copyOf(frames.values());
		}, List.of(AssertionError.class));
	}

	protected void activateViaInterpreter(TargetObject obj, TargetInterpreter interpreter)
			throws Throwable {
		String index = getStackPattern().matchIndices(obj.getPath()).get(3);
		waitOn(interpreter.execute("frame select " + index));
	}

	public abstract String getIdFromCapture(String line);

	@Override
	protected void assertActiveViaInterpreter(TargetObject expected, TargetInterpreter interpreter)
			throws Throwable {
		String line = waitOn(interpreter.executeCapture("frame info")).trim();
		assertFalse(line.contains("\n"));
		String id = getIdFromCapture(line);
		int frameId = Integer.parseInt(id, 10);
		int expId = Integer.decode(getStackPattern().matchIndices(expected.getPath()).get(3));
		assertEquals(expId, frameId);
	}

}
