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
import static org.junit.Assume.*;

import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.Test;

import SWIG.SBTarget;
import agent.lldb.model.iface2.LldbModelTargetSession;
import generic.Unique;
import ghidra.dbg.target.*;
import ghidra.dbg.test.AbstractDebuggerModelActivationTest;
import ghidra.dbg.util.PathPattern;

public abstract class AbstractModelForLldbSessionActivationTest
		extends AbstractDebuggerModelActivationTest {

	protected abstract PathPattern getSessionPattern();

	protected int getCount() {
		return 3;
	}

	protected DebuggerTestSpecimen getSpecimen() {
		return MacOSSpecimen.PRINT;
	}

	public abstract List<String> getExpectedSessionPath();

	public abstract String getIndexFromCapture(String line);

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
			Map<List<String>, TargetInterpreter> found =
				m.findAll(TargetInterpreter.class, getExpectedSessionPath(), true);
			assertEquals(count, found.size());
			return Set.copyOf(found.values());
		}, List.of(AssertionError.class));
	}

	@Override
	protected void activateViaInterpreter(TargetObject obj, TargetInterpreter interpreter)
			throws Throwable {
		LldbModelTargetSession session = (LldbModelTargetSession) obj;
		SBTarget sbt = (SBTarget) session.getModelObject();
		BigInteger procId = sbt.GetProcess().GetProcessID();
		String output = waitOn(interpreter.executeCapture("target list"));
		String[] split = output.split("\n");
		String index = null;
		for (String l : split) {
			if (l.contains(procId.toString(10))) {
				index = getIndexFromCapture(l);
				break;
			}
		}
		assertNotEquals(index, null);
		waitOn(interpreter.execute("target select " + index));
	}

	public abstract String getIdFromCapture(String line);

	@Override
	protected void assertActiveViaInterpreter(TargetObject expected, TargetInterpreter interpreter)
			throws Throwable {
		String output = waitOn(interpreter.executeCapture("target list"));
		String line = Unique.assertOne(Stream.of(output.split("\n"))
				.filter(l -> l.trim().startsWith("*"))
				.collect(Collectors.toList())).trim();
		String procId = getIdFromCapture(line);
		String expId = getSessionPattern().matchIndices(expected.getPath()).get(0);
		assertEquals(Long.parseLong(expId, 16), Long.parseLong(procId));
	}

	protected TargetInterpreter findInterpreter(TargetObject obj) throws Throwable {
		return (TargetInterpreter) obj;
	}

	// All of the original tests assertSuccessorOrExact on focusScope 
	//  which is not true in the lldb case

	@Override
	@Test
	public void testDefaultFocusIsAsExpected() throws Throwable {
		List<String> expectedDefaultFocus = getExpectedDefaultActivePath();
		assumeNotNull(expectedDefaultFocus);
		m.build();

		Set<TargetObject> activatable = getActivatableThings();
		Map<List<String>, TargetInterpreter> found =
			m.findAll(TargetInterpreter.class, getExpectedSessionPath(), true);
		// The default must be one of the activatable objects
		Object[] keys = found.keySet().toArray();
		TargetObject obj = found.get(keys[keys.length - 1]);
		assertTrue(activatable.contains(obj));
		if (m.hasInterpreter()) {
			TargetInterpreter interpreter = findInterpreter(obj);
			assertActiveViaInterpreter(obj, interpreter);
		}
	}

	@Override
	@Test
	public void testActivateEachOnce() throws Throwable {
		m.build();

		TargetActiveScope activeScope = findActiveScope();
		Set<TargetObject> activatable = getActivatableThings();
		for (TargetObject obj : activatable) {
			waitOn(activeScope.requestActivation(obj));
			if (m.hasInterpreter()) {
				TargetInterpreter interpreter = findInterpreter(obj);
				assertActiveViaInterpreter(obj, interpreter);
			}
		}

	}

	@Override
	@Test
	public void testActivateEachTwice() throws Throwable {
		m.build();

		TargetActiveScope activeScope = findActiveScope();
		Set<TargetObject> activatable = getActivatableThings();
		for (TargetObject obj : activatable) {
			waitOn(activeScope.requestActivation(obj));
			if (m.hasInterpreter()) {
				TargetInterpreter interpreter = findInterpreter(obj);
				assertActiveViaInterpreter(obj, interpreter);
			}
			waitOn(activeScope.requestActivation(obj));
			if (m.hasInterpreter()) {
				TargetInterpreter interpreter = findInterpreter(obj);
				assertActiveViaInterpreter(obj, interpreter);
			}
		}
	}

	@Override
	@Test
	public void testActivateEachViaInterpreter() throws Throwable {
		assumeTrue(m.hasInterpreter());
		m.build();

		Set<TargetObject> activatable = getActivatableThings();
		for (TargetObject obj : activatable) {
			TargetInterpreter interpreter = findInterpreter(obj);
			activateViaInterpreter(obj, interpreter);
			assertActiveViaInterpreter(obj, interpreter);
		}
	}
}
