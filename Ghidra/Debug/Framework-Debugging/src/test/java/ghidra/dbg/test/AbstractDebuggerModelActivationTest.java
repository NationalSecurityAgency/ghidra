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
package ghidra.dbg.test;

import static org.junit.Assert.*;
import static org.junit.Assume.*;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.Test;

import generic.Unique;
import ghidra.dbg.target.*;
import ghidra.dbg.util.PathUtils;

/**
 * Test model object activation and focus
 * 
 * <p>
 * Activation and focus are related but separate concepts. Focus is a little looser, and is allowed
 * by the model to exactly match the client's notion of focus, usually indicating the object of the
 * user's interest. Activation, however, commands the model to make the given object the "current"
 * object. This implies any commands issued to the CLI will affect the active object. The model
 * reflects the active object back to the client via focus. This allows the model and client to
 * synchronize their "active" objects, while reducing the likelihood of event feedback loops.
 * Furthermore, not every object can be activated. For example, activating a register will likely
 * result in the containing thread or frame becoming active instead. Or, activating a thread may
 * result in its innermost frame becoming active as well.
 */
public abstract class AbstractDebuggerModelActivationTest extends AbstractDebuggerModelTest {

	/**
	 * Use the interpreter to activate the given object
	 * 
	 * @param obj the object to activate
	 * @param interpreter the interpreter to use
	 * @throws Throwable if anything goes wrong
	 */
	protected void activateViaInterpreter(TargetObject obj, TargetInterpreter interpreter)
			throws Throwable {
		fail("Unless hasInterpreter is false, the test must implement this method");
	}

	/**
	 * Use the interpreter to verify the given object is active/current
	 * 
	 * <p>
	 * Note, it may be necessary to run and capture several commands, depending on what's being
	 * verified and what sort of commands the interpreter makes available. For example, to verify a
	 * frame is active, the test should check that the containing thread and process are active,
	 * too.
	 * 
	 * @param expected the expected active or current object
	 * @param interpreter the interpreter to use
	 * @throws Throwable if anything goes wrong
	 */
	protected void assertActiveViaInterpreter(TargetObject expected,
			TargetInterpreter interpreter) throws Throwable {
		fail("Unless hasInterpreter is false, the test must implement this method");
	}

	/**
	 * Get (possibly generate) things for this focus test to try out
	 * 
	 * @throws Throwable if anything goes wrong
	 */
	protected abstract Set<TargetObject> getActivatableThings() throws Throwable;

	/**
	 * Governs whether assertions permit the actual object to be a successor of the expected object
	 * 
	 * @return true to permit successors, false to require exact
	 */
	protected boolean permitSuccessor() {
		return true;
	}

	protected void assertSuccessorOrExact(TargetObject expected, TargetObject actual) {
		assertNotNull(actual);
		if (permitSuccessor()) {
			assertTrue("Expected successor of '" + expected.getJoinedPath(".") +
				"' got '" + actual.getJoinedPath(".") + "'",
				PathUtils.isAncestor(expected.getPath(), actual.getPath()));
		}
		else {
			assertSame(expected, actual);
		}
	}

	/**
	 * If the default focus is one of the activatable things (after generation), assert its path
	 * 
	 * @return the path of the expected default focus, or {@code null} for no assertion
	 */
	protected List<String> getExpectedDefaultActivePath() {
		return null;
	}

	@Test
	public void testDefaultFocusIsAsExpected() throws Throwable {
		List<String> expectedDefaultFocus = getExpectedDefaultActivePath();
		assumeNotNull(expectedDefaultFocus);
		m.build();

		TargetFocusScope focusScope = findFocusScope();
		Set<TargetObject> activatable = getActivatableThings();
		// The default must be one of the activatable objects
		TargetObject obj = Unique.assertOne(activatable.stream()
				.filter(f -> PathUtils.isAncestor(f.getPath(), expectedDefaultFocus))
				.collect(Collectors.toList()));
		retryVoid(() -> {
			assertEquals(expectedDefaultFocus, focusScope.getFocus().getPath());
		}, List.of(AssertionError.class));
		if (m.hasInterpreter()) {
			TargetInterpreter interpreter = findInterpreter();
			assertActiveViaInterpreter(obj, interpreter);
		}
	}

	@Test
	public void testActivateEachOnce() throws Throwable {
		m.build();

		TargetFocusScope focusScope = findFocusScope();
		TargetActiveScope activeScope = findActiveScope();
		Set<TargetObject> activatable = getActivatableThings();
		for (TargetObject obj : activatable) {
			waitOn(activeScope.requestActivation(obj));
			retryVoid(() -> {
				assertSuccessorOrExact(obj, focusScope.getFocus());
			}, List.of(AssertionError.class));
			if (m.hasInterpreter()) {
				TargetInterpreter interpreter = findInterpreter();
				assertActiveViaInterpreter(obj, interpreter);
			}
		}

	}

	@Test
	public void testActivateEachTwice() throws Throwable {
		m.build();

		TargetFocusScope focusScope = findFocusScope();
		TargetActiveScope activeScope = findActiveScope();
		Set<TargetObject> activatable = getActivatableThings();
		for (TargetObject obj : activatable) {
			waitOn(activeScope.requestActivation(obj));
			retryVoid(() -> {
				assertSuccessorOrExact(obj, focusScope.getFocus());
			}, List.of(AssertionError.class));
			if (m.hasInterpreter()) {
				TargetInterpreter interpreter = findInterpreter();
				assertActiveViaInterpreter(obj, interpreter);
			}
			waitOn(activeScope.requestActivation(obj));
			retryVoid(() -> {
				assertSuccessorOrExact(obj, focusScope.getFocus());
			}, List.of(AssertionError.class));
			if (m.hasInterpreter()) {
				TargetInterpreter interpreter = findInterpreter();
				assertActiveViaInterpreter(obj, interpreter);
			}
		}
	}

	@Test
	public void testActivateEachViaInterpreter() throws Throwable {
		assumeTrue(m.hasInterpreter());
		m.build();

		TargetFocusScope focusScope = findFocusScope();
		Set<TargetObject> activatable = getActivatableThings();
		TargetInterpreter interpreter = findInterpreter();
		for (TargetObject obj : activatable) {
			activateViaInterpreter(obj, interpreter);
			retryVoid(() -> {
				assertSuccessorOrExact(obj, focusScope.getFocus());
			}, List.of(AssertionError.class));
			assertActiveViaInterpreter(obj, interpreter);
		}
	}
}
