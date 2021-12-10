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

import static org.junit.Assume.*;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.Test;

import generic.Unique;
import ghidra.dbg.target.*;
import ghidra.dbg.test.AbstractDebuggerModelActivationTest;
import ghidra.dbg.util.PathPattern;

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
public abstract class AbstractModelForLldbActivationTest extends AbstractDebuggerModelActivationTest {

	@Test
	public void testDefaultFocusIsAsExpected() throws Throwable {
		List<String> expectedDefaultFocus = getExpectedDefaultActivePath();
		assumeNotNull(expectedDefaultFocus);
		m.build();

		PathPattern pathPattern = new PathPattern(expectedDefaultFocus);		
		Set<TargetObject> activatable = getActivatableThings();
		// The default must be one of the activatable objects
		TargetObject obj = Unique.assertOne(activatable.stream()
				.filter(f -> pathPattern.matches(f.getPath()))
				.collect(Collectors.toList()));
		if (m.hasInterpreter()) {
			TargetInterpreter interpreter = findInterpreter();
			assertActiveViaInterpreter(obj, interpreter);
		}
	}

	@Test
	public void testActivateEachOnce() throws Throwable {
		m.build();

		TargetActiveScope activeScope = findActiveScope();
		Set<TargetObject> activatable = getActivatableThings();
		for (TargetObject obj : activatable) {
			waitOn(activeScope.requestActivation(obj));
			if (m.hasInterpreter()) {
				TargetInterpreter interpreter = findInterpreter();
				assertActiveViaInterpreter(obj, interpreter);
			}
		}

	}

	@Test
	public void testActivateEachTwice() throws Throwable {
		m.build();

		TargetActiveScope activeScope = findActiveScope();
		Set<TargetObject> activatable = getActivatableThings();
		for (TargetObject obj : activatable) {
			waitOn(activeScope.requestActivation(obj));
			if (m.hasInterpreter()) {
				TargetInterpreter interpreter = findInterpreter();
				assertActiveViaInterpreter(obj, interpreter);
			}
			waitOn(activeScope.requestActivation(obj));
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

		Set<TargetObject> activatable = getActivatableThings();
		TargetInterpreter interpreter = findInterpreter();
		for (TargetObject obj : activatable) {
			activateViaInterpreter(obj, interpreter);
			assertActiveViaInterpreter(obj, interpreter);
		}
	}
}
