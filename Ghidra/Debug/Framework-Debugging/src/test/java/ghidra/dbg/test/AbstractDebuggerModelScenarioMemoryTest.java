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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

import java.lang.invoke.MethodHandles;
import java.util.Objects;

import org.junit.Assert;
import org.junit.Test;

import ghidra.dbg.AnnotatedDebuggerAttributeListener;
import ghidra.dbg.DebugModelConventions;
import ghidra.dbg.DebugModelConventions.AsyncState;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.program.model.address.Address;
import ghidra.util.Msg;

/**
 * A scenario that verifies memory writes affect the target
 */
public abstract class AbstractDebuggerModelScenarioMemoryTest extends AbstractDebuggerModelTest {

	/**
	 * This specimen must perform some observable action, which can be affected by a memory write
	 * 
	 * <p>
	 * A common example is to exit with a code read from memory. It may also be useful for debugging
	 * purposes to print a message from the same memory.
	 * 
	 * @return the specimen
	 */
	protected abstract DebuggerTestSpecimen getSpecimen();

	/**
	 * Get the destination address to write to
	 * 
	 * <p>
	 * The most reliable way to do this is to ensure an easily identifiable symbol for the
	 * destination address is exported, then use the debugging API to obtain its address.
	 * 
	 * @param process the process running the specimen
	 * @return the destination address
	 * @throws Throwable if anything goes wrong
	 */
	protected abstract Address getAddressToWrite(TargetProcess process) throws Throwable;

	/**
	 * Get the bytes to write
	 * 
	 * <p>
	 * It's probably best to use a string encoded in the platform's preferred format.
	 * 
	 * @return the bytes
	 */
	protected abstract byte[] getBytesToWrite();

	/**
	 * Get the expected bytes after read
	 * 
	 * <p>
	 * This should be the same as {@link #getBytesToWrite()}, but preferably includes some
	 * additional bytes after, so that memory reads can be verified to come from the actual target,
	 * and not just from a cached write. A common scenario is to partially write over a string, then
	 * read the entire string, verifying both the overwritten part and the remainder.
	 * 
	 * @return the bytes
	 */
	protected abstract byte[] getExpectedBytes();

	/**
	 * Perform whatever preparation is necessary to observe the expected effect
	 * 
	 * @param process the process trapped at launch -- typically at {@code main()}.
	 * @throws Throwable if anything goes wrong
	 */
	protected void postLaunch(TargetProcess process) throws Throwable {
	}

	/**
	 * Verify, using {@link Assert}, that the target exhibited the effect of the memory write
	 * 
	 * <p>
	 * Note that the given process may be invalid, depending on the model's implementation. The
	 * tester should know how the model under test behaves. If the object is invalid, it's possible
	 * its attributes were updated immediately preceding invalidation with observable information,
	 * but this is usually not the case. The better approach is to devise an effect that can be
	 * observed in an event callback. To install such a listener, override
	 * {@link #postLaunch(TargetProcess)} and record the relevant information to be validated here.
	 * Do not place assertions in the event callback, since the failures they could produce will not
	 * be recorded as test failures. If the effect can be observed in multiple ways, it is best to
	 * verify all of them.
	 * 
	 * @param process the target process, which may no longer be valid
	 * @throws Throwable if anything goes wrong or an assertion fails
	 */
	protected abstract void verifyExpectedEffect(TargetProcess process) throws Throwable;

	/**
	 * Test the following scenario:
	 * 
	 * <ol>
	 * <li>Obtain a launcher and use it to start the specimen</li>
	 * <li>Overwrite bytes at a designated address in memory</li>
	 * <li>Read those bytes and verify they were modified</li>
	 * <li>Resume the process until it is TERMINATED</li>
	 * <li>Verify some effect, usually the exit code</li>
	 * </ol>
	 */
	@Test
	public void testScenario() throws Throwable {
		DebuggerTestSpecimen specimen = getSpecimen();
		m.build();

		// For model developer diagnostics
		var stateMonitor = new AnnotatedDebuggerAttributeListener(MethodHandles.lookup()) {
			@AttributeCallback(TargetExecutionStateful.STATE_ATTRIBUTE_NAME)
			private void stateChanged(TargetObject obj, TargetExecutionState state) {
				Msg.debug(this, obj.getJoinedPath(".") + " is now " + state);
			}
		};
		m.getModel().addModelListener(stateMonitor);

		TargetLauncher launcher = findLauncher();
		Msg.debug(this, "Launching " + specimen);
		waitOn(launcher.launch(specimen.getLauncherArgs()));
		Msg.debug(this, "  Done launching");
		TargetProcess process = retryForProcessRunning(specimen, this);
		postLaunch(process);

		Address address = Objects.requireNonNull(getAddressToWrite(process));
		byte[] data = Objects.requireNonNull(getBytesToWrite());
		TargetMemory memory = Objects.requireNonNull(findMemory(process.getPath()));
		Msg.debug(this, "Writing memory");
		waitOn(memory.writeMemory(address, data));
		Msg.debug(this, "  Done");
		byte[] expected = getExpectedBytes();
		byte[] read = waitOn(memory.readMemory(address, expected.length));
		assertArrayEquals(expected, read);

		assertTrue(DebugModelConventions.isProcessAlive(process));
		AsyncState state =
			new AsyncState(m.suitable(TargetExecutionStateful.class, process.getPath()));

		for (int i = 1; DebugModelConventions.isProcessAlive(process); i++) {
			Msg.debug(this, "(" + i + ") Resuming process until terminated");
			resume(process);
			Msg.debug(this, "  Done " + i);
			waitOn(state.waitUntil(s -> s != TargetExecutionState.RUNNING));
			Msg.debug(this, "Parent state after resume-wait-not-running: " + state);
		}

		verifyExpectedEffect(process);
	}
}
