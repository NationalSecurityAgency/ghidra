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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.lang.invoke.MethodHandles;
import java.util.*;

import org.junit.Test;

import ghidra.dbg.AnnotatedDebuggerAttributeListener;
import ghidra.dbg.DebugModelConventions;
import ghidra.dbg.DebugModelConventions.AsyncState;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.util.Msg;

/**
 * A scenario which tests a single process with two threads
 */
public abstract class AbstractDebuggerModelScenarioCloneExitTest extends AbstractDebuggerModelTest {
	/**
	 * Time to wait to observe the child from the clone before resuming again
	 */
	public static final long WAIT_FOR_CHILD_MS = 1000;

	/**
	 * This specimen must clone or similar, and then both parent and child must exit immediately
	 * 
	 * <p>
	 * They may optionally print information, but they cannot spin, sleep, or otherwise hang around.
	 * 
	 * @return the specimen
	 */
	protected abstract DebuggerTestSpecimen getSpecimen();

	/**
	 * Perform whatever preparation is necessary to ensure the child will remain attached and be
	 * trapped upon its being clone from its parent
	 * 
	 * <p>
	 * If this cannot be done without a handle to the parent process, override
	 * {@link #postLaunch(TargetObject, TargetProcess)} instead.
	 * 
	 * @param launcher the launcher
	 * @throws Throwable if anything goes wrong
	 */
	protected void preLaunch(TargetLauncher launcher) throws Throwable {
	}

	/**
	 * Perform whatever preparation is necessary to ensure the child will remain attached and be
	 * trapped upon its being cloned from its parent
	 * 
	 * <p>
	 * For most debuggers, no special setup is necessary.
	 * 
	 * @param process the process trapped at launch -- typically at {@code main()}.
	 * @throws Throwable if anything goes wrong
	 */
	protected void postLaunch(TargetProcess process) throws Throwable {
	}

	/**
	 * Get a breakpoint expression that will trap both threads post-clone
	 * 
	 * @return the expression
	 */
	protected abstract String getBreakpointExpression();

	/**
	 * Test the following scenario:
	 * 
	 * <ol>
	 * <li>Obtain a launcher and use it to start the specimen</li>
	 * <li>Place a breakpoint on the new process</li>
	 * <li>Resume the process until it is TERMINATED</li>
	 * <li>Verify exactly two unique threads were trapped by the breakpoint</li>
	 * </ol>
	 * 
	 * <p>
	 * Note because some platforms, notably Windows, may produce additional threads before executing
	 * {@code main}, we cannot simply count THREAD_CREATED events. We mitigate this by using a
	 * breakpoint which should only trap threads executing user code. Note that we do not verify
	 * which thread is trapped first, since we do not control thread scheduling.
	 */
	@Test
	public void testScenario() throws Throwable {
		DebuggerTestSpecimen specimen = getSpecimen();
		m.build();

		List<TargetObject> trapped = new ArrayList<>();
		var monitor = new AnnotatedDebuggerAttributeListener(MethodHandles.lookup()) {
			// For model developer diagnostics
			@AttributeCallback(TargetExecutionStateful.STATE_ATTRIBUTE_NAME)
			private void stateChanged(TargetObject obj, TargetExecutionState state) {
				Msg.debug(this, obj.getJoinedPath(".") + " is now " + state);
			}

			@Override
			public void breakpointHit(TargetObject container, TargetObject thread,
					TargetStackFrame frame, TargetBreakpointSpec spec,
					TargetBreakpointLocation breakpoint) {
				Msg.debug(this, thread.getJoinedPath(".") + " trapped by " +
					breakpoint.getJoinedPath(".") + " (" + spec.getExpression() + ")");
				if (spec.getExpression().equals(getBreakpointExpression())) {
					Msg.debug(this, "  Counted");
					trapped.add(thread);
				}
			}
		};
		m.getModel().addModelListener(monitor);

		TargetLauncher launcher = findLauncher();
		preLaunch(launcher);
		Msg.debug(this, "Launching " + specimen);
		waitOn(launcher.launch(specimen.getLauncherArgs()));
		Msg.debug(this, "  Done launching");
		TargetProcess process = retryForProcessRunning(specimen, this);
		postLaunch(process);
		TargetBreakpointSpecContainer bpContainer =
			findBreakpointSpecContainer(process.getPath());
		Msg.debug(this, "Placing breakpoint");
		waitOn(bpContainer.placeBreakpoint(getBreakpointExpression(),
			Set.of(TargetBreakpointKind.SW_EXECUTE)));

		assertTrue(DebugModelConventions.isProcessAlive(process));
		AsyncState state =
			new AsyncState(m.suitable(TargetExecutionStateful.class, process.getPath()));

		for (int i = 1; DebugModelConventions.isProcessAlive(process); i++) {
			Msg.debug(this, "(" + i + ") Resuming process until terminated");
			resume(process);
			Msg.debug(this, "  Done " + i);
			waitOn(state.waitUntil(s -> s != TargetExecutionState.RUNNING));
		}

		assertEquals(2, trapped.size());
		assertEquals(2, Set.copyOf(trapped).size());
	}
}
