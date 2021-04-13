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

import java.lang.invoke.MethodHandles;
import java.util.List;
import java.util.Set;

import org.junit.Test;

import ghidra.dbg.AnnotatedDebuggerAttributeListener;
import ghidra.dbg.DebugModelConventions;
import ghidra.dbg.DebugModelConventions.AsyncState;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.util.PathMatcher;
import ghidra.dbg.util.PathPattern;
import ghidra.program.model.address.Address;
import ghidra.util.Msg;

public abstract class AbstractDebuggerModelScenarioStackTest extends AbstractDebuggerModelTest {

	/**
	 * This specimen must create a stack easily recognizable by examination of 4 frames' PCs
	 * 
	 * <p>
	 * This is accomplished by writing 4 functions where each calls the next, the innermost
	 * function's symbol providing an easily-placed breakpoint. When the breakpoint is hit, frame 0
	 * should be at the entry of the innermost function, and the pc for each frame after that should
	 * be within the body of its respective following function.
	 * 
	 * @return the specimen
	 */
	protected abstract DebuggerTestSpecimen getSpecimen();

	/**
	 * Perform any work needed after the specimen has been launched
	 * 
	 * @param process the process running the specimen
	 * @throws Throwable if anything goes wrong
	 */
	protected void postLaunch(TargetProcess process) throws Throwable {
	}

	/**
	 * Get the expression to break at the innermost recognizable function
	 * 
	 * <p>
	 * More than likely, this should just be the symbol for that function.
	 * 
	 * @return the expression
	 */
	protected abstract String getBreakpointExpression();

	/**
	 * Examine the address of the given frame and verify it is where expected
	 * 
	 * <p>
	 * Note if this validation needs access to the process, it should at least record where that
	 * process is by overriding {@link #postLaunch(TargetProcess)}. Ideally, it can perform all of
	 * the necessary lookups, e.g., to record symbol values, there instead of here.
	 * 
	 * @param index the index
	 * @param pc the program counter
	 */
	protected abstract void validateFramePC(int index, Address pc);

	/**
	 * Test the following scenario:
	 * 
	 * <ol>
	 * <li>Obtain a launcher and use it to start the specimen</li>
	 * <li>Place the breakpoint on the new process</li>
	 * <li>Resume the process until the breakpoint is hit</li>
	 * <li>Read the stack and verify the PC for each frame</li>
	 * <li>Resume the process until it is TERMINATED</li>
	 * </ol>
	 */
	@Test
	public void testScenario() throws Throwable {
		DebuggerTestSpecimen specimen = getSpecimen();
		m.build();

		var bpMonitor = new AnnotatedDebuggerAttributeListener(MethodHandles.lookup()) {
			boolean hit = false;

			@AttributeCallback(TargetExecutionStateful.STATE_ATTRIBUTE_NAME)
			private void stateChanged(TargetObject object, TargetExecutionState state) {
				Msg.debug(this, "STATE " + object.getJoinedPath(".") + " is now " + state);
			}

			@Override
			public void breakpointHit(TargetObject container, TargetObject trapped,
					TargetStackFrame frame, TargetBreakpointSpec spec,
					TargetBreakpointLocation breakpoint) {
				Msg.debug(this, "TRAPPED by " + spec);
				if (getBreakpointExpression().equals(spec.getExpression())) {
					hit = true;
					Msg.debug(this, "  Counted");
				}
			}
		};
		m.getModel().addModelListener(bpMonitor);

		Msg.debug(this, "Launching " + specimen);
		TargetLauncher launcher = findLauncher();
		waitOn(launcher.launch(specimen.getLauncherArgs()));
		Msg.debug(this, "  Done launching");
		TargetProcess process = retryForProcessRunning(specimen, this);
		postLaunch(process);

		TargetBreakpointSpecContainer breakpointContainer =
			findBreakpointSpecContainer(process.getPath());
		Msg.debug(this, "Placing breakpoint");
		waitOn(breakpointContainer.placeBreakpoint(getBreakpointExpression(),
			Set.of(TargetBreakpointKind.SW_EXECUTE)));

		assertTrue(DebugModelConventions.isProcessAlive(process));
		AsyncState state =
			new AsyncState(m.suitable(TargetExecutionStateful.class, process.getPath()));

		/**
		 * NB. If an assert(isAlive) is failing, check that breakpointHit() is emitted before
		 * attributeChanged(state=STOPPED)
		 */
		for (int i = 1; !bpMonitor.hit; i++) {
			assertTrue(state.get().isAlive());
			Msg.debug(this, "(" + i + ") Resuming process until breakpoint hit");
			resume(process);
			Msg.debug(this, "  Done " + i);
			waitOn(state.waitUntil(s -> s != TargetExecutionState.RUNNING));
		}
		assertTrue(state.get().isAlive());

		TargetStack stack = findStack(process.getPath());
		PathMatcher matcher = stack.getSchema().searchFor(TargetStackFrame.class, true);
		PathPattern pattern = matcher.getSingletonPattern();
		assertNotNull("Frames are not clearly indexable", pattern);
		assertEquals("Frames are not clearly indexable", 1, pattern.countWildcards());
		// Sort by path should present them innermost to outermost
		List<TargetStackFrame> frames = retry(() -> {
			List<TargetStackFrame> result =
				List.copyOf(m.findAll(TargetStackFrame.class, stack.getPath(), true).values());
			assertTrue("Fewer than 4 frames", result.size() > 4);
			return result;
		}, List.of(AssertionError.class));
		for (int i = 0; i < 4; i++) {
			TargetStackFrame f = frames.get(i);
			validateFramePC(i, f.getProgramCounter());
		}

		for (int i = 1; DebugModelConventions.isProcessAlive(process); i++) {
			Msg.debug(this, "(" + i + ") Resuming process until terminated");
			resume(process);
			Msg.debug(this, "  Done " + i);
			waitOn(state.waitUntil(s -> s != TargetExecutionState.RUNNING));
		}
	}
}
