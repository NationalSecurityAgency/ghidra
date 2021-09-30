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

import static org.junit.Assert.assertTrue;

import java.lang.invoke.MethodHandles;
import java.util.*;
import java.util.concurrent.CompletableFuture;

import org.junit.Assert;
import org.junit.Test;

import ghidra.dbg.AnnotatedDebuggerAttributeListener;
import ghidra.dbg.DebugModelConventions;
import ghidra.dbg.DebugModelConventions.AsyncState;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.util.Msg;

public abstract class AbstractDebuggerModelScenarioRegistersTest extends AbstractDebuggerModelTest {

	/**
	 * This specimen must have an observable behavior which can be effected by writing a register
	 * 
	 * <p>
	 * The simplest is probably to exit with a code from a known register. This can probably be best
	 * accomplished by having main call {@code exit(some_func(0));} where {@code some_func} has a
	 * known calling convention and simply returns its parameter. This way, the test can break on
	 * {@code some_func} and write to the register for that first parameter. On architectures where
	 * the standard calling convention passes parameters via memory, you may be able to select an
	 * alternative that uses registers, or you may have to use inline/pure assembly.
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
	 * Get the expression to break when the register write should be made
	 * 
	 * <p>
	 * More than likely, this should just be the symbol for that function.
	 * 
	 * @return the expression
	 */
	protected abstract String getBreakpointExpression();

	/**
	 * Get the registers and values to write to achieve the desired effect
	 * 
	 * @return the name-value map of registers to write
	 */
	protected abstract Map<String, byte[]> getRegisterWrites();

	/**
	 * Perform the register writing portion of the test
	 * 
	 * <p>
	 * TODO: It is necessary to override this for LLDB, since it presents its registers in various
	 * "sub" banks. For it, we need to search the banks for each register to write, and delegate to
	 * the appropriate bank.
	 * 
	 * @param toWrite
	 * 
	 * @param the trapped thread
	 */
	protected void performRegisterWrites(TargetObject target, Map<String, byte[]> toWrite)
			throws Throwable {
		TargetRegisterBank bank = Objects
				.requireNonNull(m.findWithIndex(TargetRegisterBank.class, "0", target.getPath()));
		waitOn(bank.writeRegistersNamed(toWrite));
	}

	/**
	 * Verify, using {@link Assert}, that the target exhibited the effect of the register write
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
	 * Test the following scenario
	 * 
	 * <ol>
	 * <li>Obtain a launcher and use it to start the specimen</li>
	 * <li>Place a breakpoint</li>
	 * <li>Continue until a thread hits the breakpoint</li>
	 * <li>Write that thread's registers</li>
	 * <li>Resume the process until it is TERMINATED</li>
	 * <li>Verify some effect, usually the exit code</li>
	 * </ol>
	 */
	@Test
	public void testScenario() throws Throwable {
		DebuggerTestSpecimen specimen = getSpecimen();
		m.build();

		// For model developer diagnostics
		var bpMonitor = new AnnotatedDebuggerAttributeListener(MethodHandles.lookup()) {
			CompletableFuture<TargetObject> trapped = new CompletableFuture<>();

			@AttributeCallback(TargetExecutionStateful.STATE_ATTRIBUTE_NAME)
			private void stateChanged(TargetObject obj, TargetExecutionState state) {
				Msg.debug(this, obj.getJoinedPath(".") + " is now " + state);
			}

			@Override
			public void breakpointHit(TargetObject container, TargetObject trapped,
					TargetStackFrame frame, TargetBreakpointSpec spec,
					TargetBreakpointLocation breakpoint) {
				Msg.debug(this, "TRAPPED by " + spec);
				if (getBreakpointExpression().equals(spec.getExpression())) {
					this.trapped.complete(trapped);
					Msg.debug(this, "  Counted");
				}
			}
		};
		m.getModel().addModelListener(bpMonitor);

		TargetLauncher launcher = findLauncher();
		Msg.debug(this, "Launching " + specimen);
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
		for (int i = 1; !bpMonitor.trapped.isDone(); i++) {
			assertTrue(state.get().isAlive());
			Msg.debug(this, "(" + i + ") Resuming process until breakpoint hit");
			resume(process);
			Msg.debug(this, "  Done " + i);
			waitOn(state.waitUntil(s -> s != TargetExecutionState.RUNNING));
		}
		assertTrue(state.get().isAlive());
		TargetObject target = waitOn(bpMonitor.trapped);

		Map<String, byte[]> toWrite = getRegisterWrites();
		Msg.debug(this, "Writing registers: " + toWrite.keySet());
		performRegisterWrites(target, toWrite);
		Msg.debug(this, "  Done");

		assertTrue(DebugModelConventions.isProcessAlive(process));

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
