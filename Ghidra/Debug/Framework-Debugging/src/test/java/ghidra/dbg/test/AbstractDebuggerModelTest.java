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

import java.util.*;
import java.util.concurrent.CompletableFuture;

import org.junit.After;
import org.junit.Before;

import ghidra.dbg.DebugModelConventions;
import ghidra.dbg.DebugModelConventions.AsyncState;
import ghidra.dbg.DebuggerModelListener;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.TargetEventScope.TargetEventType;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.testutil.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.Msg;

/**
 * 
 * <ul>
 * <li>TODO: ensure order: created(Thread), event(THREAD_CREATED), created(RegisterBank) ?</li>
 * <li>TODO: ensure registersUpdated(RegisterBank) immediately upon created(RegisterBank) ?</li>
 * </ul>
 */
public abstract class AbstractDebuggerModelTest extends AbstractGhidraHeadedIntegrationTest
		implements TestDebuggerModelProvider, DebuggerModelTestUtils {

	protected DummyProc dummy;
	public ModelHost m;

	/**
	 * The default seed path to use when searching for a type of object
	 * 
	 * @return the seed path
	 */
	protected List<String> seedPath() {
		return List.of();
	}

	protected TargetActiveScope findActiveScope() throws Throwable {
		return m.find(TargetActiveScope.class, seedPath());
	}

	protected TargetObject findAttachableContainer() throws Throwable {
		return m.findContainer(TargetAttachable.class, seedPath());
	}

	protected TargetAttacher findAttacher() throws Throwable {
		return m.find(TargetAttacher.class, seedPath());
	}

	protected TargetFocusScope findFocusScope() throws Throwable {
		return m.find(TargetFocusScope.class, seedPath());
	}

	protected TargetInterpreter findInterpreter() throws Throwable {
		return m.find(TargetInterpreter.class, seedPath());
	}

	/**
	 * Get the launcher under test
	 * 
	 * <p>
	 * This can be overridden to force a different launcher under the test.
	 * 
	 * @return the launcher
	 * @throws Throwable if anything goes wrong
	 */
	protected TargetLauncher findLauncher() throws Throwable {
		return m.find(TargetLauncher.class, seedPath());
	}

	/**
	 * Get the breakpoint container of a target under test
	 * 
	 * @param seedPath the path to the target
	 * @return the breakpoint container
	 * @throws Throwable if anything goes wrong
	 */
	protected TargetBreakpointSpecContainer findBreakpointSpecContainer(List<String> seedPath)
			throws Throwable {
		return m.suitable(TargetBreakpointSpecContainer.class, seedPath);
	}

	protected TargetEnvironment findEnvironment(List<String> seedPath) throws Throwable {
		return m.suitable(TargetEnvironment.class, seedPath);
	}

	/**
	 * Get the steppable object of a target under test
	 * 
	 * @param seedPath the path to the target
	 * @return the steppable object
	 * @throws Throwable if anything goes wrong
	 */
	protected TargetSteppable findSteppable(List<String> seedPath) throws Throwable {
		return m.find(TargetSteppable.class, seedPath);
	}

	/**
	 * Get the memory of a target under test
	 * 
	 * @param seedPath the path to the target
	 * @return the memory
	 * @throws Throwable if anything goes wrong
	 */
	protected TargetMemory findMemory(List<String> seedPath) throws Throwable {
		return m.find(TargetMemory.class, seedPath);
	}

	/**
	 * Find any thread to put under test
	 * 
	 * @param seedPath the path to the target process
	 * @return the thread
	 * @throws Throwable if anything goes wrong
	 */
	protected TargetThread findAnyThread(List<String> seedPath) throws Throwable {
		return m.findAny(TargetThread.class, seedPath);
	}

	// TODO: Seems TargetStack is just a container for TargetStackFrame
	// This could be replaced by findContainer(TargetStackFrame)
	protected TargetStack findStack(List<String> seedPath) throws Throwable {
		return m.find(TargetStack.class, seedPath);
	}

	protected TargetRegisterBank findAnyRegisterBank(List<String> seedPath) throws Throwable {
		return m.findAny(TargetRegisterBank.class, seedPath);
	}

	protected TargetStackFrame findAnyStackFrame(List<String> seedPath) throws Throwable {
		return m.findAny(TargetStackFrame.class, seedPath);
	}

	protected TargetObject maybeSubstituteThread(TargetObject target) throws Throwable {
		TargetThread thread = findAnyThread(target.getPath());
		return thread == null ? target : thread;
	}

	@Override
	public void validateCompletionThread() {
		m.validateCompletionThread();
	}

	@Before
	public void setUpDebuggerModelTest() throws Throwable {
		m = modelHost();
	}

	@After
	public void tearDownDebuggerModelTest() throws Throwable {
		/**
		 * NB. Model has to be closed before dummy. If dummy is suspended by a debugger, terminating
		 * it, even forcibly, may fail.
		 */
		if (m != null) {
			m.close();
		}
		if (dummy != null) {
			dummy.close();
		}
	}

	public interface DebuggerTestSpecimen {
		/**
		 * Run the specimen outside the debugger
		 * 
		 * <p>
		 * This is really only applicable to processes which are going to run/wait indefinitely,
		 * since this is likely used in tests involving attach.
		 * 
		 * @return a handle to the process
		 * @throws Throwable if anything goes wrong
		 */
		DummyProc runDummy() throws Throwable;

		/**
		 * Get the arguments to launch this specimen using the model's launcher
		 * 
		 * @return the arguments
		 */
		Map<String, Object> getLauncherArgs();

		/**
		 * Get the script to launch this specimen via the interpreter
		 */
		List<String> getLaunchScript();

		/**
		 * Check if this specimen is the image for the given process
		 * 
		 * @param process the process to examine
		 * @param test the test case
		 * @return true if the specimen is the image, false otherwise
		 * @throws Throwable if anything goes wrong
		 */
		boolean isRunningIn(TargetProcess process, AbstractDebuggerModelTest test) throws Throwable;

		/**
		 * Check if this specimen is the image for the given attachable process
		 * 
		 * <p>
		 * The actual check is usually done by the OS-assigned PID.
		 * 
		 * @param dummy the dummy process whose image is known to be this specimen
		 * @param attachable the attachable process presented by the model
		 * @param test the test case
		 * @return true if the attachable process represents the given dummy
		 * @throws Throwable if anything goes wrong
		 */
		boolean isAttachable(DummyProc dummy, TargetAttachable attachable,
				AbstractDebuggerModelTest test) throws Throwable;
	}

	/**
	 * Set a software breakpoint and resume until it is hit
	 * 
	 * @param bpExpression the expression for the breakpoint
	 * @param target the target to resume
	 * @return the object which is actually trapped, often a thread
	 * @throws Throwable if anything goes wrong
	 */
	protected TargetObject trapAt(String bpExpression, TargetObject target) throws Throwable {
		var listener = new DebuggerModelListener() {
			CompletableFuture<TargetObject> trapped = new CompletableFuture<>();

			@Override
			public void event(TargetObject object, TargetThread eventThread, TargetEventType type,
					String description, List<Object> parameters) {
				Msg.debug(this, "EVENT " + type + " '" + description + "'");
			}

			@Override
			public void breakpointHit(TargetObject container, TargetObject trapped,
					TargetStackFrame frame, TargetBreakpointSpec spec,
					TargetBreakpointLocation breakpoint) {
				if (bpExpression.equals(spec.getExpression())) {
					this.trapped.complete(trapped);
				}
			}
		};
		target.getModel().addModelListener(listener);

		TargetBreakpointSpecContainer breakpoints = findBreakpointSpecContainer(target.getPath());
		waitOn(breakpoints.placeBreakpoint(bpExpression, Set.of(TargetBreakpointKind.SW_EXECUTE)));

		AsyncState state =
			new AsyncState(m.suitable(TargetExecutionStateful.class, target.getPath()));
		while (!listener.trapped.isDone()) {
			resume(target);
			TargetExecutionState st =
				waitOn(state.waitUntil(s -> s != TargetExecutionState.RUNNING));
			assertTrue("Target terminated before it was trapped", st.isAlive());
		}
		target.getModel().removeModelListener(listener);
		return waitOn(listener.trapped);
	}

	protected void runTestDetach(DebuggerTestSpecimen specimen)
			throws Throwable {
		TargetProcess process = retryForProcessRunning(specimen, this);
		TargetDetachable detachable = m.suitable(TargetDetachable.class, process.getPath());
		waitAcc(detachable);
		waitOn(detachable.detach());
		retryVoid(() -> assertFalse(DebugModelConventions.isProcessAlive(process)),
			List.of(AssertionError.class));
	}

	protected void runTestKill(DebuggerTestSpecimen specimen)
			throws Throwable {
		TargetProcess process = retryForProcessRunning(specimen, this);
		TargetKillable killable = m.suitable(TargetKillable.class, process.getPath());
		waitAcc(killable);
		waitOn(killable.kill());
		retryVoid(() -> assertFalse(DebugModelConventions.isProcessAlive(process)),
			List.of(AssertionError.class));
	}

	protected void runTestResumeTerminates(DebuggerTestSpecimen specimen) throws Throwable {
		TargetProcess process = retryForProcessRunning(specimen, this);
		TargetResumable resumable = m.suitable(TargetResumable.class, process.getPath());
		AsyncState state =
			new AsyncState(m.suitable(TargetExecutionStateful.class, process.getPath()));
		TargetExecutionState st = waitOn(state.waitUntil(s -> s != TargetExecutionState.RUNNING));
		assertTrue(st.isAlive());
		waitOn(resumable.resume());
		retryVoid(() -> assertFalse(DebugModelConventions.isProcessAlive(process)),
			List.of(AssertionError.class));
	}

	protected void runTestResumeInterruptMany(DebuggerTestSpecimen specimen,
			int repetitions) throws Throwable {
		TargetProcess process = retryForProcessRunning(specimen, this);
		TargetResumable resumable = m.suitable(TargetResumable.class, process.getPath());
		TargetInterruptible interruptible =
			m.suitable(TargetInterruptible.class, process.getPath());
		TargetExecutionStateful stateful =
			m.suitable(TargetExecutionStateful.class, process.getPath());
		for (int i = 0; i < repetitions; i++) {
			waitAcc(resumable);
			waitOn(resumable.resume());
			if (stateful != null) {
				retryVoid(() -> {
					assertEquals(TargetExecutionState.RUNNING, stateful.getExecutionState());
				}, List.of(AssertionError.class));
			}
			// NB. Never have to waitAcc to interrupt. It's likely inaccessible, anyway.
			waitOn(interruptible.interrupt());
			if (stateful != null) {
				retryVoid(() -> {
					assertEquals(TargetExecutionState.STOPPED, stateful.getExecutionState());
				}, List.of(AssertionError.class));
			}
		}
		waitOn(m.getModel().ping("Are you still there?"));
	}
}
