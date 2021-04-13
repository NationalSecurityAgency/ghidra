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
import java.util.*;
import java.util.concurrent.CompletableFuture;

import org.junit.Test;

import ghidra.dbg.AnnotatedDebuggerAttributeListener;
import ghidra.dbg.DebugModelConventions;
import ghidra.dbg.DebugModelConventions.AsyncState;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.TargetEventScope.TargetEventType;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.util.Msg;

/**
 * A scenario which tests multiple processes -- a child forked from a parent. The debugger must
 * become attached to both. If the debugger does not support attaching to the child, while remaining
 * attached to the parent as well, then this scenario cannot be applied to test it.
 */
public abstract class AbstractDebuggerModelScenarioForkExitTest extends AbstractDebuggerModelTest {
	/**
	 * Time to wait to observe the child from the fork before resuming again
	 */
	public static final long WAIT_FOR_CHILD_MS = 1000;

	/**
	 * This specimen must fork or similar, and then both parent and child must exit immediately
	 * 
	 * <p>
	 * They may optionally print information, but they cannot spin, sleep, or otherwise hang around.
	 * For platforms without {@code fork()}, e.g., Windows, the nearest equivalent behavior should
	 * be performed, e.g., roughly {@code CreateProcess("SameSpecimen.exe /child")}.
	 * 
	 * @return the specimen
	 */
	protected abstract DebuggerTestSpecimen getSpecimen();

	/**
	 * Perform whatever preparation is necessary to ensure the child will remain attached and be
	 * trapped upon its being forked from its parent
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
	 * trapped upon its being forked from its parent
	 * 
	 * @param parentProcess the parent process
	 * @throws Throwable if anything goes wrong
	 */
	protected void postLaunch(TargetProcess parentProcess) throws Throwable {
	}

	protected void postFork(TargetProcess parentProcess, TargetProcess childProcess)
			throws Throwable {
	}

	/**
	 * Get a breakpoint expression that will trap the parent post-fork
	 * 
	 * <p>
	 * Ideally, this same expression will trap the child post-fork as well. Note this test presumes
	 * the child will be trapped by the debugger upon fork. See
	 * {@link #getChildBreakpointExpression()}
	 * 
	 * @return the expression
	 */
	protected abstract String getParentBreakpointExpression();

	/**
	 * Get a breakpoint expression that will trap the child post-fork
	 * 
	 * <p>
	 * If breakpoints are not passed from parent to child, the test will need to set a breakpoint to
	 * trap the child. Override this with a suitable expression, if needed.
	 * 
	 * @return the expression
	 */
	protected String getChildBreakpointExpression() {
		return null;
	}

	/**
	 * This is invoked for both the launch of the specimen and upon fork
	 * 
	 * <p>
	 * Because one is forked from the other, we should expect to see the same environment attributes
	 * for both processes. That said, if a tester <em>does</em> need to distinguish, and please
	 * think carefully about whether or not you should, you can examine the environment's path to
	 * determine which process it applies to.
	 * 
	 * @param environment the environment at the time the process became alive
	 */
	public abstract void assertEnvironment(TargetEnvironment environment);

	/**
	 * Test the following scenario:
	 * 
	 * <ol>
	 * <li>Obtain a launcher and use it to start the specimen</li>
	 * <li>Place a breakpoint on the new (parent) process</li>
	 * <li>Resume the process until the fork is observed, generating the child process</li>
	 * <li>Verify both processes are ALIVE</li>
	 * <li>Resume the parent process until it is TERMINATED</li>
	 * <li>Verify the child process is still ALIVE</li>
	 * <li>Resume the child process until it is TERMIANTED</li>
	 * </ol>
	 */
	@Test
	public void testScenario() throws Throwable {
		DebuggerTestSpecimen specimen = getSpecimen();
		m.build();

		var stateMonitor = new AnnotatedDebuggerAttributeListener(MethodHandles.lookup()) {
			Set<TargetProcess> observed = new HashSet<>();
			CompletableFuture<TargetProcess> observedParent = new CompletableFuture<>();
			CompletableFuture<TargetProcess> observedChild = new CompletableFuture<>();
			List<CompletableFuture<TargetProcess>> futures =
				List.of(observedParent, observedChild);

			@AttributeCallback(TargetExecutionStateful.STATE_ATTRIBUTE_NAME)
			private void stateChanged(TargetObject obj, TargetExecutionState state) {
				Msg.debug(this, "STATE: " + obj.getJoinedPath(".") + " is now " + state);

				TargetProcess process = DebugModelConventions.liveProcessOrNull(obj);
				if (process == null) {
					return;
				}

				CompletableFuture<TargetProcess> f = futures.get(observed.size());
				if (observed.add(process)) {
					try {
						TargetEnvironment env = findEnvironment(process.getPath());
						assertEnvironment(env);
						f.complete(process);
					}
					catch (Throwable e) {
						f.completeExceptionally(e);
					}
				}
			}

			@Override
			public void event(TargetObject object, TargetThread eventThread,
					TargetEventType type, String description, List<Object> parameters) {
				Msg.debug(this, "EVENT: " + object.getJoinedPath(".") + " emitted " + type +
					"(desc=" + description + ",params=" + parameters + ")");
			}
		};
		m.getModel().addModelListener(stateMonitor);

		TargetLauncher launcher = findLauncher();
		preLaunch(launcher);
		Msg.debug(this, "Launching " + specimen);
		waitOn(launcher.launch(specimen.getLauncherArgs()));
		Msg.debug(this, "  Done launching");
		TargetProcess parentProcess = waitOn(stateMonitor.observedParent);
		Msg.debug(this, "Parent is " + parentProcess.getJoinedPath("."));
		postLaunch(parentProcess);

		AsyncState parentState =
			new AsyncState(m.suitable(TargetExecutionStateful.class, parentProcess.getPath()));
		waitOn(parentState.waitValue(TargetExecutionState.STOPPED));

		placeBreakpoint("parent", parentProcess, getParentBreakpointExpression());

		TargetProcess childProcess = null;
		for (int i = 1; childProcess == null; i++) {
			Msg.debug(this, "(" + i + ") Resuming until fork");
			resume(parentProcess);
			Msg.debug(this, "  Done " + i);
			waitAcc(access(parentProcess));
			try {
				childProcess = retryForOtherProcessRunning(specimen, this,
					p -> p != parentProcess, WAIT_FOR_CHILD_MS);
			}
			catch (AssertionError e) {
				// Try resuming again
			}
		}
		Msg.debug(this, "Child is " + childProcess.getJoinedPath("."));
		assertNotSame(parentProcess, childProcess);
		assertNotEquals(parentProcess, childProcess);
		assertSame(childProcess, waitOn(stateMonitor.observedChild));

		assertTrue(DebugModelConventions.isProcessAlive(parentProcess));
		AsyncState childState =
			new AsyncState(m.suitable(TargetExecutionStateful.class, childProcess.getPath()));
		waitOn(parentState.waitUntil(s -> s == TargetExecutionState.STOPPED));
		postFork(parentProcess, childProcess);

		placeChildBreakpoint(childProcess);

		for (int i = 1; DebugModelConventions.isProcessAlive(parentProcess); i++) {
			Msg.debug(this, "(" + i + ") Resuming parent until terminated");
			resume(parentProcess);
			Msg.debug(this, "  Done " + i);
			TargetExecutionState state =
				waitOn(parentState.waitUntil(s -> s != TargetExecutionState.RUNNING));
			Msg.debug(this, "Parent state after resume-wait-not-running: " + state);
			Msg.debug(this, "  And Child: " + childState.get());
		}

		assertTrue(DebugModelConventions.isProcessAlive(childProcess));
		waitOn(childState.waitUntil(s -> s == TargetExecutionState.STOPPED));
		for (int i = 1; DebugModelConventions.isProcessAlive(childProcess); i++) {
			Msg.debug(this, "Resuming child until terminated");
			resume(childProcess);
			Msg.debug(this, "  Done " + i);
			waitOn(childState.waitUntil(s -> s != TargetExecutionState.RUNNING));
		}
	}

	protected void placeBreakpoint(String who, TargetProcess process, String expression)
			throws Throwable {
		TargetBreakpointSpecContainer container =
			findBreakpointSpecContainer(process.getPath());
		Msg.debug(this, "Placing breakpoint (on " + who + ")");
		waitOn(container.placeBreakpoint(expression, Set.of(TargetBreakpointKind.SW_EXECUTE)));
	}

	protected void placeChildBreakpoint(TargetProcess childProcess) throws Throwable {
		String expression = getChildBreakpointExpression();
		if (expression != null) {
			placeBreakpoint("child", childProcess, expression);
		}
	}
}
