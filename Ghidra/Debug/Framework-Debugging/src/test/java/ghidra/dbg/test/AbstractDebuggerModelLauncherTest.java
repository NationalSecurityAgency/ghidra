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
import static org.junit.Assume.assumeNotNull;
import static org.junit.Assume.assumeTrue;

import java.lang.invoke.MethodHandles;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.CompletableFuture;

import org.junit.Test;

import ghidra.dbg.AnnotatedDebuggerAttributeListener;
import ghidra.dbg.DebugModelConventions;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.target.TargetMethod.TargetParameterMap;
import ghidra.dbg.testutil.ElementTrackingListener;

public abstract class AbstractDebuggerModelLauncherTest extends AbstractDebuggerModelTest
		implements RequiresLaunchSpecimen {

	public List<String> getExpectedLauncherPath() {
		return null;
	}

	public List<String> getExpectedProcessesContainerPath() {
		return null;
	}

	public abstract TargetParameterMap getExpectedLauncherParameters();

	public abstract void assertEnvironment(TargetEnvironment environment);

	@Test
	public void testLauncherIsWhereExpected() throws Throwable {
		List<String> expectedLauncherPath = getExpectedLauncherPath();
		assumeNotNull(expectedLauncherPath);
		m.build();

		TargetLauncher launcher = findLauncher();
		assertEquals(expectedLauncherPath, launcher.getPath());
	}

	@Test
	public void testProcessContainerIsWhereExpected() throws Throwable {
		List<String> expectedProcessContainerPath = getExpectedProcessesContainerPath();
		assumeNotNull(expectedProcessContainerPath);
		m.build();

		TargetObject container = findProcessContainer();
		assertEquals(expectedProcessContainerPath, container.getPath());
	}

	protected void runTestLaunchParameters(TargetLauncher launcher,
			TargetParameterMap expectedParameters) throws Throwable {
		waitAcc(launcher);
		waitOn(launcher.fetchAttributes());
		assertEquals(expectedParameters, launcher.getParameters());
	}

	@Test
	public void testLaunchParameters() throws Throwable {
		TargetParameterMap expectedParameters = getExpectedLauncherParameters();
		assumeNotNull(expectedParameters);
		m.build();

		TargetLauncher launcher = findLauncher();
		runTestLaunchParameters(launcher, expectedParameters);
	}

	protected void runTestLaunch(TargetLauncher launcher) throws Throwable {
		DebuggerTestSpecimen specimen = getLaunchSpecimen();
		waitAcc(launcher);
		waitOn(launcher.launch(specimen.getLauncherArgs()));
	}

	@Test
	public void testLaunch() throws Throwable {
		m.build();

		var listener = new AnnotatedDebuggerAttributeListener(MethodHandles.lookup()) {
			CompletableFuture<Void> observedCreated = new CompletableFuture<>();

			@AttributeCallback(TargetExecutionStateful.STATE_ATTRIBUTE_NAME)
			public void stateChanged(TargetObject object, TargetExecutionState state) {
				// We're only expecting one process, so this should be fine
				TargetProcess process = DebugModelConventions.liveProcessOrNull(object);
				if (process == null) {
					return;
				}
				try {
					TargetEnvironment env = findEnvironment(process.getPath());
					assertEnvironment(env);
					observedCreated.complete(null);
				}
				catch (Throwable e) {
					observedCreated.completeExceptionally(e);
				}
			}
		};
		// NB. I've intentionally omitted the reorderer here. The model should get it right.
		m.getModel().addModelListener(listener);

		TargetLauncher launcher = findLauncher();
		runTestLaunch(launcher);
		waitOn(listener.observedCreated);
	}

	protected void runTestLaunchThenDetach(TargetLauncher launcher,
			TargetObject container) throws Throwable {
		DebuggerTestSpecimen specimen = getLaunchSpecimen();
		assertNull(getProcessRunning(container, specimen, this));
		runTestLaunch(launcher);
		runTestDetach(container, specimen);
	}

	@Test
	public void testLaunchThenDetach() throws Throwable {
		assumeTrue(m.hasDetachableProcesses());
		m.build();

		TargetLauncher launcher = findLauncher();
		TargetObject container = findProcessContainer();
		runTestLaunchThenDetach(launcher, container);
	}

	protected void runTestLaunchThenKill(TargetLauncher launcher,
			TargetObject container) throws Throwable {
		DebuggerTestSpecimen specimen = getLaunchSpecimen();
		assertNull(getProcessRunning(container, specimen, this));
		runTestLaunch(launcher);
		runTestKill(container, specimen);
	}

	@Test
	public void testLaunchThenKill() throws Throwable {
		assumeTrue(m.hasKillableProcesses());
		m.build();

		TargetLauncher launcher = findLauncher();
		TargetObject container = findProcessContainer();
		runTestLaunchThenKill(launcher, container);
	}

	protected void runTestLaunchThenResume(TargetLauncher launcher,
			TargetObject container) throws Throwable {
		DebuggerTestSpecimen specimen = getLaunchSpecimen();
		assertNull(getProcessRunning(container, specimen, this));
		runTestLaunch(launcher);
		runTestResumeTerminates(container, specimen);
	}

	@Test
	public void testLaunchThenResume() throws Throwable {
		assumeTrue(m.hasKillableProcesses());
		m.build();

		TargetLauncher launcher = findLauncher();
		TargetObject container = findProcessContainer();
		runTestLaunchThenResume(launcher, container);
	}

	protected void runTestLaunchShowsInProcessContainer(TargetLauncher launcher,
			TargetObject container) throws Throwable {
		DebuggerTestSpecimen specimen = getLaunchSpecimen();
		assertNull(getProcessRunning(container, specimen, this));
		runTestLaunch(launcher);
		retryForProcessRunning(container, specimen, this);
	}

	@Test
	public void testLaunchShowsInProcessContainer() throws Throwable {
		assumeTrue(m.hasProcessContainer());
		m.build();

		TargetLauncher launcher = findLauncher();
		TargetObject container = findProcessContainer();
		runTestLaunchShowsInProcessContainer(launcher, container);
	}

	protected void runTestLaunchShowsInProcessContainerViaListener(
			TargetLauncher launcher, TargetObject container) throws Throwable {
		DebuggerTestSpecimen specimen = getLaunchSpecimen();
		ElementTrackingListener<? extends TargetProcess> procListener =
			new ElementTrackingListener<>(TargetProcess.class);
		container.addListener(procListener);
		// NB. Have to express interest, otherwise model is not obligated to invoke listener
		Collection<TargetProcess> procsBefore = fetchProcesses(container);
		procListener.putAll(container.getCachedElements());
		assertNull(getProcessRunning(procsBefore, specimen, this));
		runTestLaunch(launcher);
		retryVoid(() -> {
			// Cannot fetch elements. rely only on listener.
			assertNotNull(getProcessRunning(procListener.elements.values(), specimen, this));
		}, List.of(AssertionError.class));
	}

	@Test
	public void testLaunchShowsInProcessContainerViaListener() throws Throwable {
		assumeTrue(m.hasProcessContainer());
		m.build();

		TargetLauncher launcher = findLauncher();
		TargetObject container = findProcessContainer();
		runTestLaunchShowsInProcessContainerViaListener(launcher, container);
	}
}
