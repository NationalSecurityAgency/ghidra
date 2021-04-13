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
import ghidra.dbg.agent.AbstractDebuggerObjectModel;
import ghidra.dbg.agent.DefaultTargetModelRoot;
import ghidra.dbg.error.DebuggerIllegalArgumentException;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.target.TargetMethod.TargetParameterMap;
import ghidra.program.model.address.AddressFactory;

public abstract class AbstractDebuggerModelAttacherTest extends AbstractDebuggerModelTest
		implements RequiresAttachSpecimen {

	public List<String> getExpectedAttacherPath() {
		return null;
	}

	public List<String> getExpectedAttachableContainerPath() {
		return null;
	}

	public abstract TargetParameterMap getExpectedAttachParameters();

	public abstract void assertEnvironment(TargetEnvironment environment);

	@Test
	public void testAttacherIsWhereExpected() throws Throwable {
		List<String> expectedAttacherPath = getExpectedAttacherPath();
		assumeNotNull(expectedAttacherPath);
		m.build();

		TargetAttacher attacher = findAttacher();
		assertEquals(expectedAttacherPath, attacher.getPath());
	}

	@Test
	public void testAttachableContainerIsWhereExpected() throws Throwable {
		List<String> expectedAttachableContainerPath = getExpectedAttachableContainerPath();
		assumeNotNull(expectedAttachableContainerPath);
		m.build();

		TargetObject container = findAttachableContainer();
		assertEquals(expectedAttachableContainerPath, container.getPath());
	}

	protected void runTestListAttachable(TargetObject container) throws Throwable {
		DebuggerTestSpecimen specimen = getAttachSpecimen();
		waitAcc(container);
		Collection<TargetAttachable> attachables = fetchAttachables(container);
		assertNotNull(getAttachable(attachables, specimen, dummy, this));
	}

	@Test
	public void testListAttachable() throws Throwable {
		DebuggerTestSpecimen specimen = getAttachSpecimen();
		assumeTrue(m.hasAttachableContainer());
		m.build();
		dummy = specimen.runDummy();

		TargetObject container = findAttachableContainer();
		runTestListAttachable(container);
	}

	// TODO: Attacher parameters, when we go that way.

	protected void runTestAttachByPid(TargetAttacher attacher) throws Throwable {
		waitAcc(attacher);
		waitOn(attacher.attach(dummy.pid));
	}

	@Test
	public void testAttachByPid() throws Throwable {
		DebuggerTestSpecimen specimen = getAttachSpecimen();
		m.build();
		dummy = specimen.runDummy();

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

		TargetAttacher attacher = m.find(TargetAttacher.class, List.of());
		runTestAttachByPid(attacher);
		waitOn(listener.observedCreated);
	}

	protected void runTestAttachByObj(TargetAttacher attacher, TargetObject container)
			throws Throwable {
		DebuggerTestSpecimen specimen = getAttachSpecimen();
		Collection<TargetAttachable> attachables = fetchAttachables(container);
		TargetAttachable target = getAttachable(attachables, specimen, dummy, this);
		waitAcc(attacher);
		waitOn(attacher.attach(target));
	}

	@Test
	public void testAttachByObj() throws Throwable {
		DebuggerTestSpecimen specimen = getAttachSpecimen();
		assumeTrue(m.hasAttachableContainer());
		m.build();
		dummy = specimen.runDummy();

		TargetAttacher attacher = findAttacher();
		TargetObject container = findAttachableContainer();
		runTestAttachByObj(attacher, container);
	}

	protected static class BogusObjectModel extends AbstractDebuggerObjectModel {
		@Override
		public AddressFactory getAddressFactory() {
			return null;
		}
	}

	protected static class BogusTargetAttachable extends DefaultTargetModelRoot
			implements TargetAttachable {
		public BogusTargetAttachable(AbstractDebuggerObjectModel model) {
			super(model, "Bogus");
		}
	}

	protected void runTestAttachByObjBogusThrowsException(TargetAttacher attacher)
			throws Throwable {
		waitAcc(attacher);
		BogusObjectModel bogusModel = new BogusObjectModel();
		TargetAttachable bogusAttachable = new BogusTargetAttachable(bogusModel);
		waitOn(attacher.attach(bogusAttachable));
	}

	@Test(expected = DebuggerIllegalArgumentException.class)
	public void testAttachByObjBogusThrowsException() throws Throwable {
		m.build();

		TargetAttacher attacher = m.find(TargetAttacher.class, List.of());
		runTestAttachByObjBogusThrowsException(attacher);
	}

	protected void runTestAttachByPidThenDetach(TargetAttacher attacher)
			throws Throwable {
		DebuggerTestSpecimen specimen = getAttachSpecimen();
		assertNull(getProcessRunning(specimen, this));
		runTestAttachByPid(attacher);
		runTestDetach(specimen);
		assertTrue(dummy.process.isAlive());
	}

	@Test
	public void testAttachByPidThenDetach() throws Throwable {
		DebuggerTestSpecimen specimen = getAttachSpecimen();
		assumeTrue(m.hasDetachableProcesses());
		m.build();
		dummy = specimen.runDummy();

		TargetAttacher attacher = findAttacher();
		runTestAttachByPidThenDetach(attacher);
	}

	protected void runTestAttachByPidThenKill(TargetAttacher attacher)
			throws Throwable {
		DebuggerTestSpecimen specimen = getAttachSpecimen();
		assertNull(getProcessRunning(specimen, this));
		runTestAttachByPid(attacher);
		runTestKill(specimen);
		retryVoid(() -> assertFalse(dummy.process.isAlive()), List.of(AssertionError.class));
	}

	@Test
	public void testAttachByPidThenKill() throws Throwable {
		DebuggerTestSpecimen specimen = getAttachSpecimen();
		assumeTrue(m.hasKillableProcesses());
		m.build();
		dummy = specimen.runDummy();

		TargetAttacher attacher = findAttacher();
		runTestAttachByPidThenKill(attacher);
	}

	protected void runTestAttachByPidThenResumeInterrupt(TargetAttacher attacher) throws Throwable {
		DebuggerTestSpecimen specimen = getAttachSpecimen();
		assertNull(getProcessRunning(specimen, this));
		runTestAttachByPid(attacher);
		runTestResumeInterruptMany(specimen, 3);
		assertTrue(dummy.process.isAlive());
	}

	@Test
	public void testAttachByPidThenResumeInterrupt() throws Throwable {
		DebuggerTestSpecimen specimen = getAttachSpecimen();
		assumeTrue(m.hasResumableProcesses());
		m.build();
		dummy = specimen.runDummy();

		TargetAttacher attacher = findAttacher();
		runTestAttachByPidThenResumeInterrupt(attacher);
	}

	protected void runTestAttachShowsInProcessContainer(TargetAttacher attacher) throws Throwable {
		DebuggerTestSpecimen specimen = getAttachSpecimen();
		assertNull(getProcessRunning(specimen, this));
		runTestAttachByPid(attacher);
		retryForProcessRunning(specimen, this);
	}

	@Test
	public void testAttachShowsInProcessContainer() throws Throwable {
		DebuggerTestSpecimen specimen = getAttachSpecimen();
		assumeTrue(m.hasProcessContainer());
		m.build();
		dummy = specimen.runDummy();

		TargetAttacher attacher = findAttacher();
		runTestAttachShowsInProcessContainer(attacher);
	}
}
