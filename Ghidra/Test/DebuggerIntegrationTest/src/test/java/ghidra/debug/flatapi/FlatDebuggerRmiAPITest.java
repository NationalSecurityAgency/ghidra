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
package ghidra.debug.flatapi;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.util.*;
import java.util.function.*;

import org.junit.Before;
import org.junit.Test;

import db.Transaction;
import generic.Unique;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingProvider;
import ghidra.app.plugin.core.debug.gui.tracermi.launcher.TestTraceRmiLaunchOpinion.TestTraceRmiLaunchOffer;
import ghidra.app.plugin.core.debug.gui.tracermi.launcher.TraceRmiLauncherServicePlugin;
import ghidra.app.plugin.core.debug.service.tracermi.TestTraceRmiConnection.TestRemoteMethod;
import ghidra.app.plugin.core.debug.service.tracermi.TraceRmiTarget;
import ghidra.debug.api.tracermi.TraceRmiLaunchOffer.LaunchResult;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.trace.database.memory.DBTraceMemorySpace;
import ghidra.trace.database.target.DBTraceObjectManager;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.thread.TraceObjectThread;
import ghidra.trace.model.thread.TraceThread;

public class FlatDebuggerRmiAPITest extends AbstractLiveFlatDebuggerAPITest<FlatDebuggerRmiAPI> {

	protected TraceRmiLauncherServicePlugin rmiLaunchPlugin;

	protected class TestFlatRmiAPI extends TestFlatAPI implements FlatDebuggerRmiAPI {
	}

	@Before
	public void setUpRmiTest() throws Throwable {
		DebuggerListingProvider listingProvider =
			waitForComponentProvider(DebuggerListingProvider.class);
		// Auto-reads hang the TaskManager because readMem calls are not expected or answered
		listingProvider.setAutoReadMemorySpec(readNone);
		rmiLaunchPlugin = addPlugin(tool, TraceRmiLauncherServicePlugin.class);
	}

	@Override
	protected FlatDebuggerRmiAPI newFlatAPI() {
		return new TestFlatRmiAPI();
	}

	protected TraceRmiTarget createTarget() throws Throwable {
		createRmiConnection();
		addExecuteMethod();
		addControlMethods();
		addMemoryMethods();
		addRegisterMethods();
		createTrace();
		try (Transaction tx = tb.startTransaction()) {
			DBTraceObjectManager objs = tb.trace.getObjectManager();
			objs.createRootObject(SCHEMA_SESSION);
			tb.createObjectsProcessAndThreads();
			tb.createObjectsFramesAndRegs(
				tb.obj("Processes[1].Threads[1]").queryInterface(TraceObjectThread.class),
				Lifespan.nowOn(0), tb.host, 2);
			addMemoryRegion(objs, Lifespan.nowOn(0), tb.range(0x00400000, 0x00400fff), ".text",
				"rx");
		}
		TraceRmiTarget target = rmiCx.publishTarget(tool, tb.trace);
		traceManager.openTrace(tb.trace);
		// Do not activate, as this pollutes the method invocation queues
		waitForSwing();
		return target;
	}

	@Test
	public void testReadLiveMemory() throws Throwable {
		TraceRmiTarget target = createTarget();
		var args = rmiMethodReadMem.expect(a -> {
			try (Transaction tx = tb.startTransaction()) {
				tb.trace.getMemoryManager()
						.putBytes(target.getSnap(), tb.addr(0x00400000),
							tb.buf(1, 2, 3, 4, 5, 6, 7, 8));
			}
			return null;
		});
		byte[] data = api.readMemory(tb.trace, target.getSnap(), tb.addr(0x00400000), 8, monitor);
		assertEquals(Map.ofEntries(
			Map.entry("process", tb.obj("Processes[1]")),
			// Framework quantizes to page
			Map.entry("range", tb.range(0x00400000, 0x00400fff))),
			waitOn(args));
		assertArrayEquals(tb.arr(1, 2, 3, 4, 5, 6, 7, 8), data);
	}

	@Test
	public void testReadLiveRegister() throws Throwable {
		TraceRmiTarget target = createTarget();
		TraceThread thread =
			tb.trace.getThreadManager().getLiveThreadByPath(0, "Processes[1].Threads[1]");
		Register r0 = tb.reg("r0");
		var args = rmiMethodReadRegs.expect(a -> {
			try (Transaction tx = tb.startTransaction()) {
				DBTraceMemorySpace regs =
					tb.trace.getMemoryManager().getMemoryRegisterSpace(thread, true);
				regs.setValue(target.getSnap(), new RegisterValue(r0, new BigInteger("1234")));
			}
			return null;
		});
		RegisterValue value = api.readRegister(tb.host, thread, 0, target.getSnap(), r0);
		assertEquals(Map.ofEntries(
			Map.entry("container", tb.obj("Processes[1].Threads[1].Stack[0].Registers"))),
			waitOn(args));
		assertEquals(new RegisterValue(r0, new BigInteger("1234")), value);
	}

	@Test
	public void testReadLiveRegisters() throws Throwable {
		TraceRmiTarget target = createTarget();
		TraceThread thread =
			tb.trace.getThreadManager().getLiveThreadByPath(0, "Processes[1].Threads[1]");
		Register r0 = tb.reg("r0");
		Register r1 = tb.reg("r1");
		var args = rmiMethodReadRegs.expect(a -> {
			try (Transaction tx = tb.startTransaction()) {
				DBTraceMemorySpace regs =
					tb.trace.getMemoryManager().getMemoryRegisterSpace(thread, true);
				regs.setValue(target.getSnap(), new RegisterValue(r0, new BigInteger("1234")));
				regs.setValue(target.getSnap(), new RegisterValue(r1, new BigInteger("5678")));
			}
			return null;
		});
		List<RegisterValue> values =
			api.readRegisters(tb.host, thread, 0, target.getSnap(), List.of(r0, r1));
		assertEquals(Map.ofEntries(
			Map.entry("container", tb.obj("Processes[1].Threads[1].Stack[0].Registers"))),
			waitOn(args));
		assertEquals(List.of(
			new RegisterValue(r0, new BigInteger("1234")),
			new RegisterValue(r1, new BigInteger("5678"))),
			values);
	}

	protected <T, U extends T> List<U> filter(Collection<T> col, Class<U> cls) {
		return col.stream().<U> mapMulti((e, m) -> {
			if (cls.isInstance(e)) {
				m.accept(cls.cast(e));
			}
		}).toList();
	}

	@Test
	public void testGetLaunchOffers() throws Throwable {
		createProgram();
		programManager.openProgram(program);
		waitForSwing();

		TestTraceRmiLaunchOffer offer =
			Unique.assertOne(filter(api.getLaunchOffers(), TestTraceRmiLaunchOffer.class));
		assertEquals(program, offer.getProgram());
	}

	@Test
	public void testGetSavedLaunchOffers() throws Throwable {
		createProgram();
		programManager.openProgram(program);
		waitForSwing();

		assertEquals(List.of(), api.getSavedLaunchOffers());

		TestTraceRmiLaunchOffer offer =
			Unique.assertOne(filter(api.getLaunchOffers(), TestTraceRmiLaunchOffer.class));
		offer.saveLauncherArgs(Map.of("image", "/test/image"));

		assertEquals(List.of(offer), api.getSavedLaunchOffers());
	}

	@Test
	public void testLaunchCustomCommandLine() throws Throwable {
		TestTraceRmiLaunchOffer offer =
			Unique.assertOne(filter(api.getLaunchOffers(), TestTraceRmiLaunchOffer.class));
		offer.saveLauncherArgs(Map.of("image", "/test/image"));

		LaunchResult result = api.launch(monitor);
		assertEquals("Test launcher cannot launch /test/image", result.exception().getMessage());
	}

	protected void runTestStep(Predicate<TraceThread> step, Supplier<TestRemoteMethod> method)
			throws Throwable {
		createTarget();
		TraceObjectThread thread =
			tb.obj("Processes[1].Threads[1]").queryInterface(TraceObjectThread.class);
		traceManager.activateThread(thread);
		waitForSwing();

		var args = method.get().expect(a -> null);
		assertTrue(step.test(thread));
		assertEquals(Map.ofEntries(
			Map.entry("thread", thread.getObject())),
			waitOn(args));
	}

	@Test
	public void testStepGivenThread() throws Throwable {
		runTestStep(api::stepInto, () -> rmiMethodStepInto);
	}

	@Test
	public void testStepInto() throws Throwable {
		runTestStep(t -> api.stepInto(), () -> rmiMethodStepInto);
	}

	@Test
	public void testStepOver() throws Throwable {
		runTestStep(t -> api.stepOver(), () -> rmiMethodStepOver);
	}

	@Test
	public void testStepOut() throws Throwable {
		runTestStep(t -> api.stepOut(), () -> rmiMethodStepOut);
	}

	@Override
	protected void runTestResume(BooleanSupplier resume) throws Throwable {
		createTarget();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		var args = rmiMethodResume.expect(a -> null);
		assertTrue(resume.getAsBoolean());
		assertEquals(Map.ofEntries(
			Map.entry("process", tb.obj("Processes[1]"))),
			waitOn(args));
	}

	@Override
	protected void runTestInterrupt(BooleanSupplier interrupt) throws Throwable {
		createTarget();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		var args = rmiMethodInterrupt.expect(a -> null);
		assertTrue(interrupt.getAsBoolean());
		assertEquals(Map.ofEntries(
			Map.entry("process", tb.obj("Processes[1]"))),
			waitOn(args));
	}

	@Override
	protected void runTestKill(BooleanSupplier kill) throws Throwable {
		createTarget();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		var args = rmiMethodKill.expect(a -> null);
		assertTrue(kill.getAsBoolean());
		assertEquals(Map.ofEntries(
			Map.entry("process", tb.obj("Processes[1]"))),
			waitOn(args));
	}

	@Override
	protected void runTestExecuteCapture(Function<String, String> executeCapture) throws Throwable {
		createTarget();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		var args = rmiMethodExecute.expect(a -> "result");
		assertEquals("result", api.executeCapture("some command"));
		assertEquals(Map.ofEntries(
			Map.entry("cmd", "some command"),
			Map.entry("to_string", true)),
			waitOn(args));
	}
}
