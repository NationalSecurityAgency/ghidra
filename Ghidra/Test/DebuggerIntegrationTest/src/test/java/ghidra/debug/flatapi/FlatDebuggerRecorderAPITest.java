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

import java.io.IOException;
import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.function.BooleanSupplier;
import java.util.function.Function;

import org.junit.Test;

import generic.Unique;
import ghidra.app.plugin.core.debug.service.model.TestDebuggerProgramLaunchOpinion.TestDebuggerProgramLaunchOffer;
import ghidra.app.plugin.core.debug.service.model.launch.AbstractDebuggerProgramLaunchOffer;
import ghidra.dbg.DebuggerModelFactory;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.model.*;
import ghidra.dbg.target.TargetLauncher.TargetCmdLineLauncher;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetSteppable.TargetStepKind;
import ghidra.debug.api.model.DebuggerProgramLaunchOffer;
import ghidra.debug.api.model.DebuggerProgramLaunchOffer.LaunchResult;
import ghidra.debug.api.model.TraceRecorder;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.Trace;
import ghidra.trace.model.thread.TraceThread;

public class FlatDebuggerRecorderAPITest
		extends AbstractLiveFlatDebuggerAPITest<FlatDebuggerRecorderAPI> {

	protected static class TestFactory implements DebuggerModelFactory {
		private final DebuggerObjectModel model;

		public TestFactory(DebuggerObjectModel model) {
			this.model = model;
		}

		@Override
		public CompletableFuture<? extends DebuggerObjectModel> build() {
			return CompletableFuture.completedFuture(model);
		}
	}

	protected class TestOffer extends AbstractDebuggerProgramLaunchOffer {
		public TestOffer(Program program, DebuggerModelFactory factory) {
			super(program, env.getTool(), factory);
		}

		public TestOffer(Program program, DebuggerObjectModel model) {
			this(program, new TestFactory(model));
		}

		@Override
		public String getConfigName() {
			return "TEST";
		}

		@Override
		public String getMenuTitle() {
			return "in Test Debugger";
		}
	}

	protected static class TestModelBuilder extends TestDebuggerModelBuilder {
		private final TestDebuggerObjectModel model;

		public TestModelBuilder(TestDebuggerObjectModel model) {
			this.model = model;
		}

		@Override
		protected TestDebuggerObjectModel newModel(String typeHint) {
			return model;
		}
	}

	protected class TestFlatRecorderAPI extends TestFlatAPI implements FlatDebuggerRecorderAPI {
	}

	@Override
	protected FlatDebuggerRecorderAPI newFlatAPI() {
		return new TestFlatRecorderAPI();
	}

	protected TraceRecorder recordTarget(TargetObject target)
			throws LanguageNotFoundException, CompilerSpecNotFoundException, IOException {
		return modelService.recordTargetAndActivateTrace(target,
			new TestDebuggerTargetTraceMapper(target));
	}

	@Test
	public void testReadLiveMemory() throws Throwable {
		createTestModel();
		mb.createTestProcessesAndThreads();
		mb.testProcess1.memory.writeMemory(mb.addr(0x00400000), mb.arr(1, 2, 3, 4, 5, 6, 7, 8));
		waitOn(mb.testModel.flushEvents());
		TraceRecorder recorder = recordTarget(mb.testProcess1);
		waitRecorder(recorder);
		useTrace(recorder.getTrace());
		waitForSwing();

		byte[] data = api.readMemory(tb.addr(0x00400000), 8, monitor);
		assertArrayEquals(tb.arr(1, 2, 3, 4, 5, 6, 7, 8), data);
	}

	@Test
	public void testReadLiveRegister() throws Throwable {
		createTestModel();
		mb.createTestProcessesAndThreads();
		mb.createTestThreadRegisterBanks();
		mb.testProcess1.regs.addRegistersFromLanguage(getToyBE64Language(), r -> true);
		mb.testBank1.writeRegister("r0", mb.arr(1, 2, 3, 4, 5, 6, 7, 8));
		waitOn(mb.testModel.flushEvents());
		TraceRecorder recorder = recordTarget(mb.testProcess1);
		waitRecorder(recorder);
		useTrace(recorder.getTrace());
		traceManager.activateThread(recorder.getTraceThread(mb.testThread1));
		waitForSwing();

		RegisterValue rv = api.readRegister("r0");
		assertEquals(BigInteger.valueOf(0x0102030405060708L), rv.getUnsignedValue());
	}

	@Test
	public void testReadLiveRegisters() throws Throwable {
		createTestModel();
		mb.createTestProcessesAndThreads();
		mb.createTestThreadRegisterBanks();
		mb.testProcess1.regs.addRegistersFromLanguage(getToyBE64Language(), r -> true);
		mb.testBank1.writeRegister("r0", mb.arr(1, 2, 3, 4, 5, 6, 7, 8));
		mb.testBank1.writeRegister("r1", mb.arr(8, 7, 6, 5, 4, 3, 2, 1));
		waitOn(mb.testModel.flushEvents());
		TraceRecorder recorder = recordTarget(mb.testProcess1);
		waitRecorder(recorder);
		useTrace(recorder.getTrace());
		traceManager.activateThread(recorder.getTraceThread(mb.testThread1));
		waitForSwing();

		Register r0 = tb.language.getRegister("r0");
		Register r1 = tb.language.getRegister("r1");
		assertEquals(List.of(
			new RegisterValue(r0, BigInteger.valueOf(0x0102030405060708L)),
			new RegisterValue(r1, BigInteger.valueOf(0x0807060504030201L))),
			api.readRegistersNamed(List.of("r0", "r1")));
	}

	@Test
	public void testGetLaunchOffers() throws Throwable {
		createProgram();
		programManager.openProgram(program);
		waitForSwing();

		Unique.assertOne(api.getLaunchOffers().stream().mapMulti((o, m) -> {
			if (o instanceof TestDebuggerProgramLaunchOffer to) {
				m.accept(to);
			}
		}));
	}

	@Test
	public void testLaunchCustomCommandLine() throws Throwable {
		createProgram();
		programManager.openProgram(program);
		waitForSwing();

		var model = new TestDebuggerObjectModel() {
			Map<String, ?> observedParams;

			@Override
			protected TestTargetSession newTestTargetSession(String rootHint) {
				return new TestTargetSession(this, "Session", ROOT_SCHEMA) {
					@Override
					public CompletableFuture<Void> launch(Map<String, ?> params) {
						observedParams = params;
						throw new CancellationException();
					}
				};
			}
		};
		DebuggerProgramLaunchOffer offer = new TestOffer(program, model);

		LaunchResult result = api.launch(offer, "custom command line", monitor);

		assertEquals("custom command line",
			model.observedParams.get(TargetCmdLineLauncher.CMDLINE_ARGS_NAME));
		assertNotNull(result.model());
		assertNull(result.target());
		assertEquals(CancellationException.class, result.exception().getClass());
	}

	@Test
	public void testGetTarget() throws Exception {
		createTestModel();
		mb.createTestProcessesAndThreads();
		TraceRecorder recorder = recordTarget(mb.testProcess1);

		assertEquals(mb.testProcess1, api.getTarget(recorder.getTrace()));
	}

	@Test
	public void testGetTargetThread() throws Throwable {
		createTestModel();
		mb.createTestProcessesAndThreads();
		TraceRecorder recorder = recordTarget(mb.testProcess1);
		waitRecorder(recorder);

		Trace trace = recorder.getTrace();
		TraceThread thread =
			trace.getThreadManager()
					.getLiveThreadByPath(recorder.getSnap(), "Processes[1].Threads[1]");
		assertNotNull(thread);
		assertEquals(mb.testThread1, api.getTargetThread(thread));
	}

	@Test
	public void testGetTargetFocus() throws Throwable {
		createTestModel();
		mb.createTestProcessesAndThreads();
		TraceRecorder recorder = recordTarget(mb.testProcess1);
		waitRecorder(recorder);

		waitOn(mb.testModel.requestFocus(mb.testThread2));
		waitRecorder(recorder);

		assertEquals(mb.testThread2, api.getTargetFocus(recorder.getTrace()));
	}

	protected void runTestStep(BooleanSupplier step, TargetStepKind kind) throws Throwable {
		var model = new TestDebuggerObjectModel() {
			TestTargetThread observedThread;
			TargetStepKind observedKind;

			@Override
			protected TestTargetThread newTestTargetThread(TestTargetThreadContainer container,
					int tid) {
				return new TestTargetThread(container, tid) {
					@Override
					public CompletableFuture<Void> step(TargetStepKind kind) {
						observedThread = this;
						observedKind = kind;
						return super.step(kind);
					}
				};
			}
		};
		mb = new TestModelBuilder(model);
		createTestModel();
		mb.createTestProcessesAndThreads();
		TraceRecorder recorder = recordTarget(mb.testProcess1);
		waitRecorder(recorder);
		assertTrue(waitOn(recorder.requestFocus(mb.testThread2)));
		waitRecorder(recorder);

		assertTrue(step.getAsBoolean());
		waitRecorder(recorder);
		assertEquals(mb.testThread2, model.observedThread);
		assertEquals(kind, model.observedKind);
	}

	@Test
	public void testStepGivenThread() throws Throwable {
		runTestStep(() -> api.step(api.getCurrentThread(), TargetStepKind.INTO),
			TargetStepKind.INTO);
	}

	@Test
	public void testStepInto() throws Throwable {
		runTestStep(api::stepInto, TargetStepKind.INTO);
	}

	@Test
	public void testStepOver() throws Throwable {
		runTestStep(api::stepOver, TargetStepKind.OVER);
	}

	@Test
	public void testStepOut() throws Throwable {
		runTestStep(api::stepOut, TargetStepKind.FINISH);
	}

	@Override
	protected void runTestResume(BooleanSupplier resume) throws Throwable {
		var model = new TestDebuggerObjectModel() {
			TestTargetThread observedThread;

			@Override
			protected TestTargetThread newTestTargetThread(TestTargetThreadContainer container,
					int tid) {
				return new TestTargetThread(container, tid) {
					@Override
					public CompletableFuture<Void> resume() {
						observedThread = this;
						return super.resume();
					}
				};
			}
		};
		mb = new TestModelBuilder(model);
		createTestModel();
		mb.createTestProcessesAndThreads();
		TraceRecorder recorder = recordTarget(mb.testProcess1);
		waitRecorder(recorder);
		assertTrue(waitOn(recorder.requestFocus(mb.testThread2)));
		waitRecorder(recorder);

		assertTrue(resume.getAsBoolean());
		waitRecorder(recorder);
		assertEquals(mb.testThread2, model.observedThread);
	}

	@Override
	protected void runTestInterrupt(BooleanSupplier interrupt) throws Throwable {
		var model = new TestDebuggerObjectModel() {
			TestTargetThread observedThread;

			@Override
			protected TestTargetThread newTestTargetThread(TestTargetThreadContainer container,
					int tid) {
				return new TestTargetThread(container, tid) {
					@Override
					public CompletableFuture<Void> interrupt() {
						observedThread = this;
						return super.interrupt();
					}
				};
			}
		};
		mb = new TestModelBuilder(model);
		createTestModel();
		mb.createTestProcessesAndThreads();
		TraceRecorder recorder = recordTarget(mb.testProcess1);
		waitRecorder(recorder);
		assertTrue(waitOn(recorder.requestFocus(mb.testThread2)));
		waitRecorder(recorder);

		assertTrue(interrupt.getAsBoolean());
		waitRecorder(recorder);
		assertEquals(mb.testThread2, model.observedThread);
	}

	@Override
	protected void runTestKill(BooleanSupplier kill) throws Throwable {
		var model = new TestDebuggerObjectModel() {
			TestTargetThread observedThread;

			@Override
			protected TestTargetThread newTestTargetThread(TestTargetThreadContainer container,
					int tid) {
				return new TestTargetThread(container, tid) {
					@Override
					public CompletableFuture<Void> kill() {
						observedThread = this;
						return super.kill();
					}
				};
			}
		};
		mb = new TestModelBuilder(model);
		createTestModel();
		mb.createTestProcessesAndThreads();
		TraceRecorder recorder = recordTarget(mb.testProcess1);
		waitRecorder(recorder);
		assertTrue(waitOn(recorder.requestFocus(mb.testThread2)));
		waitRecorder(recorder);

		assertTrue(kill.getAsBoolean());
		waitRecorder(recorder);
		assertEquals(mb.testThread2, model.observedThread);
	}

	@Override
	protected void runTestExecuteCapture(Function<String, String> executeCapture) throws Throwable {
		// NOTE: Can't use TestTargetInterpreter.queueExecute stuff, since flat API waits
		var model = new TestDebuggerObjectModel() {
			@Override
			protected TestTargetInterpreter newTestTargetInterpreter(TestTargetSession session) {
				return new TestTargetInterpreter(session) {
					@Override
					public CompletableFuture<String> executeCapture(String cmd) {
						return CompletableFuture.completedFuture("Response to " + cmd);
					}
				};
			}
		};
		mb = new TestModelBuilder(model);
		createTestModel();
		mb.createTestProcessesAndThreads();
		TraceRecorder recorder = recordTarget(mb.testProcess1);
		waitRecorder(recorder);
		assertTrue(waitOn(recorder.requestFocus(mb.testThread2)));
		waitRecorder(recorder);

		assertEquals("Response to cmd", executeCapture.apply("cmd"));
	}

	@Test
	public void testGetModelValue() throws Throwable {
		createTestModel();
		mb.createTestProcessesAndThreads();
		recordTarget(mb.testProcess1);

		assertEquals(mb.testThread2, api.getModelValue("Processes[1].Threads[2]"));
	}

	@Test
	public void testRefreshObjectChildren() throws Throwable {
		var model = new TestDebuggerObjectModel() {
			Set<TestTargetProcess> observed = new HashSet<>();

			@Override
			protected TestTargetProcess newTestTargetProcess(TestTargetProcessContainer container,
					int pid, AddressSpace space) {
				return new TestTargetProcess(container, pid, space) {
					@Override
					public CompletableFuture<Void> resync(RefreshBehavior refreshAttributes,
							RefreshBehavior refreshElements) {
						observed.add(this);
						return super.resync(refreshAttributes, refreshElements);
					}
				};
			}
		};
		mb = new TestModelBuilder(model);
		createTestModel();
		mb.createTestProcessesAndThreads();

		api.refreshObjectChildren(mb.testProcess1);
		assertEquals(Set.of(mb.testProcess1), model.observed);
	}

	@Test
	public void testRefreshSubtree() throws Throwable {
		var model = new TestDebuggerObjectModel() {
			Set<TestTargetObject> observed = new HashSet<>();

			@Override
			protected TestTargetProcess newTestTargetProcess(TestTargetProcessContainer container,
					int pid, AddressSpace space) {
				return new TestTargetProcess(container, pid, space) {
					@Override
					public CompletableFuture<Void> resync(RefreshBehavior refreshAttributes,
							RefreshBehavior refreshElements) {
						observed.add(this);
						return super.resync(refreshAttributes, refreshElements);
					}
				};
			}

			@Override
			protected TestTargetThread newTestTargetThread(TestTargetThreadContainer container,
					int tid) {
				return new TestTargetThread(container, tid) {
					@Override
					public CompletableFuture<Void> resync(RefreshBehavior refreshAttributes,
							RefreshBehavior refreshElements) {
						observed.add(this);
						return super.resync(refreshAttributes, refreshElements);
					}
				};
			}
		};
		mb = new TestModelBuilder(model);
		createTestModel();
		mb.createTestProcessesAndThreads();

		api.refreshSubtree(mb.testModel.session);
		assertEquals(Set.of(mb.testProcess1, mb.testProcess3, mb.testThread1, mb.testThread2,
			mb.testThread3, mb.testThread4), model.observed);
	}

	@Test
	public void testFlushAsyncPipelines() throws Throwable {
		createTestModel();
		mb.createTestProcessesAndThreads();
		TraceRecorder recorder = recordTarget(mb.testProcess1);

		// Ensure it works whether or not there are pending events
		for (int i = 0; i < 10; i++) {
			api.flushAsyncPipelines(recorder.getTrace());
		}
	}
}
