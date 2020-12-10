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
package ghidra.dbg.sctl.client;

import static ghidra.async.AsyncUtils.completable;
import static ghidra.async.AsyncUtils.sequence;
import static org.junit.Assert.*;
import static org.junit.Assume.assumeNoException;

import java.io.IOException;
import java.io.PrintWriter;
import java.lang.ProcessBuilder.Redirect;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.AsynchronousSocketChannel;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiFunction;
import java.util.function.Predicate;

import org.junit.Ignore;
import org.junit.Test;

import ghidra.async.*;
import ghidra.dbg.DebugModelConventions;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.attributes.*;
import ghidra.dbg.sctl.err.SctlError;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetBreakpointContainer.TargetBreakpointListener;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionStateListener;
import ghidra.dbg.target.TargetLauncher.TargetCmdLineLauncher;
import ghidra.dbg.target.TargetObject.TargetObjectListener;
import ghidra.dbg.testutil.DummyProc;
import ghidra.dbg.util.PathUtils;
import ghidra.dbg.util.TargetDataTypeConverter;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.*;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.task.TaskMonitor;

@Ignore("Not high priority")
public class SctlOnReferenceTest extends AbstractGhidraHeadlessIntegrationTest {
	private static final long TIMEOUT_MILLISECONDS =
		SystemUtilities.isInTestingBatchMode() ? 1000 : Long.MAX_VALUE;

	static class SctlStub implements AutoCloseable {
		static int nextPort = 0;
		static final boolean USER_LAUNCHED = false;

		static synchronized int nextPort() {
			return nextPort++;
		}

		final int port = USER_LAUNCHED ? 12345 : nextPort() + 12345;
		final InetSocketAddress addr = new InetSocketAddress("localhost", port);
		final Process process;

		SctlStub() throws IOException {
			if (!USER_LAUNCHED) {
				String sctl = Application.getOSFile("sctl").getAbsolutePath();
				process = new ProcessBuilder(sctl, "-p", "" + port)
						.redirectError(Redirect.INHERIT)
						.redirectOutput(Redirect.INHERIT)
						.start();
			}
			else {
				Msg.info(this, "Test is expecting user-launched sctl at " + addr);
				process = null;
			}
		}

		@Override
		public void close() throws Exception {
			if (!USER_LAUNCHED) {
				process.destroyForcibly().waitFor();
			}
		}
	}

	SctlStub runSctl() throws IOException {
		try {
			SctlStub stub = new SctlStub();
			return stub;
		}
		catch (IOException e) {
			assumeNoException("Could not launch sctl. Is it installed and in the path?", e);
			return null;
		}
	}

	protected static <T> Void handleFailure(T result, Throwable exc) {
		if (exc != null) {
			fail(exc.getMessage());
		}
		return null;
	}

	protected static final BiFunction<Object, Throwable, ?> NOP_OR_FAIL =
		SctlOnReferenceTest::handleFailure;

	protected static <T> T waitOn(CompletableFuture<T> future) throws Throwable {
		try {
			return future.get(TIMEOUT_MILLISECONDS, TimeUnit.MILLISECONDS);
		}
		catch (ExecutionException e) {
			throw e.getCause();
		}
	}

	@Test
	public void testConnect() throws Throwable {
		try (SctlStub stub = runSctl()) {
			AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
			SctlClient client = new SctlClient("Test", socket);

			waitOn(sequence(TypeSpec.VOID).then(seq -> {
				Msg.debug(this, "Connecting...");
				completable(TypeSpec.VOID, socket::connect, stub.addr).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Negotiating...");
				client.connect().handle(seq::next);
			}).finish());
		}
	}

	@Test
	public void testPing() throws Throwable {
		try (SctlStub stub = runSctl()) {
			AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
			SctlClient client = new SctlClient("Test", socket);

			waitOn(sequence(TypeSpec.VOID).then(seq -> {
				Msg.debug(this, "Connecting...");
				completable(TypeSpec.VOID, socket::connect, stub.addr).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Negotiating...");
				client.connect().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Pinging...");
				client.ping("Hello, SCTL!").handle(seq::next);
			}).finish());
		}
	}

	@Test
	public void testListAttachable() throws Throwable {
		try (DummyProc expCloneSpin = DummyProc.run("expCloneSpin"); SctlStub stub = runSctl()) {
			AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
			SctlClient client = new SctlClient("Test", socket);
			waitOn(sequence(TypeSpec.VOID).then(seq -> {
				Msg.debug(this, "Connecting...");
				completable(TypeSpec.VOID, socket::connect, stub.addr).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Negotiating...");
				client.connect().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting process list");
				client.fetchObjectElements("Attachable")
						.thenCompose(DebugModelConventions::fetchAll)
						.handle(seq::next);
			}, DebuggerObjectModel.ELEMENT_MAP_TYPE).then((elems, seq) -> {
				Msg.debug(this, "Got repsonse");
				for (TargetObject proc : elems.values()) {
					if (Objects.equals(proc.getIndex(), Long.toString(expCloneSpin.pid))) {
						assertEquals("expCloneSpin",
							proc.getTypedAttributeNowByName("cmd_line", String.class, null));
						seq.exit();
						return;
					}
				}
				fail("Did not find expected PID");
			}).finish());
		}
	}

	protected static class ThreadTracker {
		protected static ThreadTracker strongRef;

		protected static class BreakHit {
			final TargetObjectRef trapped;
			final TypedTargetObjectRef<? extends TargetBreakpointSpec<?>> spec;

			public BreakHit(TargetObjectRef trapped,
					TypedTargetObjectRef<? extends TargetBreakpointSpec<?>> spec) {
				this.trapped = trapped;
				this.spec = spec;
			}
		}

		protected final AsyncReference<TargetObjectRef, Void> lastThreadRef =
			new AsyncReference<>();
		protected final AsyncReference<TargetObjectRef, Void> lastThreadRemoved =
			new AsyncReference<>();
		protected final AsyncReference<TargetObjectRef, Void> lastProcRef = new AsyncReference<>();
		protected final AsyncReference<Long, Void> lastExitCode = new AsyncReference<>();
		protected final AsyncReference<Integer, Void> exitCount = new AsyncReference<>(0);
		protected final AsyncReference<BreakHit, Void> lastBreakHit = new AsyncReference<>();
		protected final TargetObject root;
		protected TargetObject processes;

		protected final ListenerForProcesses listenerForProcesses = new ListenerForProcesses();
		protected final ListenerForThreads listenerForThreads = new ListenerForThreads();
		protected final ListenerForExit listenerForExit = new ListenerForExit();
		protected final ListenerForBreak listenerForBreak = new ListenerForBreak();

		class ListenerForProcesses implements TargetObjectListener {
			@Override
			public void elementsChanged(TargetObject parent, Collection<String> removed,
					Map<String, ? extends TargetObjectRef> added) {
				for (TargetObjectRef ref : added.values()) {
					lastProcRef.set(ref, null);
					ref.getSuccessor("Threads").fetch().thenAccept(t -> {
						t.addListener(listenerForThreads);
						for (TargetObjectRef last : t.getCachedElements().values()) {
							lastThreadRef.set(last, null);
						}
					}).exceptionally(exc -> {
						Msg.error(this, "Could not get new process's Thread container: ", exc);
						return null;
					});
				}
			}
		}

		class ListenerForThreads implements TargetObjectListener {
			@Override
			public void elementsChanged(TargetObject parent, Collection<String> removed,
					Map<String, ? extends TargetObjectRef> added) {
				for (TargetObjectRef ref : added.values()) {
					lastThreadRef.set(ref, null);
					ref.fetch().thenAccept(t -> {
						t.addListener(listenerForExit);
					}).exceptionally(exc -> {
						Msg.error(this, "Could not get new process: ", exc);
						return null;
					});
					ref.fetchSuccessor("Breakpoints").thenAccept(b -> {
						b.addListener(listenerForBreak);
					}).exceptionally(exc -> {
						Msg.error(this, "Could not get break container: ", exc);
						return null;
					});
				}
				for (String name : removed) {
					lastThreadRemoved.set(parent.getSuccessor(name), null);
				}
			}
		}

		class ListenerForExit implements TargetObjectListener {
			@Override
			public void attributesChanged(TargetObject parent, Collection<String> removed,
					Map<String, ?> added) {
				Object exitCode = added.get("exit_code");
				if (exitCode != null) {
					Msg.debug(this, "Object " + parent + " exited with code " + exitCode);
					lastExitCode.set((Long) exitCode, null);
					exitCount.compute(c -> c + 1, null);
				}
			}
		}

		class ListenerForBreak implements TargetBreakpointListener {
			@Override
			public void breakpointHit(TargetBreakpointContainer<?> container,
					TargetObjectRef trapped,
					TypedTargetObjectRef<? extends TargetStackFrame<?>> frame,
					TypedTargetObjectRef<? extends TargetBreakpointSpec<?>> spec,
					TypedTargetObjectRef<? extends TargetBreakpointLocation<?>> breakpoint) {
				lastBreakHit.set(new BreakHit(trapped, spec), null);
			}
		}

		public ThreadTracker(TargetObject root) {
			strongRef = this;
			this.root = root;
		}

		protected CompletableFuture<Void> init() {
			return root.fetchSuccessor("Processes").thenAccept(p -> {
				this.processes = p;
				processes.addListener(listenerForProcesses);
			});
		}
	}

	protected ThreadTracker trackThreads(TargetObject root) {
		return new ThreadTracker(root);
	}

	protected static class WhileResumer extends CompletableFuture<Void>
			implements TargetExecutionStateListener {
		protected static WhileResumer strongRef;

		protected final TargetResumable<?> resumable;
		protected final Predicate<? super TargetObject> predicate;

		public WhileResumer(TargetObject thread, Predicate<? super TargetObject> predicate) {
			strongRef = this;
			thread.addListener(this);
			resumable = thread.as(TargetResumable.tclass);
			this.predicate = predicate;
			TargetExecutionStateful<?> stateful = thread.as(TargetExecutionStateful.tclass);
			doState(stateful.getExecutionState());
		}

		@Override
		public void executionStateChanged(TargetExecutionStateful<?> object,
				TargetExecutionState state) {
			doState(state);
		}

		protected void doState(TargetExecutionState state) {
			Msg.debug(this, "Thread " + resumable + " now " + state);
			if (predicate.test(resumable)) {
				if (state == TargetExecutionState.STOPPED) {
					resumable.resume().exceptionally(exc -> {
						resumable.removeListener(this);
						completeExceptionally(exc);
						return null;
					});
				}
				else if (state == TargetExecutionState.TERMINATED) {
					resumable.removeListener(this);
					complete(null);
				}
			}
			else {
				resumable.removeListener(this);
				complete(null);
			}
		}
	}

	protected CompletableFuture<Void> resumeWhile(TargetObject thread,
			Predicate<? super TargetObject> predicate) {
		return new WhileResumer(thread, predicate);
	}

	protected static String keyInt(int i) {
		return PathUtils.makeKey(PathUtils.makeIndex(i));
	}

	protected static TypedTargetObjectRef<? extends TargetAttachable<?>> refPid(
			DebuggerObjectModel model, int pid) {
		return model.createRef("Attachable", keyInt(pid)).as(TargetAttachable.tclass);
	}

	static void stupidSleep(long millis) {
		try {
			Thread.sleep(millis);
		}
		catch (InterruptedException e) {
			// Whatever
		}
	}

	@Test
	public void testLaunchCont() throws Throwable {
		try (SctlStub stub = runSctl()) {
			AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
			SctlClient client = new SctlClient("Test", socket);
			AtomicReference<TargetObject> root = new AtomicReference<>();
			long status = waitOn(sequence(TypeSpec.LONG).then(seq -> {
				Msg.debug(this, "Connecting...");
				completable(TypeSpec.VOID, socket::connect, stub.addr).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Negotiating...");
				client.connect().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting model root");
				client.fetchModelRoot().handle(seq::next);
			}, root).then(seq -> {
				Msg.debug(this, "Initializing thread tracker");
				trackThreads(root.get()).init().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Launching...");
				TargetLauncher<?> launcher = root.get().as(TargetLauncher.tclass);
				launcher.launch(Map.of(TargetCmdLineLauncher.CMDLINE_ARGS_NAME,
					DummyProc.which("echo") + " test")).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Waiting for thread");
				ThreadTracker.strongRef.lastThreadRef.waitUntil(r -> r != null).handle(seq::next);
			}, TypeSpec.cls(TargetObjectRef.class)).then((threadRef, seq) -> {
				Msg.debug(this, "Got thread ref: " + threadRef);
				threadRef.fetch().handle(seq::next);
			}, TypeSpec.cls(TargetObject.class)).then((thread, seq) -> {
				Msg.debug(this, "Continuing until exit...");
				resumeWhile(thread, t -> true).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Waiting for exit code...");
				ThreadTracker.strongRef.lastExitCode.waitUntil(v -> v != null).handle(seq::exit);
			}).finish());
			assertEquals(0, status);
		}
	}

	@Test
	public void testLaunchKill() throws Throwable {
		try (SctlStub stub = runSctl()) {
			AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
			SctlClient client = new SctlClient("Test", socket);
			AtomicReference<TargetObject> root = new AtomicReference<>();
			waitOn(sequence(TypeSpec.VOID).then(seq -> {
				Msg.debug(this, "Connecting...");
				completable(TypeSpec.VOID, socket::connect, stub.addr).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Negotiating...");
				client.connect().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting model root");
				client.fetchModelRoot().handle(seq::next);
			}, root).then(seq -> {
				Msg.debug(this, "Initializing thread tracker");
				trackThreads(root.get()).init().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Launching...");
				TargetLauncher<?> launcher = root.get().as(TargetLauncher.tclass);
				launcher.launch(Map.of(TargetCmdLineLauncher.CMDLINE_ARGS_NAME,
					DummyProc.which("echo") + " test")).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Waiting for thread");
				ThreadTracker.strongRef.lastThreadRef.waitUntil(r -> r != null).handle(seq::next);
			}, TypeSpec.cls(TargetObjectRef.class)).then((threadRef, seq) -> {
				Msg.debug(this, "Got thread ref: " + threadRef);
				threadRef.fetch().handle(seq::next);
			}, TypeSpec.cls(TargetObject.class)).then((thread, seq) -> {
				Msg.debug(this, "Killing...");
				TargetKillable<?> killable = thread.as(TargetKillable.tclass);
				killable.kill().handle(seq::next);
			}).finish());
		}
	}

	@Test
	public void testAttachKill() throws Throwable {
		try (DummyProc dd = DummyProc.run("dd"); SctlStub stub = runSctl()) {
			AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
			SctlClient client = new SctlClient("Test", socket);
			AtomicReference<TargetObject> root = new AtomicReference<>();
			waitOn(sequence(TypeSpec.VOID).then(seq -> {
				Msg.debug(this, "Connecting...");
				completable(TypeSpec.VOID, socket::connect, stub.addr).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Negotiating...");
				client.connect().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting model root");
				client.fetchModelRoot().handle(seq::next);
			}, root).then(seq -> {
				Msg.debug(this, "Initializing thread tracker");
				trackThreads(root.get()).init().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Attaching...");
				TargetAttacher<?> attacher = root.get().as(TargetAttacher.tclass);
				attacher.attach(refPid(client, (int) dd.pid)).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Waiting for thread");
				ThreadTracker.strongRef.lastThreadRef.waitUntil(r -> r != null).handle(seq::next);
			}, TypeSpec.cls(TargetObjectRef.class)).then((threadRef, seq) -> {
				Msg.debug(this, "Got thread ref: " + threadRef);
				threadRef.fetch().handle(seq::next);
			}, TypeSpec.cls(TargetObject.class)).then((thread, seq) -> {
				Msg.debug(this, "Killing...");
				TargetKillable<?> killable = thread.as(TargetKillable.tclass);
				killable.kill().handle(seq::next);
			}).finish());
		}
	}

	@Test
	public void testLaunchSetClearBreakpoint() throws Throwable {
		try (SctlStub stub = runSctl()) {
			AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
			SctlClient client = new SctlClient("Test", socket);
			AtomicReference<TargetObject> root = new AtomicReference<>();
			AtomicReference<TargetRegisterBank<?>> regs = new AtomicReference<>();
			AtomicReference<TargetBreakpointContainer<?>> traps = new AtomicReference<>();
			waitOn(sequence(TypeSpec.VOID).then(seq -> {
				Msg.debug(this, "Connecting...");
				completable(TypeSpec.VOID, socket::connect, stub.addr).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Negotiating...");
				client.connect().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting model root");
				client.fetchModelRoot().handle(seq::next);
			}, root).then(seq -> {
				Msg.debug(this, "Initializing thread tracker");
				trackThreads(root.get()).init().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Launching...");
				TargetLauncher<?> launcher = root.get().as(TargetLauncher.tclass);
				launcher.launch(Map.of(TargetCmdLineLauncher.CMDLINE_ARGS_NAME,
					DummyProc.which("echo") + " test")).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Waiting for thread");
				ThreadTracker.strongRef.lastThreadRef.waitUntil(r -> r != null).handle(seq::next);
			}, TypeSpec.cls(TargetObjectRef.class)).then((threadRef, seq) -> {
				Msg.debug(this, "Got thread ref: " + threadRef);
				AsyncFence fence = new AsyncFence();
				fence.include(threadRef.fetchSuccessor("Registers").thenAccept(obj -> {
					regs.set(obj.as(TargetRegisterBank.tclass));
				}));
				fence.include(threadRef.fetchSuccessor("Breakpoints").thenAccept(obj -> {
					traps.set(obj.as(TargetBreakpointContainer.tclass));
				}));
				fence.ready().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Reading RIP...");
				regs.get().readRegister("rip").handle(seq::next);
			}, TypeSpec.BYTE_ARRAY).then((ripBytes, seq) -> {
				long ripVal = ByteBuffer.wrap(ripBytes).order(ByteOrder.BIG_ENDIAN).getLong(0);
				Address rip = client.getAddress("ram", ripVal);
				Msg.debug(this, "Got RIP=" + rip);
				traps.get()
						.placeBreakpoint(rip, Set.of(TargetBreakpointKind.SOFTWARE))
						.handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Breakpoints: ");
				for (TargetObjectRef bref : traps.get().getCachedElements().values()) {
					Msg.debug(this, "  " + bref);
				}
				traps.get()
						.getCachedElements()
						.values()
						.iterator()
						.next()
						.fetch()
						.handle(seq::next);
			}, TypeSpec.cls(TargetObject.class)).then((obj, seq) -> {
				TargetDeletable<?> spec = obj.as(TargetDeletable.tclass);
				spec.delete().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Deleted breakpoint");
				seq.exit();
			}).finish());
		}
	}

	@Test(expected = SctlError.class)
	public void testErr() throws Throwable {
		// TODO: Translate the exception to the appropriate model exception
		try (SctlStub stub = runSctl()) {
			AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
			SctlClient client = new SctlClient("Test", socket);
			AtomicReference<TargetObject> root = new AtomicReference<>();
			waitOn(sequence(TypeSpec.VOID).then(seq -> {
				Msg.debug(this, "Connecting...");
				completable(TypeSpec.VOID, socket::connect, stub.addr).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Negotiating...");
				client.connect().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting model root");
				client.fetchModelRoot().handle(seq::next);
			}, root).then(seq -> {
				Msg.debug(this, "Attaching to bogus PID...");
				TargetAttacher<?> attacher = root.get().as(TargetAttacher.tclass);
				attacher.attach(refPid(client, -1)).handle(seq::next);
			}).then(seq -> {
				fail("Got a thread");
				seq.exit();
			}).finish());
		}
	}

	/*
	 * TODO:
	 * 
	 * 1(DONE). See what happens when we fork the process (esp., wrt. threads). According to UNIX
	 * docs, should cause a single ForkEvent, yielding a new process with one thread.
	 * 
	 * 2(DONE). See what happens when we clone the process (esp., wrt. threads). Just another
	 * thread.
	 * 
	 * 3(DONE). See what happens on pthread_create. Causes CloneEvent.
	 * 
	 * 4(DONE). See what happens when a thread exits. Do we get the status code? If not, then I need
	 * to remove the threadExited callback from the listener. It probably belongs in process
	 * listener anyway. Then again, even if the reference does not give it, shouldn't I model it
	 * here for extensibility? It seems only threads that were alive at the time the process exited
	 * are given the status code. All of them are given the same code. Threads that exit before the
	 * process are reported with a status of 0, no matter what they return.
	 * 
	 * 5(DONE). When I set a breakpoint on one CTLID of a process, will that cause the other threads
	 * to break there, too? No, it does not.
	 * 
	 * 6(DONE). Does killing one thread kill the whole process? Yes and no. When I kill the primary
	 * thread, nothing seems to be affected. When I kill the secondary thread, sctl and the target
	 * process die altogether.
	 * 
	 * 7(DONE). Does detaching one thread detach the whole process? (try main thread and spawned
	 * thread). No, detaching from either leaves the other thread attached. However, sctl appears
	 * confused beyond that point. Continuing one thread actually continues both, or the attached
	 * thread may continue immediately after the other is detached. In general, detach should be
	 * avoided until we're ready to detach the whole process. Whatever the case, it appears SCTL is
	 * meant to be able to detach a single thread, so we should assume thread granularity.
	 * 
	 * 8(DONE). What if I start a process outside of sctl, it clones, and then I attach? It seems I
	 * can only ever attach to the main thread.
	 */

	@Test
	public void testExpFork() throws Throwable {
		try (SctlStub stub = runSctl()) {
			AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
			SctlClient client = new SctlClient("Test", socket);
			AtomicReference<TargetObject> root = new AtomicReference<>();
			waitOn(sequence(TypeSpec.VOID).then(seq -> {
				Msg.debug(this, "Connecting...");
				completable(TypeSpec.VOID, socket::connect, stub.addr).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Negotiating...");
				client.connect().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting model root");
				client.fetchModelRoot().handle(seq::next);
			}, root).then(seq -> {
				Msg.debug(this, "Initializing thread tracker");
				trackThreads(root.get()).init().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Launching...");
				TargetLauncher<?> launcher = root.get().as(TargetLauncher.tclass);
				launcher.launch(
					Map.of(TargetCmdLineLauncher.CMDLINE_ARGS_NAME, DummyProc.which("expFork")))
						.handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Waiting for thread");
				ThreadTracker.strongRef.lastThreadRef.waitUntil(r -> r != null).handle(seq::next);
			}, TypeSpec.cls(TargetObjectRef.class)).then((threadRef, seq) -> {
				ThreadTracker.strongRef.lastThreadRef.set(null, null);
				Msg.debug(this, "Got thread ref: " + threadRef);
				threadRef.fetch().handle(seq::next);
			}, TypeSpec.cls(TargetObject.class)).then((thread, seq) -> {
				Msg.debug(this, "Resuming first (parent) indefinitely");
				resumeWhile(thread, t -> true).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Waiting for parent to exit");
				ThreadTracker.strongRef.lastExitCode.waitUntil(v -> v != null).handle(seq::next);
			}, TypeSpec.cls(Long.class)).then((exit, seq) -> {
				Msg.debug(this, "Parent exited with " + exit);
				ThreadTracker.strongRef.lastExitCode.set(null, null);
				// TODO: I'm not sure why this is off by a factor of 256. A byte offset somewhere?
				assertEquals(256, exit.longValue());
				Msg.debug(this, "Waiting for second (child) thread (and process)");
				ThreadTracker.strongRef.lastThreadRef.waitUntil(r -> r != null).handle(seq::next);
			}, TypeSpec.cls(TargetObjectRef.class)).then((threadRef, seq) -> {
				Msg.debug(this, "Got child thread ref: " + threadRef);
				threadRef.fetch().handle(seq::next);
			}, TypeSpec.cls(TargetObject.class)).then((thread, seq) -> {
				Msg.debug(this, "Resuming child indefinitely");
				resumeWhile(thread, t -> true).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Waiting for child to exit");
				ThreadTracker.strongRef.lastExitCode.waitUntil(v -> v != null).handle(seq::next);
			}, TypeSpec.cls(Long.class)).then((exit, seq) -> {
				Msg.debug(this, "Child exited with " + exit);
				assertEquals(0, exit.longValue());
				seq.exit();
			}).finish());
		}
	}

	/**
	 * This experiment confirms that sctl has a separate list of breakpoints per thread
	 * 
	 * @throws Throwable
	 */
	@Test
	public void testExpCloneBreak() throws Throwable {
		String expCloneExit = DummyProc.which("expCloneExit");
		try (SctlStub stub = runSctl()) {
			AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
			SctlClient client = new SctlClient("Test", socket);
			AtomicReference<TargetObject> root = new AtomicReference<>();
			AtomicReference<TargetObject> launchedThread = new AtomicReference<>();
			AtomicReference<TargetObject> clonedThread = new AtomicReference<>();
			AtomicReference<TargetSymbol<?>> work = new AtomicReference<>();
			waitOn(sequence(TypeSpec.VOID).then(seq -> {
				Msg.debug(this, "Connecting...");
				completable(TypeSpec.VOID, socket::connect, stub.addr).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Negotiating...");
				client.connect().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting model root");
				client.fetchModelRoot().handle(seq::next);
			}, root).then(seq -> {
				Msg.debug(this, "Initializing thread tracker");
				trackThreads(root.get()).init().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Launching...");
				TargetLauncher<?> launcher = root.get().as(TargetLauncher.tclass);
				launcher.launch(Map.of(TargetCmdLineLauncher.CMDLINE_ARGS_NAME, expCloneExit))
						.handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Waiting for launched thread ref");
				ThreadTracker.strongRef.lastThreadRef.waitUntil(r -> r != null).handle(seq::next);
			}, TypeSpec.cls(TargetObjectRef.class)).then((threadRef, seq) -> {
				ThreadTracker.strongRef.lastThreadRef.set(null, null);
				Msg.debug(this, "Got thread ref: " + threadRef);
				threadRef.fetch().handle(seq::next);
			}, launchedThread).then(seq -> {
				Msg.debug(this, "Resuming until another thread appears: " + launchedThread.get());
				resumeWhile(launchedThread.get(), t -> {
					TargetObjectRef ref = ThreadTracker.strongRef.lastThreadRef.get();
					Msg.debug(this, "lastThreadRef = " + ref);
					return ref == null;
				}).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Waiting for cloned thread");
				ThreadTracker.strongRef.lastThreadRef.waitUntil(r -> r != null).handle(seq::next);
			}, TypeSpec.cls(TargetObjectRef.class)).then((threadRef, seq) -> {
				Msg.debug(this, "Got thread ref: " + threadRef);
				threadRef.fetch().handle(seq::next);
			}, clonedThread).then(seq -> {
				// Verify nothing has exited, yet
				assertNull(ThreadTracker.strongRef.lastExitCode.get());
				Msg.debug(this, "Placing breakpoint at 'work'");
				ThreadTracker.strongRef.lastProcRef.get()
						.fetchSuccessor(
							PathUtils.parse("Modules[" + expCloneExit + "].Symbols[work]"))
						.handle(seq::next);
			}, TypeSpec.cls(TargetObject.class)).then((obj, seq) -> {
				work.set(obj.as(TargetSymbol.tclass));
				Msg.debug(this, "Resolved 'work' to " + work.get().getValue());
				launchedThread.get().fetchSuccessor("Breakpoints").handle(seq::next);
			}, TypeSpec.cls(TargetObject.class)).then((obj, seq) -> {
				TargetBreakpointContainer<?> traps = obj.as(TargetBreakpointContainer.tclass);
				traps.placeBreakpoint(work.get().getValue(), Set.of(TargetBreakpointKind.SOFTWARE))
						.handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Continuing secondary thread indefinitely");
				resumeWhile(clonedThread.get(), t -> true).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Waiting for secondary thread to exit");
				ThreadTracker.strongRef.lastExitCode.waitUntil(v -> v != null).handle(seq::next);
			}, TypeSpec.cls(Long.class)).then((exit, seq) -> {
				ThreadTracker.strongRef.lastExitCode.set(null, null);
				Msg.debug(this, "Exited with " + exit);
				assertNull(ThreadTracker.strongRef.lastBreakHit.get());
				Msg.debug(this, "Continuing primary thread indefinitely");
				resumeWhile(launchedThread.get(), t -> true).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Waiting for primary thread to exit");
				ThreadTracker.strongRef.lastExitCode.waitUntil(v -> v != null).handle(seq::next);
			}, TypeSpec.cls(Long.class)).then((exit, seq) -> {
				ThreadTracker.strongRef.lastExitCode.set(null, null);
				Msg.debug(this, "Exited with " + exit);
				assertNotNull(ThreadTracker.strongRef.lastBreakHit.get());
				seq.exit();
			}).finish());
		}
	}

	/**
	 * This experiment determined that a thread exiting unrelated to process termination is assigned
	 * an exit status of 0. If any thread calls exit(), then all threads are terminated with a
	 * status given by that call.
	 * 
	 * @throws Throwable
	 */
	@Test
	public void testExpCloneExit() throws Throwable {
		String expCloneExit = DummyProc.which("expCloneExit");
		try (SctlStub stub = runSctl()) {
			AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
			SctlClient client = new SctlClient("Test", socket);
			AtomicReference<TargetObject> root = new AtomicReference<>();
			AtomicReference<TargetObject> launchedThread = new AtomicReference<>();
			waitOn(sequence(TypeSpec.VOID).then(seq -> {
				Msg.debug(this, "Connecting...");
				completable(TypeSpec.VOID, socket::connect, stub.addr).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Negotiating...");
				client.connect().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting model root");
				client.fetchModelRoot().handle(seq::next);
			}, root).then(seq -> {
				Msg.debug(this, "Initializing thread tracker");
				trackThreads(root.get()).init().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Launching...");
				TargetLauncher<?> launcher = root.get().as(TargetLauncher.tclass);
				launcher.launch(Map.of(TargetCmdLineLauncher.CMDLINE_ARGS_NAME, expCloneExit))
						.handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Waiting for launched thread ref");
				ThreadTracker.strongRef.lastThreadRef.waitUntil(r -> r != null).handle(seq::next);
			}, TypeSpec.cls(TargetObjectRef.class)).then((threadRef, seq) -> {
				ThreadTracker.strongRef.lastThreadRef.set(null, null);
				Msg.debug(this, "Got thread ref: " + threadRef);
				threadRef.fetch().handle(seq::next);
			}, launchedThread).then(seq -> {
				Msg.debug(this, "Resuming launched thread indefinitely");
				resumeWhile(launchedThread.get(), t -> true).handle(seq::next);
				// Note that the cloned thread will be terminated despite not returning
			}).then(seq -> {
				Msg.debug(this, "Waiting for 2 exits");
				ThreadTracker.strongRef.exitCount.waitValue(2).handle(seq::next);
			}).finish());
		}
	}

	/**
	 * Check the behavior of sctl when a process clones and you detach the secondary thread
	 * 
	 * This test reveals what appears to be a bug. If I remove the call to continue, then neither
	 * prints until sctl is forcibly terminated.
	 */
	@Test
	public void testExpCloneDetachSecondary() throws Throwable {
		String expCloneExit = DummyProc.which("expCloneExit");
		try (SctlStub stub = runSctl()) {
			AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
			SctlClient client = new SctlClient("Test", socket);
			AtomicReference<TargetObject> root = new AtomicReference<>();
			AtomicReference<TargetObject> launchedThread = new AtomicReference<>();
			AtomicReference<TargetObject> clonedThread = new AtomicReference<>();
			waitOn(sequence(TypeSpec.VOID).then(seq -> {
				Msg.debug(this, "Connecting...");
				completable(TypeSpec.VOID, socket::connect, stub.addr).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Negotiating...");
				client.connect().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting model root");
				client.fetchModelRoot().handle(seq::next);
			}, root).then(seq -> {
				Msg.debug(this, "Initializing thread tracker");
				trackThreads(root.get()).init().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Launching...");
				TargetLauncher<?> launcher = root.get().as(TargetLauncher.tclass);
				launcher.launch(Map.of(TargetCmdLineLauncher.CMDLINE_ARGS_NAME, expCloneExit))
						.handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Waiting for launched thread ref");
				ThreadTracker.strongRef.lastThreadRef.waitUntil(r -> r != null).handle(seq::next);
			}, TypeSpec.cls(TargetObjectRef.class)).then((threadRef, seq) -> {
				ThreadTracker.strongRef.lastThreadRef.set(null, null);
				Msg.debug(this, "Got thread ref: " + threadRef);
				threadRef.fetch().handle(seq::next);
			}, launchedThread).then(seq -> {
				Msg.debug(this, "Resuming until another thread appears: " + launchedThread.get());
				resumeWhile(launchedThread.get(), t -> {
					TargetObjectRef ref = ThreadTracker.strongRef.lastThreadRef.get();
					Msg.debug(this, "lastThreadRef = " + ref);
					return ref == null;
				}).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Waiting for cloned thread");
				ThreadTracker.strongRef.lastThreadRef.waitUntil(r -> r != null).handle(seq::next);
			}, TypeSpec.cls(TargetObjectRef.class)).then((threadRef, seq) -> {
				Msg.debug(this, "Got thread ref: " + threadRef);
				threadRef.fetch().handle(seq::next);
			}, clonedThread).then(seq -> {
				// Verify nothing has exited, yet
				assertNull(ThreadTracker.strongRef.lastExitCode.get());
				Msg.debug(this, "Detaching from cloned thread");
				TargetDetachable<?> detachable = clonedThread.get().as(TargetDetachable.tclass);
				detachable.detach().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Continuing the primary thread indefinitely");
				resumeWhile(launchedThread.get(), t -> true).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Waiting on primary thread to exit");
				ThreadTracker.strongRef.exitCount.waitValue(1).handle(seq::next);
			}).finish());
		}
	}

	/**
	 * Check the behavior of sctl when a process clones and you detach the primary thread
	 * 
	 * This test reveals a minor annoyance. The primary thread resumes execution upon detaching, and
	 * so it exits, terminating the secondary thread (to which I'm still attached) immediately with
	 * the exit code of the whole process.
	 */
	@Test
	public void testExpCloneDetachPrimary() throws Throwable {
		String expCloneExit = DummyProc.which("expCloneExit");
		try (SctlStub stub = runSctl()) {
			AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
			SctlClient client = new SctlClient("Test", socket);
			AtomicReference<TargetObject> root = new AtomicReference<>();
			AtomicReference<TargetObject> launchedThread = new AtomicReference<>();
			AtomicReference<TargetObject> clonedThread = new AtomicReference<>();
			waitOn(sequence(TypeSpec.VOID).then(seq -> {
				Msg.debug(this, "Connecting...");
				completable(TypeSpec.VOID, socket::connect, stub.addr).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Negotiating...");
				client.connect().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting model root");
				client.fetchModelRoot().handle(seq::next);
			}, root).then(seq -> {
				Msg.debug(this, "Initializing thread tracker");
				trackThreads(root.get()).init().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Launching...");
				TargetLauncher<?> launcher = root.get().as(TargetLauncher.tclass);
				launcher.launch(Map.of(TargetCmdLineLauncher.CMDLINE_ARGS_NAME, expCloneExit))
						.handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Waiting for launched thread ref");
				ThreadTracker.strongRef.lastThreadRef.waitUntil(r -> r != null).handle(seq::next);
			}, TypeSpec.cls(TargetObjectRef.class)).then((threadRef, seq) -> {
				ThreadTracker.strongRef.lastThreadRef.set(null, null);
				Msg.debug(this, "Got thread ref: " + threadRef);
				threadRef.fetch().handle(seq::next);
			}, launchedThread).then(seq -> {
				Msg.debug(this, "Resuming until another thread appears: " + launchedThread.get());
				resumeWhile(launchedThread.get(), t -> {
					TargetObjectRef ref = ThreadTracker.strongRef.lastThreadRef.get();
					Msg.debug(this, "lastThreadRef = " + ref);
					return ref == null;
				}).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Waiting for cloned thread");
				ThreadTracker.strongRef.lastThreadRef.waitUntil(r -> r != null).handle(seq::next);
			}, TypeSpec.cls(TargetObjectRef.class)).then((threadRef, seq) -> {
				Msg.debug(this, "Got thread ref: " + threadRef);
				threadRef.fetch().handle(seq::next);
			}, clonedThread).then(seq -> {
				// Verify nothing has exited, yet
				assertNull(ThreadTracker.strongRef.lastExitCode.get());
				Msg.debug(this, "Detaching from primary thread");
				TargetDetachable<?> detachable = launchedThread.get().as(TargetDetachable.tclass);
				detachable.detach().handle(seq::next);
			}).then(seq -> {
				// NOTE: I don't have to continue to observe the exit event
				Msg.debug(this, "Waiting on cloned thread to exit");
				ThreadTracker.strongRef.exitCount.waitValue(1).handle(seq::next);
			}).finish());
		}
	}

	/**
	 * Killing the secondary thread causes the primary thread to terminate with status 9 (not
	 * shifted by 8).
	 */
	@Test
	public void testExpCloneKillSecondary() throws Throwable {
		String expCloneExit = DummyProc.which("expCloneExit");
		try (SctlStub stub = runSctl()) {
			AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
			SctlClient client = new SctlClient("Test", socket);
			AtomicReference<TargetObject> root = new AtomicReference<>();
			AtomicReference<TargetObject> launchedThread = new AtomicReference<>();
			AtomicReference<TargetObject> clonedThread = new AtomicReference<>();
			waitOn(sequence(TypeSpec.VOID).then(seq -> {
				Msg.debug(this, "Connecting...");
				completable(TypeSpec.VOID, socket::connect, stub.addr).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Negotiating...");
				client.connect().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting model root");
				client.fetchModelRoot().handle(seq::next);
			}, root).then(seq -> {
				Msg.debug(this, "Initializing thread tracker");
				trackThreads(root.get()).init().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Launching...");
				TargetLauncher<?> launcher = root.get().as(TargetLauncher.tclass);
				launcher.launch(Map.of(TargetCmdLineLauncher.CMDLINE_ARGS_NAME, expCloneExit))
						.handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Waiting for launched thread ref");
				ThreadTracker.strongRef.lastThreadRef.waitUntil(r -> r != null).handle(seq::next);
			}, TypeSpec.cls(TargetObjectRef.class)).then((threadRef, seq) -> {
				ThreadTracker.strongRef.lastThreadRef.set(null, null);
				Msg.debug(this, "Got thread ref: " + threadRef);
				threadRef.fetch().handle(seq::next);
			}, launchedThread).then(seq -> {
				Msg.debug(this, "Resuming until another thread appears: " + launchedThread.get());
				resumeWhile(launchedThread.get(), t -> {
					TargetObjectRef ref = ThreadTracker.strongRef.lastThreadRef.get();
					Msg.debug(this, "lastThreadRef = " + ref);
					return ref == null;
				}).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Waiting for cloned thread");
				ThreadTracker.strongRef.lastThreadRef.waitUntil(r -> r != null).handle(seq::next);
			}, TypeSpec.cls(TargetObjectRef.class)).then((threadRef, seq) -> {
				Msg.debug(this, "Got thread ref: " + threadRef);
				threadRef.fetch().handle(seq::next);
			}, clonedThread).then(seq -> {
				// Verify nothing has exited, yet
				assertNull(ThreadTracker.strongRef.lastExitCode.get());
				Msg.debug(this, "Killing cloned thread");
				TargetKillable<?> killable = clonedThread.get().as(TargetKillable.tclass);
				killable.kill().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Waiting for exit");
				ThreadTracker.strongRef.lastExitCode.waitUntil(v -> v != null).handle(seq::next);
			}, TypeSpec.cls(Long.class)).then((exit, seq) -> {
				assertEquals(9, exit.longValue());
				seq.exit();
			}).finish());
		}
	}

	/**
	 * There seems to be a bug: The primary thread is not killed, but rather seems to resume, as it
	 * prints. It then exits (with code 1, or status 256) causing the secondary thread to be
	 * terminated.
	 */
	@Test
	public void testExpCloneKillPrimary() throws Throwable {
		String expCloneExit = DummyProc.which("expCloneExit");
		try (SctlStub stub = runSctl()) {
			AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
			SctlClient client = new SctlClient("Test", socket);
			AtomicReference<TargetObject> root = new AtomicReference<>();
			AtomicReference<TargetObject> launchedThread = new AtomicReference<>();
			AtomicReference<TargetObject> clonedThread = new AtomicReference<>();
			waitOn(sequence(TypeSpec.VOID).then(seq -> {
				Msg.debug(this, "Connecting...");
				completable(TypeSpec.VOID, socket::connect, stub.addr).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Negotiating...");
				client.connect().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting model root");
				client.fetchModelRoot().handle(seq::next);
			}, root).then(seq -> {
				Msg.debug(this, "Initializing thread tracker");
				trackThreads(root.get()).init().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Launching...");
				TargetLauncher<?> launcher = root.get().as(TargetLauncher.tclass);
				launcher.launch(Map.of(TargetCmdLineLauncher.CMDLINE_ARGS_NAME, expCloneExit))
						.handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Waiting for launched thread ref");
				ThreadTracker.strongRef.lastThreadRef.waitUntil(r -> r != null).handle(seq::next);
			}, TypeSpec.cls(TargetObjectRef.class)).then((threadRef, seq) -> {
				ThreadTracker.strongRef.lastThreadRef.set(null, null);
				Msg.debug(this, "Got thread ref: " + threadRef);
				threadRef.fetch().handle(seq::next);
			}, launchedThread).then(seq -> {
				Msg.debug(this, "Resuming until another thread appears: " + launchedThread.get());
				resumeWhile(launchedThread.get(), t -> {
					TargetObjectRef ref = ThreadTracker.strongRef.lastThreadRef.get();
					Msg.debug(this, "lastThreadRef = " + ref);
					return ref == null;
				}).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Waiting for cloned thread");
				ThreadTracker.strongRef.lastThreadRef.waitUntil(r -> r != null).handle(seq::next);
			}, TypeSpec.cls(TargetObjectRef.class)).then((threadRef, seq) -> {
				Msg.debug(this, "Got thread ref: " + threadRef);
				threadRef.fetch().handle(seq::next);
			}, clonedThread).then(seq -> {
				// Verify nothing has exited, yet
				assertNull(ThreadTracker.strongRef.lastExitCode.get());
				Msg.debug(this, "Killing launched thread");
				TargetKillable<?> killable = launchedThread.get().as(TargetKillable.tclass);
				killable.kill().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Waiting for exit");
				ThreadTracker.strongRef.lastExitCode.waitUntil(v -> v != null).handle(seq::next);
			}, TypeSpec.cls(Long.class)).then((exit, seq) -> {
				assertEquals(256, exit.longValue());
				seq.exit();
			}).finish());
		}
	}

	@Test
	public void testExpCloneThenAttachKill() throws Throwable {
		try (DummyProc expCloneSpin = DummyProc.run("expCloneSpin"); SctlStub stub = runSctl()) {
			AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
			SctlClient client = new SctlClient("Test", socket);
			AtomicReference<TargetObject> root = new AtomicReference<>();
			AtomicReference<TargetObject> attachedThread = new AtomicReference<>();
			waitOn(sequence(TypeSpec.VOID).then(seq -> {
				Msg.debug(this, "Connecting...");
				completable(TypeSpec.VOID, socket::connect, stub.addr).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Negotiating...");
				client.connect().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting model root");
				client.fetchModelRoot().handle(seq::next);
			}, root).then(seq -> {
				Msg.debug(this, "Initializing thread tracker");
				trackThreads(root.get()).init().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Attaching...");
				TargetAttacher<?> attacher = root.get().as(TargetAttacher.tclass);
				attacher.attach(refPid(client, (int) expCloneSpin.pid)).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Waiting for thread");
				ThreadTracker.strongRef.lastThreadRef.waitUntil(r -> r != null).handle(seq::next);
			}, TypeSpec.cls(TargetObjectRef.class)).then((threadRef, seq) -> {
				Msg.debug(this, "Got thread ref: " + threadRef);
				threadRef.fetch().handle(seq::next);
			}, attachedThread).then(seq -> {
				Msg.debug(this, "Killing...");
				TargetKillable<?> killable = attachedThread.get().as(TargetKillable.tclass);
				killable.kill().handle(seq::next);
			}).finish());
		}
	}

	@Test
	public void testExpReadRIP() throws Throwable {
		String expCloneExit = DummyProc.which("expCloneExit");
		try (SctlStub stub = runSctl()) {
			AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
			SctlClient client = new SctlClient("Test", socket);
			AtomicReference<TargetObject> root = new AtomicReference<>();
			AtomicReference<TargetRegisterBank<?>> regs = new AtomicReference<>();
			AtomicReference<TargetMemory<?>> memory = new AtomicReference<>();
			AtomicReference<Address> rip = new AtomicReference<>();
			waitOn(sequence(TypeSpec.VOID).then(seq -> {
				Msg.debug(this, "Connecting...");
				completable(TypeSpec.VOID, socket::connect, stub.addr).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Negotiating...");
				client.connect().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting model root");
				client.fetchModelRoot().handle(seq::next);
			}, root).then(seq -> {
				Msg.debug(this, "Initializing thread tracker");
				trackThreads(root.get()).init().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Launching...");
				TargetLauncher<?> launcher = root.get().as(TargetLauncher.tclass);
				launcher.launch(Map.of(TargetCmdLineLauncher.CMDLINE_ARGS_NAME, expCloneExit))
						.handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Waiting for thread");
				ThreadTracker.strongRef.lastThreadRef.waitUntil(r -> r != null).handle(seq::next);
			}, TypeSpec.cls(TargetObjectRef.class)).then((threadRef, seq) -> {
				Msg.debug(this, "Got thread ref: " + threadRef);
				threadRef.fetchSuccessor("Registers").thenAccept(obj -> {
					regs.set(obj.as(TargetRegisterBank.tclass));
				}).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Reading rip");
				regs.get().readRegister("rip").handle(seq::next);
			}, TypeSpec.BYTE_ARRAY).then((data, seq) -> {
				long ripVal = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN).getLong(0);
				rip.set(client.getAddress("ram", ripVal));
				Msg.debug(this, "RIP = " + Long.toHexString(ripVal));
				ThreadTracker.strongRef.lastProcRef.get()
						.fetchSuccessor("Memory")
						.thenAccept(obj -> {
							memory.set(obj.as(TargetMemory.tclass));
						})
						.handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Reading memory[rip:8]");
				memory.get().readMemory(rip.get(), 8).handle(seq::next);
				// TODO: Can I assert what actual reads went over the network?
				//   Expect: [rip:8], [rip+8:1], (none)
			}, TypeSpec.BYTE_ARRAY).then((data, seq) -> {
				Msg.debug(this,
					"Read memory[rip:8]: " + NumericUtilities.convertBytesToString(data, ":"));
				memory.get().readMemory(rip.get().add(1), 8).handle(seq::next);
			}, TypeSpec.BYTE_ARRAY).then((data, seq) -> {
				Msg.debug(this,
					"Read memory[rip+1:8]: " + NumericUtilities.convertBytesToString(data, ":"));
				memory.get().readMemory(rip.get().add(2), 5).handle(seq::next);
			}, TypeSpec.BYTE_ARRAY).then((data, seq) -> {
				Msg.debug(this,
					"Read memory[rip+2:5]: " + NumericUtilities.convertBytesToString(data, ":"));
				seq.exit();
			}).finish());
		}
	}

	@Test
	public void testExpWrite() throws Throwable {
		String expPrint = DummyProc.which("expPrint");
		final String toWrite = "Speak";
		final String expected = "Speak, World!";
		try (SctlStub stub = runSctl()) {
			AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
			SctlClient client = new SctlClient("Test", socket);
			AtomicReference<TargetObject> root = new AtomicReference<>();
			AtomicReference<TargetObject> thread = new AtomicReference<>();
			AtomicReference<TargetSymbol<?>> overwrite = new AtomicReference<>();
			AtomicReference<TargetMemory<?>> memory = new AtomicReference<>();
			waitOn(sequence(TypeSpec.VOID).then(seq -> {
				Msg.debug(this, "Connecting...");
				completable(TypeSpec.VOID, socket::connect, stub.addr).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Negotiating...");
				client.connect().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting model root");
				client.fetchModelRoot().handle(seq::next);
			}, root).then(seq -> {
				Msg.debug(this, "Initializing thread tracker");
				trackThreads(root.get()).init().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Launching...");
				TargetLauncher<?> launcher = root.get().as(TargetLauncher.tclass);
				launcher.launch(Map.of(TargetCmdLineLauncher.CMDLINE_ARGS_NAME, expPrint))
						.handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Waiting for thread");
				ThreadTracker.strongRef.lastThreadRef.waitUntil(r -> r != null).handle(seq::next);
			}, TypeSpec.cls(TargetObjectRef.class)).then((threadRef, seq) -> {
				Msg.debug(this, "Got thread ref: " + threadRef);
				threadRef.fetch().handle(seq::next);
			}, thread).then(seq -> {
				ThreadTracker.strongRef.lastProcRef.get()
						.fetchSuccessor(
							PathUtils.parse("Modules[" + expPrint + "].Symbols[overwrite]"))
						.handle(seq::next);
			}, TypeSpec.cls(TargetObject.class)).then((obj, seq) -> {
				overwrite.set(obj.as(TargetSymbol.tclass));
				Msg.debug(this, "overwrite is at addr: " + overwrite.get().getValue());
				ThreadTracker.strongRef.lastProcRef.get()
						.fetchSuccessor("Memory")
						.handle(seq::next);
			}, TypeSpec.cls(TargetObject.class)).then((obj, seq) -> {
				memory.set(obj.as(TargetMemory.tclass));
				Msg.debug(this, "Writing memory");
				memory.get()
						.writeMemory(overwrite.get().getValue(), toWrite.getBytes())
						.handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Reading memory");
				memory.get()
						.readMemory(overwrite.get().getValue(), expected.getBytes().length)
						.handle(seq::next);
			}, TypeSpec.BYTE_ARRAY).then((data, seq) -> {
				Msg.debug(this, "Read: " + new String(data));
				assertEquals(expected, new String(data));
				resumeWhile(thread.get(), t -> true).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Waiting for exit");
				ThreadTracker.strongRef.lastExitCode.waitUntil(v -> v != null).handle(seq::next);
			}, TypeSpec.cls(Long.class)).then((exit, seq) -> {
				assertEquals(toWrite.getBytes()[0], exit / 256);
				seq.exit();
			}).finish());
		}
	}

	@Test
	public void testExpTypes() throws Throwable {
		String expTypes = DummyProc.which("expTypes");
		DataTypeManager dtm = new StandAloneDataTypeManager("Test") {
			{
				dataOrganization =
					DataOrganizationImpl.getDefaultOrganization(getSLEIGH_X86_64_LANGUAGE());
			}
		};

		try (SctlStub stub = runSctl()) {
			AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
			SctlClient client = new SctlClient("Test", socket);
			AtomicReference<TargetObject> root = new AtomicReference<>();
			waitOn(sequence(TypeSpec.VOID).then(seq -> {
				Msg.debug(this, "Connecting...");
				completable(TypeSpec.VOID, socket::connect, stub.addr).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Negotiating...");
				client.connect().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting model root");
				client.fetchModelRoot().handle(seq::next);
			}, root).then(seq -> {
				Msg.debug(this, "Initializing thread tracker");
				trackThreads(root.get()).init().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Launching...");
				TargetLauncher<?> launcher = root.get().as(TargetLauncher.tclass);
				launcher.launch(Map.of(TargetCmdLineLauncher.CMDLINE_ARGS_NAME, expTypes))
						.handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Waiting for process");
				ThreadTracker.strongRef.lastProcRef.waitUntil(r -> r != null).handle(seq::next);
			}, TypeSpec.cls(TargetObjectRef.class)).then((procRef, seq) -> {
				Msg.debug(this, "Got process ref: " + procRef);
				procRef.fetchSubElements(PathUtils.parse("Modules[" + expTypes + "].Types"))
						.thenCompose(DebugModelConventions::fetchAll)
						.handle(seq::next);
			}, DebuggerObjectModel.ELEMENT_MAP_TYPE).then((types, seq) -> {
				Msg.debug(this, "Converting data types");
				TargetDataTypeConverter conv = new TargetDataTypeConverter(dtm);
				AsyncFence fence = new AsyncFence();
				for (TargetObject obj : types.values()) {
					TargetDataType tdt = obj.as(TargetNamedDataType.tclass);
					fence.include(conv.convertTargetDataType(tdt).thenAccept(t -> {
						synchronized (dtm) {
							try (UndoableTransaction tid =
								UndoableTransaction.start(dtm, "Add type", true)) {
								dtm.addDataType(t, DataTypeConflictHandler.DEFAULT_HANDLER);
							}
						}
					}));
				}
				fence.ready().handle(seq::next);
			}).then(seq -> {
				// TODO: Figure out why offsets are lining up
				// I figure it's either alignment, or incorrect int size
				Msg.debug(this, "Printing data types:");
				try (PrintWriter writer = new PrintWriter(System.out)) {
					DataTypeWriter dtw = new DataTypeWriter(dtm, writer);
					List<DataType> all = new ArrayList<>();
					dtm.getAllDataTypes(all);
					dtw.write(all, TaskMonitor.DUMMY);
				}
				catch (Throwable e) {
					throw new AssertionError(e);
				}
				seq.exit();
			}).finish());
		}
	}

	@Test
	public void testExpSymbols() throws Throwable {
		String expTypes = DummyProc.which("expTypes");
		try (SctlStub stub = runSctl()) {
			AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
			SctlClient client = new SctlClient("Test", socket);
			AtomicReference<TargetObject> root = new AtomicReference<>();
			waitOn(sequence(TypeSpec.VOID).then(seq -> {
				Msg.debug(this, "Connecting...");
				completable(TypeSpec.VOID, socket::connect, stub.addr).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Negotiating...");
				client.connect().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting model root");
				client.fetchModelRoot().handle(seq::next);
			}, root).then(seq -> {
				Msg.debug(this, "Initializing thread tracker");
				trackThreads(root.get()).init().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Launching...");
				TargetLauncher<?> launcher = root.get().as(TargetLauncher.tclass);
				launcher.launch(Map.of(TargetCmdLineLauncher.CMDLINE_ARGS_NAME, expTypes))
						.handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Waiting for process");
				ThreadTracker.strongRef.lastProcRef.waitUntil(r -> r != null).handle(seq::next);
			}, TypeSpec.cls(TargetObjectRef.class)).then((procRef, seq) -> {
				Msg.debug(this, "Got process ref: " + procRef);
				procRef.fetchSubElements(PathUtils.parse("Modules[" + expTypes + "].Symbols"))
						.thenCompose(DebugModelConventions::fetchAll)
						.handle(seq::next);
			}, DebuggerObjectModel.ELEMENT_MAP_TYPE).then((symbols, seq) -> {
				Msg.debug(this, "Printing symbols:");
				for (TargetObject sym : symbols.values()) {
					Msg.debug(this, "  " + sym);
				}
				Msg.debug(this, "Done");
				seq.exit();
			}).finish());
		}
	}

	/**
	 * Experiment to see what notifications SCTL sends when we clone then exec
	 * 
	 * In particular what does it say about the threads that are destroyed by the call to exec?
	 */
	@Test
	@Ignore("Eexec is unreliable in the reference stub")
	public void testCloneExec() throws Throwable {
		String expCloneExec = DummyProc.which("expCloneExec");
		try (SctlStub stub = runSctl()) {
			AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
			SctlClient client = new SctlClient("Test", socket);
			AtomicReference<TargetObject> root = new AtomicReference<>();
			AtomicReference<TargetObject> launchedThread = new AtomicReference<>();
			waitOn(sequence(TypeSpec.VOID).then(seq -> {
				Msg.debug(this, "Connecting...");
				completable(TypeSpec.VOID, socket::connect, stub.addr).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Negotiating...");
				client.connect().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting model root");
				client.fetchModelRoot().handle(seq::next);
			}, root).then(seq -> {
				Msg.debug(this, "Initializing thread tracker");
				trackThreads(root.get()).init().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Launching...");
				TargetLauncher<?> launcher = root.get().as(TargetLauncher.tclass);
				launcher.launch(Map.of(TargetCmdLineLauncher.CMDLINE_ARGS_NAME, expCloneExec))
						.handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Waiting for launched thread ref");
				ThreadTracker.strongRef.lastThreadRef.waitUntil(r -> r != null).handle(seq::next);
			}, TypeSpec.cls(TargetObjectRef.class)).then((threadRef, seq) -> {
				ThreadTracker.strongRef.lastThreadRef.set(null, null);
				Msg.debug(this, "Got thread ref: " + threadRef);
				threadRef.fetch().handle(seq::next);
			}, launchedThread).then(seq -> {
				Msg.debug(this, "Resuming until another thread appears: " + launchedThread.get());
				resumeWhile(launchedThread.get(), t -> {
					TargetObjectRef ref = ThreadTracker.strongRef.lastThreadRef.get();
					Msg.debug(this, "lastThreadRef = " + ref);
					return ref == null;
				}).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Resuming until a thread disappears: " + launchedThread.get());
				ThreadTracker.strongRef.lastThreadRemoved.set(null, null);
				resumeWhile(launchedThread.get(), t -> {
					TargetObjectRef ref = ThreadTracker.strongRef.lastThreadRemoved.get();
					Msg.debug(this, "lastThreadRemoved = " + ref);
					return ref == null;
				}).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Checking number of threads");
				ThreadTracker.strongRef.lastProcRef.get()
						.fetchSubElements("Threads")
						.thenCompose(DebugModelConventions::fetchAll)
						.handle(seq::next);
			}, DebuggerObjectModel.ELEMENT_MAP_TYPE).then((threads, seq) -> {
				Msg.debug(this, "Got threads: " + threads);
				assertEquals(1, threads.size());
				seq.exit();
			}).finish());
		}
	}
}
