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
package agent.dbgeng.model;

import static agent.dbgeng.testutil.DummyProc.runProc;
import static ghidra.lifecycle.Unfinished.TODO;
import static org.junit.Assert.*;

import java.lang.invoke.MethodHandles;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import org.junit.*;

import agent.dbgeng.dbgeng.DbgEngTest;
import agent.dbgeng.model.iface1.DbgModelTargetLauncher;
import agent.dbgeng.testutil.DummyProc;
import ghidra.async.*;
import ghidra.dbg.*;
import ghidra.dbg.DebugModelConventions.AllRequiredAccess;
import ghidra.dbg.error.DebuggerModelNoSuchPathException;
import ghidra.dbg.error.DebuggerModelTypeException;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetBreakpointSpecContainer.TargetBreakpointKindSet;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.TargetConsole.Channel;
import ghidra.dbg.target.TargetLauncher.TargetCmdLineLauncher;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.target.schema.XmlSchemaContext;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.Address;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.*;

public abstract class AbstractModelForDbgTest
		extends AbstractGhidraHeadlessIntegrationTest {
	protected static final Map<String, byte[]> AMD64_TEST_REG_VALUES = Map.of( //
		"rax", NumericUtilities.convertStringToBytes("0123456789abcdef"), //
		"ymm0", NumericUtilities.convertStringToBytes("" + //
			"0011223344556677" + "8899aabbccddeeff"));
// TODO: for some reason, the dbgeng thinks ymm0 is VECTOR128
//"0123456789abcdef" + "fedcba9876543210" + "0011223344556677" + "8899aabbccddeeff"));
	protected static final long TIMEOUT_MILLISECONDS =
		SystemUtilities.isInTestingBatchMode() ? 5000 : Long.MAX_VALUE;

	protected static Map<String, String> hexlify(Map<String, byte[]> map) {
		return map.entrySet()
				.stream()
				.collect(Collectors.toMap(Entry::getKey,
					e -> NumericUtilities.convertBytesToString(e.getValue())));
	}

	public interface ModelHost extends AutoCloseable {
		DebuggerObjectModel getModel();

		CompletableFuture<Void> init();
	}

	protected abstract ModelHost modelHost() throws Exception;

	protected static class CatchOffThread implements AutoCloseable {
		protected Throwable caught;

		void catching(Runnable runnable) {
			try {
				runnable.run();
			}
			catch (Throwable e) {
				caught = e;
			}
		}

		@Override
		public void close() throws Exception {
			if (caught != null) {
				throw new AssertionError("Off-thread exception", caught);
			}
		}
	}

	protected static <T> T waitOn(CompletableFuture<T> future) throws Throwable {
		try {
			return future.get(TIMEOUT_MILLISECONDS, TimeUnit.MILLISECONDS);
		}
		catch (ExecutionException e) {
			throw e.getCause();
		}
	}

	@Before
	public void setUpDbgEngTest() {
		DbgEngTest.assumeDbgengDLLLoadable();
	}

	@Test
	public void testInitFinish() throws Throwable {
		try (ModelHost m = modelHost()) {
			waitOn(AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
				m.init().handle(seq::next);
			}).finish());
		}
	}

	@Test
	public void testNonExistentPathGivesNull() throws Throwable {
		try (ModelHost m = modelHost()) {
			DebuggerObjectModel model = m.getModel();

			AtomicReference<TargetObject> root = new AtomicReference<>();
			AtomicReference<AllRequiredAccess> access = new AtomicReference<>();
			waitOn(AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
				m.init().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting session root object");
				model.fetchModelObject("Sessions", "[0]").handle(seq::next);
			}, root).then(seq -> {
				Msg.debug(this, "Tracking session access...");
				DebugModelConventions.trackAccessibility(root.get()).handle(seq::next);
			}, access).then(seq -> {
				Msg.debug(this, "Waiting for session access...");
				access.get().waitValue(true).handle(seq::next);
			}).then(seq -> {
				model.fetchModelObject("Doesn't exist").handle(seq::next);
			}, TypeSpec.cls(TargetObject.class)).then((obj, seq) -> {
				assertNull(obj);
				seq.exit();
			}).finish());
		}
	}

	@Test
	public void testSessionLaunch() throws Throwable {
		try (ModelHost m = modelHost()) {
			DebuggerObjectModel model = m.getModel();

			AtomicReference<TargetObject> root = new AtomicReference<>();
			AtomicReference<AllRequiredAccess> access = new AtomicReference<>();
			AtomicReference<DbgModelTargetLauncher> launcher = new AtomicReference<>();
			TypeSpec<Map<String, ? extends TargetObject>> t = TypeSpec.auto();

			waitOn(AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
				m.init().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting session root object");
				model.fetchModelObject("Sessions", "[0]").handle(seq::next);
			}, root).then(seq -> {
				Msg.debug(this, "Tracking session access...");
				DebugModelConventions.trackAccessibility(root.get()).handle(seq::next);
			}, access).then(seq -> {
				Msg.debug(this, "Waiting for session access...");
				access.get().waitValue(true).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Finding TargetLauncher...");
				DebugModelConventions.findSuitable(DbgModelTargetLauncher.class, root.get())
						.handle(seq::next);
			}, launcher).then(seq -> {
				Msg.debug(this, "Launching...");
				launcher.get().launch("notepad", "junk.txt").handle(seq::nextIgnore);
			}).then(seq -> {
				Msg.debug(this, "Waiting for session access...");
				access.get().waitValue(true).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting Processes (after launch)...");
				model.fetchObjectElements(List.of("Sessions", "[0]"))
						.handle(seq::next);
			}, t).then((children, seq) -> {
				Msg.debug(this, "Processes after: " + children);
				assertEquals(1, children.size());
				seq.exit();
			}).finish());
		}
	}

	@Test
	public void testProcessLaunch() throws Throwable {
		try (ModelHost m = modelHost()) {
			DebuggerObjectModel model = m.getModel();

			AtomicReference<TargetObject> root = new AtomicReference<>();
			AtomicReference<TargetObject> session = new AtomicReference<>();
			AtomicReference<AllRequiredAccess> rootAccess = new AtomicReference<>();
			AtomicReference<DbgModelTargetLauncher> launcher = new AtomicReference<>();
			AtomicReference<AllRequiredAccess> launcherAccess = new AtomicReference<>();
			TypeSpec<Map<String, ? extends TargetObject>> t = TypeSpec.auto();

			waitOn(AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
				m.init().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting session root object");
				model.fetchModelObject("Sessions", "[0]").handle(seq::next);
			}, root).then(seq -> {
				Msg.debug(this, "Tracking session access...");
				DebugModelConventions.trackAccessibility(root.get()).handle(seq::next);
			}, rootAccess).then(seq -> {
				Msg.debug(this, "Waiting for session access...");
				rootAccess.get().waitValue(true).handle(seq::next);
			}).then(seq -> {
				model.fetchModelObject(List.of("Sessions", "[0]")).handle(seq::next);
			}, session).then(seq -> {
				Msg.debug(this, "Finding TargetLauncher...");
				DebugModelConventions.findSuitable(DbgModelTargetLauncher.class,
					session.get()).handle(seq::next);
			}, TypeSpec.cls(TargetObject.class)).then((obj, seq) -> {
				assertTrue(obj.getInterfaceNames().contains("Launcher"));
				launcher.set((DbgModelTargetLauncher) obj);
				Msg.debug(this, "Tracking process access...");
				DebugModelConventions.trackAccessibility(obj).handle(seq::next);
			}, launcherAccess).then(seq -> {
				Msg.debug(this, "Waiting for process access...");
				launcherAccess.get().waitValue(true).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Launching...");
				launcher.get().launch("notepad", "junk.txt").handle(seq::nextIgnore);
			}).then(seq -> {
				Msg.debug(this, "Waiting for session access (again)...");
				rootAccess.get().waitValue(true).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting Processes (after launch)...");
				model.fetchObjectElements(List.of("Sessions", "[0]", "Processes"))
						.handle(seq::next);
			}, t).then((elements, seq) -> {
				Msg.debug(this, "Processes after: " + elements);
				assertEquals(1, elements.size());
				seq.exit();
			}).finish());
		}
	}

	@Test
	public void testListAvailableProcesses() throws Throwable {
		try (DummyProc np = runProc("notepad"); ModelHost m = modelHost()) {
			DebuggerObjectModel model = m.getModel();

			AtomicReference<TargetObject> root = new AtomicReference<>();
			AtomicReference<AllRequiredAccess> access = new AtomicReference<>();

			waitOn(AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
				m.init().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting session root object");
				model.fetchModelObject("Sessions", "[0]").handle(seq::next);
			}, root).then(seq -> {
				Msg.debug(this, "Tracking session access...");
				DebugModelConventions.trackAccessibility(root.get()).handle(seq::next);
			}, access).then(seq -> {
				Msg.debug(this, "Waiting for session access...");
				access.get().waitValue(true).handle(seq::next);
			}).then(seq -> {
				model.fetchObjectElements(List.of("Sessions", "[0]", "Available"))
						.handle(seq::next);
			}, DebuggerObjectModel.ELEMENT_MAP_TYPE).then((available, seq) -> {
				assertTrue(available.containsKey(Long.toString(np.pid)));
				seq.exit();
			}).finish());
		}
	}

	@Test
	public void testListProcesses() throws Throwable {
		try (DummyProc np = runProc("notepad"); ModelHost m = modelHost()) {
			DebuggerObjectModel model = m.getModel();

			AtomicReference<TargetObject> root = new AtomicReference<>();
			AtomicReference<AllRequiredAccess> access = new AtomicReference<>();
			AtomicReference<TargetObject> proc = new AtomicReference<>();

			waitOn(AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
				m.init().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting session root object");
				model.fetchModelObject("Sessions", "[0]").handle(seq::next);
			}, root).then(seq -> {
				Msg.debug(this, "Tracking session access...");
				DebugModelConventions.trackAccessibility(root.get()).handle(seq::next);
			}, access).then(seq -> {
				Msg.debug(this, "Waiting for session access...");
				access.get().waitValue(true).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Finding TargetLauncher...");
				DebugModelConventions.findSuitable(TargetAttacher.class, root.get())
						.handle(
							seq::next);
			}, proc).then(seq -> {
				Msg.debug(this, "Attaching to bogus path...");
				TargetAttacher attacher = proc.get().as(TargetAttacher.class);
				TODO();
				seq.next(null, null);
			}).then(seq -> {
				model.fetchObjectElements(List.of("Sessions", "[0]", "Processes"))
						.handle(seq::next);
				// NB: listProcesses will fail if no process is being debugged
			}, DebuggerObjectModel.ELEMENT_MAP_TYPE).then((processes, seq) -> {
				assertEquals(1, processes.size());
				seq.exit();
			}).finish());
		}
	}

	@Test
	public void testSessionAttachKill() throws Throwable {
		try (DummyProc np = runProc("notepad"); ModelHost m = modelHost()) {
			DebuggerObjectModel model = m.getModel();

			AtomicReference<TargetObject> root = new AtomicReference<>();
			AtomicReference<AllRequiredAccess> access = new AtomicReference<>();
			AtomicReference<TargetAttacher> attacher = new AtomicReference<>();
			AtomicReference<TargetAttachable> attachable = new AtomicReference<>();
			TypeSpec<Map<String, ? extends TargetObject>> t = TypeSpec.auto();

			waitOn(AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
				m.init().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting session root object");
				model.fetchModelObject("Sessions", "[0]").handle(seq::next);
			}, root).then(seq -> {
				Msg.debug(this, "Tracking session access...");
				DebugModelConventions.trackAccessibility(root.get()).handle(seq::next);
			}, access).then(seq -> {
				Msg.debug(this, "Waiting for session access...");
				access.get().waitValue(true).handle(seq::next);
			}).then(seq -> {
//				Msg.debug(this, "Getting Processes (before attach)...");
//				model.getObjectElements(List.of("Sessions", "[0]", "Processes")).handle(seq::next);
//			}, t).then((children, seq) -> {
//				Msg.debug(this, "Processes before: " + children);
//				assertEquals(1, children.size());

				AsyncFence fence = new AsyncFence();
				Msg.debug(this, "Finding TargetAttacher...");
				fence.include(DebugModelConventions.findSuitable(TargetAttacher.class, root.get())
						.thenAccept(a -> {
							Msg.debug(this, "  Got TargetAttacher: " + a);
							attacher.set(a);
						}));
				fence.include(model.fetchModelObject("Sessions", "[0]", "Available",
					"[" + np.pid + "]")
						.thenAccept(o -> {
							Msg.debug(this, "  Got Attachable: " + o);
							assertTrue(o.getInterfaceNames().contains("Attachable"));
							attachable.set((TargetAttachable) o);
						}));
				fence.ready().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Attaching...");
				attacher.get().attach(attachable.get()).handle(seq::nextIgnore);
			}).then(seq -> {
				Msg.debug(this, "Waiting for session access (again)...");
				access.get().waitValue(true).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting Processes (after attach)...");
				model.fetchObjectElements(List.of("Sessions", "[0]", "Processes"))
						.handle(seq::next);
			}, t).then((elements, seq) -> {
				Msg.debug(this, "Processes after: " + elements);
				assertEquals(1, elements.size());
				Msg.debug(this, "Killing...");
				TargetObject attached = elements.get("0");
				assertTrue(attached.getInterfaceNames().contains("Killable"));
				TargetKillable killable = (TargetKillable) attached;
				killable.kill().handle(seq::next);
			}).finish());
		}
	}

	@Test
	public void testProcessAttachKill() throws Throwable {
		try (DummyProc np = runProc("notepad"); ModelHost m = modelHost()) {
			DebuggerObjectModel model = m.getModel();

			AtomicReference<TargetObject> root = new AtomicReference<>();
			AtomicReference<AllRequiredAccess> access = new AtomicReference<>();
			AtomicReference<TargetObject> obj = new AtomicReference<>();
			TypeSpec<Map<String, ? extends TargetObject>> t = TypeSpec.auto();

			waitOn(AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
				m.init().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting session root object");
				model.fetchModelObject("Sessions", "[0]").handle(seq::next);
			}, root).then(seq -> {
				Msg.debug(this, "Tracking session access...");
				DebugModelConventions.trackAccessibility(root.get()).handle(seq::next);
			}, access).then(seq -> {
				Msg.debug(this, "Waiting for session access...");
				access.get().waitValue(true).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Finding TargetLauncher...");
				DebugModelConventions.findSuitable(TargetAttacher.class, root.get())
						.handle(
							seq::next);
			}, obj).then(seq -> {
				Msg.debug(this, "Attaching...");
				TargetAttacher attacher = obj.get().as(TargetAttacher.class);
				attacher.attach(np.pid)
						.handle(seq::nextIgnore);
			}).then(seq -> {
				Msg.debug(this, "Waiting for session access (again, again)...");
				access.get().waitValue(true).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting Processes (after attach)...");
				model.fetchObjectElements(List.of("Sessions", "[0]", "Processes"))
						.handle(seq::next);
			}, t).then((elements, seq) -> {
				Msg.debug(this, "Processes after: " + elements);
				assertEquals(1, elements.size());
				Msg.debug(this, "Killing...");
				TargetObject attached = elements.get("0");
				assertTrue(attached.getInterfaceNames().contains("Killable"));
				TargetKillable killable = (TargetKillable) attached;
				killable.kill().handle(seq::next);
			}).finish());
		}
	}

	@Test
	public void testProcessAttachContKill() throws Throwable {
		try (DummyProc np = runProc("notepad"); ModelHost m = modelHost()) {
			DebuggerObjectModel model = m.getModel();

			AtomicReference<TargetObject> root = new AtomicReference<>();
			AtomicReference<AllRequiredAccess> access = new AtomicReference<>();
			AtomicReference<TargetObject> obj = new AtomicReference<>();
			TypeSpec<Map<String, ? extends TargetObject>> t = TypeSpec.auto();

			waitOn(AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
				m.init().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting session root object");
				model.fetchModelObject("Sessions", "[0]").handle(seq::next);
			}, root).then(seq -> {
				Msg.debug(this, "Tracking session access...");
				DebugModelConventions.trackAccessibility(root.get()).handle(seq::next);
			}, access).then(seq -> {
				Msg.debug(this, "Waiting for session access...");
				access.get().waitValue(true).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Finding TargetLauncher...");
				DebugModelConventions.findSuitable(TargetAttacher.class, root.get())
						.handle(
							seq::next);
			}, obj).then(seq -> {
				Msg.debug(this, "Attaching...");
				TargetAttacher attacher = obj.get().as(TargetAttacher.class);
				attacher.attach(np.pid)
						.handle(seq::nextIgnore);
			}).then(seq -> {
				Msg.debug(this, "Waiting for session access (again, again)...");
				access.get().waitValue(true).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting Process 1...");
				model.fetchModelObject("Sessions", "[0]", "Processes", "[0]").handle(seq::next);
			}, obj).then(seq -> {
				Msg.debug(this, "Resuming...");
				TargetResumable resumable = obj.get().as(TargetResumable.class);
				resumable.resume().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Waiting for session access (after resume)...");
				access.get().waitValue(true).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting Processes (after attach)...");
				model.fetchObjectElements(List.of("Sessions", "[0]", "Processes"))
						.handle(seq::next);
			}, t).then((elements, seq) -> {
				Msg.debug(this, "Processes after: " + elements);
				assertEquals(1, elements.size());
				Msg.debug(this, "Killing...");
				TargetObject attached = elements.get("0");
				assertTrue(attached.getInterfaceNames().contains("Killable"));
				TargetKillable killable = (TargetKillable) attached;
				killable.kill().handle(seq::nextIgnore);
			}).finish());
		}
	}

	@Test
	public void testLaunchContExit() throws Throwable {
		try (ModelHost m = modelHost()) {
			DebuggerObjectModel model = m.getModel();

			AtomicReference<TargetObject> root = new AtomicReference<>();
			AtomicReference<AllRequiredAccess> access = new AtomicReference<>();
			AtomicReference<TargetObject> obj = new AtomicReference<>();
			waitOn(AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
				m.init().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting session root object");
				model.fetchModelObject("Sessions", "[0]").handle(seq::next);
			}, root).then(seq -> {
				Msg.debug(this, "Tracking session access...");
				DebugModelConventions.trackAccessibility(root.get()).handle(seq::next);
			}, access).then(seq -> {
				Msg.debug(this, "Waiting for session access...");
				access.get().waitValue(true).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Finding TargetLauncher...");
				DebugModelConventions.findSuitable(DbgModelTargetLauncher.class, root.get())
						.handle(seq::next);
			}, obj).then(seq -> {
				Msg.debug(this, "Launching...");
				TargetLauncher launcher = obj.get().as(TargetLauncher.class);
				launcher.launch(Map.of(TargetCmdLineLauncher.CMDLINE_ARGS_NAME, "notepad junk.txt"))
						.handle(seq::nextIgnore);
			}).then(seq -> {
				Msg.debug(this, "Waiting for session access (again)...");
				access.get().waitValue(true).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting Process 1...");
				model.fetchModelObject("Sessions", "[0]", "Processes", "[0]").handle(seq::next);
			}, obj).then(seq -> {
				Msg.debug(this, "Resuming...");
				TargetResumable resumable = obj.get().as(TargetResumable.class);
				resumable.resume().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Waiting for session access (after resume)...");
				access.get().waitValue(true).handle(seq::next);
			}).finish());
		}
	}

	@Test(expected = DebuggerModelNoSuchPathException.class)
	public void testAttachNoObjectErr() throws Throwable {
		try (ModelHost m = modelHost()) {
			DebuggerObjectModel model = m.getModel();

			AtomicReference<TargetObject> root = new AtomicReference<>();
			AtomicReference<AllRequiredAccess> access = new AtomicReference<>();
			AtomicReference<TargetObject> proc = new AtomicReference<>();

			waitOn(AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
				m.init().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting session root object");
				model.fetchModelObject("Sessions", "[0]").handle(seq::next);
			}, root).then(seq -> {
				Msg.debug(this, "Tracking session access...");
				DebugModelConventions.trackAccessibility(root.get()).handle(seq::next);
			}, access).then(seq -> {
				Msg.debug(this, "Waiting for session access...");
				access.get().waitValue(true).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Finding TargetLauncher...");
				DebugModelConventions.findSuitable(TargetAttacher.class, root.get())
						.handle(
							seq::next);
			}, proc).then(seq -> {
				Msg.debug(this, "Attaching to bogus path...");
				TargetAttacher attacher = proc.get().as(TargetAttacher.class);
				TODO();
				seq.next(null, null);
			}).finish());
		}
	}

	@Test(expected = DebuggerModelTypeException.class)
	public void testAttachNonAttachableErr() throws Throwable {
		try (ModelHost m = modelHost()) {
			DebuggerObjectModel model = m.getModel();

			AtomicReference<TargetObject> root = new AtomicReference<>();
			AtomicReference<AllRequiredAccess> access = new AtomicReference<>();
			AtomicReference<TargetObject> proc = new AtomicReference<>();

			waitOn(AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
				m.init().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting session root object");
				model.fetchModelObject("Sessions", "[0]").handle(seq::next);
			}, root).then(seq -> {
				Msg.debug(this, "Tracking session access...");
				DebugModelConventions.trackAccessibility(root.get()).handle(seq::next);
			}, access).then(seq -> {
				Msg.debug(this, "Waiting for session access...");
				access.get().waitValue(true).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Finding TargetLauncher...");
				DebugModelConventions.findSuitable(TargetAttacher.class, root.get())
						.handle(
							seq::next);
			}, proc).then(seq -> {
				Msg.debug(this, "Attaching to bogus path...");
				TargetAttacher attacher = proc.get().as(TargetAttacher.class);
				TODO();
				seq.next(null, null);
			}).finish());
			fail("Exception expected");
		}
	}

	@Test
	@Ignore("for developer workstation")
	public void stressTestExecute() throws Throwable {
		for (int i = 0; i < 100; i++) {
			testExecute();
		}
	}

	//@Test
	public void testExecute() throws Throwable {
		try (ModelHost m = modelHost()) {
			DebuggerObjectModel model = m.getModel();

			AtomicReference<TargetObject> root = new AtomicReference<>();
			AtomicReference<AllRequiredAccess> access = new AtomicReference<>();
			AsyncReference<String, Void> lastOut = new AsyncReference<>();

			DebuggerModelListener l = new DebuggerModelListener() {
				@Override
				public void consoleOutput(TargetObject interpreter, Channel channel,
						byte[] out) {
					String str = new String(out);
					Msg.debug(this, "Got " + channel + " output: " + str);
					lastOut.set(str, null);
				}
			};

			waitOn(AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
				m.init().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting session root object...");
				model.fetchModelObject("Sessions", "[0]").handle(seq::next);
			}, root).then(seq -> {
				root.get().addListener(l);
				Msg.debug(this, "Tracking session access...");
				DebugModelConventions.trackAccessibility(root.get()).handle(seq::next);
			}, access).then(seq -> {
				Msg.debug(this, "Waiting for session access...");
				access.get().waitValue(true).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Running command...");
				TargetInterpreter interpreter = root.get().as(TargetInterpreter.class);
				interpreter.execute(".echo xyzzy").handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Waiting for expected output...");
				lastOut.waitValue("xyzzy\n").handle(seq::next);
			}).finish());
		}
	}

	@Test
	public void testExecuteCapture() throws Throwable {
		try (ModelHost m = modelHost(); CatchOffThread offThread = new CatchOffThread()) {
			DebuggerObjectModel model = m.getModel();

			AtomicReference<TargetObject> root = new AtomicReference<>();
			AtomicReference<AllRequiredAccess> access = new AtomicReference<>();

			DebuggerModelListener l = new DebuggerModelListener() {
				@Override
				public void consoleOutput(TargetObject interpreter, Channel channel,
						String out) {
					String str = new String(out);
					Msg.debug(this, "Got " + channel + " output: " + str);
					if (!str.contains("test")) {
						return;
					}
					offThread.catching(() -> fail("Unexpected output:" + str));
				}
			};

			waitOn(AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
				m.init().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting session root object...");
				model.fetchModelObject("Sessions", "[0]").handle(seq::next);
			}, root).then(seq -> {
				root.get().addListener(l);
				Msg.debug(this, "Tracking session access...");
				DebugModelConventions.trackAccessibility(root.get()).handle(seq::next);
			}, access).then(seq -> {
				Msg.debug(this, "Waiting for session access...");
				access.get().waitValue(true).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Running command with capture...");
				TargetInterpreter interpreter = root.get().as(TargetInterpreter.class);
				interpreter.executeCapture(".echo xyzzy").handle(seq::next);
			}, TypeSpec.STRING).then((out, seq) -> {
				Msg.debug(this, "Captured: " + out);
				assertTrue(out.contains("xyzzy"));
				seq.exit();
			}).finish());
		}
	}

	@Test
	public void testGetBreakKinds() throws Throwable {
		try (ModelHost m = modelHost()) {
			DebuggerObjectModel model = m.getModel();

			AtomicReference<TargetObject> root = new AtomicReference<>();
			AtomicReference<AllRequiredAccess> access = new AtomicReference<>();
			AtomicReference<TargetBreakpointSpecContainer> breaks = new AtomicReference<>();

			waitOn(AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
				m.init().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting session root object...");
				model.fetchModelObject("Sessions", "[0]").handle(seq::next);
			}, root).then(seq -> {
				Msg.debug(this, "Tracking session access...");
				DebugModelConventions.trackAccessibility(root.get()).handle(seq::next);
			}, access).then(seq -> {
				Msg.debug(this, "Waiting for session access...");
				access.get().waitValue(true).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Finding breakpoint container...");
				DebugModelConventions.findSuitable(TargetBreakpointSpecContainer.class, root.get())
						.handle(seq::next);
			}, breaks).then(seq -> {
				Msg.debug(this, "Got: " + breaks);
				TargetBreakpointKindSet kinds = breaks.get().getSupportedBreakpointKinds();
				Msg.debug(this, "Supports: " + kinds);
				assertEquals(4, kinds.size());
				seq.exit();
			}).finish());
		}
	}

	public static final TypeSpec<Collection<? extends TargetBreakpointLocation>> BL_COL_SPEC =
		null;

	@Test
	public void testPlaceBreakpoint() throws Throwable {
		try (ModelHost m = modelHost()) {
			DebuggerObjectModel model = m.getModel();

			AtomicReference<TargetObject> root = new AtomicReference<>();
			AtomicReference<AllRequiredAccess> access = new AtomicReference<>();
			AtomicReference<DbgModelTargetLauncher> launcher = new AtomicReference<>();
			AtomicReference<TargetBreakpointSpecContainer> breaks = new AtomicReference<>();
			AtomicReference<TargetBreakpointLocation> loc = new AtomicReference<>();

			waitOn(AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
				m.init().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting session root object...");
				model.fetchModelObject("Sessions", "[0]").handle(seq::next);
			}, root).then(seq -> {
				Msg.debug(this, "Tracking session access...");
				DebugModelConventions.trackAccessibility(root.get()).handle(seq::next);
			}, access).then(seq -> {
				Msg.debug(this, "Waiting for session access...");
				access.get().waitValue(true).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Finding TargetLauncher...");
				DebugModelConventions.findSuitable(DbgModelTargetLauncher.class, root.get())
						.handle(
							seq::next);
			}, launcher).then(seq -> {
				Msg.debug(this, "Launching...");
				launcher.get()
						.launch(Map.of(TargetCmdLineLauncher.CMDLINE_ARGS_NAME, "notepad junk.txt"))
						.handle(seq::nextIgnore);
			}).then(seq -> {
				Msg.debug(this, "Finding breakpoint container...");
				DebugModelConventions.findSuitable(TargetBreakpointSpecContainer.class, root.get())
						.handle(seq::next);
			}, breaks).then(seq -> {
				Msg.debug(this, "Placing breakpoint...");
				breaks.get()
						.placeBreakpoint("0x7ff7d52c8987",
							Set.of(TargetBreakpointKind.SW_EXECUTE))
						.handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting breakpoint specs...");
				breaks.get()
						.fetchElements()
						.handle(seq::next);
			}, DebuggerObjectModel.ELEMENT_MAP_TYPE).then((specs, seq) -> {
				Msg.debug(this, "Got specs: " + specs);
				assertEquals(1, specs.size());
				TargetBreakpointSpec spec = specs.get("0").as(TargetBreakpointSpec.class);
				spec.getLocations().handle(seq::next);
			}, BL_COL_SPEC).then((es, seq) -> {
				Msg.debug(this, "Got effectives: " + es);
				assertEquals(1, es.size());
				loc.set(es.iterator().next());
				Address addr = loc.get().getAddress();
				Msg.debug(this, "Got address: " + addr);
				seq.exit();
			}).finish());
		}
	}

	@Test
	public void testStack() throws Throwable {
		try (ModelHost m = modelHost()) {
			DebuggerObjectModel model = m.getModel();

			AtomicReference<TargetObject> root = new AtomicReference<>();
			AtomicReference<AllRequiredAccess> access = new AtomicReference<>();
			AtomicReference<TargetBreakpointSpecContainer> breaks = new AtomicReference<>();
			AtomicReference<TargetLauncher> launcher = new AtomicReference<>();
			AtomicReference<TargetObject> obj = new AtomicReference<>();
			waitOn(AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
				m.init().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting session root object");
				model.fetchModelObject("Sessions", "[0]").handle(seq::next);
			}, root).then(seq -> {
				Msg.debug(this, "Tracking session access...");
				DebugModelConventions.trackAccessibility(root.get()).handle(seq::next);
			}, access).then(seq -> {
				Msg.debug(this, "Waiting for session access...");
				access.get().waitValue(true).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Finding TargetLauncher...");
				DebugModelConventions.findSuitable(TargetLauncher.class, root.get())
						.handle(
							seq::next);
			}, launcher).then(seq -> {
				Msg.debug(this, "Launching...");
				launcher.get()
						.launch(Map.of("args", List.of("notepad", "junk.txt")))
						.handle(seq::nextIgnore);
			}).then(seq -> {
				Msg.debug(this, "Waiting for session access (again)...");
				access.get().waitValue(true).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Finding breakpoint container...");
				DebugModelConventions.findSuitable(TargetBreakpointSpecContainer.class, root.get())
						.handle(seq::next);
			}, breaks).then(seq -> {
				Msg.debug(this, "Placing breakpoint...");
				breaks.get()
						.placeBreakpoint("0x7ff7d52c8987",
							Set.of(TargetBreakpointKind.SW_EXECUTE))
						.handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting Process 1...");
				model.fetchModelObject("Sessions", "[0]", "Processes", "[0]").handle(seq::next);
			}, obj).then(seq -> {
				Msg.debug(this, "Resuming...");
				TargetResumable resumable = obj.get().as(TargetResumable.class);
				resumable.resume().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Waiting for session access (after resume)...");
				access.get().waitValue(true).handle(seq::next);
			}).then(seq -> {
				obj.get().fetchSubElements("Threads", "[0]", "Stack").handle(seq::next);
			}, DebuggerObjectModel.ELEMENT_MAP_TYPE).then((frames, seq) -> {
				Msg.debug(this, "Got stack:");
				for (Map.Entry<String, ? extends TargetObject> ent : frames.entrySet()) {
					TargetStackFrame frame = ent.getValue().as(TargetStackFrame.class);
					Msg.debug(this, ent.getKey() + ": " + frame.getProgramCounter());
				}
				long offset = frames.get("0")
						.getTypedAttributeNowByName("pc", Address.class,
							null)
						.getOffset();
				assertEquals(0x7fffadd6e890L, offset);
				//assertEquals("main", frames.get("" + (frames.size() - 1))
				//		.getTypedAttributeNowByName("function", String.class, null));
				seq.exit();
			}).finish());
		}
	}

	@Test
	public void testRegisters() throws Throwable {
		try (ModelHost m = modelHost()) {
			DebuggerObjectModel model = m.getModel();

			AtomicReference<TargetObject> root = new AtomicReference<>();
			AtomicReference<AllRequiredAccess> access = new AtomicReference<>();
			AtomicReference<TargetLauncher> launcher = new AtomicReference<>();
			AtomicReference<TargetObject> proc = new AtomicReference<>();
			AtomicReference<TargetRegisterBank> bank = new AtomicReference<>();
			Set<TargetRegister> descs = new LinkedHashSet<>();

			waitOn(AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
				m.init().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting session root object");
				model.fetchModelObject("Sessions", "[0]").handle(seq::next);
			}, root).then(seq -> {
				Msg.debug(this, "Tracking session access...");
				DebugModelConventions.trackAccessibility(root.get()).handle(seq::next);
			}, access).then(seq -> {
				Msg.debug(this, "Waiting for session access...");
				access.get().waitValue(true).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Finding TargetLauncher...");
				DebugModelConventions.findSuitable(DbgModelTargetLauncher.class, root.get())
						.handle(
							seq::next);
			}, launcher).then(seq -> {
				Msg.debug(this, "Launching...");
				launcher.get()
						.launch(Map.of("args", List.of("notepad", "junk.txt")))
						.handle(seq::nextIgnore);
			}).then(seq -> {
				Msg.debug(this, "Waiting for session access (again)...");
				access.get().waitValue(true).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting Process 1...");
				model.fetchModelObject(List.of("Sessions", "[0]", "Processes", "[0]"))
						.handle(
							seq::next);
			}, proc).then(seq -> {
				proc.get().fetchSuccessor("Threads", "[0]", "Stack", "[0]").thenAccept(top -> {
					bank.set(top.as(TargetRegisterBank.class));
				}).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Got bank: " + bank.get());
				Msg.debug(this, "Descriptions ref: " + bank.get().getDescriptions());
				TargetRegisterContainer cont = bank.get().getDescriptions();
				Msg.debug(this, "Register descriptions: " + cont);
				cont.getRegisters().thenAccept(descs::addAll).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Elements: ");
				for (TargetRegister reg : descs) {
					Msg.debug(this, "  " + reg.getIndex() + ": " + reg.getBitLength());
				}
				bank.get().readRegisters(descs).handle(seq::next);
			}, TypeSpec.map(String.class, byte[].class)).then((data, seq) -> {
				Msg.debug(this, "Values: ");
				for (Map.Entry<String, byte[]> ent : data.entrySet()) {
					Msg.debug(this, "  " + ent.getKey() + " = " +
						NumericUtilities.convertBytesToString(ent.getValue()));
				}
				// TODO: Implement Environment, and port these tests
				Msg.debug(this, "Writing two registers, general and vector");
				bank.get().writeRegistersNamed(AMD64_TEST_REG_VALUES).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Flushing cache");
				bank.get().invalidateCaches().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Re-reading values");
				// NOTE: Can't reliably step here since rax may be referenced by the instruction
				bank.get().readRegistersNamed(AMD64_TEST_REG_VALUES.keySet()).handle(seq::next);
			}, TypeSpec.map(String.class, byte[].class)).then((data, seq) -> {
				assertEquals(hexlify(AMD64_TEST_REG_VALUES), hexlify(data));
				seq.exit();
			}).finish());
		}
	}

	@Test
	public void testFocusProcesses() throws Throwable {
		try (DummyProc np = runProc("notepad"); ModelHost m = modelHost()) {
			DebuggerObjectModel model = m.getModel();

			AtomicReference<TargetObject> root = new AtomicReference<>();
			AtomicReference<TargetFocusScope> scope = new AtomicReference<>();
			AtomicReference<AllRequiredAccess> access = new AtomicReference<>();
			AtomicReference<TargetObject> processes = new AtomicReference<>();
			AtomicReference<TargetObject> obj1 = new AtomicReference<>();
			AtomicReference<TargetObject> obj2 = new AtomicReference<>();
			AsyncReference<List<String>, Void> focusProcPath = new AsyncReference<>();
			AsyncReference<Integer, Void> processCount = new AsyncReference<>();

			DebuggerModelListener procListener = new DebuggerModelListener() {
				@Override
				public void elementsChanged(TargetObject parent, Collection<String> removed,
						Map<String, ? extends TargetObject> added) {
					processCount.set(processes.get().getCachedElements().size(), null);
				}
			};
			DebuggerModelListener focusListener =
				new AnnotatedDebuggerAttributeListener(MethodHandles.lookup()) {
					@AttributeCallback(TargetFocusScope.FOCUS_ATTRIBUTE_NAME)
					public void focusChanged(TargetObject object, TargetObject focused) {
						// Truncate the path to the parent process
						focusProcPath.set(focused.getPath().subList(0, 2), null);
					}
				};

			waitOn(AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
				m.init().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting session root object");
				model.fetchModelObject("Sessions", "[0]").handle(seq::next);
			}, root).then(seq -> {
				scope.set(root.get().as(TargetFocusScope.class));
				scope.get().addListener(focusListener);
				Msg.debug(this, "Tracking session access...");
				DebugModelConventions.trackAccessibility(root.get()).handle(seq::next);
			}, access).then(seq -> {
				Msg.debug(this, "Waiting for session access...");
				access.get().waitValue(true).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Finding TargetLauncher...");
				DebugModelConventions.findSuitable(DbgModelTargetLauncher.class, root.get())
						.handle(
							seq::next);
			}, obj1).then(seq -> {
				Msg.debug(this, "Attaching...");
				TargetAttacher attacher = obj1.get().as(TargetAttacher.class);
				attacher.attach(np.pid).handle(seq::nextIgnore);
			}).then(seq -> {
				Msg.debug(this, "Getting processes container");
				model.fetchModelObject("Sessions", "[0]", "Processes").handle(seq::next);
			}, processes).then(seq -> {
				processes.get().addListener(procListener);
				Msg.debug(this, "Finding TargetLauncher...");
				DebugModelConventions.findSuitable(DbgModelTargetLauncher.class, root.get())
						.handle(
							seq::next);
			}, obj2).then(seq -> {
				Msg.debug(this, "Creating another process");
				TargetLauncher launcher = obj2.get().as(TargetLauncher.class);
				launcher.launch(Map.of(TargetCmdLineLauncher.CMDLINE_ARGS_NAME, "notepad junk.txt"))
						.handle(seq::nextIgnore);
			}).then(seq -> {
				Msg.debug(this, "Waiting for session access (again)...");
				access.get().waitValue(true).handle(seq::next);
			}).then(seq -> {
				assertTrue(PathUtils.isAncestor(List.of("Sessions", "[0]", "Processes", "[1]"),
					scope.get().getFocus().getPath()));
				// Redundant, but verifies the listener is keeping up
				assertEquals(List.of("Sessions", "[0]", "Processes", "[1]"), focusProcPath.get());

				Msg.debug(this, "Requesting focus on process 0");
				AsyncFence fence = new AsyncFence();
				TargetObject p2 = model.getModelObject("Sessions", "[0]", "Processes", "[0]");
				fence.include(focusProcPath.waitValue(p2.getPath()));
				fence.include(scope.get().requestFocus(p2));
				fence.ready().handle(seq::next);
			}).then(seq -> {
				assertTrue(PathUtils.isAncestor(List.of("Sessions", "[0]", "Processes", "[0]"),
					scope.get().getFocus().getPath()));
				// Redundant, but verifies the listener is keeping up
				assertEquals(List.of("Sessions", "[0]", "Processes", "[0]"), focusProcPath.get());
				seq.exit();
			}).finish());
		}
	}

	protected void init(ModelHost m) throws Throwable {
		waitOn(m.init());
	}

	@Test
	public void testSerializeSchema() throws Throwable {
		try (ModelHost m = modelHost()) {
			DebuggerObjectModel model = m.getModel();
			init(m);

			TargetObjectSchema rootSchema = model.getRootSchema();
			String serialized = XmlSchemaContext.serialize(rootSchema.getContext());
			System.out.println(serialized);

			assertEquals("Debugger", rootSchema.getName().toString());
		}
	}
}
