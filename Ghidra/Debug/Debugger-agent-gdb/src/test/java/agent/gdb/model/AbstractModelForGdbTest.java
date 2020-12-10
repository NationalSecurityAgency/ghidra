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
package agent.gdb.model;

import static ghidra.dbg.testutil.DummyProc.run;
import static ghidra.dbg.testutil.DummyProc.which;
import static org.junit.Assert.*;

import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import org.junit.Ignore;
import org.junit.Test;

import agent.gdb.manager.GdbManager;
import agent.gdb.model.EventSequenceListener.EventRecord;
import agent.gdb.model.impl.GdbModelTargetInferior;
import agent.gdb.model.impl.GdbModelTargetStackFrame;
import ghidra.async.AsyncReference;
import ghidra.async.AsyncUtils;
import ghidra.dbg.DebugModelConventions;
import ghidra.dbg.DebugModelConventions.AllRequiredAccess;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.attributes.TargetObjectRef;
import ghidra.dbg.attributes.TargetObjectRefList;
import ghidra.dbg.error.DebuggerModelNoSuchPathException;
import ghidra.dbg.error.DebuggerModelTypeException;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetBreakpointContainer.TargetBreakpointKindSet;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.TargetConsole.Channel;
import ghidra.dbg.target.TargetEventScope.TargetEventType;
import ghidra.dbg.target.TargetFocusScope.TargetFocusScopeListener;
import ghidra.dbg.target.TargetLauncher.TargetCmdLineLauncher;
import ghidra.dbg.target.TargetMethod.ParameterDescription;
import ghidra.dbg.target.TargetObject.TargetObjectListener;
import ghidra.dbg.target.TargetSteppable.TargetStepKind;
import ghidra.dbg.testutil.DummyProc;
import ghidra.dbg.util.*;
import ghidra.program.model.address.Address;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.*;

@Ignore("Need correct version for CI")
public abstract class AbstractModelForGdbTest
		extends AbstractGhidraHeadlessIntegrationTest implements DebuggerModelTestUtils {
	protected static final Map<String, byte[]> AMD64_TEST_REG_VALUES = Map.of( //
		"rax", NumericUtilities.convertStringToBytes("0123456789abcdef"), //
		"ymm0", NumericUtilities.convertStringToBytes("" + //
			"0123456789abcdef" +
			"fedcba9876543210" +
			"0011223344556677" +
			"8899aabbccddeeff"));
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

	protected abstract ModelHost modelHost(String gdbCmd) throws Exception;

	protected ModelHost modelHost() throws Exception {
		return modelHost(GdbManager.DEFAULT_GDB_CMD);
	}

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

	protected void init(ModelHost m) throws Throwable {
		waitOn(m.init());
	}

	protected static boolean isTerminationError(Throwable ex) {
		ex = AsyncUtils.unwrapThrowable(ex);
		// TODO: Marshall this exception better via GADP
		if (ex instanceof RuntimeException || ex instanceof IllegalStateException) {
			if (ex.getMessage().contains("GDB is terminating") ||
				ex.getMessage().contains("Unknown: Unknown server-side error")) {
				return true;
			}
		}
		if (ex instanceof InterruptedException) {
			return true; // TODO: This is way too broad
		}
		return false;
	}

	protected static <T> T ignoreTermination(Throwable t) {
		Throwable ex = AsyncUtils.unwrapThrowable(t);
		// TODO: Should it be an error if there's no exception here?
		// As long as state is correct and root is invalid after?
		if (isTerminationError(ex)) {
			return null; // pass
		}
		throw new AssertionError(t);
	}

	@Test
	public void testInitFinish() throws Throwable {
		try (ModelHost m = modelHost()) {
			init(m);
		}
	}

	@Test
	@Ignore("abstract test case is failing on off-thread exceptions")
	public void testBadGdbCmd() throws Throwable {
		try (ModelHost m = modelHost("/usr/bin/this_shouldnt_exit")) {
			init(m);
			// TODO: assert model state is TERMINATE or something
		}
		catch (Exception ex) {
			ignoreTermination(ex);
		}
	}

	@Test
	public void testNonExistentPathGivesNull() throws Throwable {
		try (ModelHost m = modelHost()) {
			DebuggerObjectModel model = m.getModel();
			init(m);
			Msg.debug(this, "Getting root object");
			TargetObject root = root(model);
			Msg.debug(this, "Tracking session access...");
			AllRequiredAccess access = access(root);
			Msg.debug(this, "Waiting for session access...");
			waitAcc(access);
			TargetObject obj = waitOn(model.fetchModelObject("Doesn't exist"));
			assertNull(obj);
		}
	}

	@Test
	public void testSessionLaunch() throws Throwable {
		try (ModelHost m = modelHost()) {
			DebuggerObjectModel model = m.getModel();
			init(m);
			Msg.debug(this, "Getting root object");
			TargetObject root = root(model);
			Msg.debug(this, "Tracking session access...");
			AllRequiredAccess access = access(root);
			Msg.debug(this, "Waiting for session access...");
			waitAcc(access);
			Msg.debug(this, "Getting Inferiors (before launch)...");
			Map<String, ? extends TargetObjectRef> inferiors =
				waitOn(model.fetchObjectElements(List.of("Inferiors")));
			Msg.debug(this, "Inferiors before: " + inferiors);
			assertEquals(1, inferiors.size());
			Msg.debug(this, "Finding TargetLauncher...");
			TargetLauncher<?> launcher = suitable(TargetLauncher.tclass, root);
			Msg.debug(this, "Launching...");
			waitOn(launcher.launch(
				Map.of(TargetCmdLineLauncher.CMDLINE_ARGS_NAME, "/bin/echo Hello, World!")));
			Msg.debug(this, "Waiting for session access...");
			waitAcc(access);
			Msg.debug(this, "Getting Inferiors (after launch)...");
			inferiors = waitOn(model.fetchObjectElements(List.of("Inferiors")));
			Msg.debug(this, "Inferiors after: " + inferiors);
			assertEquals(2, inferiors.size());
		}
	}

	@Test
	public void testInferiorLaunchParameters() throws Throwable {
		try (ModelHost m = modelHost()) {
			DebuggerObjectModel model = m.getModel();
			init(m);
			Msg.debug(this, "Getting root object");
			TargetObject root = root(model);
			Msg.debug(this, "Tracking session access...");
			AllRequiredAccess rootAccess = access(root);
			Msg.debug(this, "Waiting for session access...");
			waitAcc(rootAccess);
			Msg.debug(this, "Getting Inferior 1...");
			TargetObject inferior = waitOn(model.fetchModelObject(List.of("Inferiors", "[1]")));
			Msg.debug(this, "Tracking inferior access...");
			AllRequiredAccess infAccess = access(inferior);
			Msg.debug(this, "Waiting for inferior access...");
			waitAcc(infAccess);
			Msg.debug(this, "Reflecting parameters");
			TargetLauncher<?> launcher = inferior.as(TargetLauncher.tclass);
			for (ParameterDescription<?> param : launcher.getParameters().values()) {
				Msg.info(this, "  Parameter: " + param);
			}
			waitOn(launcher.launch(Map.of("args", "/bin/echo Hello, World!")));

			Msg.debug(this, "Waiting for session access (again)...");
			waitAcc(rootAccess);
			Msg.debug(this, "Getting Inferiors (after launch)...");
			Map<String, ? extends TargetObjectRef> inferiors =
				waitOn(model.fetchObjectElements(List.of("Inferiors")));
			Msg.debug(this, "Inferiors after: " + inferiors);
			assertEquals(1, inferiors.size());
		}
	}

	@Test
	public void testInferiorLaunch() throws Throwable {
		try (ModelHost m = modelHost()) {
			DebuggerObjectModel model = m.getModel();
			init(m);
			Msg.debug(this, "Getting root object");
			TargetObject root = root(model);
			Msg.debug(this, "Tracking session access...");
			AllRequiredAccess rootAccess = access(root);
			Msg.debug(this, "Waiting for session access...");
			waitAcc(rootAccess);
			Msg.debug(this, "Getting Inferior 1...");
			TargetObject inferior = waitOn(model.fetchModelObject(List.of("Inferiors", "[1]")));
			Msg.debug(this, "Tracking inferior access...");
			AllRequiredAccess infAccess = access(inferior);
			Msg.debug(this, "Waiting for inferior access...");
			waitAcc(infAccess);
			Msg.debug(this, "Launching...");
			launch(inferior,
				Map.of(TargetCmdLineLauncher.CMDLINE_ARGS_NAME, "/bin/echo Hello, World!"));
			Msg.debug(this, "Waiting for session access (again)...");
			waitAcc(rootAccess);
			Msg.debug(this, "Getting Inferiors (after launch)...");
			Map<String, ? extends TargetObjectRef> inferiors =
				waitOn(model.fetchObjectElements(List.of("Inferiors")));
			Msg.debug(this, "Inferiors after: " + inferiors);
			assertEquals(1, inferiors.size());
		}
	}

	@Test
	public void testListProcesses() throws Throwable {
		try (DummyProc dd = run("dd"); ModelHost m = modelHost()) {
			DebuggerObjectModel model = m.getModel();
			init(m);
			Msg.debug(this, "Getting root object");
			TargetObject root = root(model);
			Msg.debug(this, "Tracking session access...");
			AllRequiredAccess access = access(root);
			Msg.debug(this, "Waiting for session access...");
			waitAcc(access);
			Map<String, ? extends TargetObjectRef> available =
				waitOn(model.fetchObjectElements(List.of("Available")));
			assertTrue(available.containsKey(Long.toString(dd.pid)));
		}
	}

	@Test
	public void testSessionAttachKill() throws Throwable {
		try (DummyProc dd = run("dd"); ModelHost m = modelHost()) {
			DebuggerObjectModel model = m.getModel();
			init(m);
			Msg.debug(this, "Getting root object");
			TargetObject root = root(model);
			Msg.debug(this, "Tracking session access...");
			AllRequiredAccess access = access(root);
			Msg.debug(this, "Waiting for session access...");
			waitAcc(access);
			Msg.debug(this, "Getting Inferiors (before attach)...");
			Map<String, ? extends TargetObjectRef> inferiors =
				waitOn(model.fetchObjectElements(List.of("Inferiors")));
			Msg.debug(this, "Inferiors before: " + inferiors);
			assertEquals(1, inferiors.size());
			Msg.debug(this, "Finding TargetAttacher...");
			TargetAttacher<?> attacher = suitable(TargetAttacher.tclass, root);
			Msg.debug(this, "  Got TargetAttacher: " + attacher);
			TargetAttachable<?> attachable =
				waitOn(model.fetchModelObject("Available", "[" + dd.pid + "]"))
						.as(TargetAttachable.tclass);
			Msg.debug(this, "  Got Attachable: " + attachable);
			Msg.debug(this, "Attaching...");
			waitOn(attacher.attach(attachable));
			Msg.debug(this, "Waiting for session access (again)...");
			waitAcc(access);
			Msg.debug(this, "Getting Inferiors (after attach)...");
			inferiors = waitOn(model.fetchObjectElements(List.of("Inferiors")));
			Msg.debug(this, "Inferiors after: " + inferiors);
			assertEquals(2, inferiors.size());
			Msg.debug(this, "Killing...");
			TargetKillable<?> killable =
				waitOn(inferiors.get("2").as(TargetKillable.tclass).fetch());
			waitOn(killable.kill());
		}
	}

	@Test
	public void testInferiorAttachKill() throws Throwable {
		try (DummyProc dd = run("dd"); ModelHost m = modelHost()) {
			DebuggerObjectModel model = m.getModel();
			init(m);
			Msg.debug(this, "Getting root object");
			TargetObject root = root(model);
			Msg.debug(this, "Tracking session access...");
			AllRequiredAccess access = access(root);
			Msg.debug(this, "Waiting for session access...");
			waitAcc(access);
			Msg.debug(this, "Getting Inferior 1...");
			TargetObject inferior = waitOn(model.fetchModelObject(List.of("Inferiors", "[1]")));
			TargetAttacher<?> attacher = inferior.as(TargetAttacher.tclass);
			Msg.debug(this, "Waiting for session access (again)...");
			waitAcc(access);
			Msg.debug(this, "Attaching...");
			waitOn(attacher.attach(dd.pid));
			Msg.debug(this, "Waiting for session access (again, again)...");
			waitAcc(access);
			Msg.debug(this, "Getting Inferiors (after attach)...");
			Map<String, ? extends TargetObjectRef> inferiors =
				waitOn(model.fetchObjectElements(List.of("Inferiors")));
			Msg.debug(this, "Inferiors after: " + inferiors);
			assertEquals(1, inferiors.size());
			Msg.debug(this, "Killing...");
			TargetObject attached = waitOn(inferiors.get("1").fetch());
			TargetKillable<?> killable = attached.as(TargetKillable.tclass);
			waitOn(killable.kill());
		}
	}

	@Test
	public void testLaunchContExit() throws Throwable {
		try (ModelHost m = modelHost()) {
			DebuggerObjectModel model = m.getModel();
			init(m);
			Msg.debug(this, "Getting root object");
			TargetObject root = root(model);
			Msg.debug(this, "Tracking session access...");
			AllRequiredAccess access = access(root);
			Msg.debug(this, "Waiting for session access...");
			waitAcc(access);
			Msg.debug(this, "Getting Inferior 1...");
			TargetObject inferior = waitOn(model.fetchModelObject("Inferiors", "[1]"));
			Msg.debug(this, "Launching...");
			launch(inferior, Map.of(TargetCmdLineLauncher.CMDLINE_ARGS_NAME, "echo Hello, World!"));
			Msg.debug(this, "Waiting for session access (again)...");
			waitAcc(access);
			Msg.debug(this, "Resuming...");
			resume(inferior);
			Msg.debug(this, "Waiting for session access (after resume)...");
			waitAcc(access);
		}
	}

	@Test(expected = DebuggerModelNoSuchPathException.class)
	public void testAttachNoObjectErr() throws Throwable {
		try (ModelHost m = modelHost()) {
			DebuggerObjectModel model = m.getModel();
			init(m);
			Msg.debug(this, "Getting root object");
			TargetObject root = root(model);
			Msg.debug(this, "Tracking session access...");
			AllRequiredAccess access = access(root);
			Msg.debug(this, "Waiting for session access...");
			waitAcc(access);
			Msg.debug(this, "Getting Inferior 1...");
			TargetObject inferior = waitOn(model.fetchModelObject("Inferiors", "[1]"));
			Msg.debug(this, "Attaching to bogus path...");
			TargetAttacher<?> attacher = inferior.as(TargetAttacher.tclass);
			waitOn(attacher.attach(model.createRef("Available", "Process -1")
					.as(TargetAttachable.tclass)));
		}
	}

	@Test(expected = DebuggerModelTypeException.class)
	public void testAttachNonAttachableErr() throws Throwable {
		try (ModelHost m = modelHost()) {
			DebuggerObjectModel model = m.getModel();
			init(m);
			Msg.debug(this, "Getting root object");
			TargetObject root = root(model);
			Msg.debug(this, "Tracking session access...");
			AllRequiredAccess access = access(root);
			Msg.debug(this, "Waiting for session access...");
			waitAcc(access);
			Msg.debug(this, "Getting Inferior 1...");
			TargetObject inferior = waitOn(model.fetchModelObject("Inferiors", "[1]"));
			Msg.debug(this, "Attaching to bogus path...");
			TargetAttacher<?> attacher = inferior.as(TargetAttacher.tclass);
			waitOn(attacher.attach(model.createRef("Available").as(TargetAttachable.tclass)));
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

	@Test
	public void testExecute() throws Throwable {
		try (ModelHost m = modelHost()) {
			DebuggerObjectModel model = m.getModel();

			AsyncReference<String, Void> lastOut = new AsyncReference<>();
			AllTargetObjectListenerAdapter l = new AllTargetObjectListenerAdapter() {
				@Override
				public void consoleOutput(TargetObject interpreter, Channel channel,
						String out) {
					Msg.debug(this, "Got " + channel + " output: " + out);
					lastOut.set(out, null);
				}
			};

			init(m);
			Msg.debug(this, "Getting root object...");
			TargetObject root = root(model);
			root.addListener(l);
			Msg.debug(this, "Tracking session access...");
			AllRequiredAccess access = access(root);
			Msg.debug(this, "Waiting for session access...");
			waitAcc(access);
			Msg.debug(this, "Running command...");
			cli(root, "echo test");
			Msg.debug(this, "Waiting for expected output...");
			waitOn(lastOut.waitValue("test"));
		}
	}

	@Test
	@Ignore("Abstract test case is failing on off-thread exceptions")
	public void testExecuteQuit() throws Throwable {
		try (ModelHost m = modelHost()) {
			DebuggerObjectModel model = m.getModel();
			init(m);
			Msg.debug(this, "Getting root object");
			TargetObject root = root(model);
			Msg.debug(this, "Tracking session access...");
			AllRequiredAccess access = access(root);
			Msg.debug(this, "Waiting for session access...");
			waitAcc(access);
			Msg.debug(this, "Quitting...");
			cli(root, "quit");
			// TODO: Assert model state is TERMINATED, or something
			// (pending merging of DebuggerClient stuff into DebuggerObjectModel
			// For now, best option is to assert root is invalid
			assertFalse(root.isValid());
		}
		catch (Throwable ex) {
			ignoreTermination(ex);
		}
	}

	@Test
	public void testExecuteCapture() throws Throwable {
		try (ModelHost m = modelHost(); CatchOffThread offThread = new CatchOffThread()) {
			DebuggerObjectModel model = m.getModel();

			AllTargetObjectListenerAdapter l = new AllTargetObjectListenerAdapter() {
				@Override
				public void consoleOutput(TargetObject interpreter, Channel channel,
						String out) {
					Msg.debug(this, "Got " + channel + " output: " + out);
					if (!out.contains("test")) {
						return;
					}
					offThread.catching(() -> fail("Unexpected output:" + out));
				}
			};

			init(m);
			Msg.debug(this, "Getting root object...");
			TargetObject root = root(model);
			root.addListener(l);
			Msg.debug(this, "Tracking session access...");
			AllRequiredAccess access = access(root);
			Msg.debug(this, "Waiting for session access...");
			waitAcc(access);
			Msg.debug(this, "Running command with capture...");
			String out = captureCli(root, "echo test");
			Msg.debug(this, "Captured: " + out);
			assertEquals("test", out);
		}
	}

	@Test
	public void testGetBreakKinds() throws Throwable {
		try (ModelHost m = modelHost()) {
			DebuggerObjectModel model = m.getModel();
			init(m);
			Msg.debug(this, "Getting root object...");
			TargetObject root = root(model);
			Msg.debug(this, "Tracking session access...");
			AllRequiredAccess access = access(root);
			Msg.debug(this, "Waiting for session access...");
			waitAcc(access);
			Msg.debug(this, "Finding breakpoint container...");
			TargetBreakpointContainer<?> breaks = suitable(TargetBreakpointContainer.tclass, root);
			Msg.debug(this, "Got: " + breaks);
			TargetBreakpointKindSet kinds = breaks.getSupportedBreakpointKinds();
			Msg.debug(this, "Supports: " + kinds);
			assertEquals(4, kinds.size());
		}
	}

	@Test
	public void testPlaceBreakpoint() throws Throwable {
		String specimen = which("expFork");
		try (ModelHost m = modelHost()) {
			DebuggerObjectModel model = m.getModel();
			init(m);
			Msg.debug(this, "Getting root object...");
			TargetObject root = root(model);
			Msg.debug(this, "Tracking session access...");
			AllRequiredAccess access = access(root);
			Msg.debug(this, "Waiting for session access...");
			waitAcc(access);
			Msg.debug(this, "Setting file to " + specimen + "...");
			cli(root, "file " + specimen);
			Msg.debug(this, "Finding breakpoint container...");
			TargetBreakpointContainer<?> breaks = suitable(TargetBreakpointContainer.tclass, root);
			Msg.debug(this, "Placing breakpoint...");
			waitOn(breaks.placeBreakpoint("func", Set.of(TargetBreakpointKind.SOFTWARE)));
			Msg.debug(this, "Getting breakpoint specs...");
			Map<String, ? extends TargetObjectRef> specs = waitOn(breaks.fetchElements());
			Msg.debug(this, "Got specs: " + specs);
			assertEquals(1, specs.size());
			TargetBreakpointSpec<?> spec =
				waitOn(specs.get("1").as(TargetBreakpointSpec.tclass).fetch());
			Collection<? extends TargetBreakpointLocation<?>> ls = waitOn(spec.getLocations());
			Msg.debug(this, "Got locations: " + ls);
			assertEquals(1, ls.size());
			TargetBreakpointLocation<?> loc = ls.iterator().next();
			Address addr = loc.getAddress();
			Msg.debug(this, "Got address: " + addr);
			TargetObjectRefList<?> list = loc.getAffects();
			Msg.debug(this, "Got affects: " + list);
			assertEquals(1, list.size());
		}
	}

	@Test
	public void testPlaceWatchpoint() throws Throwable {
		String specimen = which("expTypes");
		try (ModelHost m = modelHost()) {
			DebuggerObjectModel model = m.getModel();
			init(m);
			Msg.debug(this, "Getting root object...");
			TargetObject root = root(model);
			Msg.debug(this, "Tracking session access...");
			AllRequiredAccess access = access(root);
			Msg.debug(this, "Waiting for session access...");
			waitAcc(access);
			Msg.debug(this, "Setting file to " + specimen + "...");
			cli(root, "file " + specimen);
			Msg.debug(this, "Finding breakpoint container...");
			TargetBreakpointContainer<?> breaks = suitable(TargetBreakpointContainer.tclass, root);
			Msg.debug(this, "Placing breakpoint...");
			waitOn(breaks.placeBreakpoint("int_var",
				Set.of(TargetBreakpointKind.READ, TargetBreakpointKind.WRITE)));
			Msg.debug(this, "Getting breakpoint specs...");
			Map<String, ? extends TargetObjectRef> specs = waitOn(breaks.fetchElements());
			Msg.debug(this, "Got specs: " + specs);
			assertEquals(1, specs.size());
			TargetBreakpointSpec<?> spec =
				waitOn(specs.get("1").as(TargetBreakpointSpec.tclass).fetch());
			Collection<? extends TargetBreakpointLocation<?>> ls = waitOn(spec.getLocations());
			Msg.debug(this, "Got locations: " + ls);
			assertEquals(1, ls.size());
			TargetBreakpointLocation<?> loc = ls.iterator().next();
			Address addr = loc.getAddress();
			Msg.debug(this, "Got address: " + addr);
			assertNotNull(addr);
			TargetObjectRefList<?> list = loc.getAffects();
			Msg.debug(this, "Got affects: " + list);
			assertEquals(1, list.size());
		}
	}

	@Test
	public void testExpFork() throws Throwable {
		try (ModelHost m = modelHost()) {
			DebuggerObjectModel model = m.getModel();
			Set<Address> locAddresses = new HashSet<>();
			Set<TargetObjectRef> locAffecteds = new HashSet<>();

			init(m);
			Msg.debug(this, "Getting root object");
			TargetObject root = root(model);
			Msg.debug(this, "Tracking session access...");
			AllRequiredAccess access = access(root);
			Msg.debug(this, "Waiting for session access...");
			waitAcc(access);
			Msg.debug(this, "Getting Inferior 1...");
			TargetObject inferior = waitOn(model.fetchModelObject("Inferiors", "[1]"));
			Msg.debug(this, "Launching...");
			launch(inferior, Map.of(TargetCmdLineLauncher.CMDLINE_ARGS_NAME, which("expFork")));
			Msg.debug(this, "Waiting for session access (again)...");
			waitAcc(access);
			Msg.debug(this, "Setting to stay attached to forks");
			cli(root, "set detach-on-fork off");
			TargetBreakpointContainer<?> breaks =
				suitable(TargetBreakpointContainer.tclass, inferior);
			Msg.debug(this, "Setting break on func");
			waitOn(breaks.placeBreakpoint("func", Set.of(TargetBreakpointKind.SOFTWARE)));
			Msg.debug(this, "Resuming execution (first time)");
			resume(inferior);
			Msg.debug(this, "Waiting for session access...");
			waitAcc(access);
			Map<String, ? extends TargetObjectRef> inferiors =
				waitOn(model.fetchObjectElements("Inferiors"));
			Msg.debug(this, "After first break, inferiors are: " + inferiors);
			assertEquals(2, inferiors.size());
			// NOTE: Breakpoint 1 was the temporary one on 'main'
			Map<String, ? extends TargetObjectRef> ls =
				waitOn(model.fetchObjectElements("Breakpoints", "[2]"));
			Msg.debug(this, "Locations: " + ls);
			assertEquals(2, ls.size());
			for (TargetObjectRef ref : ls.values()) {
				TargetBreakpointLocation<?> loc =
					waitOn(ref.as(TargetBreakpointLocation.tclass).fetch());
				locAddresses.add(loc.getAddress());
				locAffecteds.addAll(loc.getAffects());
			}
			Msg.debug(this, "Addresses: " + locAddresses + ", affected: " + locAffecteds);
			assertEquals(1, locAddresses.size());
			assertEquals(Set.of(List.of("Inferiors", "[1]"), List.of("Inferiors", "[2]")),
				locAffecteds.stream().map(TargetObjectRef::getPath).collect(Collectors.toSet()));
		}
	}

	@Test
	@Ignore("Known issue")
	public void testExpForkWithListeners() throws Throwable {
		ElementTrackingListener<TargetObject> infListener =
			new ElementTrackingListener<>(TargetObject.class);
		ElementTrackingListener<? extends TargetBreakpointSpec<?>> bkListener =
			new ElementTrackingListener<>(TargetBreakpointSpec.tclass);
		ElementTrackingListener<? extends TargetBreakpointLocation<?>> blListener =
			new ElementTrackingListener<>(TargetBreakpointLocation.tclass);
		EventSequenceListener evtListener = new EventSequenceListener();

		try (ModelHost m = modelHost()) {
			DebuggerObjectModel model = m.getModel();
			Set<Address> ebAddresses = new HashSet<>();
			Set<TargetObjectRef> ebAffecteds = new HashSet<>();

			init(m);
			Msg.debug(this, "Getting root object");
			TargetObject root = root(model);
			Msg.debug(this, "Tracking session events and access...");
			root.addListener(evtListener);
			AllRequiredAccess access = access(root);
			Msg.debug(this, "Waiting for session access...");
			waitAcc(access);
			Msg.debug(this, "Getting Inferior 1...");
			TargetObject infCont = waitOn(model.fetchModelObject("Inferiors"));
			Msg.debug(this, "Installing listener for inferiors");
			infCont.addListener(infListener);
			Msg.debug(this, "Getting inferiors");
			Map<String, ? extends TargetObject> inferiors = waitOn(infCont.fetchElements()
					.thenCompose(DebugModelConventions::fetchAll));
			infListener.putAll(inferiors);
			Msg.debug(this, "Launching...");
			launch(infListener.elements.get("1"),
				Map.of(TargetCmdLineLauncher.CMDLINE_ARGS_NAME, which("expFork")));
			Msg.debug(this, "Waiting for session access (again)...");
			waitAcc(access);
			Msg.debug(this, "Setting to stay attached to forks");
			cli(root, "set detach-on-fork off");
			TargetBreakpointContainer<?> bkCont =
				suitable(TargetBreakpointContainer.tclass, infCont);
			Msg.debug(this, "Installing listener for breakpoints");
			bkCont.addListener(bkListener);
			Msg.debug(this, "Getting breakpoints");
			Map<String, ? extends TargetObject> bkElems = waitOn(bkCont.fetchElements()
					.thenCompose(DebugModelConventions::fetchAll));
			bkListener.putAll(bkElems);
			Msg.debug(this, "Setting break on func");
			waitOn(bkCont.placeBreakpoint("func", Set.of(TargetBreakpointKind.SOFTWARE)));
			Msg.debug(this, "Breakpoint elements: " + bkListener.elements);
			TargetBreakpointSpec<?> bk2 =
				waitOn(bkListener.refElement("2").waitUntil(t -> t != null));
			Msg.debug(this, "Installing listener on Breakpoint 2");
			bk2.addListener(blListener);
			Msg.debug(this, "Getting locations for 2");
			Map<String, ? extends TargetObject> bk2ls = waitOn(bk2.fetchElements()
					.thenCompose(DebugModelConventions::fetchAll));
			blListener.putAll(bk2ls);
			Msg.debug(this, "Resuming execution (first time)");
			resume(infListener.elements.get("1"));
			Msg.debug(this, "Waiting for session access...");
			waitAcc(access);
			Msg.debug(this, "After first break, inferiors are: " + infListener.elements);
			waitOn(infListener.size.waitValue(2));
			assertEquals(2, infListener.elements.size());
			waitOn(blListener.size.waitValue(2));
			Msg.debug(this, "Locations: " + blListener.elements);
			assertEquals(2, blListener.elements.size());
			for (TargetObject obj : blListener.elements.values()) {
				TargetBreakpointLocation<?> eb = obj.as(TargetBreakpointLocation.tclass);
				ebAddresses.add(eb.getAddress());
				ebAffecteds.addAll(eb.getAffects());
			}
			Msg.debug(this, "Addresses: " + ebAddresses + ", affected: " + ebAffecteds);
			assertEquals(1, ebAddresses.size());
			assertEquals(Set.of(List.of("Inferiors", "[1]"), List.of("Inferiors", "[2]")),
				ebAffecteds.stream().map(TargetObjectRef::getPath).collect(Collectors.toSet()));

			// Getting more precise than this could become fragile, as library paths vary
			TargetEventType lastType = null;
			List<TargetEventType> typesNoRepeat = new ArrayList<>();
			for (EventRecord rec : evtListener.events) {
				if (rec.type == TargetEventType.RUNNING) {
					continue;
				}
				if (rec.type == lastType) {
					continue;
				}
				lastType = rec.type;
				typesNoRepeat.add(lastType);
			}
			assertEquals(List.of(
				TargetEventType.PROCESS_CREATED,
				TargetEventType.THREAD_CREATED,
				TargetEventType.MODULE_LOADED,
				TargetEventType.BREAKPOINT_HIT,
				TargetEventType.PROCESS_CREATED,
				TargetEventType.THREAD_CREATED,
				TargetEventType.MODULE_LOADED //
			), typesNoRepeat);
		}
	}

	@Test
	public void testExpClone() throws Throwable {
		try (ModelHost m = modelHost()) {
			DebuggerObjectModel model = m.getModel();
			init(m);
			Msg.debug(this, "Getting root object");
			TargetObject root = root(model);
			Msg.debug(this, "Tracking session access...");
			AllRequiredAccess access = access(root);
			Msg.debug(this, "Waiting for session access...");
			waitAcc(access);
			Msg.debug(this, "Getting Inferior 1...");
			TargetObject inferior = waitOn(model.fetchModelObject("Inferiors", "[1]"));
			Msg.debug(this, "Launching...");
			launch(inferior,
				Map.of(TargetCmdLineLauncher.CMDLINE_ARGS_NAME, which("expCloneExit")));
			Msg.debug(this, "Waiting for session access (again)...");
			waitAcc(access);
			TargetBreakpointContainer<?> breaks =
				suitable(TargetBreakpointContainer.class, inferior);
			Msg.debug(this, "Setting break on work");
			waitOn(breaks.placeBreakpoint("work", Set.of(TargetBreakpointKind.SOFTWARE)));
			Msg.debug(this, "Resuming execution (first time)");
			resume(inferior);
			Msg.debug(this, "Waiting for session access...");
			waitAcc(access);
			Map<String, ? extends TargetObjectRef> threads =
				waitOn(model.fetchObjectElements("Inferiors", "[1]", "Threads"));
			Msg.debug(this, "After first break, threads are: " + threads);
			assertEquals(2, threads.size());
		}
	}

	@Test
	public void testExpWrite() throws Throwable {
		String expPrint = which("expPrint");
		final String toWrite = "Speak";
		final String expected = "Speak, World!";

		try (ModelHost m = modelHost()) {
			DebuggerObjectModel model = m.getModel();
			init(m);
			Msg.debug(this, "Getting root object");
			TargetObject root = root(model);
			Msg.debug(this, "Tracking session access...");
			AllRequiredAccess access = access(root);
			Msg.debug(this, "Waiting for session access...");
			waitAcc(access);
			Msg.debug(this, "Getting Inferior 1...");
			TargetObject inferior = waitOn(model.fetchModelObject("Inferiors", "[1]"));
			Msg.debug(this, "Launching...");
			launch(inferior, Map.of(TargetCmdLineLauncher.CMDLINE_ARGS_NAME, expPrint));
			Msg.debug(this, "Waiting for session access (again)...");
			waitAcc(access);
			Msg.debug(this, "Getting symbol to overwrite");
			TargetSymbol<?> overwrite = waitOn(inferior.fetchSuccessor(
				"Modules", "[" + expPrint + "]", "Symbols", "[overwrite]")).as(TargetSymbol.tclass);
			Msg.debug(this, "Symbol 'overwrite' is at addr: " + overwrite.getValue());
			Msg.debug(this, "Getting Memory");
			TargetMemory<?> memory = (TargetMemory<?>) waitOn(inferior.fetchSuccessor("Memory"));
			Msg.debug(this, "Writing");
			waitOn(memory.writeMemory(overwrite.getValue(), toWrite.getBytes()));
			Msg.debug(this, "Getting thread (for stepping)");
			TargetObject thread = waitOn(inferior.fetchSuccessor("Threads", "[1]"));
			Msg.debug(this, "Got: " + thread);
			Msg.debug(this, "Stepping to clear caches...");
			step(thread, TargetStepKind.INTO);
			Msg.debug(this, "Waiting for access...");
			waitAcc(access);
			Msg.debug(this, "Reading back...");
			byte[] data =
				waitOn(memory.readMemory(overwrite.getValue(), expected.getBytes().length));
			Msg.debug(this, "Read: " + new String(data));
			assertArrayEquals(expected.getBytes(), data);
			resume(inferior);
			Msg.debug(this, "Waiting for access (i.e., exit)...");
			waitAcc(access);
			Msg.debug(this, "Getting exit code...");

			long status = inferior.getTypedAttributeNowByName(
				GdbModelTargetInferior.EXIT_CODE_ATTRIBUTE_NAME, Long.class, 0L);
			assertEquals(toWrite.getBytes()[0], status);
		}
	}

	@Test
	public void testStack() throws Throwable {
		try (ModelHost m = modelHost()) {
			DebuggerObjectModel model = m.getModel();
			init(m);
			Msg.debug(this, "Getting root object");
			TargetObject root = root(model);
			Msg.debug(this, "Tracking session access...");
			AllRequiredAccess access = access(root);
			Msg.debug(this, "Waiting for session access...");
			waitAcc(access);
			Msg.debug(this, "Getting Inferior 1...");
			TargetObject inferior = waitOn(model.fetchModelObject("Inferiors", "[1]"));
			Msg.debug(this, "Launching...");
			launch(inferior, Map.of(TargetCmdLineLauncher.CMDLINE_ARGS_NAME, "echo Hello, World!"));
			Msg.debug(this, "Waiting for session access (again)...");
			waitAcc(access);
			Msg.debug(this, "Finding breakpoint container...");
			TargetBreakpointContainer<?> breaks = suitable(TargetBreakpointContainer.tclass, root);
			Msg.debug(this, "Placing breakpoint...");
			waitOn(breaks.placeBreakpoint("write", Set.of(TargetBreakpointKind.SOFTWARE)));
			Msg.debug(this, "Resuming...");
			resume(inferior);
			Msg.debug(this, "Waiting for session access (after resume)...");
			waitAcc(access);
			Map<String, ? extends TargetObject> frames =
				waitOn(inferior.fetchSubElements("Threads", "[1]", "Stack")
						.thenCompose(DebugModelConventions::fetchAll));
			Msg.debug(this, "Got stack:");
			for (Map.Entry<String, ? extends TargetObject> ent : frames.entrySet()) {
				TargetStackFrame<?> frame = ent.getValue().as(TargetStackFrame.tclass);
				Msg.debug(this, ent.getKey() + ": " + frame.getProgramCounter());
			}
			assertEquals("write", frames.get("0")
					.getTypedAttributeNowByName(GdbModelTargetStackFrame.FUNC_ATTRIBUTE_NAME,
						String.class, null));
			assertEquals("main", frames.get("" + (frames.size() - 1))
					.getTypedAttributeNowByName(GdbModelTargetStackFrame.FUNC_ATTRIBUTE_NAME,
						String.class, null));
		}
	}

	@Test
	public void testRegisters() throws Throwable {
		try (ModelHost m = modelHost()) {
			DebuggerObjectModel model = m.getModel();
			Set<TargetRegister<?>> descs = new LinkedHashSet<>();

			init(m);
			Msg.debug(this, "Getting root object");
			TargetObject root = root(model);
			Msg.debug(this, "Tracking session access...");
			AllRequiredAccess access = access(root);
			Msg.debug(this, "Waiting for session access...");
			waitAcc(access);
			Msg.debug(this, "Getting Inferior 1...");
			TargetObject inferior = waitOn(model.fetchModelObject("Inferiors", "[1]"));
			launch(inferior, Map.of(TargetCmdLineLauncher.CMDLINE_ARGS_NAME, "echo Hello, World!"));
			Msg.debug(this, "Waiting for session access (again)...");
			waitAcc(access);
			TargetRegisterBank<?> bank =
				waitOn(inferior.fetchSuccessor("Threads", "[1]", "Stack", "[0]"))
						.as(TargetRegisterBank.tclass);
			Msg.debug(this, "Got bank: " + bank);
			Msg.debug(this, "Descriptions ref: " + bank.getDescriptions());
			TargetRegisterContainer<?> cont = waitOn(bank.getDescriptions().fetch());
			Msg.debug(this, "Register descriptions: " + cont);
			descs.addAll(waitOn(cont.getRegisters()));
			Msg.debug(this, "Elements: ");
			for (TargetRegister<?> reg : descs) {
				Msg.debug(this, "  " + reg.getIndex() + ": " + reg.getBitLength());
			}
			Map<String, byte[]> data = waitOn(bank.readRegisters(descs));
			Msg.debug(this, "Values: ");
			for (Map.Entry<String, byte[]> ent : data.entrySet()) {
				Msg.debug(this, "  " + ent.getKey() + " = " +
					NumericUtilities.convertBytesToString(ent.getValue()));
			}
			// TODO: Implement Environment, and port these tests
			Msg.debug(this, "Writing two registers, general and vector");
			waitOn(bank.writeRegistersNamed(AMD64_TEST_REG_VALUES));
			Msg.debug(this, "Flushing cache");
			waitOn(bank.invalidateCaches());
			Msg.debug(this, "Re-reading values");
			// NOTE: Can't reliably step here since rax may be referenced by the instruction
			data = waitOn(bank.readRegistersNamed(AMD64_TEST_REG_VALUES.keySet()));
			assertEquals(hexlify(AMD64_TEST_REG_VALUES), hexlify(data));
		}
	}

	@Test
	public void testFocusInferiors() throws Throwable {
		try (ModelHost m = modelHost()) {
			DebuggerObjectModel model = m.getModel();

			AsyncReference<TargetObjectRef, Void> focus = new AsyncReference<>();
			AsyncReference<Integer, Void> inferiorCount = new AsyncReference<>();

			TargetFocusScopeListener focusListener = new TargetFocusScopeListener() {
				@Override
				public void focusChanged(TargetFocusScope<?> object, TargetObjectRef focused) {
					focus.set(focused, null);
				}
			};

			init(m);
			Msg.debug(this, "Getting root object");
			TargetObject root = root(model);
			root.addListener(focusListener);
			Msg.debug(this, "Tracking session access...");
			AllRequiredAccess access = access(root);
			Msg.debug(this, "Waiting for session access...");
			waitAcc(access);
			Msg.debug(this, "Getting inferiors container");
			TargetObject infCont = waitOn(model.fetchModelObject("Inferiors"));

			TargetObjectListener infListener = new TargetObjectListener() {
				@Override
				public void elementsChanged(TargetObject parent, Collection<String> removed,
						Map<String, ? extends TargetObjectRef> added) {
					inferiorCount.set(infCont.getCachedElements().size(), null);
				}
			};

			infCont.addListener(infListener);
			Msg.debug(this, "Creating another inferior");
			cli(root, "add-inferior");
			waitOn(inferiorCount.waitValue(2));
			assertEquals(model.createRef("Inferiors", "[1]"), getFocus(root));
			focus(root, model.createRef("Inferiors", "[2]"));
			assertEquals(model.createRef("Inferiors", "[2]"), getFocus(root));
		}
	}

	@Test
	public void testThreadFocusOnLaunch() throws Throwable {
		try (ModelHost m = modelHost()) {
			DebuggerObjectModel model = m.getModel();

			Deque<TargetObjectRef> focusSeq = new LinkedList<>();
			AsyncReference<Integer, Void> focusSeqSize = new AsyncReference<>();

			TargetFocusScopeListener focusListener = new TargetFocusScopeListener() {
				@Override
				public void focusChanged(TargetFocusScope<?> object, TargetObjectRef focused) {
					Msg.debug(this, "Focused: " + focused);
					if (focused instanceof TargetProcess) {
						return;
					}
					synchronized (focusSeq) {
						focusSeq.add(focused);
						focusSeqSize.set(focusSeq.size(), null);
					}
				}
			};

			init(m);
			Msg.debug(this, "Getting root object");
			TargetObject root = root(model);
			root.addListener(focusListener);
			Msg.debug(this, "Tracking session access...");
			AllRequiredAccess access = access(root);
			Msg.debug(this, "Waiting for session access...");
			waitAcc(access);
			Msg.debug(this, "Getting Inferior 1...");
			TargetObject inferior = waitOn(model.fetchModelObject(List.of("Inferiors", "[1]")));
			Msg.debug(this, "Launching");
			launch(inferior,
				Map.of(TargetCmdLineLauncher.CMDLINE_ARGS_NAME, "/bin/echo Hello, World!"));
			waitOn(focusSeqSize.waitValue(1));
			assertEquals(model.createRef(PathUtils.parse("Inferiors[1].Threads[1].Stack[0]")),
				focusSeq.peekLast());
		}
	}
}
