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
package agent.gdb.manager.impl;

import static ghidra.dbg.testutil.DummyProc.run;
import static org.junit.Assert.*;
import static org.junit.Assume.assumeFalse;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import org.junit.*;

import com.google.common.collect.*;

import agent.gdb.manager.*;
import agent.gdb.manager.GdbManager.StepCmd;
import agent.gdb.manager.breakpoint.GdbBreakpointInfo;
import agent.gdb.pty.PtyFactory;
import ghidra.async.AsyncReference;
import ghidra.dbg.testutil.DummyProc;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;

public abstract class AbstractGdbManagerTest extends AbstractGhidraHeadlessIntegrationTest {
	protected static final long TIMEOUT_MILLISECONDS =
		SystemUtilities.isInTestingBatchMode() ? 5000 : Long.MAX_VALUE;

	protected abstract PtyFactory getPtyFactory();

	protected abstract CompletableFuture<Void> startManager(GdbManager manager);

	protected void stopManager() throws IOException {
		// Nothing by default
	}

	protected <T> T waitOn(CompletableFuture<T> future) throws Throwable {
		try {
			return future.get(TIMEOUT_MILLISECONDS, TimeUnit.MILLISECONDS);
		}
		catch (ExecutionException e) {
			throw e.getCause();
		}
	}

	@After
	public void tearDownGdbManagerTest() throws IOException {
		stopManager();
	}

	@Test
	public void testAddInferior() throws Throwable {
		try (GdbManager mgr = GdbManager.newInstance(getPtyFactory())) {
			waitOn(startManager(mgr));
			GdbInferior inferior = waitOn(mgr.addInferior());
			assertEquals(2, inferior.getId());
			assertEquals(Set.of(1, 2), mgr.getKnownInferiors().keySet());
		}
	}

	@Test
	public void testRemoveInferior() throws Throwable {
		try (GdbManager mgr = GdbManager.newInstance(getPtyFactory())) {
			waitOn(startManager(mgr));
			GdbInferior inf = waitOn(mgr.addInferior());
			assertEquals(2, mgr.getKnownInferiors().size());
			waitOn(inf.remove());
			assertEquals(1, mgr.getKnownInferiors().size());
			assertEquals(1, mgr.currentInferior().getId());
			assertEquals(Set.of(1), mgr.getKnownInferiors().keySet());
		}
	}

	@Test
	public void testRemoveCurrentInferior() throws Throwable {
		try (GdbManager mgr = GdbManager.newInstance(getPtyFactory())) {
			List<Integer> selEvtIdsTemp = new ArrayList<>();
			AsyncReference<List<Integer>, Void> selEvtIds = new AsyncReference<>(List.of());
			mgr.addEventsListener(new GdbEventsListenerAdapter() {
				@Override
				public void inferiorSelected(GdbInferior inferior, GdbCause cause) {
					selEvtIdsTemp.add(inferior.getId());
					selEvtIds.set(List.copyOf(selEvtIdsTemp), null);
				}
			});
			waitOn(startManager(mgr));
			waitOn(selEvtIds.waitValue(List.of(1)));
			waitOn(mgr.addInferior());
			assertEquals(2, mgr.getKnownInferiors().size());
			waitOn(mgr.currentInferior().remove());
			assertEquals(1, mgr.getKnownInferiors().size());
			assertEquals(2, mgr.currentInferior().getId());
			assertEquals(Set.of(2), mgr.getKnownInferiors().keySet());
			waitOn(selEvtIds.waitValue(List.of(1, 2)));
		}
	}

	@Test
	public void testConsoleCapture() throws Throwable {
		try (GdbManager mgr = GdbManager.newInstance(getPtyFactory())) {
			waitOn(startManager(mgr));
			String out = waitOn(mgr.consoleCapture("echo test"));
			assertEquals("test", out.trim());
		}
	}

	@Test
	public void testListInferiors() throws Throwable {
		try (GdbManager mgr = GdbManager.newInstance(getPtyFactory())) {
			waitOn(startManager(mgr));
			Map<Integer, GdbInferior> inferiors = waitOn(mgr.listInferiors());
			assertEquals(new HashSet<>(Arrays.asList(new Integer[] { 1 })), inferiors.keySet());
		}
	}

	@Test
	public void testListAvailableProcesses() throws Throwable {
		try (GdbManager mgr = GdbManager.newInstance(getPtyFactory())) {
			waitOn(startManager(mgr));
			List<GdbProcessThreadGroup> procs = waitOn(mgr.listAvailableProcesses());
			List<Integer> pids = procs.stream().map(p -> p.getPid()).collect(Collectors.toList());
			assertTrue(pids.contains(1)); // Weak check, but on Linux, 1 (init) is always running
		}
	}

	@Test
	public void testInfoOs() throws Throwable {
		try (GdbManager mgr = GdbManager.newInstance(getPtyFactory())) {
			waitOn(startManager(mgr));
			GdbTable infoThreads = waitOn(mgr.infoOs("threads"));
			assertEquals(new LinkedHashSet<>(Arrays.asList("pid", "command", "tid", "core")),
				infoThreads.columns().keySet());
			assertTrue(infoThreads.columns().get("command").contains("java"));
		}
	}

	@Test
	public void testStart() throws Throwable {
		try (GdbManager mgr = GdbManager.newInstance(getPtyFactory())) {
			waitOn(startManager(mgr));
			waitOn(mgr.currentInferior().fileExecAndSymbols("/usr/bin/echo"));
			waitOn(mgr.console("break main"));
			GdbThread thread = waitOn(mgr.currentInferior().run());
			assertNotNull(thread.getInferior().getPid());
		}
	}

	@Test
	public void testAttachDetach() throws Throwable {
		try (DummyProc echo = run("dd"); GdbManager mgr = GdbManager.newInstance(getPtyFactory())) {
			waitOn(startManager(mgr));
			Set<GdbThread> threads = waitOn(mgr.currentInferior().attach(echo.pid));
			// Attach stops the process, so no need to wait for STOPPED or prompt
			for (GdbThread t : threads) {
				assertEquals(echo.pid, (long) t.getInferior().getPid());
				waitOn(t.detach());
			}
		}
	}

	@Test
	@Ignore("At developer's desk only")
	public void stressTestStartInterrupt() throws Throwable {
		// Just re-run the testStartInterrupt test many,many times
		for (int i = 0; i < 100; i++) {
			testStartInterrupt();
		}
	}

	public static class LibraryWaiter extends CompletableFuture<String>
			implements GdbEventsListenerAdapter {
		protected final Predicate<String> predicate;

		public LibraryWaiter(Predicate<String> predicate) {
			this.predicate = predicate;
		}

		@Override
		public void libraryLoaded(GdbInferior inferior, String name, GdbCause cause) {
			if (predicate.test(name)) {
				complete(name);
			}
		}
	}

	public void assertResponsive(GdbManager mgr) throws Throwable {
		//Msg.debug(this, "Waiting for prompt");
		//waitOn(mgr.waitForPrompt());
		Msg.debug(this, "Testing echo test");
		String out = waitOn(mgr.consoleCapture("echo test"));
		assertEquals("test", out.trim());
	}

	@Test
	public void testStartInterrupt() throws Throwable {
		assumeFalse("I know no way to get this to pass with these conditions",
			this instanceof JoinedGdbManagerTest);
		try (GdbManager mgr = GdbManager.newInstance(getPtyFactory())) {
			/*
			 * Not sure the details here, but it seems GDB will give ^running as soon as the process
			 * has started. I suspect there are some nuances between the time the process is started
			 * and the time its signal handlers are installed. It seems waiting for libc to load
			 * guarantees that GDB is ready to interrupt the process.
			 */
			LibraryWaiter libcLoaded = new LibraryWaiter(name -> name.contains("libc"));
			mgr.addEventsListener(libcLoaded);
			waitOn(startManager(mgr));
			waitOn(mgr.currentInferior().fileExecAndSymbols("/usr/bin/sleep"));
			waitOn(mgr.currentInferior().console("set args 3"));
			waitOn(mgr.currentInferior().run());
			waitOn(libcLoaded);
			Thread.sleep(100); // TODO: Why?
			Msg.debug(this, "Interrupting");
			waitOn(mgr.interrupt());
			waitOn(mgr.waitForState(GdbState.STOPPED));
			assertResponsive(mgr);
		}
	}

	@Test
	public void testStepSyscallInterrupt() throws Throwable {
		assumeFalse("I know no way to get this to pass with these conditions",
			this instanceof JoinedGdbManagerTest);
		// Repeat the start-interrupt sequence, then verify we're preparing to step a syscall
		try (GdbManager mgr = GdbManager.newInstance(getPtyFactory())) {
			LibraryWaiter libcLoaded = new LibraryWaiter(name -> name.contains("libc"));
			mgr.addEventsListener(libcLoaded);
			waitOn(startManager(mgr));
			waitOn(mgr.currentInferior().fileExecAndSymbols("/usr/bin/sleep"));
			waitOn(mgr.currentInferior().console("set args 5"));
			waitOn(mgr.currentInferior().run());
			waitOn(libcLoaded);
			Thread.sleep(100); // TODO: Why?
			Msg.debug(this, "Interrupting");
			waitOn(mgr.interrupt());
			Msg.debug(this, "Verifying at syscall");
			String out = waitOn(mgr.consoleCapture("x/1i $pc-2"));
			// TODO: This is x86-specific
			assertTrue("Didn't stop at syscall", out.contains("syscall"));

			// Now the real test
			waitOn(mgr.currentInferior().step(StepCmd.STEPI));
			CompletableFuture<Void> stopped = mgr.waitForState(GdbState.STOPPED);
			Thread.sleep(100); // NB: Not exactly reliable, but verify we're waiting
			assertFalse(stopped.isDone());
			waitOn(mgr.interrupt());
			waitOn(stopped);
			assertResponsive(mgr);
		}
	}

	@Test
	public void testSetVarEvaluate() throws Throwable {
		try (GdbManager mgr = GdbManager.newInstance(getPtyFactory())) {
			waitOn(startManager(mgr));
			waitOn(mgr.currentInferior().fileExecAndSymbols("/usr/bin/echo"));
			waitOn(mgr.insertBreakpoint("main"));
			waitOn(mgr.currentInferior().run());
			waitOn(mgr.waitForState(GdbState.STOPPED));
			//waitOn(mgr.waitForPrompt());
			waitOn(mgr.currentInferior().setVar("$rax=", "0xdeadbeef")); // Corrupts it
			String val = waitOn(mgr.currentInferior().evaluate("$rax+1"));
			assertEquals(0xdeadbeef + 1, Integer.parseUnsignedInt(val));
		}
	}

	@Test
	public void testSetVarGetVar() throws Throwable {
		try (GdbManager mgr = GdbManager.newInstance(getPtyFactory())) {
			waitOn(startManager(mgr));
			String val = waitOn(mgr.currentInferior().getVar("args"));
			assertEquals(null, val);
			waitOn(mgr.currentInferior().setVar("args", "test"));
			val = waitOn(mgr.currentInferior().getVar("args"));
			assertEquals("test", val);
		}
	}

	@Test
	public void testInsertListDeleteBreakpoint() throws Throwable {
		try (GdbManager mgr = GdbManager.newInstance(getPtyFactory())) {
			waitOn(startManager(mgr));
			waitOn(mgr.currentInferior().fileExecAndSymbols("/usr/bin/echo"));
			GdbBreakpointInfo breakpoint = waitOn(mgr.insertBreakpoint("main"));
			Map<Long, GdbBreakpointInfo> bl = waitOn(mgr.listBreakpoints());
			assertEquals(Map.of(1L, breakpoint), bl);
			waitOn(mgr.deleteBreakpoints(breakpoint.getNumber()));
			bl = waitOn(mgr.listBreakpoints());
			assertEquals(Map.of(), bl);
		}
	}

	@Test
	public void testListReadWriteReadRegisters() throws Throwable {
		try (GdbManager mgr = GdbManager.newInstance(getPtyFactory())) {
			waitOn(startManager(mgr));
			waitOn(mgr.currentInferior().fileExecAndSymbols("/usr/bin/echo"));
			waitOn(mgr.insertBreakpoint("main"));
			GdbThread thread = waitOn(mgr.currentInferior().run());
			waitOn(mgr.waitForState(GdbState.STOPPED));
			//waitOn(mgr.waitForPrompt());
			GdbRegisterSet regs = waitOn(thread.listRegisters());
			Set<GdbRegister> toRead = new HashSet<>();
			toRead.add(regs.get("eflags"));
			toRead.add(regs.get("rax"));
			Map<GdbRegister, BigInteger> read = waitOn(thread.readRegisters(toRead));
			// Verify eflags is rendered numerically
			assertNotNull(read.get(regs.get("eflags")));
			assertNotNull(read.get(regs.get("rax")));
			Map<GdbRegister, BigInteger> toWrite = new HashMap<>();
			// NOTE: Not all flags are mutable from user-space.
			// Turns out GDB/MI does not honor this, but CLI does....
			toWrite.put(regs.get("eflags"), BigInteger.valueOf(0L));
			toWrite.put(regs.get("rax"), BigInteger.valueOf(0x1122334455667788L));
			waitOn(thread.writeRegisters(toWrite));
			toRead = new HashSet<>();
			toRead.add(regs.get("eflags"));
			// Verify register structure is reflected in API
			toRead.add(regs.get("eax"));
			read = waitOn(thread.readRegisters(toRead));
			// IF and that other reserved bit cannot be cleared
			// Verified the same behavior in vanilla GDB at the CLI.
			assertEquals(0x202L, read.get(regs.get("eflags")).longValue());
			assertEquals(0x55667788L, read.get(regs.get("eax")).longValue());
		}
	}

	@Test
	public void testWriteReadMemory() throws Throwable {
		ByteBuffer rBuf = ByteBuffer.allocate(1024);
		try (GdbManager mgr = GdbManager.newInstance(getPtyFactory())) {
			waitOn(startManager(mgr));
			waitOn(mgr.currentInferior().fileExecAndSymbols("/usr/bin/echo"));
			waitOn(mgr.insertBreakpoint("main"));
			GdbThread thread = waitOn(mgr.currentInferior().run());
			waitOn(mgr.waitForState(GdbState.STOPPED));
			//waitOn(mgr.waitForPrompt());
			String str = waitOn(mgr.currentInferior().evaluate("(long)main"));
			long addr = Long.parseLong(str);
			ByteBuffer buf = ByteBuffer.allocate(1024);
			buf.order(ByteOrder.LITTLE_ENDIAN);
			for (int i = 0; i < 10; i++) {
				buf.putInt(i);
			}
			buf.flip();
			waitOn(thread.writeMemory(addr, buf));
			RangeSet<Long> rng = waitOn(thread.readMemory(addr, rBuf));
			rBuf.flip();
			rBuf.order(ByteOrder.LITTLE_ENDIAN);
			RangeSet<Long> exp = TreeRangeSet.create();
			exp.add(Range.closedOpen(addr, addr + 1024));
			assertEquals(exp, rng);
			for (int i = 0; i < 10; i++) {
				assertEquals(i, rBuf.getInt());
			}
		}
	}

	@Test
	public void testContinue() throws Throwable {
		try (GdbManager mgr = GdbManager.newInstance(getPtyFactory())) {
			waitOn(startManager(mgr));
			waitOn(mgr.currentInferior().fileExecAndSymbols("/usr/bin/echo"));
			waitOn(mgr.insertBreakpoint("main"));
			GdbThread thread = waitOn(mgr.currentInferior().run());
			waitOn(mgr.waitForState(GdbState.STOPPED));
			//waitOn(mgr.waitForPrompt());
			waitOn(thread.cont());
			waitOn(mgr.waitForState(GdbState.STOPPED));
			assertEquals(0L, (long) mgr.currentInferior().getExitCode());
		}
	}

	@Test
	public void testStep() throws Throwable {
		try (GdbManager mgr = GdbManager.newInstance(getPtyFactory())) {
			waitOn(startManager(mgr));
			waitOn(mgr.currentInferior().fileExecAndSymbols("/usr/bin/echo"));
			waitOn(mgr.insertBreakpoint("main"));
			GdbThread thread = waitOn(mgr.currentInferior().run());
			waitOn(mgr.waitForState(GdbState.STOPPED));
			//waitOn(mgr.waitForPrompt());
			waitOn(thread.step(StepCmd.NEXTI));
			waitOn(mgr.waitForState(GdbState.STOPPED));
			assertNull(mgr.currentInferior().getExitCode());
		}
	}

	@Test
	public void testThreadSelect() throws Throwable {
		try (GdbManager mgr = GdbManager.newInstance(getPtyFactory())) {
			waitOn(startManager(mgr));
			waitOn(mgr.currentInferior().fileExecAndSymbols("/usr/bin/echo"));
			waitOn(mgr.insertBreakpoint("main"));
			GdbThread thread = waitOn(mgr.currentInferior().run());
			waitOn(mgr.waitForState(GdbState.STOPPED));
			//waitOn(mgr.waitForPrompt());
			waitOn(thread.setActive(false));
		}
	}

	@Test
	public void testListFrames() throws Throwable {
		try (GdbManager mgr = GdbManager.newInstance(getPtyFactory())) {
			waitOn(startManager(mgr));
			waitOn(mgr.currentInferior().fileExecAndSymbols("/usr/bin/echo"));
			waitOn(mgr.insertBreakpoint("main"));
			GdbThread thread = waitOn(mgr.currentInferior().run());
			waitOn(mgr.waitForState(GdbState.STOPPED));
			//waitOn(mgr.waitForPrompt());
			waitOn(mgr.insertBreakpoint("write"));
			waitOn(mgr.currentInferior().cont());
			waitOn(mgr.waitForState(GdbState.STOPPED));
			List<GdbStackFrame> stack = waitOn(thread.listStackFrames());
			Msg.debug(this, "Got stack:");
			for (GdbStackFrame frame : stack) {
				Msg.debug(this, "  " + frame);
			}
			assertEquals("write", stack.get(0).getFunction());
			assertEquals("main", stack.get(stack.size() - 1).getFunction());
		}
	}
}
