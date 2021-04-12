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
package agent.dbgeng.manager.impl;

import static agent.dbgeng.testutil.DummyProc.runProc;
import static ghidra.async.AsyncUtils.sequence;
import static org.junit.Assert.*;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.commons.lang3.tuple.Pair;
import org.junit.*;

import com.google.common.collect.*;

import agent.dbgeng.dbgeng.DbgEngTest;
import agent.dbgeng.dbgeng.DebugProcessId;
import agent.dbgeng.manager.*;
import agent.dbgeng.manager.DbgManager.ExecSuffix;
import agent.dbgeng.manager.breakpoint.DbgBreakpointInfo;
import agent.dbgeng.testutil.DummyProc;
import ghidra.async.AsyncFence;
import ghidra.async.TypeSpec;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.Msg;

public abstract class AbstractDbgManagerTest extends AbstractGhidraHeadlessIntegrationTest {
	protected static final int TIMEOUT = 2000 * 1000;

	protected abstract CompletableFuture<Void> startManager(DbgManager manager);

	protected void stopManager() throws IOException {
		// Nothing by default
	}

	protected <T> T waitOn(CompletableFuture<T> future) throws Throwable {
		try {
			return future.get(TIMEOUT, TimeUnit.MILLISECONDS);
		}
		catch (ExecutionException e) {
			throw e.getCause();
		}
	}

	@Before
	public void setUpDbgManagerTest() {
		DbgEngTest.assumeDbgengDLLLoadable();
	}

	@After
	public void tearDownDbgManagerTest() throws IOException {
		stopManager();
	}

	@Test
	public void testAddProcess() throws Throwable {
		try (DbgManager mgr = DbgManager.newInstance()) {
			DbgProcess process = waitOn(sequence(TypeSpec.cls(DbgProcess.class)).then(seq -> {
				startManager(mgr).handle(seq::next);
			}).then(seq -> {
				mgr.addProcess().handle(seq::exit);
			}).finish());
			assertEquals(2, process.getId());
			assertEquals(Set.of(1, 2), mgr.getKnownProcesses().keySet());
		}
	}

	@Test
	public void testRemoveProcess() throws Throwable {
		try (DbgManager mgr = DbgManager.newInstance()) {
			waitOn(sequence(TypeSpec.VOID).then(seq -> {
				startManager(mgr).handle(seq::next);
			}).then(seq -> {
				mgr.addProcess().handle(seq::next);
			}, TypeSpec.cls(DbgProcess.class)).then((inf, seq) -> {
				assertEquals(2, mgr.getKnownProcesses().size());
				inf.remove().handle(seq::next);
			}).then(seq -> {
				assertEquals(1, mgr.getKnownProcesses().size());
				assertEquals(1, mgr.currentProcess().getId());
				seq.exit();
			}).finish());
			assertEquals(Set.of(1), mgr.getKnownProcesses().keySet());
		}
	}

	@Test
	public void testRemoveCurrentProcess() throws Throwable {
		try (DbgManager mgr = DbgManager.newInstance()) {
			List<DebugProcessId> selEvtIds = new ArrayList<>();
			mgr.addEventsListener(new DbgEventsListenerAdapter() {
				@Override
				public void processSelected(DbgProcess process, DbgCause cause) {
					selEvtIds.add(process.getId());
				}
			});
			waitOn(sequence(TypeSpec.VOID).then(seq -> {
				startManager(mgr).handle(seq::next);
			}).then(seq -> {
				assertEquals(List.of(1), selEvtIds);
				mgr.addProcess().handle(seq::nextIgnore);
			}).then(seq -> {
				assertEquals(2, mgr.getKnownProcesses().size());
				mgr.currentProcess().remove().handle(seq::next);
			}).then(seq -> {
				assertEquals(1, mgr.getKnownProcesses().size());
				assertEquals(2, mgr.currentProcess().getId());
				seq.exit();
			}).finish());
			assertEquals(Set.of(2), mgr.getKnownProcesses().keySet());
			assertEquals(List.of(1, 2), selEvtIds);
		}
	}

	@Test
	public void testConsoleCapture() throws Throwable {
		try (DbgManager mgr = DbgManager.newInstance()) {
			String out = waitOn(sequence(TypeSpec.STRING).then(seq -> {
				startManager(mgr).handle(seq::next);
			}).then(seq -> {
				mgr.consoleCapture("echo test").handle(seq::exit);
			}).finish());
			assertEquals("test", out.trim());
		}
	}

	@Test
	public void testListProcesses() throws Throwable {
		try (DbgManager mgr = DbgManager.newInstance()) {
			Map<DebugProcessId, DbgProcess> processes =
				waitOn(sequence(TypeSpec.obj((Map<DebugProcessId, DbgProcess>) null)).then(seq -> {
					startManager(mgr).handle(seq::next);
				}).then(seq -> {
					mgr.listProcesses().handle(seq::exit);
				}).finish());
			assertEquals(new HashSet<>(Arrays.asList(new Integer[] { 1 })), processes.keySet());
		}
	}

	@Test
	public void testListAvailableProcesses() throws Throwable {
		try (DbgManager mgr = DbgManager.newInstance()) {
			List<Pair<Integer, String>> pids =
				waitOn(sequence(TypeSpec.obj((List<Pair<Integer, String>>) null)).then(seq -> {
					startManager(mgr).handle(seq::next);
				}).then(seq -> {
					mgr.listAvailableProcesses().handle(seq::exit);
				}).finish());
			assertTrue(pids.get(0).getLeft().equals(0)); // Weak check, but on Linux, 1 (init) is always running
		}
	}

	@Test
	public void testStart() throws Throwable {
		try (DbgManager mgr = DbgManager.newInstance()) {
			DbgThread thread = waitOn(sequence(TypeSpec.cls(DbgThread.class)).then(seq -> {
				startManager(mgr).handle(seq::next);
			}).then(seq -> {
				mgr.currentProcess().fileExecAndSymbols("/usr/bin/echo").handle(seq::next);
			}).then(seq -> {
				mgr.console("break main").handle(seq::next);
			}).then(seq -> {
				mgr.currentProcess().run().handle(seq::exit);
			}).finish());
			assertNotNull(thread.getProcess().getPid());
		}
	}

	@Test
	public void testAttachDetach() throws Throwable {
		try (DummyProc echo = runProc("dd"); DbgManager mgr = DbgManager.newInstance()) {
			AtomicReference<Set<DbgThread>> threads = new AtomicReference<>();
			waitOn(sequence(TypeSpec.VOID).then(seq -> {
				startManager(mgr).handle(seq::next);
			}).then(seq -> {
				mgr.currentProcess().attach((int) echo.pid).handle(seq::next);
			}, threads).then(seq -> {
				// Attach stops the process, so no need to wait for STOPPED or prompt
				AsyncFence fence = new AsyncFence();
				for (DbgThread t : threads.get()) {
					assertEquals(echo.pid, (long) t.getProcess().getPid());
					fence.include(t.detach());
				}
				fence.ready().handle(seq::exit);
			}).finish());
		}
	}

	public void stupidSleep(long millis) {
		try {
			Thread.sleep(millis);
		}
		catch (InterruptedException e) {
			// Whatever
		}
	}

	@Test
	public void testInsertListDeleteBreakpoint() throws Throwable {
		AtomicReference<DbgBreakpointInfo> breakpoint = new AtomicReference<>();
		try (DbgManager mgr = DbgManager.newInstance()) {
			waitOn(sequence(TypeSpec.VOID).then(seq -> {
				startManager(mgr).handle(seq::next);
			}).then(seq -> {
				mgr.currentProcess().fileExecAndSymbols("/usr/bin/echo").handle(seq::next);
			}).then(seq -> {
				mgr.insertBreakpoint("main").handle(seq::next);
			}, breakpoint).then(seq -> {
				mgr.listBreakpoints().handle(seq::next);
			}, TypeSpec.obj((Map<Long, DbgBreakpointInfo>) null)).then((bl, seq) -> {
				assertEquals(Map.of(1L, breakpoint.get()), bl);
				mgr.deleteBreakpoints(breakpoint.get().getNumber()).handle(seq::next);
			}).then(seq -> {
				mgr.listBreakpoints().handle(seq::next);
			}, TypeSpec.obj((Map<Long, DbgBreakpointInfo>) null)).then((bl, seq) -> {
				assertEquals(Map.of(), bl);
				seq.exit();
			}).finish());
		}
	}

	@Test
	public void testListReadWriteReadRegisters() throws Throwable {
		AtomicReference<DbgThread> thread = new AtomicReference<>();
		AtomicReference<DbgRegisterSet> regs = new AtomicReference<>();
		AtomicReference<Map<DbgRegister, BigInteger>> read = new AtomicReference<>();
		try (DbgManager mgr = DbgManager.newInstance()) {
			waitOn(sequence(TypeSpec.VOID).then(seq -> {
				startManager(mgr).handle(seq::next);
			}).then(seq -> {
				mgr.currentProcess().fileExecAndSymbols("/usr/bin/echo").handle(seq::next);
			}).then(seq -> {
				mgr.insertBreakpoint("main").handle(seq::nextIgnore);
			}).then(seq -> {
				mgr.currentProcess().run().handle(seq::next);
			}, thread).then(seq -> {
				mgr.waitForState(DbgState.STOPPED).handle(seq::next);
			}).then(seq -> {
				mgr.waitForPrompt().handle(seq::next);
			}).then(seq -> {
				thread.get().listRegisters().handle(seq::next);
			}, regs).then(seq -> {
				Set<DbgRegister> toRead = new HashSet<>();
				toRead.add(regs.get().get("eflags"));
				toRead.add(regs.get().get("rax"));
				thread.get().readRegisters(toRead).handle(seq::next);
			}, read).then(seq -> {
				// Verify eflags is rendered numerically
				assertNotNull(read.get().get(regs.get().get("eflags")));
				assertNotNull(read.get().get(regs.get().get("rax")));
				Map<DbgRegister, BigInteger> toWrite = new HashMap<>();
				// NOTE: Not all flags are mutable from user-space.
				// Turns out GDB/MI does not honor this, but CLI does....
				toWrite.put(regs.get().get("eflags"), BigInteger.valueOf(0L));
				toWrite.put(regs.get().get("rax"), BigInteger.valueOf(0x1122334455667788L));
				thread.get().writeRegisters(toWrite).handle(seq::next);
			}).then(seq -> {
				Set<DbgRegister> toRead = new HashSet<>();
				toRead.add(regs.get().get("eflags"));
				// Verify register structure is reflected in API
				toRead.add(regs.get().get("eax"));
				thread.get().readRegisters(toRead).handle(seq::next);
			}, read).then(seq -> {
				// IF and that other reserved bit cannot be cleared
				// Verified the same behavior in vanilla GDB at the CLI.
				assertEquals(0x202L, read.get().get(regs.get().get("eflags")).longValue());
				assertEquals(0x55667788L, read.get().get(regs.get().get("eax")).longValue());
				seq.exit();
			}).finish());
		}
	}

	@Test
	public void testWriteReadMemory() throws Throwable {
		AtomicReference<DbgThread> thread = new AtomicReference<>();
		AtomicLong addr = new AtomicLong();
		ByteBuffer rBuf = ByteBuffer.allocate(1024);
		try (DbgManager mgr = DbgManager.newInstance()) {
			waitOn(sequence(TypeSpec.VOID).then(seq -> {
				startManager(mgr).handle(seq::next);
			}).then(seq -> {
				mgr.currentProcess().fileExecAndSymbols("/usr/bin/echo").handle(seq::next);
			}).then(seq -> {
				mgr.insertBreakpoint("main").handle(seq::nextIgnore);
			}).then(seq -> {
				mgr.currentProcess().run().handle(seq::next);
			}, thread).then(seq -> {
				mgr.waitForState(DbgState.STOPPED).handle(seq::next);
			}).then(seq -> {
				mgr.waitForPrompt().handle(seq::next);
			}).then(seq -> {
				mgr.currentProcess().evaluate("(long)main").handle(seq::next);
			}, TypeSpec.STRING).then((str, seq) -> {
				addr.set(Long.parseLong(str));
				ByteBuffer buf = ByteBuffer.allocate(1024);
				buf.order(ByteOrder.LITTLE_ENDIAN);
				for (int i = 0; i < 10; i++) {
					buf.putInt(i);
				}
				buf.flip();
				thread.get().writeMemory(addr.get(), buf).handle(seq::next);
			}).then(seq -> {
				thread.get().readMemory(addr.get(), rBuf).handle(seq::next);
			}, TypeSpec.obj((RangeSet<Long>) null)).then((rng, seq) -> {
				rBuf.flip();
				rBuf.order(ByteOrder.LITTLE_ENDIAN);
				RangeSet<Long> exp = TreeRangeSet.create();
				exp.add(Range.closedOpen(addr.get(), addr.get() + 1024));
				assertEquals(exp, rng);
				for (int i = 0; i < 10; i++) {
					assertEquals(i, rBuf.getInt());
				}
				seq.exit();
			}).finish());
		}
	}

	@Test
	public void testContinue() throws Throwable {
		AtomicReference<DbgThread> thread = new AtomicReference<>();
		try (DbgManager mgr = DbgManager.newInstance()) {
			waitOn(sequence(TypeSpec.VOID).then(seq -> {
				startManager(mgr).handle(seq::next);
			}).then(seq -> {
				mgr.currentProcess().fileExecAndSymbols("/usr/bin/echo").handle(seq::next);
			}).then(seq -> {
				mgr.insertBreakpoint("main").handle(seq::nextIgnore);
			}).then(seq -> {
				mgr.currentProcess().run().handle(seq::next);
			}, thread).then(seq -> {
				mgr.waitForState(DbgState.STOPPED).handle(seq::next);
			}).then(seq -> {
				mgr.waitForPrompt().handle(seq::next);
			}).then(seq -> {
				thread.get().cont().handle(seq::next);
			}).then(seq -> {
				mgr.waitForState(DbgState.STOPPED).handle(seq::next);
			}).then(seq -> {
				assertEquals(0L, (long) mgr.currentProcess().getExitCode());
				seq.exit();
			}).finish());
		}
	}

	@Test
	public void testStep() throws Throwable {
		AtomicReference<DbgThread> thread = new AtomicReference<>();
		try (DbgManager mgr = DbgManager.newInstance()) {
			waitOn(sequence(TypeSpec.VOID).then(seq -> {
				startManager(mgr).handle(seq::next);
			}).then(seq -> {
				mgr.currentProcess().fileExecAndSymbols("/usr/bin/echo").handle(seq::next);
			}).then(seq -> {
				mgr.insertBreakpoint("main").handle(seq::nextIgnore);
			}).then(seq -> {
				mgr.currentProcess().run().handle(seq::next);
			}, thread).then(seq -> {
				mgr.waitForState(DbgState.STOPPED).handle(seq::next);
			}).then(seq -> {
				mgr.waitForPrompt().handle(seq::next);
			}).then(seq -> {
				thread.get().step(ExecSuffix.NEXT_INSTRUCTION).handle(seq::next);
			}).then(seq -> {
				mgr.waitForState(DbgState.STOPPED).handle(seq::next);
			}).then(seq -> {
				assertNull(mgr.currentProcess().getExitCode());
				seq.exit();
			}).finish());
		}
	}

	@Test
	public void testThreadSelect() throws Throwable {
		AtomicReference<DbgThread> thread = new AtomicReference<>();
		try (DbgManager mgr = DbgManager.newInstance()) {
			waitOn(sequence(TypeSpec.VOID).then(seq -> {
				startManager(mgr).handle(seq::next);
			}).then(seq -> {
				mgr.currentProcess().fileExecAndSymbols("/usr/bin/echo").handle(seq::next);
			}).then(seq -> {
				mgr.insertBreakpoint("main").handle(seq::nextIgnore);
			}).then(seq -> {
				mgr.currentProcess().run().handle(seq::next);
			}, thread).then(seq -> {
				mgr.waitForState(DbgState.STOPPED).handle(seq::next);
			}).then(seq -> {
				mgr.waitForPrompt().handle(seq::next);
			}).then(seq -> {
				thread.get().setActive().handle(seq::next);
			}).finish());
		}
	}

	@Test
	public void testListFrames() throws Throwable {
		AtomicReference<DbgThread> thread = new AtomicReference<>();
		try (DbgManager mgr = DbgManager.newInstance()) {
			waitOn(sequence(TypeSpec.VOID).then(seq -> {
				startManager(mgr).handle(seq::next);
			}).then(seq -> {
				mgr.currentProcess().fileExecAndSymbols("/usr/bin/echo").handle(seq::next);
			}).then(seq -> {
				mgr.insertBreakpoint("main").handle(seq::nextIgnore);
			}).then(seq -> {
				mgr.currentProcess().run().handle(seq::next);
			}, thread).then(seq -> {
				mgr.waitForState(DbgState.STOPPED).handle(seq::next);
			}).then(seq -> {
				mgr.waitForPrompt().handle(seq::next);
			}).then(seq -> {
				mgr.insertBreakpoint("write").handle(seq::nextIgnore);
			}).then(seq -> {
				mgr.currentProcess().cont().handle(seq::next);
			}).then(seq -> {
				mgr.waitForState(DbgState.STOPPED).handle(seq::next);
			}).then(seq -> {
				thread.get().listStackFrames().handle(seq::next);
			}, TypeSpec.cls(DbgStackFrame.class).list()).then((stack, seq) -> {
				Msg.debug(this, "Got stack:");
				for (DbgStackFrame frame : stack) {
					Msg.debug(this, "  " + frame);
				}
				assertEquals("write", stack.get(0).getFunction());
				assertEquals("main", stack.get(stack.size() - 1).getFunction());
				seq.exit();
			}).finish());
		}
	}
}
