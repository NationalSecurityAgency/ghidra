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
package agent.gdb.rmi;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

import java.nio.ByteBuffer;
import java.util.List;

import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import generic.test.category.NightlyCategory;
import ghidra.app.plugin.core.debug.utils.ManagedDomainObject;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.testutil.DummyProc;
import ghidra.dbg.util.PathPattern;
import ghidra.dbg.util.PathPredicates;
import ghidra.program.model.address.AddressSpace;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.time.TraceSnapshot;

@Category(NightlyCategory.class) // this may actually be an @PortSensitive test
public class GdbHooksTest extends AbstractGdbTraceRmiTest {
	private static final long RUN_TIMEOUT_MS = 20000;
	private static final long RETRY_MS = 500;

	record GdbAndTrace(GdbAndHandler conn, ManagedDomainObject mdo) implements AutoCloseable {
		public void execute(String cmd) {
			conn.execute(cmd);
		}

		public String executeCapture(String cmd) {
			return conn.executeCapture(cmd);
		}

		@Override
		public void close() throws Exception {
			conn.close();
			mdo.close();
		}
	}

	@SuppressWarnings("resource")
	protected GdbAndTrace startAndSyncGdb() throws Exception {
		GdbAndHandler conn = startAndConnectGdb();
		try {
			// TODO: Why does using 'set arch' cause a hang at quit?
			conn.execute("""
					set ghidra-language x86:LE:64:default
					ghidra trace start
					ghidra trace sync-enable""");
			ManagedDomainObject mdo = waitDomainObject("/New Traces/gdb/noname");
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			return new GdbAndTrace(conn, mdo);
		}
		catch (Exception e) {
			conn.close();
			throw e;
		}
	}

	@Test
	public void testOnNewInferior() throws Exception {
		try (GdbAndTrace conn = startAndSyncGdb()) {
			conn.execute("add-inferior");
			waitForPass(() -> assertEquals(2, tb.objValues(0, "Inferiors[]").size()));
		}
	}

	protected String getIndex(TraceObject object, String pattern) {
		if (object == null) {
			return null;
		}
		PathPattern pat = PathPredicates.parse(pattern).getSingletonPattern();
		if (pat.countWildcards() != 1) {
			throw new IllegalArgumentException("Exactly one wildcard required");
		}
		List<String> path = object.getCanonicalPath().getKeyList();
		if (path.size() < pat.asPath().size()) {
			return null;
		}
		List<String> matched = pat.matchKeys(path.subList(0, pat.asPath().size()));
		if (matched == null) {
			return null;
		}
		return matched.get(0);
	}

	protected String inferiorIndex(TraceObject object) {
		return getIndex(object, "Inferiors[]");
	}

	@Test
	public void testOnInferiorSelected() throws Exception {
		try (GdbAndTrace conn = startAndSyncGdb()) {
			traceManager.openTrace(tb.trace);
			// Both inferiors must have sync enabled
			conn.execute("""
					add-inferior
					inferior 2
					ghidra trace sync-enable""");

			conn.execute("inferior 1");
			waitForPass(() -> assertEquals("1", inferiorIndex(traceManager.getCurrentObject())));

			conn.execute("inferior 2");
			waitForPass(() -> assertEquals("2", inferiorIndex(traceManager.getCurrentObject())));

			conn.execute("inferior 1");
			waitForPass(() -> assertEquals("1", inferiorIndex(traceManager.getCurrentObject())));
		}
	}

	@Test
	public void testOnInferiorDeleted() throws Exception {
		try (GdbAndTrace conn = startAndSyncGdb()) {
			conn.execute("add-inferior");
			waitForPass(() -> assertEquals(2, tb.objValues(0, "Inferiors[]").size()));

			conn.execute("remove-inferior 2");
			waitForPass(() -> assertEquals(1, tb.objValues(0, "Inferiors[]").size()));
		}
	}

	protected long lastSnap(GdbAndTrace conn) {
		return conn.conn.handler().getLastSnapshot(tb.trace);
	}

	@Test
	public void testOnNewThread() throws Exception {
		String cloneExit = DummyProc.which("expCloneExit");
		try (GdbAndTrace conn = startAndSyncGdb()) {
			conn.execute("""
					file %s
					break work
					start""".formatted(cloneExit));
			waitForPass(() -> {
				TraceObject inf = tb.obj("Inferiors[1]");
				assertNotNull(inf);
				assertEquals("STOPPED", tb.objValue(inf, lastSnap(conn), "_state"));
			}, RUN_TIMEOUT_MS, RETRY_MS);
			waitForPass(() -> assertEquals(1,
				tb.objValues(lastSnap(conn), "Inferiors[1].Threads[]").size()),
				RUN_TIMEOUT_MS, RETRY_MS);

			conn.execute("continue");
			waitForPass(() -> assertEquals(2,
				tb.objValues(lastSnap(conn), "Inferiors[1].Threads[]").size()),
				RUN_TIMEOUT_MS, RETRY_MS);
		}
	}

	protected String threadIndex(TraceObject object) {
		return getIndex(object, "Inferiors[1].Threads[]");
	}

	@Test
	public void testOnThreadSelected() throws Exception {
		String cloneExit = DummyProc.which("expCloneExit");
		try (GdbAndTrace conn = startAndSyncGdb()) {
			traceManager.openTrace(tb.trace);

			conn.execute("""
					file %s
					break work
					run""".formatted(cloneExit));
			waitForPass(() -> {
				TraceObject inf = tb.obj("Inferiors[1]");
				assertNotNull(inf);
				assertEquals("STOPPED", tb.objValue(inf, lastSnap(conn), "_state"));
			}, RUN_TIMEOUT_MS, RETRY_MS);
			waitForPass(() -> assertEquals(2,
				tb.objValues(lastSnap(conn), "Inferiors[1].Threads[]").size()),
				RUN_TIMEOUT_MS, RETRY_MS);

			// Now the real test
			conn.execute("thread 1");
			waitForPass(() -> assertEquals("1", threadIndex(traceManager.getCurrentObject())));

			conn.execute("thread 2");
			waitForPass(() -> assertEquals("2", threadIndex(traceManager.getCurrentObject())));

			conn.execute("thread 1");
			waitForPass(() -> assertEquals("1", threadIndex(traceManager.getCurrentObject())));
		}
	}

	protected String frameIndex(TraceObject object) {
		return getIndex(object, "Inferiors[1].Threads[1].Stack[]");
	}

	@Test
	public void testOnFrameSelected() throws Exception {
		String stack = DummyProc.which("expStack");
		try (GdbAndTrace conn = startAndSyncGdb()) {
			traceManager.openTrace(tb.trace);

			conn.execute("""
					file %s
					break break_here
					run""".formatted(stack));
			waitForPass(() -> assertThat(
				tb.objValues(lastSnap(conn), "Inferiors[1].Threads[1].Stack[]").size(),
				greaterThan(2)),
				RUN_TIMEOUT_MS, RETRY_MS);

			conn.execute("frame 1");
			waitForPass(() -> assertEquals("1", frameIndex(traceManager.getCurrentObject())),
				RUN_TIMEOUT_MS, RETRY_MS);

			conn.execute("frame 0");
			waitForPass(() -> assertEquals("0", frameIndex(traceManager.getCurrentObject())),
				RUN_TIMEOUT_MS, RETRY_MS);
		}
	}

	@Test
	@Ignore
	public void testOnSyscallMemory() throws Exception {
		// TODO: Need a specimen
		// FWIW, I've already seen this getting exercised in other tests.
	}

	@Test
	public void testOnMemoryChanged() throws Exception {
		try (GdbAndTrace conn = startAndSyncGdb()) {
			conn.execute("""
					file bash
					start""");

			long address = Long.decode(conn.executeCapture("print/x &main").split("\\s+")[2]);
			conn.execute("set *((char*) &main) = 0x7f");
			waitForPass(() -> {
				ByteBuffer buf = ByteBuffer.allocate(1);
				tb.trace.getMemoryManager().getBytes(lastSnap(conn), tb.addr(address), buf);
				assertEquals(0x7f, buf.get(0));
			}, RUN_TIMEOUT_MS, RETRY_MS);
		}
	}

	@Test
	public void testOnRegisterChanged() throws Exception {
		try (GdbAndTrace conn = startAndSyncGdb()) {
			conn.execute("""
					file bash
					start""");

			TraceObject thread = waitForValue(() -> tb.obj("Inferiors[1].Threads[1]"));
			waitForPass(
				() -> assertEquals("STOPPED", tb.objValue(thread, lastSnap(conn), "_state")),
				RUN_TIMEOUT_MS, RETRY_MS);

			conn.execute("set $rax = 0x1234");
			AddressSpace space = tb.trace.getBaseAddressFactory()
					.getAddressSpace("Inferiors[1].Threads[1].Stack[0].Registers");
			TraceMemorySpace regs = tb.trace.getMemoryManager().getMemorySpace(space, false);
			waitForPass(() -> assertEquals("1234",
				regs.getValue(lastSnap(conn), tb.reg("RAX")).getUnsignedValue().toString(16)));
		}
	}

	@Test
	public void testOnCont() throws Exception {
		try (GdbAndTrace conn = startAndSyncGdb()) {
			conn.execute("""
					file bash
					run""");

			TraceObject inf = waitForValue(() -> tb.obj("Inferiors[1]"));
			TraceObject thread = waitForValue(() -> tb.obj("Inferiors[1].Threads[1]"));
			waitForPass(() -> {
				assertEquals("RUNNING", tb.objValue(inf, lastSnap(conn), "_state"));
				assertEquals("RUNNING", tb.objValue(thread, lastSnap(conn), "_state"));
			}, RUN_TIMEOUT_MS, RETRY_MS);
		}
	}

	@Test
	public void testOnStop() throws Exception {
		try (GdbAndTrace conn = startAndSyncGdb()) {
			conn.execute("""
					file bash
					start""");

			TraceObject inf = waitForValue(() -> tb.obj("Inferiors[1]"));
			TraceObject thread = waitForValue(() -> tb.obj("Inferiors[1].Threads[1]"));
			waitForPass(() -> {
				assertEquals("STOPPED", tb.objValue(inf, lastSnap(conn), "_state"));
				assertEquals("STOPPED", tb.objValue(thread, lastSnap(conn), "_state"));
			}, RUN_TIMEOUT_MS, RETRY_MS);
		}
	}

	@Test
	public void testOnExited() throws Exception {
		try (GdbAndTrace conn = startAndSyncGdb()) {
			conn.execute("""
					file bash
					set args -c "exit 1"
					run""");

			waitForPass(() -> {
				TraceSnapshot snapshot =
					tb.trace.getTimeManager().getSnapshot(lastSnap(conn), false);
				assertNotNull(snapshot);
				assertEquals("Exited with code 1", snapshot.getDescription());

				TraceObject inf1 = tb.obj("Inferiors[1]");
				assertNotNull(inf1);
				Object val = tb.objValue(inf1, lastSnap(conn), "_exit_code");
				assertThat(val, instanceOf(Number.class));
				assertEquals(1, ((Number) val).longValue());
			}, RUN_TIMEOUT_MS, RETRY_MS);
		}
	}

	/**
	 * Test on_clear_objfiles, on_new_objfile, on_free_objfile.
	 * 
	 * <p>
	 * Technically, this probably doesn't hit on_free_objfile, but all three just call
	 * modules_changed, so I'm not concerned.
	 */
	@Test
	public void testOnEventsObjfiles() throws Exception {
		String print = DummyProc.which("expPrint");
		String modPrint = "Inferiors[1].Modules[%s]".formatted(print);
		try (GdbAndTrace conn = startAndSyncGdb()) {
			conn.execute("""
					file %s
					start""".formatted(print));
			waitForPass(() -> assertEquals(1, tb.objValues(lastSnap(conn), modPrint).size()),
				RUN_TIMEOUT_MS, RETRY_MS);

			conn.execute("continue");
			waitState(1, () -> lastSnap(conn), TargetExecutionState.TERMINATED);
			/**
			 * Termination does not clear objfiles. Not until we run a new target.
			 */
			conn.execute("""
					file bash
					set args -c "exit 1"
					run""");
			waitForPass(() -> assertEquals(0, tb.objValues(lastSnap(conn), modPrint).size()),
				RUN_TIMEOUT_MS, RETRY_MS);
		}
	}

	@Test
	public void testOnBreakpointCreated() throws Exception {
		String print = DummyProc.which("expPrint");
		try (GdbAndTrace conn = startAndSyncGdb()) {
			conn.execute("file " + print);
			assertEquals(0, tb.objValues(lastSnap(conn), "Breakpoints[]").size());

			conn.execute("break main");
			waitForPass(() -> {
				List<Object> brks = tb.objValues(lastSnap(conn), "Breakpoints[]");
				assertEquals(1, brks.size());
				return (TraceObject) brks.get(0);
			});
		}
	}

	@Test
	public void testOnBreakpointModified() throws Exception {
		String print = DummyProc.which("expPrint");
		try (GdbAndTrace conn = startAndSyncGdb()) {
			conn.execute("file " + print);
			assertEquals(0, tb.objValues(lastSnap(conn), "Breakpoints[]").size());

			conn.execute("break main");
			TraceObject brk = waitForPass(() -> {
				List<Object> brks = tb.objValues(lastSnap(conn), "Breakpoints[]");
				assertEquals(1, brks.size());
				return (TraceObject) brks.get(0);
			});
			assertEquals(null, tb.objValue(brk, lastSnap(conn), "Commands"));

			conn.execute("""
					commands %s
					  echo test
					end""".formatted(brk.getCanonicalPath().index()));
			waitForPass(
				() -> assertEquals("echo test\n", tb.objValue(brk, lastSnap(conn), "Commands")));
		}
	}

	@Test
	public void testOnBreakpointDeleted() throws Exception {
		String print = DummyProc.which("expPrint");
		try (GdbAndTrace conn = startAndSyncGdb()) {
			conn.execute("file " + print);
			assertEquals(0, tb.objValues(lastSnap(conn), "Breakpoints[]").size());

			conn.execute("break main");
			TraceObject brk = waitForPass(() -> {
				List<Object> brks = tb.objValues(lastSnap(conn), "Breakpoints[]");
				assertEquals(1, brks.size());
				return (TraceObject) brks.get(0);
			});

			conn.execute("delete %s".formatted(brk.getCanonicalPath().index()));
			waitForPass(
				() -> assertEquals(0, tb.objValues(lastSnap(conn), "Breakpoints[]").size()));
		}
	}
}
