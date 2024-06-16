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
package agent.lldb.rmi;

import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.Assert.*;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Objects;

import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import generic.test.category.NightlyCategory;
import ghidra.app.plugin.core.debug.utils.ManagedDomainObject;
import ghidra.dbg.testutil.DummyProc;
import ghidra.dbg.util.PathPattern;
import ghidra.dbg.util.PathPredicates;
import ghidra.program.model.address.AddressSpace;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.time.TraceSnapshot;

@Category(NightlyCategory.class) // this may actually be an @PortSensitive test
public class LldbHooksTest extends AbstractLldbTraceRmiTest {
	private static final long RUN_TIMEOUT_MS = 5000;
	private static final long RETRY_MS = 500;

	record LldbAndTrace(LldbAndConnection conn, ManagedDomainObject mdo) implements AutoCloseable {
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
	protected LldbAndTrace startAndSyncLldb() throws Exception {
		LldbAndConnection conn = startAndConnectLldb();
		try {
			conn.execute("ghidra trace start");
			ManagedDomainObject mdo = waitDomainObject("/New Traces/lldb/noname");
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			return new LldbAndTrace(conn, mdo);
		}
		catch (Exception e) {
			conn.close();
			throw e;
		}
	}

	protected long lastSnap(LldbAndTrace conn) {
		return conn.conn.connection().getLastSnapshot(tb.trace);
	}

	// TODO: This passes if you single-step through it but fails on some transactional stuff if run
	//@Test
	public void testOnNewThread() throws Exception {
		String cloneExit = DummyProc.which("expCloneExit");
		try (LldbAndTrace conn = startAndSyncLldb()) {

			start(conn, "%s".formatted(cloneExit));
			conn.execute("break set -n work");
			waitForPass(() -> {
				TraceObject proc = tb.objAny("Processes[]");
				assertNotNull(proc);
				assertEquals("STOPPED", tb.objValue(proc, lastSnap(conn), "_state"));
			}, RUN_TIMEOUT_MS, RETRY_MS);

			txPut(conn, "threads");
			waitForPass(() -> assertEquals(1,
				tb.objValues(lastSnap(conn), "Processes[].Threads[]").size()),
				RUN_TIMEOUT_MS, RETRY_MS);

			conn.execute("continue");
			waitStopped(conn.conn);
			txPut(conn, "threads");
			waitForPass(() -> assertEquals(2,
				tb.objValues(lastSnap(conn), "Processes[].Threads[]").size()),
				RUN_TIMEOUT_MS, RETRY_MS);
		}
	}

	// TODO: This passes if you single-step through it but fails on some transactional stuff if run
	//@Test
	public void testOnThreadSelected() throws Exception {
		String cloneExit = DummyProc.which("expCloneExit");
		try (LldbAndTrace conn = startAndSyncLldb()) {
			traceManager.openTrace(tb.trace);

			start(conn, "%s".formatted(cloneExit));
			conn.execute("break set -n work");

			waitForPass(() -> {
				TraceObject inf = tb.objAny("Processes[]");
				assertNotNull(inf);
				assertEquals("STOPPED", tb.objValue(inf, lastSnap(conn), "_state"));
			}, RUN_TIMEOUT_MS, RETRY_MS);
			txPut(conn, "threads");
			waitForPass(() -> assertEquals(1,
				tb.objValues(lastSnap(conn), "Processes[].Threads[]").size()),
				RUN_TIMEOUT_MS, RETRY_MS);

			conn.execute("continue");
			waitStopped(conn.conn);
			waitForPass(() -> {
				TraceObject inf = tb.objAny("Processes[]");
				assertNotNull(inf);
				assertEquals("STOPPED", tb.objValue(inf, lastSnap(conn), "_state"));
			}, RUN_TIMEOUT_MS, RETRY_MS);

			waitForPass(() -> assertEquals(2,
				tb.objValues(lastSnap(conn), "Processes[].Threads[]").size()),
				RUN_TIMEOUT_MS, RETRY_MS);

			// Now the real test
			conn.execute("thread select 1");
			conn.execute("frame select 0");
			waitForPass(() -> {
				String ti0 = conn.executeCapture("thread info");
				assertTrue(ti0.contains("#1"));
				String threadIndex = threadIndex(traceManager.getCurrentObject());
				assertTrue(ti0.contains(threadIndex));
			}, RUN_TIMEOUT_MS, RETRY_MS);

			conn.execute("thread select 2");
			conn.execute("frame select 0");
			waitForPass(() -> {
				String ti0 = conn.executeCapture("thread info");
				assertTrue(ti0.contains("#2"));
				String threadIndex = threadIndex(traceManager.getCurrentObject());
				assertTrue(ti0.contains(threadIndex));
			}, RUN_TIMEOUT_MS, RETRY_MS);

			conn.execute("thread select 1");
			conn.execute("frame select 0");
			waitForPass(() -> {
				String ti0 = conn.executeCapture("thread info");
				assertTrue(ti0.contains("#1"));
				String threadIndex = threadIndex(traceManager.getCurrentObject());
				assertTrue(ti0.contains(threadIndex));
			}, RUN_TIMEOUT_MS, RETRY_MS);
		}
	}

	protected String getIndex(TraceObject object, String pattern, int n) {
		if (object == null) {
			return null;
		}
		PathPattern pat = PathPredicates.parse(pattern).getSingletonPattern();
//		if (pat.countWildcards() != 1) {
//			throw new IllegalArgumentException("Exactly one wildcard required");
//		}
		List<String> path = object.getCanonicalPath().getKeyList();
		if (path.size() < pat.asPath().size()) {
			return null;
		}
		List<String> matched = pat.matchKeys(path.subList(0, pat.asPath().size()));
		if (matched == null) {
			return null;
		}
		if (matched.size() <= n) {
			return null;
		}
		return matched.get(n);
	}

	protected String threadIndex(TraceObject object) {
		return getIndex(object, "Processes[].Threads[]", 1);
	}

	protected String frameIndex(TraceObject object) {
		return getIndex(object, "Processes[].Threads[].Stack[]", 2);
	}

	@Test
	public void testOnFrameSelected() throws Exception {
		try (LldbAndTrace conn = startAndSyncLldb()) {
			traceManager.openTrace(tb.trace);

			start(conn, getSpecimenPrint());
			conn.execute("breakpoint set -n puts");
			conn.execute("cont");

			waitStopped(conn.conn);
			waitForPass(() -> assertThat(
				tb.objValues(lastSnap(conn), "Processes[].Threads[].Stack[]").size(),
				greaterThan(2)),
				RUN_TIMEOUT_MS, RETRY_MS);

			conn.execute("frame select 1");
			waitForPass(() -> assertEquals("1", frameIndex(traceManager.getCurrentObject())),
				RUN_TIMEOUT_MS, RETRY_MS);

			conn.execute("frame select 0");
			waitForPass(() -> assertEquals("0", frameIndex(traceManager.getCurrentObject())),
				RUN_TIMEOUT_MS, RETRY_MS);

			conn.execute("kill");
		}
	}

	@Test
	@Ignore
	public void testOnSyscallMemory() throws Exception {
		// TODO: Need a specimen
		// FWIW, I've already seen this getting exercised in other tests.
	}

	//@Test // LLDB does not provide the necessary events
	public void testOnMemoryChanged() throws Exception {
		try (LldbAndTrace conn = startAndSyncLldb()) {
			start(conn, getSpecimenPrint());

			long address = Long.decode(conn.executeCapture("dis -c1 -n main").split("\\s+")[1]);
			conn.execute("expr *((char*)(void(*)())main) = 0x7f");
			//conn.execute("ghidra trace tx-start 'Tx'");
			//conn.execute("ghidra trace putmem '(void(*)())main' 10");
			//conn.execute("ghidra trace tx-commit");

			waitForPass(() -> {
				ByteBuffer buf = ByteBuffer.allocate(10);
				tb.trace.getMemoryManager().getBytes(lastSnap(conn), tb.addr(address), buf);
				assertEquals(0x7f, buf.get(0));
			}, RUN_TIMEOUT_MS, RETRY_MS);
		}
	}

	//@Test // LLDB does not provide the necessary events
	public void testOnRegisterChanged() throws Exception {
		try (LldbAndTrace conn = startAndSyncLldb()) {
			start(conn, getSpecimenPrint());

			conn.execute("expr $%s = 0x1234".formatted(PLAT.intReg()));
			//conn.execute("ghidra trace tx-start 'Tx'");
			//conn.execute("ghidra trace putreg");
			//conn.execute("ghidra trace tx-commit");

			String path = "Processes[].Threads[].Stack[].Registers";
			TraceObject registers = Objects.requireNonNull(tb.objAny(path, Lifespan.at(0)));
			AddressSpace space = tb.trace.getBaseAddressFactory()
					.getAddressSpace(registers.getCanonicalPath().toString());
			TraceMemorySpace regs = tb.trace.getMemoryManager().getMemorySpace(space, false);
			waitForPass(() -> assertEquals("1234",
				regs.getValue(lastSnap(conn), tb.reg(PLAT.intReg()))
						.getUnsignedValue()
						.toString(16)));
		}
	}

	@Test
	public void testOnCont() throws Exception {
		try (LldbAndTrace conn = startAndSyncLldb()) {
			start(conn, getSpecimenRead());

			conn.execute("cont");
			waitRunning(conn.conn);

			TraceObject proc = waitForValue(() -> tb.objAny("Processes[]"));
			waitForPass(() -> {
				assertEquals("RUNNING", tb.objValue(proc, lastSnap(conn), "_state"));
			}, RUN_TIMEOUT_MS, RETRY_MS);

			conn.execute("process interrupt");
		}
	}

	@Test
	public void testOnStop() throws Exception {
		try (LldbAndTrace conn = startAndSyncLldb()) {
			start(conn, getSpecimenPrint());

			TraceObject inf = waitForValue(() -> tb.objAny("Processes[]"));
			waitForPass(() -> {
				assertEquals("STOPPED", tb.objValue(inf, lastSnap(conn), "_state"));
			}, RUN_TIMEOUT_MS, RETRY_MS);
		}
	}

	@Test
	public void testOnExited() throws Exception {
		try (LldbAndTrace conn = startAndSyncLldb()) {
			start(conn, getSpecimenPrint());

			conn.execute("cont");
			waitRunning(conn.conn);

			waitForPass(() -> {
				TraceSnapshot snapshot =
					tb.trace.getTimeManager().getSnapshot(lastSnap(conn), false);
				assertNotNull(snapshot);
				assertEquals("Exited with code 72", snapshot.getDescription());

				TraceObject proc = tb.objAny("Processes[]");
				assertNotNull(proc);
				Object val = tb.objValue(proc, lastSnap(conn), "_exit_code");
				assertThat(val, instanceOf(Number.class));
				assertEquals(72, ((Number) val).longValue());
			}, RUN_TIMEOUT_MS, RETRY_MS);
		}
	}

	@Test
	public void testOnBreakpointCreated() throws Exception {
		try (LldbAndTrace conn = startAndSyncLldb()) {
			start(conn, getSpecimenPrint());
			assertEquals(0, tb.objValues(lastSnap(conn), "Processes[].Breakpoints[]").size());

			conn.execute("breakpoint set -n main");
			conn.execute("stepi");

			waitForPass(() -> {
				List<Object> brks = tb.objValues(lastSnap(conn), "Processes[].Breakpoints[]");
				assertEquals(1, brks.size());
				return (TraceObject) brks.get(0);
			});
		}
	}

	@Test
	public void testOnBreakpointModified() throws Exception {
		try (LldbAndTrace conn = startAndSyncLldb()) {
			start(conn, getSpecimenPrint());
			assertEquals(0, tb.objValues(lastSnap(conn), "Breakpoints[]").size());

			//conn.execute("script lldb.debugger.SetAsync(False)");
			conn.execute("breakpoint set -n main");
			conn.execute("stepi");
			TraceObject brk = waitForPass(() -> {
				List<Object> brks = tb.objValues(lastSnap(conn), "Breakpoints[]");
				assertEquals(1, brks.size());
				return (TraceObject) brks.get(0);
			});
			assertEquals(null, tb.objValue(brk, lastSnap(conn), "Condition"));

			waitStopped(conn.conn);
			conn.execute("breakpoint modify -c 'x>3'");
			conn.execute("stepi");
			// NB: Testing "Commands" requires multi-line input - not clear how to do this
			//assertEquals(null, tb.objValue(brk, lastSnap(conn), "Commands"));
			//conn.execute("breakpoint command add 'echo test'");
			//conn.execute("DONE");

			waitForPass(
				() -> assertEquals("x>3", tb.objValue(brk, lastSnap(conn), "Condition")));
		}
	}

	@Test
	public void testOnBreakpointDeleted() throws Exception {
		try (LldbAndTrace conn = startAndSyncLldb()) {
			start(conn, getSpecimenPrint());
			assertEquals(0, tb.objValues(lastSnap(conn), "Processes[].Breakpoints[]").size());

			conn.execute("breakpoint set -n main");
			conn.execute("stepi");

			TraceObject brk = waitForPass(() -> {
				List<Object> brks = tb.objValues(lastSnap(conn), "Processes[].Breakpoints[]");
				assertEquals(1, brks.size());
				return (TraceObject) brks.get(0);
			});

			waitStopped(conn.conn);
			conn.execute("breakpoint delete %s".formatted(brk.getCanonicalPath().index()));
			conn.execute("stepi");

			waitForPass(
				() -> assertEquals(0,
					tb.objValues(lastSnap(conn), "Processes[].Breakpoints[]").size()));
		}
	}

	private void start(LldbAndTrace conn, String obj) {
		conn.execute("file " + obj);
		conn.execute("ghidra trace sync-enable");
		conn.execute("process launch --stop-at-entry");
		txPut(conn, "processes");
	}

	private void txPut(LldbAndTrace conn, String obj) {
		conn.execute("ghidra trace tx-start 'Tx" + obj + "'");
		conn.execute("ghidra trace put-" + obj);
		conn.execute("ghidra trace tx-commit");
	}

}
