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
package agent.dbgeng.rmi;

import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.Assert.*;

import java.util.*;

import org.junit.Ignore;
import org.junit.Test;

import ghidra.app.plugin.core.debug.utils.ManagedDomainObject;
import ghidra.dbg.util.PathPattern;
import ghidra.dbg.util.PathPredicates;
import ghidra.debug.api.tracermi.RemoteMethod;
import ghidra.program.model.address.AddressSpace;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.time.TraceSnapshot;

public class DbgEngHooksTest extends AbstractDbgEngTraceRmiTest {
	private static final long RUN_TIMEOUT_MS = 5000;
	private static final long RETRY_MS = 500;

	record PythonAndTrace(PythonAndConnection conn, ManagedDomainObject mdo)
			implements AutoCloseable {
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
	protected PythonAndTrace startAndSyncPython(String exec) throws Exception {
		PythonAndConnection conn = startAndConnectPython();
		try {
			ManagedDomainObject mdo;
			conn.execute("from ghidradbg.commands import *");
			conn.execute(
				"util.set_convenience_variable('ghidra-language', 'x86:LE:64:default')");
			if (exec != null) {
				start(conn, exec);
				mdo = waitDomainObject("/New Traces/pydbg/" + exec);
			}
			else {
				conn.execute("ghidra_trace_start()");
				mdo = waitDomainObject("/New Traces/pydbg/noname");
			}
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			return new PythonAndTrace(conn, mdo);
		}
		catch (Exception e) {
			conn.close();
			throw e;
		}
	}

	protected long lastSnap(PythonAndTrace conn) {
		return conn.conn.connection().getLastSnapshot(tb.trace);
	}

	@Test
	public void testOnNewThread() throws Exception {
		final int INIT_NOTEPAD_THREAD_COUNT = 4; // This could be fragile
		try (PythonAndTrace conn = startAndSyncPython("notepad.exe")) {
			conn.execute("from ghidradbg.commands import *");
			txPut(conn, "processes");

			waitForPass(() -> {
				TraceObject proc = tb.objAny("Processes[]");
				assertNotNull(proc);
				assertEquals("STOPPED", tb.objValue(proc, lastSnap(conn), "_state"));
			}, RUN_TIMEOUT_MS, RETRY_MS);

			txPut(conn, "threads");
			waitForPass(() -> assertEquals(INIT_NOTEPAD_THREAD_COUNT,
				tb.objValues(lastSnap(conn), "Processes[].Threads[]").size()),
				RUN_TIMEOUT_MS, RETRY_MS);

			// Via method, go is asynchronous
			RemoteMethod go = conn.conn.getMethod("go");
			TraceObject proc = tb.objAny("Processes[]");
			go.invoke(Map.of("process", proc));

			waitForPass(
				() -> assertThat(tb.objValues(lastSnap(conn), "Processes[].Threads[]").size(),
					greaterThan(INIT_NOTEPAD_THREAD_COUNT)),
				RUN_TIMEOUT_MS, RETRY_MS);
		}
	}

	@Test
	public void testOnThreadSelected() throws Exception {
		try (PythonAndTrace conn = startAndSyncPython("notepad.exe")) {
			txPut(conn, "processes");

			waitForPass(() -> {
				TraceObject proc = tb.obj("Processes[0]");
				assertNotNull(proc);
				assertEquals("STOPPED", tb.objValue(proc, lastSnap(conn), "_state"));
			}, RUN_TIMEOUT_MS, RETRY_MS);

			txPut(conn, "threads");
			waitForPass(() -> assertEquals(4,
				tb.objValues(lastSnap(conn), "Processes[0].Threads[]").size()),
				RUN_TIMEOUT_MS, RETRY_MS);

			// Now the real test
			conn.execute("print('Selecting 1')");
			conn.execute("util.select_thread(1)");
			waitForPass(() -> {
				String tnum = conn.executeCapture("print(util.selected_thread())").strip();
				assertEquals("1", tnum);
				assertEquals(tb.obj("Processes[0].Threads[1]"), traceManager.getCurrentObject());
			}, RUN_TIMEOUT_MS, RETRY_MS);

			conn.execute("util.select_thread(2)");
			waitForPass(() -> {
				String tnum = conn.executeCapture("print(util.selected_thread())").strip();
				assertEquals("2", tnum);
				String threadIndex = threadIndex(traceManager.getCurrentObject());
				assertEquals("2", threadIndex);
			}, RUN_TIMEOUT_MS, RETRY_MS);

			conn.execute("util.select_thread(0)");
			waitForPass(() -> {
				String tnum = conn.executeCapture("print(util.selected_thread())").strip();
				assertEquals("0", tnum);
				String threadIndex = threadIndex(traceManager.getCurrentObject());
				assertEquals("0", threadIndex);
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
	@Ignore
	public void testOnSyscallMemory() throws Exception {
		// TODO: Need a specimen
		// FWIW, I've already seen this getting exercised in other tests.
	}

	/**
	 * dbgeng has limited support via DEBUG_CDS_DATA. It tells us what space has changed, but not
	 * the address(es). We have some options:
	 * 
	 * 1) Ignore it. This puts the onus of refreshing on the user. The upside is that past
	 * observations are preserved. The downside is we can't be certain of their accuracy.
	 * 
	 * 2) Invalidate the entire space. This will ensure the UI either updates automatically or
	 * indicates the possible staleness. The downside is that we lose past observations.
	 * 
	 * 3) Remember what addresses have been fetched since last BREAK, and refresh them all. This is
	 * better than refreshing the entire space (prohibitive), but we could get right back there if
	 * the user has captured the full space and then modifies a single byte.
	 * 
	 * For the moment, we favor option (2), as we'd prefer never to display inaccurate data,
	 * especially as non-stale. The lost observations are a small price to pay, since they're not
	 * particularly important for the interactive use case.
	 */
	@Test
	public void testOnMemoryChanged() throws Exception {
		try (PythonAndTrace conn = startAndSyncPython("notepad.exe")) {

			long address = getAddressAtOffset(conn, 0);

			conn.execute("ghidra_trace_txstart('Tx')");
			conn.execute("ghidra_trace_putmem(%d, 10)".formatted(address));
			conn.execute("ghidra_trace_txcommit()");

			waitForPass(() -> {
				assertEquals(TraceMemoryState.KNOWN,
					tb.trace.getMemoryManager().getState(lastSnap(conn), tb.addr(address)));
			}, RUN_TIMEOUT_MS, RETRY_MS);

			conn.execute("util.dbg.write(%d, b'\\x7f')".formatted(address));

			waitForPass(() -> {
				assertEquals(TraceMemoryState.UNKNOWN,
					tb.trace.getMemoryManager().getState(lastSnap(conn), tb.addr(address)));
			}, RUN_TIMEOUT_MS, RETRY_MS);
		}
	}

	@Test
	public void testOnRegisterChanged() throws Exception {
		try (PythonAndTrace conn = startAndSyncPython("notepad.exe")) {

			conn.execute("ghidra_trace_txstart('Tx')");
			conn.execute("ghidra_trace_putreg()");
			conn.execute("ghidra_trace_txcommit()");
			conn.execute("util.dbg.cmd('r rax=0x1234')");

			String path = "Processes[].Threads[].Registers";
			TraceObject registers = Objects.requireNonNull(tb.objAny(path, Lifespan.at(0)));
			AddressSpace space = tb.trace.getBaseAddressFactory()
					.getAddressSpace(registers.getCanonicalPath().toString());
			TraceMemorySpace regs = tb.trace.getMemoryManager().getMemorySpace(space, false);
			waitForPass(() -> assertEquals("1234",
				regs.getValue(lastSnap(conn), tb.reg("RAX")).getUnsignedValue().toString(16)));
		}
	}

	@Test
	public void testOnCont() throws Exception {
		try (PythonAndTrace conn = startAndSyncPython("notepad.exe")) {
			txPut(conn, "processes");

			// WaitForEvents is not required for this test to pass. 
			conn.execute("""
					@util.dbg.eng_thread
					def go_no_wait():
					    util.dbg._base._control.SetExecutionStatus(DbgEng.DEBUG_STATUS_GO)

					go_no_wait()
					""");
			waitRunning("Missed running after go");

			TraceObject proc = waitForValue(() -> tb.objAny("Processes[]"));
			waitForPass(() -> {
				assertEquals("RUNNING", tb.objValue(proc, lastSnap(conn), "_state"));
			}, RUN_TIMEOUT_MS, RETRY_MS);
		}
	}

	@Test
	public void testOnStop() throws Exception {
		try (PythonAndTrace conn = startAndSyncPython("notepad.exe")) {
			txPut(conn, "processes");

			TraceObject proc = waitForValue(() -> tb.objAny("Processes[]"));
			waitForPass(() -> {
				assertEquals("STOPPED", tb.objValue(proc, lastSnap(conn), "_state"));
			}, RUN_TIMEOUT_MS, RETRY_MS);
		}
	}

	@Test
	public void testOnExited() throws Exception {
		try (PythonAndTrace conn = startAndSyncPython("netstat.exe")) {
			txPut(conn, "processes");
			waitStopped("Missed initial stop");

			// Do the synchronous wait here, since netstat should terminate
			conn.execute("util.dbg.go()");

			waitForPass(() -> {
				TraceSnapshot snapshot =
					tb.trace.getTimeManager().getSnapshot(lastSnap(conn), false);
				assertNotNull(snapshot);
				assertEquals("Exited with code 0", snapshot.getDescription());

				TraceObject proc = tb.objAny("Processes[]");
				assertNotNull(proc);
				Object val = tb.objValue(proc, lastSnap(conn), "_exit_code");
				assertThat(val, instanceOf(Number.class));
				assertEquals(0, ((Number) val).longValue());
			}, RUN_TIMEOUT_MS, RETRY_MS);
		}
	}

	@Test
	public void testOnBreakpointCreated() throws Exception {
		try (PythonAndTrace conn = startAndSyncPython("notepad.exe")) {
			txPut(conn, "breakpoints");
			assertEquals(0, tb.objValues(lastSnap(conn), "Processes[].Breakpoints[]").size());

			conn.execute("pc = util.get_pc()");
			conn.execute("util.dbg.bp(expr=pc)");

			waitForPass(() -> {
				List<Object> brks = tb.objValues(lastSnap(conn), "Processes[].Breakpoints[]");
				assertEquals(1, brks.size());
			});
		}
	}

	@Test
	public void testOnBreakpointModified() throws Exception {
		try (PythonAndTrace conn = startAndSyncPython("notepad.exe")) {
			txPut(conn, "breakpoints");
			assertEquals(0, tb.objValues(lastSnap(conn), "Processes[].Breakpoints[]").size());

			conn.execute("pc = util.get_pc()");
			conn.execute("util.dbg.bp(expr=pc)");

			TraceObject brk = waitForPass(() -> {
				List<Object> brks = tb.objValues(lastSnap(conn), "Processes[].Breakpoints[]");
				assertEquals(1, brks.size());
				return (TraceObject) brks.get(0);
			});

			assertEquals(true, tb.objValue(brk, lastSnap(conn), "Enabled"));
			conn.execute("util.dbg.bd(0)");
			assertEquals(false, tb.objValue(brk, lastSnap(conn), "Enabled"));

			/* Not currently enabled
			assertEquals("", tb.objValue(brk, lastSnap(conn), "Command"));
			conn.execute("util.dbg.bp(expr=pc, windbgcmd='bl')");
			assertEquals("bl", tb.objValue(brk, lastSnap(conn), "Command"));
			*/
		}
	}

	@Test
	public void testOnBreakpointDeleted() throws Exception {
		try (PythonAndTrace conn = startAndSyncPython("notepad.exe")) {
			txPut(conn, "breakpoints");
			assertEquals(0, tb.objValues(lastSnap(conn), "Processes[].Breakpoints[]").size());

			conn.execute("pc = util.get_pc()");
			conn.execute("util.dbg.bp(expr=pc)");

			TraceObject brk = waitForPass(() -> {
				List<Object> brks = tb.objValues(lastSnap(conn), "Processes[].Breakpoints[]");
				assertEquals(1, brks.size());
				return (TraceObject) brks.get(0);
			});
			String id = brk.getCanonicalPath().index();
			assertEquals("0", id);

			// Causes access violation in pybag/comtypes during tear-down
			//conn.execute("util.dbg.bc(%s)".formatted(id));
			conn.execute("util.dbg.cmd('bc %s')".formatted(id));

			waitForPass(() -> assertEquals(0,
				tb.objValues(lastSnap(conn), "Processes[].Breakpoints[]").size()));
		}
	}

	private void start(PythonAndConnection conn, String obj) {
		conn.execute("from ghidradbg.commands import *");
		if (obj != null)
			conn.execute("ghidra_trace_create('" + obj + "')");
		else
			conn.execute("ghidra_trace_create()");
		conn.execute("ghidra_trace_sync_enable()");
	}

	private void txPut(PythonAndTrace conn, String obj) {
		conn.execute("ghidra_trace_txstart('Tx" + obj + "')");
		conn.execute("ghidra_trace_put_" + obj + "()");
		conn.execute("ghidra_trace_txcommit()");
	}

	private long getAddressAtOffset(PythonAndTrace conn, int offset) {
		String inst = "print(util.get_inst(util.get_pc()+" + offset + "))";
		String ret = conn.executeCapture(inst);
		String[] split = ret.split("\\s+");  // get target
		return Long.decode(split[1]);
	}
}
