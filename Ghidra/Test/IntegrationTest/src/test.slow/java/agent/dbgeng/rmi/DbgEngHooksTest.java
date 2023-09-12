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

import static org.hamcrest.Matchers.instanceOf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Objects;

import org.junit.Ignore;
import org.junit.Test;

import ghidra.app.plugin.core.debug.service.rmi.trace.RemoteMethod;
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
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;

public class DbgEngHooksTest extends AbstractDbgEngTraceRmiTest {
	private static final long RUN_TIMEOUT_MS = 20000;
	private static final long RETRY_MS = 500;

	record PythonAndTrace(PythonAndHandler conn, ManagedDomainObject mdo) implements AutoCloseable {
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
		PythonAndHandler conn = startAndConnectPython();
		try {
			ManagedDomainObject mdo;
			conn.execute("from ghidradbg.commands import *");
			conn.execute(
				"util.set_convenience_variable('ghidra-language', 'x86:LE:64:default')");
            if (exec != null) {
			    start(conn, exec);
		        mdo = waitDomainObject("/New Traces/pydbg/"+exec);
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
		return conn.conn.handler().getLastSnapshot(tb.trace);
	}

	@Test  // The 10s wait makes this a pretty expensive test
	public void testOnNewThread() throws Exception {
		try (PythonAndTrace conn = startAndSyncPython("notepad.exe")) {
			conn.execute("from ghidradbg.commands import *");
			txPut(conn, "processes");

			waitForPass(() -> {
				TraceObject proc = tb.objAny("Processes[]");
				assertNotNull(proc);
				assertEquals("STOPPED", tb.objValue(proc, lastSnap(conn), "_state"));
			}, RUN_TIMEOUT_MS, RETRY_MS);

			txPut(conn, "threads");
			waitForPass(() -> assertEquals(4,
				tb.objValues(lastSnap(conn), "Processes[].Threads[]").size()),
				RUN_TIMEOUT_MS, RETRY_MS);

			conn.execute("dbg().go(10)");

			waitForPass(() -> assertTrue(tb.objValues(lastSnap(conn), "Processes[].Threads[]").size() > 4),
				RUN_TIMEOUT_MS, RETRY_MS);
		}
	}

	@Test
	public void testOnThreadSelected() throws Exception {
		try (PythonAndTrace conn = startAndSyncPython("notepad.exe")) {
			txPut(conn, "processes");

			waitForPass(() -> {
				TraceObject inf = tb.objAny("Processes[]");
				assertNotNull(inf);
				assertEquals("STOPPED", tb.objValue(inf, lastSnap(conn), "_state"));
			}, RUN_TIMEOUT_MS, RETRY_MS);

			txPut(conn, "threads");
			waitForPass(() -> assertEquals(4,
				tb.objValues(lastSnap(conn), "Processes[].Threads[]").size()),
				RUN_TIMEOUT_MS, RETRY_MS);

			// Now the real test
			conn.execute("util.select_thread(1)");
			waitForPass(() -> {
				String tnum = conn.executeCapture("util.selected_thread()");
				assertTrue(tnum.contains("1"));
				String threadIndex = threadIndex(traceManager.getCurrentObject());
				assertTrue(tnum.contains(threadIndex));
			}, RUN_TIMEOUT_MS, RETRY_MS);

			conn.execute("util.select_thread(2)");
			waitForPass(() -> {
				String tnum = conn.executeCapture("util.selected_thread()");
				assertTrue(tnum.contains("2"));
				String threadIndex = threadIndex(traceManager.getCurrentObject());
				assertTrue(tnum.contains(threadIndex));
			}, RUN_TIMEOUT_MS, RETRY_MS);

			conn.execute("util.select_thread(0)");
			waitForPass(() -> {
				String tnum = conn.executeCapture("util.selected_thread()");
				assertTrue(tnum.contains("0"));
				String threadIndex = threadIndex(traceManager.getCurrentObject());
				assertTrue(tnum.contains(threadIndex));
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

	//@Test - dbgeng has limited support via DEBUG_CDS_DATA, 
	//     but expensive to implement anything here
	public void testOnMemoryChanged() throws Exception {
		try (PythonAndTrace conn = startAndSyncPython("notepad.exe")) {

			conn.execute("ghidra_trace_txstart('Tx')");
			conn.execute("ghidra_trace_putmem('$pc 10')");
			conn.execute("ghidra_trace_txcommit()");
			long address = getAddressAtOffset(conn, 0);				
			conn.execute("util.get_debugger().write("+address+", b'\\x7f')");

			waitForPass(() -> {
				ByteBuffer buf = ByteBuffer.allocate(10);
				tb.trace.getMemoryManager().getBytes(lastSnap(conn), tb.addr(address), buf);
				assertEquals(0x7f, buf.get(0));
			}, RUN_TIMEOUT_MS, RETRY_MS);
		}
	}

	@Test
	public void testOnRegisterChanged() throws Exception {
		try (PythonAndTrace conn = startAndSyncPython("notepad.exe")) {

			conn.execute("ghidra_trace_txstart('Tx')");
			conn.execute("ghidra_trace_putreg()");
			conn.execute("ghidra_trace_txcommit()");
			conn.execute("util.get_debugger().reg._set_register('rax', 0x1234)");
			conn.execute("util.get_debugger().stepi()");

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

			conn.execute("util.get_debugger()._control.SetExecutionStatus(DbgEng.DEBUG_STATUS_GO)");
			waitRunning();

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
			waitStopped();

			conn.execute("util.get_debugger().go()");

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
			assertEquals(0, tb.objValues(lastSnap(conn), "Processes[].Breakpoints[]").size());

			conn.execute("dbg = util.get_debugger()");
			conn.execute("pc = dbg.reg.get_pc()");
			conn.execute("dbg.bp(expr=pc)");
			conn.execute("dbg.stepi()");

			waitForPass(() -> {
				List<Object> brks = tb.objValues(lastSnap(conn), "Processes[].Breakpoints[]");
				assertEquals(1, brks.size());
				return (TraceObject) brks.get(0);
			});
		}
	}

	@Test
	public void testOnBreakpointModified() throws Exception {
		try (PythonAndTrace conn = startAndSyncPython("notepad.exe")) {
			assertEquals(0, tb.objValues(lastSnap(conn), "Processes[].Breakpoints[]").size());

			conn.execute("dbg = util.get_debugger()");
			conn.execute("pc = dbg.reg.get_pc()");
			conn.execute("dbg.bp(expr=pc)");
			conn.execute("dbg.stepi()");

			TraceObject brk = waitForPass(() -> {
				List<Object> brks = tb.objValues(lastSnap(conn), "Processes[].Breakpoints[]");
				assertEquals(1, brks.size());
				return (TraceObject) brks.get(0);
			});
			assertEquals(true, tb.objValue(brk, lastSnap(conn), "Enabled"));
			conn.execute("dbg.bd(0)");
			conn.execute("dbg.stepi()");
			assertEquals(false, tb.objValue(brk, lastSnap(conn), "Enabled"));

            /* Not currently enabled
			assertEquals("", tb.objValue(brk, lastSnap(conn), "Command"));
			conn.execute("dbg.bp(expr=pc, windbgcmd='bl')");
			conn.execute("dbg.stepi()");
			assertEquals("bl", tb.objValue(brk, lastSnap(conn), "Command"));
			*/
		}
	}

	@Test
	public void testOnBreakpointDeleted() throws Exception {
		try (PythonAndTrace conn = startAndSyncPython("notepad.exe")) {
			assertEquals(0, tb.objValues(lastSnap(conn), "Processes[].Breakpoints[]").size());

			conn.execute("dbg = util.get_debugger()");
			conn.execute("pc = dbg.reg.get_pc()");
			conn.execute("dbg.bp(expr=pc)");
			conn.execute("dbg.stepi()");

			TraceObject brk = waitForPass(() -> {
				List<Object> brks = tb.objValues(lastSnap(conn), "Processes[].Breakpoints[]");
				assertEquals(1, brks.size());
				return (TraceObject) brks.get(0);
			});

			conn.execute("dbg.cmd('bc %s')".formatted(brk.getCanonicalPath().index()));
			conn.execute("dbg.stepi()");

			waitForPass(
				() -> assertEquals(0,
					tb.objValues(lastSnap(conn), "Processes[].Breakpoints[]").size()));
		}
	}

	private void start(PythonAndHandler conn, String obj) {
		conn.execute("from ghidradbg.commands import *");
		if (obj != null)
			conn.execute("ghidra_trace_create('"+obj+"')");
		else 
			conn.execute("ghidra_trace_create()");	
		conn.execute("ghidra_trace_sync_enable()");
	}

	private void txPut(PythonAndTrace conn, String obj) {
		conn.execute("ghidra_trace_txstart('Tx" + obj + "')");
		conn.execute("ghidra_trace_put_" + obj +"()");
		conn.execute("ghidra_trace_txcommit()");
	}

	private long getAddressAtOffset(PythonAndTrace conn, int offset) {
		String inst = "util.get_inst(util.get_debugger().reg.get_pc()+"+offset+")";
		String ret = conn.executeCapture(inst);
		String[] split = ret.split("\\s+");  // get target
		return Long.decode(split[1]);
	}
}
