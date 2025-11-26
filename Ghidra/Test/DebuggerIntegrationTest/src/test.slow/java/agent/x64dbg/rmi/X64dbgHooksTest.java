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
package agent.x64dbg.rmi;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

import java.util.*;

import org.junit.Test;

import ghidra.app.plugin.core.debug.utils.ManagedDomainObject;
import ghidra.debug.api.tracermi.RemoteMethod;
import ghidra.program.model.address.AddressSpace;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.path.*;
import ghidra.trace.model.time.TraceSnapshot;

public class X64dbgHooksTest extends AbstractX64dbgTraceRmiTest {
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
			try {
				conn.execute("util.terminate_session()");
				conn.close();
			} catch (Exception e) {
				//IGNORE
			}
			try {
				mdo.close();
			} catch (Exception e) {
				//IGNORE
			}
			
		}
	}

	@SuppressWarnings("resource")
	protected PythonAndTrace startAndSyncPython(String exec) throws Exception {
		PythonAndConnection conn = startAndConnectPython();
		try {
			ManagedDomainObject mdo;
			conn.execute("from ghidraxdbg.commands import *");
			conn.execute(
				"util.set_convenience_variable('ghidra-language', 'x86:LE:64:default')");
			if (exec != null) {
				start(conn, exec);
				mdo = waitDomainObject("/New Traces/x64dbg/" + exec.substring(exec.lastIndexOf("\\")+1));
			}
			else {
				conn.execute("ghidra_trace_start()");
				mdo = waitDomainObject("/New Traces/x64dbg/noname");
			}
			clearBreakpoints(conn);
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			return new PythonAndTrace(conn, mdo);
		}
		catch (Exception e) {
			clearBreakpoints(conn);
			conn.execute("util.terminate_session()");
			conn.close();
			throw e;
		}
	}

	protected long lastSnap(PythonAndTrace conn) {
		return conn.conn.connection().getLastSnapshot(tb.trace);
	}

	static final int INIT_NOTEPAD_THREAD_COUNT = 4; // This could be fragile

	//@Test - doesn't generate more than the initial 4
	public void testOnNewThread() throws Exception {
		try (PythonAndTrace conn = startAndSyncPython(NOTEPAD)) {
			conn.execute("from ghidraxdbg.commands import *");
			txPut(conn, "processes");

			waitForPass(() -> {
				TraceObject proc = tb.objAny0("Sessions[].Processes[]");
				assertNotNull(proc);
				assertEquals("STOPPED", tb.objValue(proc, lastSnap(conn), "_state"));
			}, RUN_TIMEOUT_MS, RETRY_MS);

			txPut(conn, "threads");
			waitForPass(() -> assertEquals(INIT_NOTEPAD_THREAD_COUNT,
				tb.objValues(lastSnap(conn), "Sessions[].Processes[].Threads[]").size()),
				RUN_TIMEOUT_MS, RETRY_MS);

			// Via method, go is asynchronous
			RemoteMethod go = conn.conn.getMethod("go");
			TraceObject proc = tb.objAny0("Sessions[].Processes[]");
			go.invoke(Map.of("process", proc));  // Initial breakpoint
			go.invoke(Map.of("process", proc));

			waitForPass(() -> assertThat(
				tb.objValues(lastSnap(conn), "Sessions[].Processes[].Threads[]").size(),
				greaterThan(INIT_NOTEPAD_THREAD_COUNT)),
				RUN_TIMEOUT_MS, RETRY_MS);			
		}
	}

	@Test
	public void testOnNewModule() throws Exception {
		try (PythonAndTrace conn = startAndSyncPython(NOTEPAD)) {
			conn.execute("from ghidraxdbg.commands import *");
			txPut(conn, "processes");

			TraceObject proc = tb.objAny0("Sessions[].Processes[]");
			waitForPass(() -> {
				assertNotNull(proc);
				assertEquals("STOPPED", tb.objValue(proc, lastSnap(conn), "_state"));
			}, RUN_TIMEOUT_MS, RETRY_MS);

			txPut(conn, "modules");
			waitForPass(() -> assertThat(
				tb.objValues(lastSnap(conn), "Sessions[].Processes[].Modules[]").size(),
				greaterThan(0)),
				RUN_TIMEOUT_MS, RETRY_MS);

			int size = tb.objValues(lastSnap(conn), "Sessions[].Processes[].Modules[]").size();
			// Via method, go is asynchronous
			RemoteMethod go = conn.conn.getMethod("go");
			go.invoke(Map.of("process", proc));  // Initial breakpoint
			go.invoke(Map.of("process", proc));

			waitForPass(() -> assertThat(
				tb.objValues(lastSnap(conn), "Sessions[].Processes[].Modules[]").size(),
				greaterThan(size)),
				RUN_TIMEOUT_MS, RETRY_MS);
		}
	}

	@Test
	public void testOnThreadSelected() throws Exception {
		try (PythonAndTrace conn = startAndSyncPython(NOTEPAD)) {
			txPut(conn, "processes");
			conn.execute("util.dbg.client.stepi()");  // no initial event

			waitForPass(() -> {
				TraceObject proc = tb.objAny0("Sessions[0].Processes[]");
				assertNotNull(proc);
				assertEquals("STOPPED", tb.objValue(proc, lastSnap(conn), "_state"));
			}, RUN_TIMEOUT_MS, RETRY_MS);

			txPut(conn, "threads");
			waitForPass(() -> {
				List<Object> values = tb.objValues(lastSnap(conn), "Sessions[0].Processes[].Threads[]");
				assertEquals(INIT_NOTEPAD_THREAD_COUNT, values.size());
			}, RUN_TIMEOUT_MS, RETRY_MS);

			// Now the real test
			List<Object> values = tb.objValues(lastSnap(conn), "Sessions[0].Processes[].Threads[]");
			TraceObject thread = (TraceObject) values.get(0);
			Object tid0 = tb.objValue(thread, lastSnap(conn), "TID");
			conn.execute("util.select_thread("+tid0.toString()+")");
			waitForPass(() -> {
				String tnum = conn.executeCapture("print(util.selected_thread())").strip();
				assertEquals(tid0.toString(), tnum);
			}, RUN_TIMEOUT_MS, RETRY_MS);

			thread = (TraceObject) values.get(1);
			Object tid1 = tb.objValue(thread, lastSnap(conn), "TID");
			conn.execute("util.select_thread("+tid1.toString()+")");
			waitForPass(() -> {
				String tnum = conn.executeCapture("print(util.selected_thread())").strip();
				assertEquals(tid1.toString(), tnum);
			}, RUN_TIMEOUT_MS, RETRY_MS);

			thread = (TraceObject) values.get(2);
			Object tid2 = tb.objValue(thread, lastSnap(conn), "TID");
			conn.execute("util.select_thread("+tid2.toString()+")");
			waitForPass(() -> {
				String tnum = conn.executeCapture("print(util.selected_thread())").strip();
				assertEquals(tid2.toString(), tnum);
			}, RUN_TIMEOUT_MS, RETRY_MS);
		}
	}

	protected String getIndex(TraceObject object, String pattern, int n) {
		if (object == null) {
			return null;
		}
		PathPattern pat = PathFilter.parse(pattern).getSingletonPattern();
		KeyPath path = object.getCanonicalPath();
		if (path.size() < pat.asPath().size()) {
			return null;
		}
		List<String> matched = pat.matchKeys(path, false);
		if (matched == null) {
			return null;
		}
		if (matched.size() <= n) {
			return null;
		}
		return matched.get(n);
	}

	protected String threadIndex(TraceObject object) {
		return getIndex(object, "Sessions[].Processes[].Threads[]", 2);
	}

	protected String frameIndex(TraceObject object) {
		return getIndex(object, "Sessions[].Processes[].Threads[].Stack.Frames[]", 3);
	}

	@Test
	public void testOnRegisterChanged() throws Exception {
		try (PythonAndTrace conn = startAndSyncPython(NOTEPAD)) {

			conn.execute("ghidra_trace_txstart('Tx')");
			conn.execute("ghidra_trace_putreg()");
			conn.execute("ghidra_trace_txcommit()");
			conn.execute("util.dbg.cmd('rax=0x1234')");
			conn.execute("util.dbg.client.stepi()");  // no real event for register changes

			String path = "Sessions[].Processes[].Threads[].Registers";
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
		try (PythonAndTrace conn = startAndSyncPython(NOTEPAD)) {
			txPut(conn, "processes");

			conn.execute("util.dbg.client.go()");
			conn.execute("util.dbg.client.go()");

			TraceObject proc = waitForValue(() -> tb.objAny0("Sessions[].Processes[]"));
			waitForPass(() -> {
				assertEquals("RUNNING", tb.objValue(proc, lastSnap(conn), "_state"));
			}, RUN_TIMEOUT_MS, RETRY_MS);
		}
	}

	@Test
	public void testOnStop() throws Exception {
		try (PythonAndTrace conn = startAndSyncPython(NOTEPAD)) {
			txPut(conn, "processes");

			TraceObject proc = waitForValue(() -> tb.objAny0("Sessions[].Processes[]"));
			waitForPass(() -> {
				conn.execute("util.terminate_session()");
				assertEquals("STOPPED", tb.objValue(proc, lastSnap(conn), "_state"));
			}, RUN_TIMEOUT_MS, RETRY_MS);
		}
	}

	//@Test - TODO: currently missing relevant events
	public void testOnExited() throws Exception {
		try (PythonAndTrace conn = startAndSyncPython("netstat.exe")) {
			txPut(conn, "processes");

			// Do the synchronous wait here, since netstat should terminate
			conn.execute("util.dbg.client.go()");

			waitForPass(() -> {
				TraceSnapshot snapshot =
					tb.trace.getTimeManager().getSnapshot(lastSnap(conn), false);
				assertNotNull(snapshot);
				assertEquals("Exited with code 0", snapshot.getDescription());

				TraceObject proc = tb.objAny0("Sessions[].Processes[]");
				assertNotNull(proc);
				Object val = tb.objValue(proc, lastSnap(conn), "_exit_code");
				assertThat(val, instanceOf(Number.class));
				assertEquals(0, ((Number) val).longValue());
				conn.execute("util.terminate_session()");
			}, RUN_TIMEOUT_MS, RETRY_MS);
		}
	}

	@Test
	public void testOnBreakpointCreated() throws Exception {
		try (PythonAndTrace conn = startAndSyncPython(NOTEPAD)) {
			txPut(conn, "breakpoints");
			assertEquals(0,
				tb.objValues(lastSnap(conn), "Sessions[].Processes[].Debug.Software Breakpoints[]").size());

			conn.execute("pc = util.get_pc()");
			conn.execute("util.dbg.client.set_breakpoint(address_or_symbol=pc)");
			conn.execute("util.dbg.client.stepi()");  // no real event for bpt changes

			waitForPass(() -> {
				List<Object> brks =
					tb.objValues(lastSnap(conn), "Sessions[].Processes[].Debug.Software Breakpoints[]");
				assertEquals(1, brks.size());
			});
		}
	}

	//@Test - works but has timing issues
	public void testOnBreakpointModified() throws Exception {
		try (PythonAndTrace conn = startAndSyncPython(NOTEPAD)) {
			txPut(conn, "breakpoints");
			assertEquals(0,
				tb.objValues(lastSnap(conn), "Sessions[].Processes[].Debug.Software Breakpoints[]").size());

			conn.execute("pc = util.get_pc()");
			conn.execute("util.dbg.client.set_breakpoint(address_or_symbol=pc)");
			conn.execute("util.dbg.client.stepi()");  // no real event for bpt changes

			TraceObject brk = waitForPass(() -> {
				List<Object> brks =
					tb.objValues(lastSnap(conn), "Sessions[].Processes[].Debug.Software Breakpoints[]");
				assertEquals(1, brks.size());
				return (TraceObject) brks.get(0);
			});

			assertEquals(true, tb.objValue(brk, lastSnap(conn), "Enabled"));
			conn.execute("util.dbg.client.toggle_breakpoint(address_name_symbol_or_none=pc, on=False)");
			conn.execute("util.dbg.client.stepi()");
			conn.execute("util.dbg.client.wait_until_stopped()");
			conn.execute("util.dbg.client.stepi()");
			assertEquals(false, tb.objValue(brk, lastSnap(conn), "Enabled"));
		}
	}

	@Test
	public void testOnBreakpointDeleted() throws Exception {
		try (PythonAndTrace conn = startAndSyncPython(NOTEPAD)) {
			txPut(conn, "breakpoints");
			assertEquals(0,
				tb.objValues(lastSnap(conn), "Sessions[].Processes[].Debug.Software Breakpoints[]").size());

			conn.execute("pc = util.get_pc()");
			conn.execute("util.dbg.client.set_breakpoint(address_or_symbol=pc)");
			conn.execute("util.dbg.client.stepi()");  // no real event for bpt changes

			TraceObject brk = waitForPass(() -> {
				List<Object> brks =
					tb.objValues(lastSnap(conn), "Sessions[].Processes[].Debug.Software Breakpoints[]");
				assertEquals(1, brks.size());
				return (TraceObject) brks.get(0);
			});

			conn.execute("util.dbg.client.clear_breakpoint(address_name_symbol_or_none=pc)");
			conn.execute("util.dbg.client.stepi()");

			waitForPass(() -> assertEquals(0,
				tb.objValues(lastSnap(conn), "Sessions[].Processes[].Debug.Software Breakpoints[]").size()));
		}
	}

	private void start(PythonAndConnection conn, String obj) {
		conn.execute("from ghidraxdbg.commands import *");
		if (obj != null)
			conn.execute("ghidra_trace_create('" + obj + "', wait=True)");
		else
			conn.execute("ghidra_trace_create()");
		conn.execute("ghidra_trace_sync_enable()");
	}

	private void txPut(PythonAndTrace conn, String obj) {
		conn.execute("ghidra_trace_txstart('Tx" + obj + "')");
		conn.execute("ghidra_trace_put_" + obj + "()");
		conn.execute("ghidra_trace_txcommit()");
	}

	private void clearBreakpoints(PythonAndConnection conn) {
		conn.execute("util.dbg.client.clear_breakpoint(None)");
		conn.execute("util.dbg.client.clear_hardware_breakpoint(None)");
		conn.execute("util.dbg.client.clear_memory_breakpoint(None)");	
	}
}
