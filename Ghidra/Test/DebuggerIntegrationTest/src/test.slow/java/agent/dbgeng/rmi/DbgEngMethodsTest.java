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

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.greaterThan;
import static org.junit.Assert.*;

import java.util.*;

import org.junit.Test;

import generic.Unique;
import ghidra.app.plugin.core.debug.utils.ManagedDomainObject;
import ghidra.dbg.testutil.DummyProc;
import ghidra.dbg.util.PathPattern;
import ghidra.dbg.util.PathPredicates;
import ghidra.debug.api.tracermi.RemoteMethod;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.RegisterValue;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectValue;

public class DbgEngMethodsTest extends AbstractDbgEngTraceRmiTest {

	@Test
	public void testEvaluate() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			RemoteMethod evaluate = conn.getMethod("evaluate");
			assertEquals("11",
				evaluate.invoke(Map.of("expr", "3+4*2")));
		}
	}

	@Test
	public void testExecuteCapture() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			RemoteMethod execute = conn.getMethod("execute");
			assertEquals(false, execute.parameters().get("to_string").getDefaultValue());
			assertEquals("11\n",
				execute.invoke(Map.of("cmd", "print(3+4*2)", "to_string", true)));
		}
	}

	@Test
	public void testExecute() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, "notepad.exe");
			conn.execute("ghidra_trace_kill()");
		}
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
			// Just confirm it's present
		}
	}

	@Test
	public void testRefreshAvailable() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, null);
			txCreate(conn, "Available");

			RemoteMethod refreshAvailable = conn.getMethod("refresh_available");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/noname")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				TraceObject available = Objects.requireNonNull(tb.objAny("Available"));

				refreshAvailable.invoke(Map.of("node", available));

				// Would be nice to control / validate the specifics
				List<TraceObject> list = tb.trace.getObjectManager()
						.getValuePaths(Lifespan.at(0), PathPredicates.parse("Available[]"))
						.map(p -> p.getDestination(null))
						.toList();
				assertThat(list.size(), greaterThan(2));
			}
		}
	}

	@Test
	public void testRefreshBreakpoints() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, "notepad.exe");
			txPut(conn, "processes");

			RemoteMethod refreshBreakpoints = conn.getMethod("refresh_breakpoints");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				conn.execute("pc = util.get_pc()");
				conn.execute("util.dbg.bp(expr=pc)");
				conn.execute("util.dbg.ba(expr=pc+4)");
				txPut(conn, "breakpoints");
				TraceObject breakpoints =
					Objects.requireNonNull(tb.objAny("Processes[].Breakpoints"));
				refreshBreakpoints.invoke(Map.of("node", breakpoints));

				List<TraceObjectValue> procBreakLocVals = tb.trace.getObjectManager()
						.getValuePaths(Lifespan.at(0),
							PathPredicates.parse("Processes[].Breakpoints[]"))
						.map(p -> p.getLastEntry())
						.sorted(Comparator.comparing(TraceObjectValue::getEntryKey))
						.toList();
				assertEquals(2, procBreakLocVals.size());
				AddressRange rangeMain =
					procBreakLocVals.get(0).getChild().getValue(0, "_range").castValue();
				Address main = rangeMain.getMinAddress();

				assertBreakLoc(procBreakLocVals.get(0), "[0]", main, 1,
					Set.of(TraceBreakpointKind.SW_EXECUTE),
					"ntdll!LdrInit");
				assertBreakLoc(procBreakLocVals.get(1), "[1]", main.add(4), 1,
					Set.of(TraceBreakpointKind.HW_EXECUTE),
					"ntdll!LdrInit");
			}
		}
	}

	@Test
	public void testRefreshBreakpoints2() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, "notepad.exe");
			txPut(conn, "all");

			RemoteMethod refreshProcWatchpoints = conn.getMethod("refresh_breakpoints");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				conn.execute("pc = util.get_pc()");
				conn.execute("util.dbg.ba(expr=pc, access=DbgEng.DEBUG_BREAK_EXECUTE)");
				conn.execute("util.dbg.ba(expr=pc+4, access=DbgEng.DEBUG_BREAK_READ)");
				conn.execute("util.dbg.ba(expr=pc+8, access=DbgEng.DEBUG_BREAK_WRITE)");
				TraceObject locations =
					Objects.requireNonNull(tb.objAny("Processes[].Breakpoints"));
				refreshProcWatchpoints.invoke(Map.of("node", locations));

				List<TraceObjectValue> procBreakVals = tb.trace.getObjectManager()
						.getValuePaths(Lifespan.at(0),
							PathPredicates.parse("Processes[].Breakpoints[]"))
						.map(p -> p.getLastEntry())
						.sorted(Comparator.comparing(TraceObjectValue::getEntryKey))
						.toList();
				assertEquals(3, procBreakVals.size());
				AddressRange rangeMain0 =
					procBreakVals.get(0).getChild().getValue(0, "_range").castValue();
				Address main0 = rangeMain0.getMinAddress();
				AddressRange rangeMain1 =
					procBreakVals.get(1).getChild().getValue(0, "_range").castValue();
				Address main1 = rangeMain1.getMinAddress();
				AddressRange rangeMain2 =
					procBreakVals.get(2).getChild().getValue(0, "_range").castValue();
				Address main2 = rangeMain2.getMinAddress();

				assertWatchLoc(procBreakVals.get(0), "[0]", main0, (int) rangeMain0.getLength(),
					Set.of(TraceBreakpointKind.HW_EXECUTE),
					"main");
				assertWatchLoc(procBreakVals.get(1), "[1]", main1, (int) rangeMain1.getLength(),
					Set.of(TraceBreakpointKind.WRITE),
					"main+4");
				assertWatchLoc(procBreakVals.get(2), "[2]", main2, (int) rangeMain1.getLength(),
					Set.of(TraceBreakpointKind.READ),
					"main+8");
			}
		}
	}

	@Test
	public void testRefreshProcesses() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, null);
			txCreate(conn, "Processes");
			txCreate(conn, "Processes[1]");

			RemoteMethod refreshProcesses = conn.getMethod("refresh_processes");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/noname")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				TraceObject processes = Objects.requireNonNull(tb.objAny("Processes"));

				refreshProcesses.invoke(Map.of("node", processes));

				// Would be nice to control / validate the specifics
				List<TraceObject> list = tb.trace.getObjectManager()
						.getValuePaths(Lifespan.at(0), PathPredicates.parse("Processes[]"))
						.map(p -> p.getDestination(null))
						.toList();
				assertEquals(1, list.size());
			}
		}
	}

	@Test
	public void testRefreshEnvironment() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			String path = "Processes[].Environment";
			start(conn, "notepad.exe");
			txPut(conn, "all");

			RemoteMethod refreshEnvironment = conn.getMethod("refresh_environment");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				TraceObject env = Objects.requireNonNull(tb.objAny(path));

				refreshEnvironment.invoke(Map.of("node", env));

				// Assumes pydbg on Windows amd64
				assertEquals("pydbg", env.getValue(0, "_debugger").getValue());
				assertEquals("x86_64", env.getValue(0, "_arch").getValue());
				assertEquals("windows", env.getValue(0, "_os").getValue());
				assertEquals("little", env.getValue(0, "_endian").getValue());
			}
		}
	}

	@Test
	public void testRefreshThreads() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			String path = "Processes[].Threads";
			start(conn, "notepad.exe");
			txCreate(conn, path);

			RemoteMethod refreshThreads = conn.getMethod("refresh_threads");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				TraceObject threads = Objects.requireNonNull(tb.objAny(path));

				refreshThreads.invoke(Map.of("node", threads));

				// Would be nice to control / validate the specifics
				int listSize = tb.trace.getThreadManager().getAllThreads().size();
				assertEquals(4, listSize);
			}
		}
	}

	@Test
	public void testRefreshStack() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			String path = "Processes[].Threads[].Stack";
			start(conn, "notepad.exe");
			txPut(conn, "processes");

			RemoteMethod refreshStack = conn.getMethod("refresh_stack");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				txPut(conn, "frames");
				TraceObject stack = Objects.requireNonNull(tb.objAny(path));
				refreshStack.invoke(Map.of("node", stack));

				// Would be nice to control / validate the specifics
				List<TraceObject> list = tb.trace.getObjectManager()
						.getValuePaths(Lifespan.at(0),
							PathPredicates.parse("Processes[].Threads[].Stack[]"))
						.map(p -> p.getDestination(null))
						.toList();
				assertTrue(list.size() > 1);
			}
		}
	}

	@Test
	public void testRefreshRegisters() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			String path = "Processes[].Threads[].Registers";
			start(conn, "notepad.exe");
			conn.execute("ghidra_trace_txstart('Tx')");
			conn.execute("ghidra_trace_putreg()");
			conn.execute("ghidra_trace_txcommit()");

			RemoteMethod refreshRegisters = conn.getMethod("refresh_registers");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				conn.execute("util.dbg.cmd('r rax=0xdeadbeef')");

				TraceObject registers = Objects.requireNonNull(tb.objAny(path, Lifespan.at(0)));
				refreshRegisters.invoke(Map.of("node", registers));

				long snap = 0;
				AddressSpace t1f0 = tb.trace.getBaseAddressFactory()
						.getAddressSpace(registers.getCanonicalPath().toString());
				TraceMemorySpace regs = tb.trace.getMemoryManager().getMemorySpace(t1f0, false);
				RegisterValue rax = regs.getValue(snap, tb.reg("rax"));
				assertEquals("deadbeef", rax.getUnsignedValue().toString(16));
			}
		}
	}

	@Test
	public void testRefreshMappings() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			String path = "Processes[].Memory";
			start(conn, "notepad.exe");
			txCreate(conn, path);

			RemoteMethod refreshMappings = conn.getMethod("refresh_mappings");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				TraceObject memory = Objects.requireNonNull(tb.objAny(path));

				refreshMappings.invoke(Map.of("node", memory));

				// Would be nice to control / validate the specifics
				Collection<? extends TraceMemoryRegion> all =
					tb.trace.getMemoryManager().getAllRegions();
				assertThat(all.size(), greaterThan(2));
			}
		}
	}

	@Test
	public void testRefreshModules() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			String path = "Processes[].Modules";
			start(conn, "notepad.exe");
			txCreate(conn, path);

			RemoteMethod refreshModules = conn.getMethod("refresh_modules");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				TraceObject modules = Objects.requireNonNull(tb.objAny(path));

				refreshModules.invoke(Map.of("node", modules));

				// Would be nice to control / validate the specifics
				Collection<? extends TraceModule> all = tb.trace.getModuleManager().getAllModules();
				TraceModule modBash =
					Unique.assertOne(all.stream().filter(m -> m.getName().contains("notepad.exe")));
				assertNotEquals(tb.addr(0), Objects.requireNonNull(modBash.getBase()));
			}
		}
	}

	@Test
	public void testActivateThread() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, "notepad.exe");
			txPut(conn, "processes");

			RemoteMethod activateThread = conn.getMethod("activate_thread");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				txPut(conn, "threads");

				PathPattern pattern =
					PathPredicates.parse("Processes[].Threads[]").getSingletonPattern();
				List<TraceObject> list = tb.trace.getObjectManager()
						.getValuePaths(Lifespan.at(0), pattern)
						.map(p -> p.getDestination(null))
						.toList();
				assertEquals(4, list.size());

				for (TraceObject t : list) {
					activateThread.invoke(Map.of("thread", t));
					String out = conn.executeCapture("print(util.dbg.get_thread())").strip();
					List<String> indices = pattern.matchKeys(t.getCanonicalPath().getKeyList());
					assertEquals("%s".formatted(indices.get(1)), out);
				}
			}
		}
	}

	@Test
	public void testRemoveProcess() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, "netstat.exe");
			txPut(conn, "processes");

			RemoteMethod removeProcess = conn.getMethod("remove_process");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/netstat.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				TraceObject proc2 = Objects.requireNonNull(tb.objAny("Processes[]"));
				removeProcess.invoke(Map.of("process", proc2));

				String out = conn.executeCapture("print(list(util.process_list()))");
				assertThat(out, containsString("[]"));
			}
		}
	}

	@Test
	public void testAttachObj() throws Exception {
		try (DummyProc dproc = DummyProc.run("notepad.exe")) {
			try (PythonAndConnection conn = startAndConnectPython()) {
				start(conn, null);
				txPut(conn, "available");

				RemoteMethod attachObj = conn.getMethod("attach_obj");
				try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/noname")) {
					tb = new ToyDBTraceBuilder((Trace) mdo.get());
					TraceObject target =
						Objects.requireNonNull(tb.obj("Available[%d]".formatted(dproc.pid)));
					attachObj.invoke(Map.of("target", target));

					String out = conn.executeCapture("print(list(util.process_list()))");
					assertThat(out, containsString("%d".formatted(dproc.pid)));
				}
			}
		}
	}

	@Test
	public void testAttachPid() throws Exception {
		try (DummyProc dproc = DummyProc.run("notepad.exe")) {
			try (PythonAndConnection conn = startAndConnectPython()) {
				start(conn, null);
				txPut(conn, "available");

				RemoteMethod attachPid = conn.getMethod("attach_pid");
				try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/noname")) {
					tb = new ToyDBTraceBuilder((Trace) mdo.get());
					Objects.requireNonNull(
						tb.objAny("Available[" + dproc.pid + "]", Lifespan.at(0)));
					attachPid.invoke(Map.of("pid", dproc.pid));

					String out = conn.executeCapture("print(list(util.process_list()))");
					assertThat(out, containsString("%d".formatted(dproc.pid)));
				}
			}
		}
	}

	@Test
	public void testDetach() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, "netstat.exe");
			txPut(conn, "processes");

			RemoteMethod detach = conn.getMethod("detach");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/netstat.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				TraceObject proc = Objects.requireNonNull(tb.objAny("Processes[]"));
				detach.invoke(Map.of("process", proc));

				String out = conn.executeCapture("print(list(util.process_list()))");
				assertThat(out, containsString("[]"));
			}
		}
	}

	@Test
	public void testLaunchEntry() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, null);
			txPut(conn, "processes");

			RemoteMethod launch = conn.getMethod("launch_loader");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/noname")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				launch.invoke(Map.ofEntries(
					Map.entry("file", "notepad.exe")));

				String out = conn.executeCapture("print(list(util.process_list()))");
				assertThat(out, containsString("notepad.exe"));
			}
		}
	}

	@Test
	public void testLaunch() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, null);
			txPut(conn, "processes");

			RemoteMethod launch = conn.getMethod("launch");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/noname")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				launch.invoke(Map.ofEntries(
					Map.entry("initial_break", true),
					Map.entry("file", "notepad.exe")));

				txPut(conn, "processes");

				String out = conn.executeCapture("print(list(util.process_list()))");
				assertThat(out, containsString("notepad.exe"));
			}
		}
	}

	@Test
	public void testKill() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, "notepad.exe");
			txPut(conn, "processes");

			RemoteMethod kill = conn.getMethod("kill");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped("Missed initial stop");

				TraceObject proc = Objects.requireNonNull(tb.objAny("Processes[]"));
				kill.invoke(Map.of("process", proc));

				String out = conn.executeCapture("print(list(util.process_list()))");
				assertThat(out, containsString("[]"));
			}
		}
	}

	@Test
	public void testGoInterrupt5() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, "notepad.exe");
			txPut(conn, "processes");

			conn.execute(INSTRUMENT_STATE);

			RemoteMethod go = conn.getMethod("go");
			RemoteMethod interrupt = conn.getMethod("interrupt");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped("Missed initial stop");

				TraceObject proc = Objects.requireNonNull(tb.objAny("Processes[]"));

				for (int i = 0; i < 5; i++) {
					go.invoke(Map.of("process", proc));
					waitRunning("Missed running " + i);

					interrupt.invoke(Map.of("process", proc));
					waitStopped("Missed stopped " + i);
				}
			}
			// The waits are the assertions
		}
	}

	@Test
	public void testStepInto() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, "notepad.exe");
			txPut(conn, "processes");

			RemoteMethod stepInto = conn.getMethod("step_into");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped("Missed initial stop");
				txPut(conn, "threads");

				TraceObject thread = Objects.requireNonNull(tb.objAny("Processes[].Threads[]"));

				while (!getInst(conn).contains("call")) {
					stepInto.invoke(Map.of("thread", thread));
				}

				String disCall = getInst(conn);
				// lab0:
				//    -> addr0
				// 
				// lab1:
				//    addr1
				String[] split = disCall.split("\\s+");  // get target
				long pcCallee = Long.decode(split[split.length - 1]);

				stepInto.invoke(Map.of("thread", thread));
				long pc = getAddressAtOffset(conn, 0);
				assertEquals(pcCallee, pc);
			}
		}
	}

	@Test
	public void testStepOver() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, "notepad.exe");
			txPut(conn, "processes");

			RemoteMethod stepOver = conn.getMethod("step_over");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped("Missed initial stop");
				txPut(conn, "threads");

				TraceObject thread = Objects.requireNonNull(tb.objAny("Processes[].Threads[]"));

				while (!getInst(conn).contains("call")) {
					stepOver.invoke(Map.of("thread", thread));
				}

				String disCall = getInst(conn);
				String[] split = disCall.split("\\s+");  // get target
				long pcCallee = Long.decode(split[split.length - 1]);

				stepOver.invoke(Map.of("thread", thread));
				long pc = getAddressAtOffset(conn, 0);
				assertNotEquals(pcCallee, pc);
			}
		}
	}

	@Test
	public void testStepTo() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, "notepad.exe");

			RemoteMethod stepInto = conn.getMethod("step_into");
			RemoteMethod stepTo = conn.getMethod("step_to");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				txPut(conn, "threads");

				TraceObject thread = Objects.requireNonNull(tb.objAny("Processes[].Threads[]"));
				while (!getInst(conn).contains("call")) {
					stepInto.invoke(Map.of("thread", thread));
				}
				stepInto.invoke(Map.of("thread", thread));

				int sz = Integer.parseInt(getInstSizeAtOffset(conn, 0));
				for (int i = 0; i < 4; i++) {
					sz += Integer.parseInt(getInstSizeAtOffset(conn, sz));
				}

				long pcNext = getAddressAtOffset(conn, sz);
				stepTo.invoke(Map.of("thread", thread, "address", tb.addr(pcNext), "max", 10));

				long pc = getAddressAtOffset(conn, 0);
				assertEquals(pcNext, pc);
			}
		}
	}

	@Test
	public void testStepOut() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, "notepad.exe");
			txPut(conn, "processes");

			RemoteMethod stepInto = conn.getMethod("step_into");
			RemoteMethod stepOut = conn.getMethod("step_out");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped("Missed initial stop");
				txPut(conn, "threads");

				TraceObject thread = Objects.requireNonNull(tb.objAny("Processes[].Threads[]"));

				while (!getInst(conn).contains("call")) {
					stepInto.invoke(Map.of("thread", thread));
				}

				int sz = Integer.parseInt(getInstSizeAtOffset(conn, 0));
				long pcNext = getAddressAtOffset(conn, sz);

				stepInto.invoke(Map.of("thread", thread));
				stepOut.invoke(Map.of("thread", thread));
				long pc = getAddressAtOffset(conn, 0);
				assertEquals(pcNext, pc);
			}
		}
	}

	@Test
	public void testBreakAddress() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, "notepad.exe");
			txPut(conn, "processes");

			RemoteMethod breakAddress = conn.getMethod("break_address");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				TraceObject proc = Objects.requireNonNull(tb.objAny("Processes[]"));

				long address = getAddressAtOffset(conn, 0);
				breakAddress.invoke(Map.of("process", proc, "address", tb.addr(address)));

				String out = conn.executeCapture("print(list(util.get_breakpoints()))");
				assertThat(out, containsString(Long.toHexString(address)));
			}
		}
	}

	@Test
	public void testBreakExpression() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, "notepad.exe");
			txPut(conn, "processes");

			RemoteMethod breakExpression = conn.getMethod("break_expression");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped("Missed initial stop");

				breakExpression.invoke(Map.of("expression", "entry"));

				String out = conn.executeCapture("print(list(util.get_breakpoints()))");
				assertThat(out, containsString("entry"));
			}
		}
	}

	@Test
	public void testBreakHardwareAddress() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, "notepad.exe");
			txPut(conn, "processes");

			RemoteMethod breakAddress = conn.getMethod("break_hw_address");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				TraceObject proc = Objects.requireNonNull(tb.objAny("Processes[]"));

				long address = getAddressAtOffset(conn, 0);
				breakAddress.invoke(Map.of("process", proc, "address", tb.addr(address)));

				String out = conn.executeCapture("print(list(util.get_breakpoints()))");
				assertThat(out, containsString(Long.toHexString(address)));
			}
		}
	}

	@Test
	public void testBreakHardwareExpression() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, "notepad.exe");
			txPut(conn, "processes");

			RemoteMethod breakExpression = conn.getMethod("break_hw_expression");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped("Missed initial stop");

				breakExpression.invoke(Map.of("expression", "entry"));

				String out = conn.executeCapture("print(list(util.get_breakpoints()))");
				assertThat(out, containsString("entry"));
			}
		}
	}

	@Test
	public void testBreakReadRange() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, "notepad.exe");
			txPut(conn, "processes");

			RemoteMethod breakRange = conn.getMethod("break_read_range");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped("Missed initial stop");

				TraceObject proc = Objects.requireNonNull(tb.objAny("Processes[]"));
				long address = getAddressAtOffset(conn, 0);
				AddressRange range = tb.range(address, address + 3); // length 4
				breakRange.invoke(Map.of("process", proc, "range", range));

				String out = conn.executeCapture("print(list(util.get_breakpoints()))");
				assertThat(out, containsString("%x".formatted(address)));
				assertThat(out, containsString("sz=4"));
				assertThat(out, containsString("type=r"));
			}
		}
	}

	@Test
	public void testBreakReadExpression() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, "notepad.exe");
			txPut(conn, "processes");

			RemoteMethod breakExpression = conn.getMethod("break_read_expression");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				breakExpression.invoke(Map.of("expression", "ntdll!LdrInitShimEngineDynamic"));
				long address = getAddressAtOffset(conn, 0);

				String out = conn.executeCapture("print(list(util.get_breakpoints()))");
				assertThat(out, containsString(Long.toHexString(address >> 24)));
				assertThat(out, containsString("sz=1"));
				assertThat(out, containsString("type=r"));
			}
		}
	}

	@Test
	public void testBreakWriteRange() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, "notepad.exe");
			txPut(conn, "processes");

			RemoteMethod breakRange = conn.getMethod("break_write_range");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped("Missed initial stop");

				TraceObject proc = Objects.requireNonNull(tb.objAny("Processes[]"));
				long address = getAddressAtOffset(conn, 0);
				AddressRange range = tb.range(address, address + 3); // length 4
				breakRange.invoke(Map.of("process", proc, "range", range));

				String out = conn.executeCapture("print(list(util.get_breakpoints()))");
				assertThat(out, containsString("%x".formatted(address)));
				assertThat(out, containsString("sz=4"));
				assertThat(out, containsString("type=w"));
			}
		}
	}

	@Test
	public void testBreakWriteExpression() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, "notepad.exe");
			txPut(conn, "processes");

			RemoteMethod breakExpression = conn.getMethod("break_write_expression");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				breakExpression.invoke(Map.of("expression", "ntdll!LdrInitShimEngineDynamic"));
				long address = getAddressAtOffset(conn, 0);

				String out = conn.executeCapture("print(list(util.get_breakpoints()))");
				assertThat(out, containsString(Long.toHexString(address >> 24)));
				assertThat(out, containsString("sz=1"));
				assertThat(out, containsString("type=w"));
			}
		}
	}

	@Test
	public void testBreakAccessRange() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, "notepad.exe");
			txPut(conn, "processes");

			RemoteMethod breakRange = conn.getMethod("break_access_range");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped("Missed initial stop");

				TraceObject proc = Objects.requireNonNull(tb.objAny("Processes[]"));
				long address = getAddressAtOffset(conn, 0);
				AddressRange range = tb.range(address, address + 3); // length 4
				breakRange.invoke(Map.of("process", proc, "range", range));

				String out = conn.executeCapture("print(list(util.get_breakpoints()))");
				assertThat(out, containsString("%x".formatted(address)));
				assertThat(out, containsString("sz=4"));
				assertThat(out, containsString("type=rw"));
			}
		}
	}

	@Test
	public void testBreakAccessExpression() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, "notepad.exe");
			txPut(conn, "processes");

			RemoteMethod breakExpression = conn.getMethod("break_access_expression");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				breakExpression.invoke(Map.of("expression", "ntdll!LdrInitShimEngineDynamic"));
				long address = getAddressAtOffset(conn, 0);

				String out = conn.executeCapture("print(list(util.get_breakpoints()))");
				assertThat(out, containsString(Long.toHexString(address >> 24)));
				assertThat(out, containsString("sz=1"));
				assertThat(out, containsString("type=rw"));
			}
		}
	}

	@Test
	public void testToggleBreakpoint() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, "notepad.exe");
			txPut(conn, "processes");

			RemoteMethod breakAddress = conn.getMethod("break_address");
			RemoteMethod toggleBreakpoint = conn.getMethod("toggle_breakpoint");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				long address = getAddressAtOffset(conn, 0);
				TraceObject proc = Objects.requireNonNull(tb.objAny("Processes[]"));
				breakAddress.invoke(Map.of("process", proc, "address", tb.addr(address)));

				txPut(conn, "breakpoints");
				TraceObject bpt = Objects.requireNonNull(tb.objAny("Processes[].Breakpoints[]"));

				toggleBreakpoint.invoke(Map.of("breakpoint", bpt, "enabled", false));

				String out = conn.executeCapture("print(list(util.get_breakpoints()))");
				assertThat(out, containsString("disabled"));
			}
		}
	}

	@Test
	public void testDeleteBreakpoint() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, "notepad.exe");
			txPut(conn, "processes");

			RemoteMethod breakAddress = conn.getMethod("break_address");
			RemoteMethod deleteBreakpoint = conn.getMethod("delete_breakpoint");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				long address = getAddressAtOffset(conn, 0);
				TraceObject proc = Objects.requireNonNull(tb.objAny("Processes[]"));
				breakAddress.invoke(Map.of("process", proc, "address", tb.addr(address)));

				txPut(conn, "breakpoints");
				TraceObject bpt = Objects.requireNonNull(tb.objAny("Processes[].Breakpoints[]"));

				deleteBreakpoint.invoke(Map.of("breakpoint", bpt));

				String out = conn.executeCapture("print(list(util.get_breakpoints()))");
				assertThat(out, containsString("[]"));
			}
		}
	}

	private void start(PythonAndConnection conn, String obj) {
		conn.execute("from ghidradbg.commands import *");
		if (obj != null)
			conn.execute("ghidra_trace_create('" + obj + "')");
		else
			conn.execute("ghidra_trace_create()");
	}

	private void txPut(PythonAndConnection conn, String obj) {
		conn.execute("ghidra_trace_txstart('Tx')");
		conn.execute("ghidra_trace_put_" + obj + "()");
		conn.execute("ghidra_trace_txcommit()");
	}

	private void txCreate(PythonAndConnection conn, String path) {
		conn.execute("ghidra_trace_txstart('Fake')");
		conn.execute("ghidra_trace_create_obj('%s')".formatted(path));
		conn.execute("ghidra_trace_txcommit()");
	}

	private String getInst(PythonAndConnection conn) {
		return getInstAtOffset(conn, 0);
	}

	private String getInstAtOffset(PythonAndConnection conn, int offset) {
		String inst = "print(util.get_inst(util.get_pc()+" + offset + "))";
		String ret = conn.executeCapture(inst).strip();
		return ret.substring(1, ret.length() - 1);    // remove <>
	}

	private String getInstSizeAtOffset(PythonAndConnection conn, int offset) {
		String instSize = "print(util.get_inst_sz(util.get_pc()+" + offset + "))";
		return conn.executeCapture(instSize).strip();
	}

	private long getAddressAtOffset(PythonAndConnection conn, int offset) {
		String inst = "print(util.get_inst(util.get_pc()+" + offset + "))";
		String ret = conn.executeCapture(inst).strip();
		String[] split = ret.split("\\s+");  // get target
		return Long.decode(split[1]);
	}

}
