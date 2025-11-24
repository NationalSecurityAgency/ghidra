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

import db.Transaction;
import generic.Unique;
import ghidra.app.plugin.core.debug.utils.ManagedDomainObject;
import ghidra.debug.api.tracermi.RemoteMethod;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.RegisterValue;
import ghidra.pty.testutil.DummyProc;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObject.ConflictResolution;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.trace.model.target.path.*;

public class X64dbgMethodsTest extends AbstractX64dbgTraceRmiTest {

	@Test
	public void testEvaluate() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, null);

			RemoteMethod evaluate = conn.getMethod("evaluate");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/x64dbg/noname")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				assertEquals("11",
					evaluate.invoke(Map.ofEntries(
						Map.entry("session", tb.obj("Sessions[0]")),
						Map.entry("expr", "3+4*2"))));
			}
		}
	}

	@Test
	public void testExecuteCapture() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			conn.execute("from ghidraxdbg.commands import *");
			RemoteMethod execute = conn.getMethod("execute");
			assertEquals(false, execute.parameters().get("to_string").getDefaultValue());
			assertEquals("11\n",
				execute.invoke(Map.of("cmd", "print(3+4*2)", "to_string", true)));
			conn.execute("util.terminate_session()");
		}
	}

	@Test
	public void testExecute() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, NOTEPAD);
			conn.execute("ghidra_trace_kill()");
			conn.execute("util.terminate_session()");
		}
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/x64dbg/notepad.exe")) {
			// Just confirm it's present
		}
	}

	@Test
	public void testRefreshAvailable() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, null);
			// Fake its creation, so it's empty before the refresh
			txCreate(conn, "Sessions[0].Available");

			RemoteMethod refreshAvailable = conn.getMethod("refresh_available");
			conn.execute("util.terminate_session()");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/x64dbg/noname")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				TraceObject available = Objects.requireNonNull(tb.objAny0("Sessions[].Available"));

				refreshAvailable.invoke(Map.of("node", available));

				// Would be nice to control / validate the specifics
				List<TraceObject> list = tb.trace.getObjectManager()
						.getValuePaths(Lifespan.at(0), PathFilter.parse("Sessions[].Available[]"))
						.map(p -> p.getDestination(null))
						.toList();
				assertThat(list.size(), greaterThan(2));
			}
		}
	}

	@Test
	public void testRefreshBreakpoints() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, NOTEPAD);
			txPut(conn, "processes");

			RemoteMethod refreshBreakpoints = conn.getMethod("refresh_breakpoints");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/x64dbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				conn.execute("pc = util.get_pc()");
				clearBreakpoints(conn);
				
				conn.execute("util.dbg.client.set_breakpoint(address_or_symbol=pc)");
				conn.execute("util.dbg.client.set_hardware_breakpoint(address_or_symbol=pc+4, bp_type=HardwareBreakpointType.x)");
				txPut(conn, "breakpoints");
				TraceObject breakpoints =
					Objects.requireNonNull(tb.objAny0("Sessions[].Processes[].Debug.Software Breakpoints"));
				refreshBreakpoints.invoke(Map.of("node", breakpoints));

				clearBreakpoints(conn);
				conn.execute("util.terminate_session()");

				List<TraceObjectValue> procSBreakLocVals = tb.trace.getObjectManager()
						.getValuePaths(Lifespan.at(0),
							PathFilter.parse("Sessions[].Processes[].Debug.Software Breakpoints[]"))
						.map(p -> p.getLastEntry())
						.sorted(Comparator.comparing(TraceObjectValue::getEntryKey))
						.toList();
				List<TraceObjectValue> procHBreakLocVals = tb.trace.getObjectManager()
						.getValuePaths(Lifespan.at(0),
							PathFilter.parse("Sessions[].Processes[].Debug.Hardware Breakpoints[]"))
						.map(p -> p.getLastEntry())
						.sorted(Comparator.comparing(TraceObjectValue::getEntryKey))
						.toList();
				assertEquals(1, procSBreakLocVals.size());
				assertEquals(1, procHBreakLocVals.size());
				AddressRange rangeMain =
					procSBreakLocVals.get(0).getChild().getValue(1, "_range").castValue();
				Address main = rangeMain.getMinAddress();

				assertBreakLoc(procSBreakLocVals.get(0), main, 1, "1");
				assertBreakLoc(procHBreakLocVals.get(0), main.add(4), 1, "2");
			}
		}
	}

	@Test
	public void testRefreshBreakpoints2() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, NOTEPAD);
			txPut(conn, "all");

			RemoteMethod refreshProcWatchpoints = conn.getMethod("refresh_breakpoints");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/x64dbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				conn.execute("pc = util.get_pc()");
				clearBreakpoints(conn);
				
				conn.execute("util.dbg.client.set_hardware_breakpoint(address_or_symbol=pc, bp_type=HardwareBreakpointType.x)");
				conn.execute("util.dbg.client.set_hardware_breakpoint(address_or_symbol=pc+4, bp_type=HardwareBreakpointType.r)");
				conn.execute("util.dbg.client.set_hardware_breakpoint(address_or_symbol=pc+8, bp_type=HardwareBreakpointType.w)");
				TraceObject locations =
					Objects.requireNonNull(tb.objAny0("Sessions[].Processes[].Debug.Hardware Breakpoints"));
				refreshProcWatchpoints.invoke(Map.of("node", locations));

				clearBreakpoints(conn);
				conn.execute("util.terminate_session()");

				List<TraceObjectValue> procBreakVals = tb.trace.getObjectManager()
						.getValuePaths(Lifespan.at(0),
							PathFilter.parse("Sessions[].Processes[].Debug.Hardware Breakpoints[]"))
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

				assertWatchLoc(procBreakVals.get(0), main0, (int) rangeMain0.getLength(), "2");
				assertWatchLoc(procBreakVals.get(1), main1, (int) rangeMain1.getLength(), "0");
				assertWatchLoc(procBreakVals.get(2), main2, (int) rangeMain1.getLength(), "1");
			}
		}
	}

	@Test
	public void testRefreshProcesses() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, NOTEPAD);
			txCreate(conn, "Sessions[0].Processes");

			RemoteMethod refreshProcesses = conn.getMethod("refresh_processes");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/x64dbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				TraceObject processes = Objects.requireNonNull(tb.objAny0("Sessions[].Processes"));

				refreshProcesses.invoke(Map.of("node", processes));
				conn.execute("util.terminate_session()");

				// Would be nice to control / validate the specifics
				List<TraceObject> list = tb.trace.getObjectManager()
						.getValuePaths(Lifespan.at(0), PathFilter.parse("Sessions[].Processes[]"))
						.map(p -> p.getDestination(null))
						.toList();
				assertEquals(1, list.size());
			}
		}
	}

	@Test
	public void testRefreshEnvironment() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, NOTEPAD);
			txPut(conn, "all");

			RemoteMethod refreshEnvironment = conn.getMethod("refresh_environment");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/x64dbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				TraceObject env =
					Objects.requireNonNull(tb.objAny0("Sessions[].Processes[].Environment"));

				refreshEnvironment.invoke(Map.of("node", env));
				conn.execute("util.terminate_session()");

				// Assumes x64dbg on Windows amd64
				assertEquals("x64dbg", env.getValue(0, "_debugger").getValue());
				assertEquals("x86_64", env.getValue(0, "_arch").getValue());
				assertEquals("windows", env.getValue(0, "_os").getValue());
				assertEquals("little", env.getValue(0, "_endian").getValue());
			}
		}
	}

	@Test
	public void testRefreshThreads() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, NOTEPAD);
			txPut(conn, "processes");

			RemoteMethod refreshThreads = conn.getMethod("refresh_threads");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/x64dbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				TraceObject proc = tb.objAny0("Sessions[].Processes[]");
				TraceObject threads = fakeEmpty(proc, "Threads");
				refreshThreads.invoke(Map.of("node", threads));
				conn.execute("util.terminate_session()");

				// Would be nice to control / validate the specifics
				int listSize = tb.trace.getThreadManager().getAllThreads().size();
				assertEquals(4, listSize);
			}
		}
	}

	@Test
	public void testRefreshRegisters() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			String path = "Sessions[].Processes[].Threads[].Registers";
			start(conn, NOTEPAD);
			conn.execute("ghidra_trace_txstart('Tx')");
			conn.execute("ghidra_trace_putreg()");
			conn.execute("ghidra_trace_txcommit()");

			RemoteMethod refreshRegisters = conn.getMethod("refresh_registers");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/x64dbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				conn.execute("util.dbg.cmd('rax=0xdeadbeef')");

				TraceObject registers = Objects.requireNonNull(tb.objAny(path, Lifespan.at(0)));
				refreshRegisters.invoke(Map.of("node", registers));
				conn.execute("util.terminate_session()");

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
			start(conn, NOTEPAD);
			txPut(conn, "processes");

			RemoteMethod refreshMappings = conn.getMethod("refresh_mappings");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/x64dbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				TraceObject proc = tb.objAny0("Sessions[].Processes[]");
				TraceObject memory = fakeEmpty(proc, "Memory");
				refreshMappings.invoke(Map.of("node", memory));
				conn.execute("util.terminate_session()");

				// Would be nice to control / validate the specifics
				Collection<? extends TraceMemoryRegion> all =
					tb.trace.getMemoryManager().getAllRegions();
				assertThat(all.size(), greaterThan(2));
			}
		}
	}

	protected TraceObject fakeEmpty(TraceObject parent, String ext) {
		KeyPath path = parent.getCanonicalPath().extend(KeyPath.parse(ext));
		Trace trace = parent.getTrace();
		try (Transaction tx = trace.openTransaction("Fake %s".formatted(path))) {
			TraceObject obj = trace.getObjectManager().createObject(path);
			obj.insert(parent.getLife().bound(), ConflictResolution.DENY);
			return obj;
		}
	}

	@Test
	public void testRefreshModules() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, NOTEPAD);
			txPut(conn, "processes");

			RemoteMethod refreshModules = conn.getMethod("refresh_modules");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/x64dbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				TraceObject proc = tb.objAny0("Sessions[].Processes[]");
				TraceObject modules = fakeEmpty(proc, "Modules");
				refreshModules.invoke(Map.of("node", modules));
				conn.execute("util.terminate_session()");

				// Would be nice to control / validate the specifics
				Collection<? extends TraceModule> all = tb.trace.getModuleManager().getAllModules();
				TraceModule modBash = Unique.assertOne(
					all.stream().filter(m -> m.getName(SNAP).contains("notepad.exe")));
				assertNotEquals(tb.addr(0), Objects.requireNonNull(modBash.getBase(SNAP)));
			}
		}
	}

	@Test
	public void testActivateThread() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, NOTEPAD);
			txPut(conn, "processes");

			RemoteMethod activateThread = conn.getMethod("activate_thread");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/x64dbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				txPut(conn, "threads");

				PathPattern pattern =
					PathFilter.parse("Sessions[].Processes[].Threads[]").getSingletonPattern();
				List<TraceObject> list = tb.trace.getObjectManager()
						.getValuePaths(Lifespan.at(0), pattern)
						.map(p -> p.getDestination(null))
						.toList();
				assertEquals(4, list.size());

				for (TraceObject t : list) {
					activateThread.invoke(Map.of("thread", t));
					String out = conn.executeCapture("print(util.selected_thread())").strip();
					List<String> indices = pattern.matchKeys(t.getCanonicalPath(), true);
					assertEquals("%s".formatted(indices.get(2)), out);
				}
			}
			conn.execute("util.terminate_session()");
		}
	}

	@Test
	public void testRemoveProcess() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, NETSTAT);
			txPut(conn, "processes");

			RemoteMethod removeProcess = conn.getMethod("remove_process");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/x64dbg/netstat.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				TraceObject proc2 = Objects.requireNonNull(tb.objAny0("Sessions[].Processes[]"));
				removeProcess.invoke(Map.of("process", proc2));

				String out = conn.executeCapture("print(list(util.process_list0()))");
				conn.execute("util.terminate_session()");

				assertEquals(out, "[]\n");
			}
		}
	}

	//@Test
	public void testAttachObj() throws Exception {
		try (DummyProc dproc = DummyProc.run(NOTEPAD)) {
			try (PythonAndConnection conn = startAndConnectPython()) {
				start(conn, null);
				txPut(conn, "available");

				RemoteMethod attachObj = conn.getMethod("attach_obj");
				try (ManagedDomainObject mdo = openDomainObject("/New Traces/x64dbg/noname")) {
					tb = new ToyDBTraceBuilder((Trace) mdo.get());
					TraceObject target = Objects.requireNonNull(tb.obj(
						"Sessions[0].Available[%d]".formatted(dproc.pid)));
					attachObj.invoke(Map.ofEntries(
						Map.entry("target", target)));

					String out = conn.executeCapture("print(list(util.process_list0()))");
					conn.execute("util.terminate_session()");

					assertThat(out, containsString("%d".formatted(dproc.pid)));
				}
			}
		}
	}

	@Test
	public void testAttachPid() throws Exception {
		try (DummyProc dproc = DummyProc.run(NOTEPAD)) {
			try (PythonAndConnection conn = startAndConnectPython()) {
				start(conn, null);
				txPut(conn, "available");

				RemoteMethod attachPid = conn.getMethod("attach_pid");
				try (ManagedDomainObject mdo = openDomainObject("/New Traces/x64dbg/noname")) {
					tb = new ToyDBTraceBuilder((Trace) mdo.get());
					Objects.requireNonNull(tb.obj(
						"Sessions[0].Available[%d]".formatted(dproc.pid)));
					try {
						attachPid.invoke(Map.ofEntries(
							Map.entry("session", tb.obj("Sessions[0]")),
							Map.entry("pid", dproc.pid)));
					} catch (Exception e) {
						// IGNORE
					}

					String out = conn.executeCapture("print(list(util.process_list()))");
					conn.execute("util.terminate_session()");

					assertThat(out, containsString("%d".formatted(dproc.pid)));
				}
			}
		}
	}

	@Test
	public void testDetach() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, NETSTAT);
			txPut(conn, "processes");

			RemoteMethod detach = conn.getMethod("detach");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/x64dbg/netstat.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				TraceObject proc = Objects.requireNonNull(tb.objAny0("Sessions[].Processes[]"));
				detach.invoke(Map.of("process", proc));

				String out = conn.executeCapture("print(list(util.process_list0()))");
				conn.execute("util.terminate_session()");

				assertThat(out, containsString("python.exe"));
			}
		}
	}

	@Test
	public void testLaunch() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, null);
			txPut(conn, "processes");

			RemoteMethod launch = conn.getMethod("launch");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/x64dbg/noname")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				launch.invoke(Map.ofEntries(
					Map.entry("Session", tb.obj("Sessions[0]")),
					Map.entry("initial_dir", "."),
					Map.entry("file", NOTEPAD),
					Map.entry("wait", true)));

				txPut(conn, "processes");

				String out = conn.executeCapture("print(list(util.process_list()))");
				conn.execute("util.terminate_session()");

				assertThat(out, containsString("notepad.exe"));
			}
		}
	}

	@Test
	public void testKill() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, NOTEPAD);
			txPut(conn, "processes");

			RemoteMethod kill = conn.getMethod("kill");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/x64dbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				TraceObject proc = Objects.requireNonNull(tb.objAny0("Sessions[].Processes[]"));
				kill.invoke(Map.of("process", proc));

				String out = conn.executeCapture("print(list(util.process_list0()))");
				conn.execute("util.terminate_session()");

				assertEquals(out, "[]\n");
			}
		}
	}

	//@Test - works but has timing issues
	public void testGoInterrupt5() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, NOTEPAD);
			txPut(conn, "processes");

			conn.execute(INSTRUMENT_STATE);

			RemoteMethod go = conn.getMethod("go");
			RemoteMethod interrupt = conn.getMethod("interrupt");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/x64dbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				TraceObject proc = Objects.requireNonNull(tb.objAny0("Sessions[].Processes[]"));

				go.invoke(Map.of("process", proc));
				for (int i = 0; i < 5; i++) {
					go.invoke(Map.of("process", proc));
					waitRunning("Missed running " + i);

					interrupt.invoke(Map.of("process", proc));
					waitStopped("Missed stopped " + i);
				}
				conn.execute("util.terminate_session()");
			}
			// The waits are the assertions
		}
	}

	@Test
	public void testStepInto() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, NOTEPAD);
			txPut(conn, "processes");

			RemoteMethod stepInto = conn.getMethod("step_into");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/x64dbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				txPut(conn, "threads");

				TraceObject thread =
					Objects.requireNonNull(tb.objAny0("Sessions[].Processes[].Threads[]"));

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
				conn.execute("util.terminate_session()");

				assertEquals(pcCallee, pc);
			}
		}
	}

	@Test
	public void testStepOver() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, NOTEPAD);
			txPut(conn, "processes");

			RemoteMethod stepOver = conn.getMethod("step_over");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/x64dbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				txPut(conn, "threads");

				TraceObject thread =
					Objects.requireNonNull(tb.objAny0("Sessions[].Processes[].Threads[]"));

				while (!getInst(conn).contains("call")) {
					stepOver.invoke(Map.of("thread", thread));
				}

				String disCall = getInst(conn);
				String[] split = disCall.split("\\s+");  // get target
				long pcCallee = Long.decode(split[split.length - 1]);

				stepOver.invoke(Map.of("thread", thread));
				long pc = getAddressAtOffset(conn, 0);
				conn.execute("util.terminate_session()");

				assertNotEquals(pcCallee, pc);
			}
		}
	}

	// @Test - this has some consistency issues
	public void testStepOut() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, NOTEPAD);
			txPut(conn, "processes");

			RemoteMethod stepInto = conn.getMethod("step_into");
			RemoteMethod stepOut = conn.getMethod("step_out");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/x64dbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				txPut(conn, "threads");

				TraceObject thread =
					Objects.requireNonNull(tb.objAny0("Sessions[].Processes[].Threads[]"));

				while (!getInst(conn).contains("call")) {
					stepInto.invoke(Map.of("thread", thread));
				}

				int sz = Integer.parseInt(getInstSizeAtOffset(conn, 0));
				long pcNext = getAddressAtOffset(conn, sz);

				stepInto.invoke(Map.of("thread", thread));
				stepOut.invoke(Map.of("thread", thread));  // step to ret
				stepInto.invoke(Map.of("thread", thread));
				long pc = getAddressAtOffset(conn, 0);
				conn.execute("util.terminate_session()");
				
				assertEquals(pcNext, pc);
			}
		}
	}

	@Test
	public void testBreakAddress() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, NOTEPAD);
			txPut(conn, "processes");

			RemoteMethod breakAddress = conn.getMethod("break_address");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/x64dbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				clearBreakpoints(conn);
				TraceObject proc = Objects.requireNonNull(tb.objAny0("Sessions[].Processes[]"));
				long address = getAddressAtOffset(conn, 0);
				breakAddress.invoke(Map.of("process", proc, "address", tb.addr(address)));

				String out = conn.executeCapture("print(list(util.dbg.client.get_breakpoints(BreakpointType.BpNormal)))");

				clearBreakpoints(conn);
				conn.execute("util.terminate_session()");
				
				assertThat(out, containsString(Long.toHexString(address)));
			}
		}
	}

	@Test
	public void testBreakExpression() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, NOTEPAD);
			txPut(conn, "processes");

			RemoteMethod breakExpression = conn.getMethod("break_expression");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/x64dbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				clearBreakpoints(conn);
				breakExpression.invoke(Map.of("expression", "CreateFileW"));

				String out = conn.executeCapture("print(list(util.dbg.client.get_breakpoints(BreakpointType.BpNormal)))");

				clearBreakpoints(conn);
				conn.execute("util.terminate_session()");

				assertThat(out, containsString("CreateFileW"));
			}
		}
	}

	@Test
	public void testBreakHardwareAddress() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, NOTEPAD);
			txPut(conn, "processes");

			RemoteMethod breakAddress = conn.getMethod("break_hw_address");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/x64dbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				TraceObject proc = Objects.requireNonNull(tb.objAny0("Sessions[].Processes[]"));

				clearBreakpoints(conn);
				long address = getAddressAtOffset(conn, 0);
				breakAddress.invoke(Map.of("process", proc, "address", tb.addr(address)));

				String out = conn.executeCapture("print(list(util.dbg.client.get_breakpoints(BreakpointType.BpHardware)))");
				
				clearBreakpoints(conn);
				conn.execute("util.terminate_session()");
				
				assertThat(out, containsString(Long.toString(address)));
			}
		}
	}

	@Test
	public void testBreakHardwareExpression() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, NOTEPAD);
			txPut(conn, "processes");

			RemoteMethod breakExpression = conn.getMethod("break_hw_expression");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/x64dbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				clearBreakpoints(conn);
				breakExpression.invoke(Map.of("expression", "CreateFileW"));

				String out = conn.executeCapture("print(list(util.dbg.client.get_breakpoints(BreakpointType.BpHardware)))");

				clearBreakpoints(conn);
				conn.execute("util.terminate_session()");
				
				assertThat(out, containsString("kernel32.dll"));
			}
		}
	}

	@Test
	public void testBreakReadAddress() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, NOTEPAD);
			txPut(conn, "processes");

			RemoteMethod breakAddr = conn.getMethod("break_read_address");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/x64dbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				clearBreakpoints(conn);
				
				TraceObject proc = Objects.requireNonNull(tb.objAny0("Sessions[].Processes[]"));
				long address = getAddressAtOffset(conn, 0);
				breakAddr.invoke(Map.of("process", proc, "address", tb.addr(address), "size", 1L));

				String out = conn.executeCapture("print(list(util.dbg.client.get_breakpoints(BreakpointType.BpHardware)))");

				clearBreakpoints(conn);
				conn.execute("util.terminate_session()");
				
				assertThat(out, containsString("%d".formatted(address)));
				assertThat(out, containsString("hwSize=0"));
				assertThat(out, containsString("typeEx=0"));
			}
		}
	}

	@Test
	public void testBreakReadExpression() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, NOTEPAD);
			txPut(conn, "processes");

			RemoteMethod breakExpression = conn.getMethod("break_read_expression");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/x64dbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				clearBreakpoints(conn);
				breakExpression.invoke(Map.of("expression", "CreateFileW"));
				long address = getAddressAtOffset(conn, 0);

				String out = conn.executeCapture("print(list(util.dbg.client.get_breakpoints(BreakpointType.BpHardware)))");

				clearBreakpoints(conn);
				conn.execute("util.terminate_session()");
				
				assertThat(out, containsString("kernel32.dll"));
				assertThat(out, containsString("hwSize=0"));
				assertThat(out, containsString("typeEx=0"));
			}
		}
	}

	@Test
	public void testBreakWriteAddress() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, NOTEPAD);
			txPut(conn, "processes");

			RemoteMethod breakAddr = conn.getMethod("break_write_address");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/x64dbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				clearBreakpoints(conn);

				TraceObject proc = Objects.requireNonNull(tb.objAny0("Sessions[].Processes[]"));
				long address = getAddressAtOffset(conn, 0);
				breakAddr.invoke(Map.of("process", proc, "address", tb.addr(address), "size", 1L));

				String out = conn.executeCapture("print(list(util.dbg.client.get_breakpoints(BreakpointType.BpHardware)))");

				clearBreakpoints(conn);
				conn.execute("util.terminate_session()");
				
				assertThat(out, containsString("%d".formatted(address)));
				assertThat(out, containsString("hwSize=0"));
				assertThat(out, containsString("typeEx=1"));
			}
		}
	}

	@Test
	public void testBreakWriteExpression() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, NOTEPAD);
			txPut(conn, "processes");

			RemoteMethod breakExpression = conn.getMethod("break_write_expression");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/x64dbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				clearBreakpoints(conn);

				breakExpression.invoke(Map.of("expression", "CreateFileW"));
				long address = getAddressAtOffset(conn, 0);

				String out = conn.executeCapture("print(list(util.dbg.client.get_breakpoints(BreakpointType.BpHardware)))");

				clearBreakpoints(conn);
				conn.execute("util.terminate_session()");
				
				assertThat(out, containsString("kernel32.dll"));
				assertThat(out, containsString("hwSize=0"));
				assertThat(out, containsString("typeEx=1"));
			}
		}
	}

	@Test
	public void testBreakAccessAddress() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, NOTEPAD);
			txPut(conn, "processes");

			RemoteMethod breakAddr = conn.getMethod("break_access_address");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/x64dbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				clearBreakpoints(conn);
				TraceObject proc = Objects.requireNonNull(tb.objAny0("Sessions[].Processes[]"));
				long address = getAddressAtOffset(conn, 0);
				breakAddr.invoke(Map.of("process", proc, "address", tb.addr(address)));

				String out = conn.executeCapture("print(list(util.dbg.client.get_breakpoints(BreakpointType.BpMemory)))");

				clearBreakpoints(conn);
				conn.execute("util.terminate_session()");

				assertThat(out, containsString("%d".formatted(address).substring(0,6)));  // page boundary
				assertThat(out, containsString("hwSize=0"));
				assertThat(out, containsString("typeEx=0"));
			}
		}
	}

	@Test
	public void testBreakAccessExpression() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, NOTEPAD);
			txPut(conn, "processes");

			RemoteMethod breakExpression = conn.getMethod("break_access_expression");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/x64dbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				clearBreakpoints(conn);
				breakExpression.invoke(Map.of("expression", "CreateFileW"));
				long address = getAddressAtOffset(conn, 0);

				String out = conn.executeCapture("print(list(util.dbg.client.get_breakpoints(BreakpointType.BpMemory)))");

				clearBreakpoints(conn);
				conn.execute("util.terminate_session()");
				
				assertThat(out, containsString("kernel32.dll"));  
				assertThat(out, containsString("hwSize=0"));
				assertThat(out, containsString("typeEx=0"));
			}
		}
	}

	@Test
	public void testToggleBreakpoint() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, NOTEPAD);
			txPut(conn, "processes");

			RemoteMethod breakAddress = conn.getMethod("break_address");
			RemoteMethod toggleBreakpoint = conn.getMethod("toggle_breakpoint");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/x64dbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				clearBreakpoints(conn);
				
				long address = getAddressAtOffset(conn, 0);
				TraceObject proc = Objects.requireNonNull(tb.objAny0("Sessions[].Processes[]"));
				breakAddress.invoke(Map.of("process", proc, "address", tb.addr(address)));

				txPut(conn, "breakpoints");
				TraceObject bpt = Objects
						.requireNonNull(tb.objAny0("Sessions[].Processes[].Debug.Software Breakpoints[]"));

				toggleBreakpoint.invoke(Map.of("breakpoint", bpt, "enabled", false));

				String out = conn.executeCapture("print(list(util.dbg.client.get_breakpoints(0)))");
				
				clearBreakpoints(conn);
				conn.execute("util.terminate_session()");
				
				assertThat(out, containsString("enabled=False"));
			}
		}
	}

	@Test
	public void testDeleteBreakpoint() throws Exception {
		try (PythonAndConnection conn = startAndConnectPython()) {
			start(conn, NOTEPAD);
			txPut(conn, "processes");

			RemoteMethod breakAddress = conn.getMethod("break_address");
			RemoteMethod deleteBreakpoint = conn.getMethod("delete_breakpoint");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/x64dbg/notepad.exe")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				clearBreakpoints(conn);
				
				long address = getAddressAtOffset(conn, 0);
				TraceObject proc = Objects.requireNonNull(tb.objAny0("Sessions[].Processes[]"));
				breakAddress.invoke(Map.of("process", proc, "address", tb.addr(address)));

				txPut(conn, "breakpoints");
				TraceObject bpt = Objects.requireNonNull(tb.objAny0("Sessions[].Processes[].Debug.Software Breakpoints[]"));

				deleteBreakpoint.invoke(Map.of("breakpoint", bpt));
				String out = conn.executeCapture("print(list(util.dbg.client.get_breakpoints(BreakpointType.BpNormal)))");

				clearBreakpoints(conn);
				conn.execute("util.terminate_session()");
				
				assertThat(out, containsString("[]"));
			}
		}
	}

	private void start(PythonAndConnection conn, String obj) {
		conn.execute("from ghidraxdbg.commands import *");
		if (obj != null)
			conn.execute("ghidra_trace_create('%s', wait=True)".formatted(obj));
		else
			conn.execute("ghidra_trace_create()");
	}

	private void txPut(PythonAndConnection conn, String obj) {
		conn.execute("ghidra_trace_txstart('Tx-put %s')".formatted(obj));
		try {
			conn.execute("ghidra_trace_put_%s()".formatted(obj));
		} catch (Exception e) {
			// IGNORE
		}
		conn.execute("ghidra_trace_txcommit()");
	}

	private void txCreate(PythonAndConnection conn, String path) {
		conn.execute("ghidra_trace_txstart('Fake %s')".formatted(path));
		conn.execute("ghidra_trace_create_obj('%s')".formatted(path));
		conn.execute("ghidra_trace_txcommit()");
	}

	private String getInst(PythonAndConnection conn) {
		return getInstAtOffset(conn, 0);
	}

	private String getInstAtOffset(PythonAndConnection conn, int offset) {
		String inst = "print(util.get_inst(util.get_pc()+" + offset + "))";
		String ret = conn.executeCapture(inst).strip();
		ret = ret.substring(ret.indexOf("'")+1);  
		return ret.substring(0, ret.indexOf("'"));
	}

	private String getInstSizeAtOffset(PythonAndConnection conn, int offset) {
		String instSize = "print(util.get_inst(util.get_pc()+" + offset + "))";
		String ret = conn.executeCapture(instSize).strip();
		ret = ret.substring(ret.indexOf("instr_size"));
		return ret.substring(ret.indexOf("=")+1, ret.indexOf(" "));
	}

	private long getAddressAtOffset(PythonAndConnection conn, int offset) {
		String inst = "print(util.get_pc()+" + offset + ")";
		String ret = conn.executeCapture(inst).strip();
		return Long.decode(ret);
	}

	private void clearBreakpoints(PythonAndConnection conn) {
		conn.execute("util.dbg.client.clear_breakpoint(None)");
		conn.execute("util.dbg.client.clear_hardware_breakpoint(None)");
		conn.execute("util.dbg.client.clear_memory_breakpoint(None)");	
	}
}
