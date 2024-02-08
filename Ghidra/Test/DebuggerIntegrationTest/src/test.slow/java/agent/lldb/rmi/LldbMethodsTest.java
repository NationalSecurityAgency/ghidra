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

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.greaterThan;
import static org.junit.Assert.*;

import java.util.*;

import org.junit.Test;
import org.junit.experimental.categories.Category;

import generic.Unique;
import generic.test.category.NightlyCategory;
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

@Category(NightlyCategory.class) // this may actually be an @PortSensitive test
public class LldbMethodsTest extends AbstractLldbTraceRmiTest {

	@Test
	public void testExecuteCapture() throws Exception {
		try (LldbAndConnection conn = startAndConnectLldb()) {
			RemoteMethod execute = conn.getMethod("execute");
			assertEquals(false, execute.parameters().get("to_string").getDefaultValue());
			assertEquals("test\n",
				execute.invoke(Map.of("cmd", "script print('test')", "to_string", true)));
		}
	}

	@Test
	public void testExecute() throws Exception {
		try (LldbAndConnection conn = startAndConnectLldb()) {
			start(conn, "bash");
			conn.execute("kill");
		}
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
			// Just confirm it's present
		}
	}

	@Test
	public void testRefreshAvailable() throws Exception {
		try (LldbAndConnection conn = startAndConnectLldb()) {
			conn.execute("ghidra_trace_start");
			txCreate(conn, "Available");

			RemoteMethod refreshAvailable = conn.getMethod("refresh_available");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/noname")) {
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
		try (LldbAndConnection conn = startAndConnectLldb()) {
			start(conn, "bash");
			txPut(conn, "processes");

			RemoteMethod refreshBreakpoints = conn.getMethod("refresh_breakpoints");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				//waitStopped();

				conn.execute("breakpoint set --name main");
				conn.execute("breakpoint set -H --name main");
				txPut(conn, "breakpoints");
				TraceObject breakpoints = Objects.requireNonNull(tb.objAny("Breakpoints"));
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

				// The temporary breakpoint uses up number 1
				assertBreakLoc(procBreakLocVals.get(0), "[1.1]", main, 1,
					Set.of(TraceBreakpointKind.SW_EXECUTE),
					"main");
				assertBreakLoc(procBreakLocVals.get(1), "[2.1]", main, 1,
					Set.of(TraceBreakpointKind.HW_EXECUTE),
					"main");
			}
		}
	}

	@Test
	public void testRefreshProcBreakpoints() throws Exception {
		try (LldbAndConnection conn = startAndConnectLldb()) {
			start(conn, "bash");
			txPut(conn, "processes");
			txPut(conn, "breakpoints");

			RemoteMethod refreshProcBreakpoints = conn.getMethod("refresh_proc_breakpoints");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();

				TraceObject locations =
					Objects.requireNonNull(tb.objAny("Processes[].Breakpoints"));
				conn.execute("breakpoint set --name main");
				conn.execute("breakpoint set -H --name main");
				refreshProcBreakpoints.invoke(Map.of("node", locations));

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

				assertBreakLoc(procBreakLocVals.get(0), "[1.1]", main, 1,
					Set.of(TraceBreakpointKind.SW_EXECUTE),
					"main");
				assertBreakLoc(procBreakLocVals.get(1), "[2.1]", main, 1,
					Set.of(TraceBreakpointKind.HW_EXECUTE),
					"main");
			}
		}
	}

	@Test
	public void testRefreshProcWatchpoints() throws Exception {
		try (LldbAndConnection conn = startAndConnectLldb()) {
			start(conn, "bash");
			txPut(conn, "all");

			RemoteMethod refreshProcWatchpoints = conn.getMethod("refresh_proc_watchpoints");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();

				TraceObject locations =
					Objects.requireNonNull(tb.objAny("Processes[].Watchpoints"));
				conn.execute("watchpoint set expression -- `(void(*)())main`");
				conn.execute("watchpoint set expression -w read -- `(void(*)())main`+-0x20");
				conn.execute("watchpoint set expression -w read_write -- `(void(*)())main`+0x30");
				refreshProcWatchpoints.invoke(Map.of("node", locations));

				List<TraceObjectValue> procWatchLocVals = tb.trace.getObjectManager()
						.getValuePaths(Lifespan.at(0),
							PathPredicates.parse("Processes[].Watchpoints[]"))
						.map(p -> p.getLastEntry())
						.sorted(Comparator.comparing(TraceObjectValue::getEntryKey))
						.toList();
				assertEquals(3, procWatchLocVals.size());
				AddressRange rangeMain0 =
					procWatchLocVals.get(0).getChild().getValue(0, "_range").castValue();
				Address main0 = rangeMain0.getMinAddress();
				AddressRange rangeMain1 =
					procWatchLocVals.get(1).getChild().getValue(0, "_range").castValue();
				Address main1 = rangeMain1.getMinAddress();
				AddressRange rangeMain2 =
					procWatchLocVals.get(2).getChild().getValue(0, "_range").castValue();
				Address main2 = rangeMain2.getMinAddress();

				assertWatchLoc(procWatchLocVals.get(0), "[1]", main0, (int) rangeMain0.getLength(),
					Set.of(TraceBreakpointKind.WRITE),
					"main");
				assertWatchLoc(procWatchLocVals.get(1), "[2]", main1, (int) rangeMain1.getLength(),
					Set.of(TraceBreakpointKind.READ),
					"main+0x20");
				assertWatchLoc(procWatchLocVals.get(2), "[3]", main2, (int) rangeMain1.getLength(),
					Set.of(TraceBreakpointKind.READ, TraceBreakpointKind.WRITE),
					"main+0x30");
			}
		}
	}

	@Test
	public void testRefreshProcesses() throws Exception {
		try (LldbAndConnection conn = startAndConnectLldb()) {
			conn.execute("ghidra_trace_start");
			txCreate(conn, "Processes");
			txCreate(conn, "Processes[1]");

			RemoteMethod refreshProcesses = conn.getMethod("refresh_processes");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/noname")) {
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
		try (LldbAndConnection conn = startAndConnectLldb()) {
			String path = "Processes[].Environment";
			start(conn, "bash");
			txPut(conn, "all");

			RemoteMethod refreshEnvironment = conn.getMethod("refresh_environment");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				TraceObject env = Objects.requireNonNull(tb.objAny(path));

				refreshEnvironment.invoke(Map.of("node", env));

				// Assumes LLDB on Linux amd64
				assertEquals("lldb", env.getValue(0, "_debugger").getValue());
				assertEquals("x86_64", env.getValue(0, "_arch").getValue());
				assertEquals("linux", env.getValue(0, "_os").getValue());
				assertEquals("little", env.getValue(0, "_endian").getValue());
			}
		}
	}

	@Test
	public void testRefreshThreads() throws Exception {
		try (LldbAndConnection conn = startAndConnectLldb()) {
			String path = "Processes[].Threads";
			start(conn, "bash");
			txCreate(conn, path);

			RemoteMethod refreshThreads = conn.getMethod("refresh_threads");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				TraceObject threads = Objects.requireNonNull(tb.objAny(path));

				refreshThreads.invoke(Map.of("node", threads));

				// Would be nice to control / validate the specifics
				Unique.assertOne(tb.trace.getThreadManager().getAllThreads());
			}
		}
	}

	@Test
	public void testRefreshStack() throws Exception {
		try (LldbAndConnection conn = startAndConnectLldb()) {
			String path = "Processes[].Threads[].Stack";
			conn.execute("file bash");
			conn.execute("ghidra_trace_start");
			txPut(conn, "processes");
			breakAt(conn, "read");

			RemoteMethod refreshStack = conn.getMethod("refresh_stack");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();

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
		try (LldbAndConnection conn = startAndConnectLldb()) {
			String path = "Processes[].Threads[].Stack[].Registers";
			start(conn, "bash");
			conn.execute("ghidra_trace_txstart 'Tx'");
			conn.execute("ghidra_trace_putreg");
			conn.execute("ghidra_trace_txcommit");

			RemoteMethod refreshRegisters = conn.getMethod("refresh_registers");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				conn.execute("expr $rax = 0xdeadbeef");

				TraceObject registers = Objects.requireNonNull(tb.objAny(path, Lifespan.at(0)));
				refreshRegisters.invoke(Map.of("node", registers));

				long snap = 0;
				AddressSpace t1f0 = tb.trace.getBaseAddressFactory()
						.getAddressSpace(registers.getCanonicalPath().toString());
				TraceMemorySpace regs = tb.trace.getMemoryManager().getMemorySpace(t1f0, false);
				RegisterValue rax = regs.getValue(snap, tb.reg("rax"));
				// LLDB treats registers in arch's endian
				assertEquals("deadbeef", rax.getUnsignedValue().toString(16));
			}
		}
	}

	@Test
	public void testRefreshMappings() throws Exception {
		try (LldbAndConnection conn = startAndConnectLldb()) {
			String path = "Processes[].Memory";
			start(conn, "bash");
			txCreate(conn, path);

			RemoteMethod refreshMappings = conn.getMethod("refresh_mappings");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
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
		try (LldbAndConnection conn = startAndConnectLldb()) {
			String path = "Processes[].Modules";
			start(conn, "bash");
			txCreate(conn, path);

			RemoteMethod refreshModules = conn.getMethod("refresh_modules");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				TraceObject modules = Objects.requireNonNull(tb.objAny(path));

				refreshModules.invoke(Map.of("node", modules));

				// Would be nice to control / validate the specifics
				Collection<? extends TraceModule> all = tb.trace.getModuleManager().getAllModules();
				TraceModule modBash =
					Unique.assertOne(all.stream().filter(m -> m.getName().contains("bash")));
				assertNotEquals(tb.addr(0), Objects.requireNonNull(modBash.getBase()));
			}
		}
	}

	@Test
	public void testActivateThread() throws Exception {
		try (LldbAndConnection conn = startAndConnectLldb()) {
			// TODO:  need to find this file (same issue in LldbHookTests
			String dproc = DummyProc.which("expCloneExit");
			conn.execute("file " + dproc);
			conn.execute("ghidra_trace_start");
			txPut(conn, "processes");
			breakAt(conn, "work");

			RemoteMethod activateThread = conn.getMethod("activate_thread");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/expCloneExit")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();

				txPut(conn, "threads");

				PathPattern pattern =
					PathPredicates.parse("Processes[].Threads[]").getSingletonPattern();
				List<TraceObject> list = tb.trace.getObjectManager()
						.getValuePaths(Lifespan.at(0), pattern)
						.map(p -> p.getDestination(null))
						.toList();
				assertEquals(2, list.size());

				for (TraceObject t : list) {
					activateThread.invoke(Map.of("thread", t));
					String out = conn.executeCapture("thread info");
					List<String> indices = pattern.matchKeys(t.getCanonicalPath().getKeyList());
					assertThat(out, containsString("tid = %s".formatted(indices.get(1))));
				}
			}
		}
	}

	@Test
	public void testActivateFrame() throws Exception {
		try (LldbAndConnection conn = startAndConnectLldb()) {
			conn.execute("file bash");
			conn.execute("ghidra_trace_start");
			txPut(conn, "processes");
			breakAt(conn, "read");

			RemoteMethod activateFrame = conn.getMethod("activate_frame");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();

				txPut(conn, "frames");

				List<TraceObject> list = tb.trace.getObjectManager()
						.getValuePaths(Lifespan.at(0),
							PathPredicates.parse("Processes[].Threads[].Stack[]"))
						.map(p -> p.getDestination(null))
						.toList();
				//assertThat(list.size(), greaterThan(2));

				for (TraceObject f : list) {
					activateFrame.invoke(Map.of("frame", f));
					String out = conn.executeCapture("frame info");
					String level = f.getCanonicalPath().index();
					assertThat(out, containsString("#%s".formatted(level)));
				}
			}
		}
	}

	@Test
	public void testRemoveProcess() throws Exception {
		try (LldbAndConnection conn = startAndConnectLldb()) {
			start(conn, "bash");
			txPut(conn, "processes");

			RemoteMethod removeProcess = conn.getMethod("remove_process");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				TraceObject proc2 = Objects.requireNonNull(tb.objAny("Processes[]"));
				removeProcess.invoke(Map.of("process", proc2));

				String out = conn.executeCapture("target list");
				assertThat(out, containsString("No targets"));
			}
		}
	}

	@Test
	public void testAttachObj() throws Exception {
		String sleep = DummyProc.which("expTraceableSleep");
		try (DummyProc dproc = DummyProc.run(sleep)) {
			try (LldbAndConnection conn = startAndConnectLldb()) {
				conn.execute("ghidra_trace_start");
				txPut(conn, "available");
				txPut(conn, "processes");

				RemoteMethod attachObj = conn.getMethod("attach_obj");
				try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/noname")) {
					tb = new ToyDBTraceBuilder((Trace) mdo.get());
					TraceObject proc =
						Objects.requireNonNull(tb.objAny("Processes[]", Lifespan.at(0)));
					TraceObject target =
						Objects.requireNonNull(tb.obj("Available[%d]".formatted(dproc.pid)));
					attachObj.invoke(Map.of("process", proc, "target", target));

					String out = conn.executeCapture("target list");
					assertThat(out, containsString("pid=%d".formatted(dproc.pid)));
				}
			}
		}
	}

	@Test
	public void testAttachPid() throws Exception {
		String sleep = DummyProc.which("expTraceableSleep");
		try (DummyProc dproc = DummyProc.run(sleep)) {
			try (LldbAndConnection conn = startAndConnectLldb()) {
				conn.execute("ghidra_trace_start");
				txPut(conn, "processes");

				RemoteMethod attachPid = conn.getMethod("attach_pid");
				try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/noname")) {
					tb = new ToyDBTraceBuilder((Trace) mdo.get());
					TraceObject proc =
						Objects.requireNonNull(tb.objAny("Processes[]", Lifespan.at(0)));
					attachPid.invoke(Map.of("process", proc, "pid", dproc.pid));

					String out = conn.executeCapture("target list");
					assertThat(out, containsString("pid=%d".formatted(dproc.pid)));
				}
			}
		}
	}

	@Test
	public void testDetach() throws Exception {
		try (LldbAndConnection conn = startAndConnectLldb()) {
			start(conn, "bash");
			txPut(conn, "processes");
			//conn.execute("process attach -p %d".formatted(dproc.pid));

			RemoteMethod detach = conn.getMethod("detach");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				TraceObject proc = Objects.requireNonNull(tb.objAny("Processes[]"));
				detach.invoke(Map.of("process", proc));

				String out = conn.executeCapture("target list");
				//assertThat(out, containsString("pid=%d".formatted(dproc.pid)));
				assertThat(out, containsString("detached"));
			}
		}
	}

	@Test
	public void testLaunchEntry() throws Exception {
		try (LldbAndConnection conn = startAndConnectLldb()) {
			conn.execute("ghidra_trace_start");
			txPut(conn, "processes");

			RemoteMethod launch = conn.getMethod("launch_loader");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/noname")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				TraceObject proc = Objects.requireNonNull(tb.objAny("Processes[]"));
				launch.invoke(Map.ofEntries(
					Map.entry("process", proc),
					Map.entry("file", "bash")));
				waitStopped();

				String out = conn.executeCapture("target list");
				assertThat(out, containsString("bash"));
			}
		}
	}

	@Test //Not clear how to send interrupt
	public void testLaunch() throws Exception {
		try (LldbAndConnection conn = startAndConnectLldb()) {
			conn.execute("ghidra_trace_start");
			txPut(conn, "processes");

			RemoteMethod launch = conn.getMethod("launch");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/noname")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				TraceObject proc = Objects.requireNonNull(tb.objAny("Processes[]"));
				launch.invoke(Map.ofEntries(
					Map.entry("process", proc),
					Map.entry("file", "bash")));

				txPut(conn, "processes");

				waitRunning();
				Thread.sleep(100); // Give it plenty of time to block on read

				conn.execute("process interrupt");
				txPut(conn, "processes");

				waitStopped();

				String out = conn.executeCapture("bt");
				assertThat(out, containsString("read"));
			}
		}
	}

	@Test
	public void testKill() throws Exception {
		try (LldbAndConnection conn = startAndConnectLldb()) {
			start(conn, "bash");
			txPut(conn, "processes");

			RemoteMethod kill = conn.getMethod("kill");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();

				TraceObject proc = Objects.requireNonNull(tb.objAny("Processes[]"));
				kill.invoke(Map.of("process", proc));

				String out = conn.executeCapture("target list");
				assertThat(out, containsString("exited"));
			}
		}
	}

	@Test
	public void testStepInto() throws Exception {
		try (LldbAndConnection conn = startAndConnectLldb()) {
			start(conn, "bash");
			txPut(conn, "processes");

			RemoteMethod step_into = conn.getMethod("step_into");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();
				txPut(conn, "threads");

				TraceObject thread = Objects.requireNonNull(tb.objAny("Processes[].Threads[]"));

				while (!conn.executeCapture("dis -c1 -s '$pc'").contains("call")) {
					step_into.invoke(Map.of("thread", thread));
				}

				String dis2 = conn.executeCapture("dis -c2 -s '$pc'");
				// lab0:
				//    -> addr0
				// 
				// lab1:
				//    addr1
				long pcNext = Long.decode(dis2.strip().split("\n")[4].strip().split("\\s+")[0]);

				step_into.invoke(Map.of("thread", thread));
				String disAt = conn.executeCapture("dis -c1 -s '$pc'");
				long pc = Long.decode(disAt.strip().split("\n")[1].strip().split("\\s+")[1]);
				assertNotEquals(pcNext, pc);
			}
		}
	}

	@Test
	public void testStepOver() throws Exception {
		try (LldbAndConnection conn = startAndConnectLldb()) {
			conn.execute("file bash");
			conn.execute("ghidra_trace_start");
			txPut(conn, "processes");
			breakAt(conn, "read");

			RemoteMethod step_over = conn.getMethod("step_over");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();
				txPut(conn, "threads");

				TraceObject thread = Objects.requireNonNull(tb.objAny("Processes[].Threads[]"));

				while (!conn.executeCapture("dis -c1 -s '$pc'").contains("call")) {
					step_over.invoke(Map.of("thread", thread));
				}

				String dis2 = conn.executeCapture("dis -c2 -s '$pc'");
				// lab0:
				//    -> addr0
				//    addr1
				long pcNext = Long.decode(dis2.strip().split("\n")[2].strip().split("\\s+")[0]);

				step_over.invoke(Map.of("thread", thread));
				String disAt = conn.executeCapture("dis -c1 -s '$pc'");
				long pc = Long.decode(disAt.strip().split("\n")[1].strip().split("\\s+")[1]);
				assertEquals(pcNext, pc);
			}
		}
	}

	//@Test Not obvious "thread until -a" works (and definitely requires debug info")
	public void testAdvance() throws Exception {
		try (LldbAndConnection conn = startAndConnectLldb()) {
			start(conn, "bash");

			RemoteMethod step_ext = conn.getMethod("step_ext");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				//waitStopped();
				txPut(conn, "threads");

				TraceObject thread = Objects.requireNonNull(tb.objAny("Processes[].Threads[]"));
				String dis3 = conn.executeCapture("disassemble -c3 -s '$pc'");
				// TODO: Examine for control transfer?
				long pcTarget = Long.decode(dis3.strip().split("\n")[2].strip().split("\\s+")[0]);

				step_ext.invoke(Map.of("thread", thread, "address", tb.addr(pcTarget)));

				String dis1 = conn.executeCapture("disassemble -c1 -s '$pc'");
				long pc = Long.decode(dis1.strip().split("\n")[1].strip().split("\\s+")[1]);
				assertEquals(pcTarget, pc);
			}
		}
	}

	@Test
	public void testFinish() throws Exception {
		try (LldbAndConnection conn = startAndConnectLldb()) {
			conn.execute("file bash");
			conn.execute("ghidra_trace_start");
			txPut(conn, "processes");
			breakAt(conn, "read");

			RemoteMethod activate = conn.getMethod("activate_thread");
			RemoteMethod step_out = conn.getMethod("step_out");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();
				txPut(conn, "threads");

				TraceObject thread = Objects.requireNonNull(tb.objAny("Processes[].Threads[]"));
				activate.invoke(Map.of("thread", thread));

				int initDepth = getDepth(conn);

				step_out.invoke(Map.of("thread", thread));

				int finalDepth = getDepth(conn);
				assertEquals(initDepth - 1, finalDepth);
			}
		}
	}

	@Test
	public void testReturn() throws Exception {
		try (LldbAndConnection conn = startAndConnectLldb()) {
			conn.execute("file bash");
			conn.execute("ghidra_trace_start");
			txPut(conn, "processes");
			breakAt(conn, "read");

			RemoteMethod activate = conn.getMethod("activate_thread");
			RemoteMethod ret = conn.getMethod("return");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();
				txPut(conn, "threads");

				TraceObject thread = Objects.requireNonNull(tb.objAny("Processes[].Threads[]"));
				activate.invoke(Map.of("thread", thread));

				int initDepth = getDepth(conn);

				ret.invoke(Map.of("thread", thread));

				int finalDepth = getDepth(conn);
				assertEquals(initDepth - 1, finalDepth);
			}
		}
	}

	@Test
	public void testBreakAddress() throws Exception {
		try (LldbAndConnection conn = startAndConnectLldb()) {
			start(conn, "bash");
			txPut(conn, "processes");

			RemoteMethod breakAddress = conn.getMethod("break_address");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				TraceObject proc = Objects.requireNonNull(tb.objAny("Processes[]"));
				long address = Long.decode(conn.executeCapture("dis -c1 -n main").split("\\s+")[1]);
				breakAddress.invoke(Map.of("process", proc, "address", tb.addr(address)));

				String out = conn.executeCapture("breakpoint list");
				assertThat(out, containsString("main"));
				assertThat(out, containsString(Long.toHexString(address)));
			}
		}
	}

	@Test
	public void testBreakExpression() throws Exception {
		try (LldbAndConnection conn = startAndConnectLldb()) {
			start(conn, "bash");
			txPut(conn, "processes");

			RemoteMethod breakExpression = conn.getMethod("break_expression");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();

				breakExpression.invoke(Map.of("expression", "main"));

				String out = conn.executeCapture("breakpoint list");
				assertThat(out, containsString("main"));
			}
		}
	}

	//@Test  stderr getting populated with warning about exhausted hardware breakpoints
	//   Are hardware breakpoints available on our VMs?
	public void testBreakHardwareAddress() throws Exception {
		try (LldbAndConnection conn = startAndConnectLldb()) {
			start(conn, "bash");
			txPut(conn, "processes");

			RemoteMethod breakAddress = conn.getMethod("break_hw_address");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();

				TraceObject proc = Objects.requireNonNull(tb.objAny("Processes[]"));
				long address = Long.decode(conn.executeCapture("dis -c1 -n main").split("\\s+")[1]);
				breakAddress.invoke(Map.of("process", proc, "address", tb.addr(address)));

				String out = conn.executeCapture("breakpoint list");
				assertThat(out, containsString(Long.toHexString(address)));
			}
		}
	}

	//@Test There appear to be issues with hardware register availability in our virtual environments
	public void testBreakHardwareExpression() throws Exception {
		try (LldbAndConnection conn = startAndConnectLldb()) {
			start(conn, "bash");
			txPut(conn, "processes");

			RemoteMethod breakExpression = conn.getMethod("break_hw_expression");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();

				breakExpression.invoke(Map.of("expression", "`(void(*)())main`"));

				String out = conn.executeCapture("breakpoint list");
				long address = Long.decode(conn.executeCapture("dis -c1 -n main").split("\\s+")[1]);
				//NB: a little odd that this isn't in hex
				assertThat(out, containsString(Long.toString(address)));
			}
		}
	}

	@Test
	public void testBreakReadRange() throws Exception {
		try (LldbAndConnection conn = startAndConnectLldb()) {
			start(conn, "bash");
			txPut(conn, "processes");

			RemoteMethod breakRange = conn.getMethod("break_read_range");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();

				TraceObject proc = Objects.requireNonNull(tb.objAny("Processes[]"));
				long address = Long.decode(conn.executeCapture("dis -c1 -n main").split("\\s+")[1]);
				AddressRange range = tb.range(address, address + 3); // length 4
				breakRange.invoke(Map.of("process", proc, "range", range));

				String out = conn.executeCapture("watchpoint list");
				assertThat(out, containsString("0x%x".formatted(address)));
				assertThat(out, containsString("size = 4"));
				assertThat(out, containsString("type = r"));
			}
		}
	}

	@Test
	public void testBreakReadExpression() throws Exception {
		try (LldbAndConnection conn = startAndConnectLldb()) {
			start(conn, "bash");
			txPut(conn, "processes");

			RemoteMethod breakExpression = conn.getMethod("break_read_expression");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				breakExpression.invoke(Map.of("expression", "`(void(*)())main`"));
				long address = Long.decode(conn.executeCapture("dis -c1 -n main").split("\\s+")[1]);

				String out = conn.executeCapture("watchpoint list");
				assertThat(out, containsString(Long.toHexString(address)));
				assertThat(out, containsString("type = r"));
			}
		}
	}

	@Test
	public void testBreakWriteRange() throws Exception {
		try (LldbAndConnection conn = startAndConnectLldb()) {
			start(conn, "bash");
			txPut(conn, "processes");

			RemoteMethod breakRange = conn.getMethod("break_write_range");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();

				TraceObject proc = Objects.requireNonNull(tb.objAny("Processes[]"));
				long address = Long.decode(conn.executeCapture("dis -c1 -n main").split("\\s+")[1]);
				AddressRange range = tb.range(address, address + 3); // length 4
				breakRange.invoke(Map.of("process", proc, "range", range));

				String out = conn.executeCapture("watchpoint list");
				assertThat(out, containsString("0x%x".formatted(address)));
				assertThat(out, containsString("size = 4"));
				assertThat(out, containsString("type = w"));
			}
		}
	}

	@Test
	public void testBreakWriteExpression() throws Exception {
		try (LldbAndConnection conn = startAndConnectLldb()) {
			start(conn, "bash");
			txPut(conn, "processes");

			RemoteMethod breakExpression = conn.getMethod("break_write_expression");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				breakExpression.invoke(Map.of("expression", "`(void(*)())main`"));
				long address = Long.decode(conn.executeCapture("dis -c1 -n main").split("\\s+")[1]);

				String out = conn.executeCapture("watchpoint list");
				assertThat(out, containsString(Long.toHexString(address)));
				assertThat(out, containsString("type = w"));
			}
		}
	}

	@Test
	public void testBreakAccessRange() throws Exception {
		try (LldbAndConnection conn = startAndConnectLldb()) {
			start(conn, "bash");
			txPut(conn, "processes");

			RemoteMethod breakRange = conn.getMethod("break_access_range");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();

				TraceObject proc = Objects.requireNonNull(tb.objAny("Processes[]"));
				long address = Long.decode(conn.executeCapture("dis -c1 -n main").split("\\s+")[1]);
				AddressRange range = tb.range(address, address + 3); // length 4
				breakRange.invoke(Map.of("process", proc, "range", range));

				String out = conn.executeCapture("watchpoint list");
				assertThat(out, containsString("0x%x".formatted(address)));
				assertThat(out, containsString("size = 4"));
				assertThat(out, containsString("type = rw"));
			}
		}
	}

	@Test
	public void testBreakAccessExpression() throws Exception {
		try (LldbAndConnection conn = startAndConnectLldb()) {
			start(conn, "bash");
			txPut(conn, "processes");

			RemoteMethod breakExpression = conn.getMethod("break_access_expression");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				breakExpression.invoke(Map.of("expression", "`(void(*)())main`"));
				long address = Long.decode(conn.executeCapture("dis -c1 -n main").split("\\s+")[1]);

				String out = conn.executeCapture("watchpoint list");
				assertThat(out, containsString(Long.toHexString(address)));
				assertThat(out, containsString("type = rw"));
			}
		}
	}

	// NB: not really equivalent to gdb's "catch" but...
	@Test
	public void testBreakException() throws Exception {
		try (LldbAndConnection conn = startAndConnectLldb()) {
			start(conn, "bash");
			txPut(conn, "processes");

			RemoteMethod breakExc = conn.getMethod("break_exception");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				breakExc.invoke(Map.of("lang", "C++"));

				String out = conn.executeCapture("breakpoint list");
				assertThat(out, containsString("Exception"));
				assertThat(out, containsString("__cxa_throw"));
			}
		}
	}

	@Test
	public void testToggleBreakpoint() throws Exception {
		try (LldbAndConnection conn = startAndConnectLldb()) {
			conn.execute("file bash");
			conn.execute("ghidra_trace_start");
			txPut(conn, "processes");
			breakAt(conn, "main");

			RemoteMethod toggleBreakpoint = conn.getMethod("toggle_breakpoint");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();

				txPut(conn, "breakpoints");
				TraceObject bpt = Objects.requireNonNull(tb.objAny("Breakpoints[]"));

				toggleBreakpoint.invoke(Map.of("breakpoint", bpt, "enabled", false));

				String out = conn.executeCapture("breakpoint list");
				assertThat(out, containsString("disabled"));
			}
		}
	}

	@Test
	public void testToggleBreakpointLocation() throws Exception {
		try (LldbAndConnection conn = startAndConnectLldb()) {
			conn.execute("file bash");
			conn.execute("ghidra_trace_start");
			txPut(conn, "processes");
			breakAt(conn, "main");

			RemoteMethod toggleBreakpointLocation = conn.getMethod("toggle_breakpoint_location");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();

				txPut(conn, "breakpoints");

				// NB. Requires canonical path. Inf[].Brk[] is a link
				TraceObject loc = Objects.requireNonNull(tb.objAny("Breakpoints[][]"));

				toggleBreakpointLocation.invoke(Map.of("location", loc, "enabled", false));

				String out = conn.executeCapture("breakpoint list");
				assertThat(out, containsString("disabled"));
			}
		}
	}

	@Test
	public void testDeleteBreakpoint() throws Exception {
		try (LldbAndConnection conn = startAndConnectLldb()) {
			conn.execute("file bash");
			conn.execute("ghidra_trace_start");
			txPut(conn, "processes");
			breakAt(conn, "main");

			RemoteMethod deleteBreakpoint = conn.getMethod("delete_breakpoint");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();

				txPut(conn, "breakpoints");
				TraceObject bpt = Objects.requireNonNull(tb.objAny("Breakpoints[]"));

				deleteBreakpoint.invoke(Map.of("breakpoint", bpt));

				String out = conn.executeCapture("breakpoint list");
				assertThat(out, containsString("No breakpoints"));
			}
		}
	}

	@Test
	public void testDeleteWatchpoint() throws Exception {
		try (LldbAndConnection conn = startAndConnectLldb()) {
			start(conn, "bash");
			txPut(conn, "processes");

			RemoteMethod breakExpression = conn.getMethod("break_read_expression");
			RemoteMethod deleteWatchpoint = conn.getMethod("delete_watchpoint");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				breakExpression.invoke(Map.of("expression", "`(void(*)())main`"));
				long address = Long.decode(conn.executeCapture("dis -c1 -n main").split("\\s+")[1]);

				String out = conn.executeCapture("watchpoint list");
				assertThat(out, containsString(Long.toHexString(address)));

				txPut(conn, "watchpoints");
				TraceObject wpt = Objects.requireNonNull(tb.objAny("Processes[].Watchpoints[]"));

				deleteWatchpoint.invoke(Map.of("watchpoint", wpt));

				out = conn.executeCapture("watchpoint list");
				assertThat(out, containsString("No watchpoints"));
			}
		}
	}

	private void start(LldbAndConnection conn, String obj) {
		conn.execute("file " + obj);
		conn.execute("ghidra_trace_start");
		conn.execute("process launch --stop-at-entry");
	}

	private void txPut(LldbAndConnection conn, String obj) {
		conn.execute("ghidra_trace_txstart 'Tx'");
		conn.execute("ghidra_trace_put_" + obj);
		conn.execute("ghidra_trace_txcommit");
	}

	private void txCreate(LldbAndConnection conn, String path) {
		conn.execute("ghidra_trace_txstart 'Fake'");
		conn.execute("ghidra_trace_create_obj %s".formatted(path));
		conn.execute("ghidra_trace_txcommit");
	}

	private void breakAt(LldbAndConnection conn, String fn) {
		conn.execute("ghidra_trace_sync_enable");
		conn.execute("breakpoint set -n " + fn);
		conn.execute("run");
	}

	private int getDepth(LldbAndConnection conn) {
		String[] split = conn.executeCapture("bt").split("\n");
		int initDepth = 0;
		for (String str : split) {
			if (str.contains("frame #")) {
				initDepth++;
			}
		}
		return initDepth;
	}

}
