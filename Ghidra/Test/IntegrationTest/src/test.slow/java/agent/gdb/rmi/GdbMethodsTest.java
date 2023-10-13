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

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.junit.Test;
import org.junit.experimental.categories.Category;

import db.Transaction;
import generic.Unique;
import generic.test.category.NightlyCategory;
import ghidra.app.plugin.core.debug.utils.ManagedDomainObject;
import ghidra.dbg.testutil.DummyProc;
import ghidra.dbg.util.PathPattern;
import ghidra.dbg.util.PathPredicates;
import ghidra.debug.api.tracermi.RemoteMethod;
import ghidra.program.model.address.*;
import ghidra.program.model.data.Float10DataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.listing.TraceCodeSpace;
import ghidra.trace.model.listing.TraceData;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectValue;

@Category(NightlyCategory.class) // this may actually be an @PortSensitive test
public class GdbMethodsTest extends AbstractGdbTraceRmiTest {

	@Test
	public void testExecuteCapture() throws Exception {
		try (GdbAndConnection conn = startAndConnectGdb()) {
			RemoteMethod execute = conn.getMethod("execute");
			assertEquals(false, execute.parameters().get("to_string").getDefaultValue());
			assertEquals("test", execute.invoke(Map.of("cmd", "echo test", "to_string", true)));
		}
	}

	@Test
	public void testExecute() throws Exception {
		try (GdbAndConnection conn = startAndConnectGdb()) {
			RemoteMethod execute = conn.getMethod("execute");
			execute.invoke(Map.of("cmd", """
					file bash
					start
					ghidra trace start
					kill"""));
		}
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
			// Just confirm it's present
		}
	}

	@Test
	public void testRefreshAvailable() throws Exception {
		try (GdbAndConnection conn = startAndConnectGdb()) {
			conn.execute("""
					ghidra trace start
					ghidra trace tx-open "Fake" 'ghidra trace create-obj Available'""");
			RemoteMethod refreshAvailable = conn.getMethod("refresh_available");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/noname")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				TraceObject available = Objects.requireNonNull(tb.obj("Available"));

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
		try (GdbAndConnection conn = startAndConnectGdb()) {
			conn.execute("""
					file bash
					ghidra trace start
					%s
					ghidra trace tx-open "Fake" 'ghidra trace create-obj Breakpoints'
					start"""
					.formatted(INSTRUMENT_STOPPED));
			RemoteMethod refreshBreakpoints = conn.getMethod("refresh_breakpoints");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();

				conn.execute("""
						break main
						hbreak *main+10
						watch -l *((char*)(&main+20))
						rwatch -l *((char(*)[8])(&main+30))
						awatch -l *((char(*)[5])(&main+40))""");
				TraceObject breakpoints = Objects.requireNonNull(tb.obj("Breakpoints"));
				refreshBreakpoints.invoke(Map.of("node", breakpoints));

				List<TraceObjectValue> infBreakLocVals = tb.trace.getObjectManager()
						.getValuePaths(Lifespan.at(0),
							PathPredicates.parse("Inferiors[1].Breakpoints[]"))
						.map(p -> p.getLastEntry())
						.toList();
				assertEquals(5, infBreakLocVals.size());
				AddressRange rangeMain =
					infBreakLocVals.get(0).getChild().getValue(0, "_range").castValue();
				Address main = rangeMain.getMinAddress();

				// The temporary breakpoint uses up number 1
				assertBreakLoc(infBreakLocVals.get(0), "[2.1]", main, 1,
					Set.of(TraceBreakpointKind.SW_EXECUTE),
					"main");
				assertBreakLoc(infBreakLocVals.get(1), "[3.1]", main.add(10), 1,
					Set.of(TraceBreakpointKind.HW_EXECUTE),
					"*main+10");
				assertBreakLoc(infBreakLocVals.get(2), "[4.1]", main.add(20), 1,
					Set.of(TraceBreakpointKind.WRITE),
					"-location *((char*)(&main+20))");
				assertBreakLoc(infBreakLocVals.get(3), "[5.1]", main.add(30), 8,
					Set.of(TraceBreakpointKind.READ),
					"-location *((char(*)[8])(&main+30))");
				assertBreakLoc(infBreakLocVals.get(4), "[6.1]", main.add(40), 5,
					Set.of(TraceBreakpointKind.READ, TraceBreakpointKind.WRITE),
					"-location *((char(*)[5])(&main+40))");
			}
		}
	}

	@Test
	public void testRefreshInfBreakpoints() throws Exception {
		try (GdbAndConnection conn = startAndConnectGdb()) {
			conn.execute("""
					file bash
					ghidra trace start
					%s
					ghidra trace tx-open "Fake" 'ghidra trace create-obj Inferiors[1].Breakpoints'
					start"""
					.formatted(INSTRUMENT_STOPPED));
			RemoteMethod refreshInfBreakpoints = conn.getMethod("refresh_inf_breakpoints");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();

				TraceObject locations = Objects.requireNonNull(tb.obj("Inferiors[1].Breakpoints"));
				conn.execute("""
						break main
						hbreak *main+10
						watch -l *((char*)(&main+20))
						rwatch -l *((char(*)[8])(&main+30))
						awatch -l *((char(*)[5])(&main+40))""");
				refreshInfBreakpoints.invoke(Map.of("node", locations));

				List<TraceObjectValue> infBreakLocVals = tb.trace.getObjectManager()
						.getValuePaths(Lifespan.at(0),
							PathPredicates.parse("Inferiors[1].Breakpoints[]"))
						.map(p -> p.getLastEntry())
						.toList();
				assertEquals(5, infBreakLocVals.size());
				AddressRange rangeMain =
					infBreakLocVals.get(0).getChild().getValue(0, "_range").castValue();
				Address main = rangeMain.getMinAddress();

				// The temporary breakpoint uses up number 1
				assertBreakLoc(infBreakLocVals.get(0), "[2.1]", main, 1,
					Set.of(TraceBreakpointKind.SW_EXECUTE),
					"main");
				assertBreakLoc(infBreakLocVals.get(1), "[3.1]", main.add(10), 1,
					Set.of(TraceBreakpointKind.HW_EXECUTE),
					"*main+10");
				assertBreakLoc(infBreakLocVals.get(2), "[4.1]", main.add(20), 1,
					Set.of(TraceBreakpointKind.WRITE),
					"-location *((char*)(&main+20))");
				assertBreakLoc(infBreakLocVals.get(3), "[5.1]", main.add(30), 8,
					Set.of(TraceBreakpointKind.READ),
					"-location *((char(*)[8])(&main+30))");
				assertBreakLoc(infBreakLocVals.get(4), "[6.1]", main.add(40), 5,
					Set.of(TraceBreakpointKind.READ, TraceBreakpointKind.WRITE),
					"-location *((char(*)[5])(&main+40))");
			}
		}
	}

	@Test
	public void testRefreshInferiors() throws Exception {
		try (GdbAndConnection conn = startAndConnectGdb()) {
			conn.execute("""
					add-inferior
					ghidra trace start
					ghidra trace tx-open "Fake" 'ghidra trace create-obj Inferiors'""");
			RemoteMethod refreshInferiors = conn.getMethod("refresh_inferiors");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/noname")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				TraceObject inferiors = Objects.requireNonNull(tb.obj("Inferiors"));

				refreshInferiors.invoke(Map.of("node", inferiors));

				// Would be nice to control / validate the specifics
				List<TraceObject> list = tb.trace.getObjectManager()
						.getValuePaths(Lifespan.at(0), PathPredicates.parse("Inferiors[]"))
						.map(p -> p.getDestination(null))
						.toList();
				assertEquals(2, list.size());
			}
		}
	}

	@Test
	public void testRefreshEnvironment() throws Exception {
		try (GdbAndConnection conn = startAndConnectGdb()) {
			String path = "Inferiors[1].Environment";
			conn.execute("""
					file bash
					start
					ghidra trace start
					ghidra trace tx-open "Fake" 'ghidra trace create-obj %s'""".formatted(path));
			RemoteMethod refreshEnvironment = conn.getMethod("refresh_environment");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				TraceObject env = Objects.requireNonNull(tb.obj(path));

				refreshEnvironment.invoke(Map.of("node", env));

				// Assumes GDB on Linux amd64
				assertEquals("gdb", env.getValue(0, "_debugger").getValue());
				assertEquals("i386:x86-64", env.getValue(0, "_arch").getValue());
				assertEquals("GNU/Linux", env.getValue(0, "_os").getValue());
				assertEquals("little", env.getValue(0, "_endian").getValue());
			}
		}
	}

	@Test
	public void testRefreshThreads() throws Exception {
		try (GdbAndConnection conn = startAndConnectGdb()) {
			String path = "Inferiors[1].Threads";
			conn.execute("""
					file bash
					start
					ghidra trace start
					ghidra trace tx-open "Fake" 'ghidra trace create-obj %s'""".formatted(path));
			RemoteMethod refreshThreads = conn.getMethod("refresh_threads");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				TraceObject threads = Objects.requireNonNull(tb.obj(path));

				refreshThreads.invoke(Map.of("node", threads));

				// Would be nice to control / validate the specifics
				Unique.assertOne(tb.trace.getThreadManager().getAllThreads());
			}
		}
	}

	@Test
	public void testRefreshStack() throws Exception {
		try (GdbAndConnection conn = startAndConnectGdb()) {
			String path = "Inferiors[1].Threads[1].Stack";
			conn.execute("""
					file bash
					ghidra trace start
					%s
					ghidra trace tx-open "Fake" 'ghidra trace create-obj %s'
					break read
					run"""
					.formatted(INSTRUMENT_STOPPED, path));
			RemoteMethod refreshStack = conn.getMethod("refresh_stack");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();

				TraceObject stack = Objects.requireNonNull(tb.obj(path));
				refreshStack.invoke(Map.of("node", stack));

				// Would be nice to control / validate the specifics
				List<TraceObject> list = tb.trace.getObjectManager()
						.getValuePaths(Lifespan.at(0),
							PathPredicates.parse("Inferiors[1].Threads[1].Stack[]"))
						.map(p -> p.getDestination(null))
						.toList();
				assertThat(list.size(), greaterThan(2));
			}
		}
	}

	@Test
	public void testRefreshRegisters() throws Exception {
		String count = IntStream.iterate(0, i -> i < 32, i -> i + 1)
				.mapToObj(Integer::toString)
				.collect(Collectors.joining(",", "{", "}"));
		try (GdbAndConnection conn = startAndConnectGdb()) {
			String path = "Inferiors[1].Threads[1].Stack[0].Registers";
			conn.execute("""
					file bash
					ghidra trace start
					%s
					ghidra trace tx-open "Fake" 'ghidra trace create-obj %s'
					start"""
					.formatted(INSTRUMENT_STOPPED, path));
			RemoteMethod refreshRegisters = conn.getMethod("refresh_registers");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();

				conn.execute("""
						set $ymm0.v32_int8 = %s
						set $st0 = 1.5
						""".formatted(count));

				TraceObject registers = Objects.requireNonNull(tb.obj(path));
				refreshRegisters.invoke(Map.of("node", registers));

				long snap = 0;
				AddressSpace t1f0 = tb.trace.getBaseAddressFactory()
						.getAddressSpace("Inferiors[1].Threads[1].Stack[0].Registers");
				TraceMemorySpace regs = tb.trace.getMemoryManager().getMemorySpace(t1f0, false);
				RegisterValue ymm0 = regs.getValue(snap, tb.reg("ymm0"));
				// GDB treats registers in arch's endian
				assertEquals("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100",
					ymm0.getUnsignedValue().toString(16));

				TraceData st0;
				try (Transaction tx = tb.trace.openTransaction("Float80 unit")) {
					TraceCodeSpace code = tb.trace.getCodeManager().getCodeSpace(t1f0, true);
					st0 = code.definedData()
							.create(Lifespan.nowOn(0), tb.reg("st0"), Float10DataType.dataType);
				}

				assertEquals("1.5", st0.getDefaultValueRepresentation());
			}
		}
	}

	@Test
	public void testRefreshMappings() throws Exception {
		try (GdbAndConnection conn = startAndConnectGdb()) {
			String path = "Inferiors[1].Memory";
			conn.execute("""
					file bash
					start
					ghidra trace start
					ghidra trace tx-open "Fake" 'ghidra trace create-obj %s'""".formatted(path));
			RemoteMethod refreshMappings = conn.getMethod("refresh_mappings");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				TraceObject memory = Objects.requireNonNull(tb.obj(path));

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
		try (GdbAndConnection conn = startAndConnectGdb()) {
			String path = "Inferiors[1].Modules";
			conn.execute("""
					file bash
					start
					ghidra trace start
					ghidra trace tx-open "Fake" 'ghidra trace create-obj %s'""".formatted(path));
			RemoteMethod refreshModules = conn.getMethod("refresh_modules");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				TraceObject modules = Objects.requireNonNull(tb.obj(path));

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
	public void testActivateInferior() throws Exception {
		try (GdbAndConnection conn = startAndConnectGdb()) {
			conn.execute("""
					add-inferior
					ghidra trace start
					ghidra trace tx-open Init 'ghidra trace put-inferiors'""");
			RemoteMethod activateInferior = conn.getMethod("activate_inferior");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/noname")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				List<TraceObject> list = tb.trace.getObjectManager()
						.getValuePaths(Lifespan.at(0), PathPredicates.parse("Inferiors[]"))
						.map(p -> p.getDestination(null))
						.toList();
				assertEquals(2, list.size());

				for (TraceObject inf : list) {
					activateInferior.invoke(Map.of("inferior", inf));
					String out = conn.executeCapture("inferior");
					String num = inf.getCanonicalPath().index();
					assertThat(out, containsString("Current inferior is %s".formatted(num)));
				}
			}
		}
	}

	@Test
	public void testActivateThread() throws Exception {
		try (GdbAndConnection conn = startAndConnectGdb()) {
			conn.execute("""
					add-inferior
					ghidra trace start
					file bash
					start
					ghidra trace tx-open Start1 'ghidra trace put-threads'
					add-inferior
					inferior 2
					file bash
					start
					ghidra trace tx-open Start2 'ghidra trace put-threads'""");
			RemoteMethod activateThread = conn.getMethod("activate_thread");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/noname")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				PathPattern pattern =
					PathPredicates.parse("Inferiors[].Threads[]").getSingletonPattern();
				List<TraceObject> list = tb.trace.getObjectManager()
						.getValuePaths(Lifespan.at(0), pattern)
						.map(p -> p.getDestination(null))
						.toList();
				assertEquals(2, list.size());

				for (TraceObject t : list) {
					activateThread.invoke(Map.of("thread", t));
					String out = conn.executeCapture("thread");
					List<String> indices = pattern.matchKeys(t.getCanonicalPath().getKeyList());
					assertThat(out, containsString(
						"Current thread is %s.%s".formatted(indices.get(0), indices.get(1))));
				}
			}
		}
	}

	@Test
	public void testActivateFrame() throws Exception {
		try (GdbAndConnection conn = startAndConnectGdb()) {
			conn.execute("""
					file bash
					ghidra trace start
					%s
					break read
					run"""
					.formatted(INSTRUMENT_STOPPED));
			RemoteMethod activateFrame = conn.getMethod("activate_frame");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();

				conn.execute("ghidra trace tx-open Init 'ghidra trace put-frames'");

				List<TraceObject> list = tb.trace.getObjectManager()
						.getValuePaths(Lifespan.at(0),
							PathPredicates.parse("Inferiors[1].Threads[1].Stack[]"))
						.map(p -> p.getDestination(null))
						.toList();
				assertThat(list.size(), greaterThan(2));

				for (TraceObject f : list) {
					activateFrame.invoke(Map.of("frame", f));
					String out = conn.executeCapture("frame");
					String level = f.getCanonicalPath().index();
					assertThat(out, containsString("#%s".formatted(level)));
				}
			}
		}
	}

	@Test
	public void testDeleteInferior() throws Exception {
		try (GdbAndConnection conn = startAndConnectGdb()) {
			conn.execute("""
					add-inferior
					ghidra trace start
					ghidra trace tx-open Init 'ghidra trace put-inferiors'""");
			RemoteMethod deleteInferior = conn.getMethod("delete_inferior");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/noname")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				TraceObject inf2 = Objects.requireNonNull(tb.obj("Inferiors[2]"));
				deleteInferior.invoke(Map.of("inferior", inf2));

				String out = conn.executeCapture("info inferiors");
				assertThat(out, not(containsString("2")));
				assertEquals(2, out.strip().split("\n").length); // Header + 1 inferior
			}
		}
	}

	@Test
	public void testAttachObj() throws Exception {
		String sleep = DummyProc.which("expTraceableSleep");
		try (DummyProc proc = DummyProc.run(sleep)) {
			try (GdbAndConnection conn = startAndConnectGdb()) {
				conn.execute("""
						ghidra trace start
						ghidra trace tx-open Init 'ghidra trace put-available'
						ghidra trace tx-open Init 'ghidra trace put-inferiors'""");
				RemoteMethod attachObj = conn.getMethod("attach_obj");
				try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/noname")) {
					tb = new ToyDBTraceBuilder((Trace) mdo.get());
					TraceObject inf = Objects.requireNonNull(tb.obj("Inferiors[1]"));
					TraceObject target =
						Objects.requireNonNull(tb.obj("Available[%d]".formatted(proc.pid)));
					attachObj.invoke(Map.of("inferior", inf, "target", target));

					String out = conn.executeCapture("info inferiors");
					assertThat(out, containsString("process %d".formatted(proc.pid)));
					assertThat(out, containsString("expTraceableSleep"));
				}
			}
		}
	}

	@Test
	public void testAttachPid() throws Exception {
		String sleep = DummyProc.which("expTraceableSleep");
		try (DummyProc proc = DummyProc.run(sleep)) {
			try (GdbAndConnection conn = startAndConnectGdb()) {
				conn.execute("""
						ghidra trace start
						ghidra trace tx-open Init 'ghidra trace put-inferiors'""");
				RemoteMethod attachPid = conn.getMethod("attach_pid");
				try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/noname")) {
					tb = new ToyDBTraceBuilder((Trace) mdo.get());
					TraceObject inf = Objects.requireNonNull(tb.obj("Inferiors[1]"));
					attachPid.invoke(Map.of("inferior", inf, "pid", proc.pid));

					String out = conn.executeCapture("info inferiors");
					assertThat(out, containsString("process %d".formatted(proc.pid)));
					assertThat(out, containsString("expTraceableSleep"));
				}
			}
		}
	}

	@Test
	public void testDetach() throws Exception {
		String sleep = DummyProc.which("expTraceableSleep");
		try (DummyProc proc = DummyProc.run(sleep)) {
			try (GdbAndConnection conn = startAndConnectGdb()) {
				conn.execute("""
						ghidra trace start
						%s
						ghidra trace tx-open Init 'ghidra trace put-inferiors'
						attach %d"""
						.formatted(INSTRUMENT_STOPPED, proc.pid));
				RemoteMethod detach = conn.getMethod("detach");
				try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/noname")) {
					tb = new ToyDBTraceBuilder((Trace) mdo.get());
					waitStopped();

					TraceObject inf = Objects.requireNonNull(tb.obj("Inferiors[1]"));
					detach.invoke(Map.of("inferior", inf));

					String out = conn.executeCapture("info inferiors");
					assertThat(out, containsString("<null>"));
				}
			}
		}
	}

	@Test
	public void testLaunchMain() throws Exception {
		try (GdbAndConnection conn = startAndConnectGdb()) {
			conn.execute("""
					ghidra trace start
					%s
					ghidra trace tx-open Init 'ghidra trace put-inferiors'"""
					.formatted(INSTRUMENT_STOPPED));
			RemoteMethod launchMain = conn.getMethod("launch_main");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/noname")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				TraceObject inf = Objects.requireNonNull(tb.obj("Inferiors[1]"));
				launchMain.invoke(Map.ofEntries(
					Map.entry("inferior", inf),
					Map.entry("file", "bash")));
				waitStopped();

				String out = conn.executeCapture("info inferiors");
				assertThat(out, containsString("bash"));
			}
		}
	}

	@Test
	public void testLaunchLoader() throws Exception {
		try (GdbAndConnection conn = startAndConnectGdb()) {
			conn.execute("""
					ghidra trace start
					%s
					ghidra trace tx-open Init 'ghidra trace put-inferiors'"""
					.formatted(INSTRUMENT_STOPPED));
			RemoteMethod launchLoader = conn.getMethod("launch_loader");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/noname")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				TraceObject inf = Objects.requireNonNull(tb.obj("Inferiors[1]"));
				launchLoader.invoke(Map.ofEntries(
					Map.entry("inferior", inf),
					Map.entry("file", "bash")));
				waitStopped();

				String out = conn.executeCapture("frame");
				assertThat(out, containsString("ld-linux"));
			}
		}
	}

	@Test
	public void testLaunchRun() throws Exception {
		try (GdbAndConnection conn = startAndConnectGdb()) {
			conn.execute("""
					ghidra trace start
					%s
					%s
					ghidra trace tx-open Init 'ghidra trace put-inferiors'"""
					.formatted(INSTRUMENT_STOPPED, INSTRUMENT_RUNNING));
			RemoteMethod launchRun = conn.getMethod("launch_run");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/noname")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				TraceObject inf = Objects.requireNonNull(tb.obj("Inferiors[1]"));
				launchRun.invoke(Map.ofEntries(
					Map.entry("inferior", inf),
					Map.entry("file", "bash")));
				waitRunning();
				Thread.sleep(100); // Give it plenty of time to block on read

				conn.execute("interrupt");
				waitStopped();

				String out = conn.executeCapture("frame");
				assertThat(out, containsString("read"));
			}
		}
	}

	@Test
	public void testKill() throws Exception {
		try (GdbAndConnection conn = startAndConnectGdb()) {
			conn.execute("""
					file bash
					ghidra trace start
					%s
					ghidra trace tx-open Init 'ghidra trace put-inferiors'
					start"""
					.formatted(INSTRUMENT_STOPPED));
			RemoteMethod kill = conn.getMethod("kill");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();

				TraceObject inf = Objects.requireNonNull(tb.obj("Inferiors[1]"));
				kill.invoke(Map.of("inferior", inf));

				String out = conn.executeCapture("info inferiors");
				assertThat(out, containsString("<null>"));
			}
		}
	}

	@Test
	public void testResumeInterrupt5() throws Exception {
		try (GdbAndConnection conn = startAndConnectGdb()) {
			RemoteMethod resume = conn.getMethod("resume");
			RemoteMethod interrupt = conn.getMethod("interrupt");
			conn.execute("""
					define do-put-before
					  ghidra trace new-snap Before
					  ghidra trace put-inferiors
					  ghidra trace putreg
					end
					define do-put-after
					  ghidra trace new-snap After
					  ghidra trace putreg
					end
					file bash
					ghidra trace start
					%s
					%s
					start"""
					.formatted(INSTRUMENT_STOPPED, INSTRUMENT_RUNNING));
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();
				conn.execute("ghidra trace tx-open Before do-put-before");

				TraceObject inf1 = Objects.requireNonNull(tb.obj("Inferiors[1]"));

				for (int i = 0; i < 5; i++) {
					resume.invoke(Map.of("inferior", inf1));
					waitRunning();

					interrupt.invoke(Map.of());
					waitStopped();
				}

				conn.execute("ghidra trace tx-open After do-put-after");

				Register pc = tb.language.getProgramCounter();
				AddressSpace t1s = tb.trace.getBaseAddressFactory()
						.getAddressSpace("Inferiors[1].Threads[1].Stack[0].Registers");
				TraceMemorySpace regs = tb.trace.getMemoryManager().getMemorySpace(t1s, false);
				RegisterValue pc0 = regs.getValue(0, pc);
				RegisterValue pc1 = regs.getValue(1, pc);
				assertNotEquals(pc0, pc1);
			}
		}
	}

	@Test
	public void testStepInto() throws Exception {
		try (GdbAndConnection conn = startAndConnectGdb()) {
			conn.execute("""
					file bash
					ghidra trace start
					%s
					start"""
					.formatted(INSTRUMENT_STOPPED));
			RemoteMethod stepInto = conn.getMethod("step_into");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();
				conn.execute("ghidra trace tx-open Init 'ghidra trace put-threads'");

				TraceObject thread = Objects.requireNonNull(tb.obj("Inferiors[1].Threads[1]"));

				while (!conn.executeCapture("x/1i $pc").contains("call")) {
					stepInto.invoke(Map.of("thread", thread));
				}

				String dis2 = conn.executeCapture("x/2i $pc");
				long pcNext = Long.decode(dis2.strip().split("\n")[1].strip().split("\\s+")[0]);

				stepInto.invoke(Map.of("thread", thread));
				long pc = Long.decode(conn.executeCapture("print/x $pc").split("\\s+")[2]);
				assertNotEquals(pcNext, pc);
			}
		}
	}

	@Test
	public void testStepOver() throws Exception {
		try (GdbAndConnection conn = startAndConnectGdb()) {
			conn.execute("""
					file bash
					ghidra trace start
					%s
					start"""
					.formatted(INSTRUMENT_STOPPED));
			RemoteMethod step_over = conn.getMethod("step_over");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();
				conn.execute("ghidra trace tx-open Init 'ghidra trace put-threads'");

				TraceObject thread = Objects.requireNonNull(tb.obj("Inferiors[1].Threads[1]"));

				while (!conn.executeCapture("x/1i $pc").contains("call")) {
					step_over.invoke(Map.of("thread", thread));
				}

				String dis2 = conn.executeCapture("x/2i $pc");
				long pcNext = Long.decode(dis2.strip().split("\n")[1].strip().split("\\s+")[0]);

				step_over.invoke(Map.of("thread", thread));
				long pc = Long.decode(conn.executeCapture("print/x $pc").split("\\s+")[2]);
				assertEquals(pcNext, pc);
			}
		}
	}

	@Test
	public void testStepOut() throws Exception {
		try (GdbAndConnection conn = startAndConnectGdb()) {
			conn.execute("""
					file bash
					ghidra trace start
					%s
					start"""
					.formatted(INSTRUMENT_STOPPED));
			RemoteMethod stepOut = conn.getMethod("step_out");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();
				conn.execute("ghidra trace tx-open Init 'ghidra trace put-threads'");

				int initDepth = conn.executeCapture("bt").split("\n").length;
				while (conn.executeCapture("bt").split("\n").length <= initDepth) {
					conn.execute("stepi");
				}

				// TODO: Not likely, but the return could block on a syscall
				TraceObject thread = Objects.requireNonNull(tb.obj("Inferiors[1].Threads[1]"));
				stepOut.invoke(Map.of("thread", thread));
				assertEquals(initDepth, conn.executeCapture("bt").split("\n").length);
			}
		}
	}

	@Test
	public void testStepAdvance() throws Exception {
		try (GdbAndConnection conn = startAndConnectGdb()) {
			conn.execute("""
					file bash
					ghidra trace start
					%s
					start"""
					.formatted(INSTRUMENT_STOPPED));
			RemoteMethod stepAdvance = conn.getMethod("step_advance");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();
				conn.execute("ghidra trace tx-open Init 'ghidra trace put-threads'");

				TraceObject thread = Objects.requireNonNull(tb.obj("Inferiors[1].Threads[1]"));
				String dis3 = conn.executeCapture("x/3i $pc");
				// TODO: Examine for control transfer?
				long pcTarget = Long.decode(dis3.strip().split("\n")[2].strip().split("\\s+")[0]);

				stepAdvance.invoke(Map.of("thread", thread, "address", tb.addr(pcTarget)));

				long pc = Long.decode(conn.executeCapture("print/x $pc").split("\\s+")[2]);
				assertEquals(pcTarget, pc);
			}
		}
	}

	@Test
	public void testStepReturn() throws Exception {
		try (GdbAndConnection conn = startAndConnectGdb()) {
			conn.execute("""
					file bash
					ghidra trace start
					%s
					start"""
					.formatted(INSTRUMENT_STOPPED));
			RemoteMethod stepReturn = conn.getMethod("step_return");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();
				conn.execute("ghidra trace tx-open Init 'ghidra trace put-threads'");

				int initDepth = conn.executeCapture("bt").split("\n").length;
				while (conn.executeCapture("bt").split("\n").length <= initDepth) {
					conn.execute("stepi");
				}

				TraceObject thread = Objects.requireNonNull(tb.obj("Inferiors[1].Threads[1]"));
				stepReturn.invoke(Map.of("thread", thread));
				assertEquals(initDepth, conn.executeCapture("bt").split("\n").length);
			}
		}
	}

	@Test
	public void testBreakSwExecuteAddress() throws Exception {
		try (GdbAndConnection conn = startAndConnectGdb()) {
			conn.execute("""
					file bash
					ghidra trace start
					%s
					start"""
					.formatted(INSTRUMENT_STOPPED));
			RemoteMethod breakSwExecuteAddress = conn.getMethod("break_sw_execute_address");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();

				TraceObject inf = Objects.requireNonNull(tb.obj("Inferiors[1]"));
				long address = Long.decode(conn.executeCapture("print/x &main").split("\\s+")[2]);
				breakSwExecuteAddress.invoke(Map.of("inferior", inf, "address", tb.addr(address)));

				String out = conn.executeCapture("info break");
				assertThat(out, containsString("<main>"));
			}
		}
	}

	@Test
	public void testBreakSwExecuteExpression() throws Exception {
		try (GdbAndConnection conn = startAndConnectGdb()) {
			conn.execute("""
					file bash
					ghidra trace start
					%s
					start"""
					.formatted(INSTRUMENT_STOPPED));
			RemoteMethod breakSwExecuteExpression = conn.getMethod("break_sw_execute_expression");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();

				breakSwExecuteExpression.invoke(Map.of("expression", "main"));

				String out = conn.executeCapture("info break");
				assertThat(out, containsString("<main>"));
			}
		}
	}

	@Test
	public void testBreakHwExecuteAddress() throws Exception {
		try (GdbAndConnection conn = startAndConnectGdb()) {
			conn.execute("""
					file bash
					ghidra trace start
					%s
					start"""
					.formatted(INSTRUMENT_STOPPED));
			RemoteMethod breakHwExecuteAddress = conn.getMethod("break_hw_execute_address");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();

				TraceObject inf = Objects.requireNonNull(tb.obj("Inferiors[1]"));
				long address = Long.decode(conn.executeCapture("print/x &main").split("\\s+")[2]);
				breakHwExecuteAddress.invoke(Map.of("inferior", inf, "address", tb.addr(address)));

				String out = conn.executeCapture("info break");
				assertThat(out, containsString("<main>"));
				assertThat(out, containsString("hw breakpoint"));
			}
		}
	}

	@Test
	public void testBreakHwExecuteExpression() throws Exception {
		try (GdbAndConnection conn = startAndConnectGdb()) {
			conn.execute("""
					file bash
					ghidra trace start
					%s
					start"""
					.formatted(INSTRUMENT_STOPPED));
			RemoteMethod breakHwExecuteExpression = conn.getMethod("break_hw_execute_expression");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();

				breakHwExecuteExpression.invoke(Map.of("expression", "main"));

				String out = conn.executeCapture("info break");
				assertThat(out, containsString("<main>"));
				assertThat(out, containsString("hw breakpoint"));
			}
		}
	}

	@Test
	public void testBreakReadRange() throws Exception {
		try (GdbAndConnection conn = startAndConnectGdb()) {
			conn.execute("""
					file bash
					ghidra trace start
					%s
					start"""
					.formatted(INSTRUMENT_STOPPED));
			RemoteMethod breakReadRange = conn.getMethod("break_read_range");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();

				TraceObject inf = Objects.requireNonNull(tb.obj("Inferiors[1]"));
				long address = Long.decode(conn.executeCapture("print/x &main").split("\\s+")[2]);
				AddressRange range = tb.range(address, address + 3); // length 4
				breakReadRange.invoke(Map.of("inferior", inf, "range", range));

				String out = conn.executeCapture("info break");
				assertThat(out, containsString("0x%x".formatted(address)));
				assertThat(out, containsString("[4]"));
				assertThat(out, containsString("read watchpoint"));
			}
		}
	}

	@Test
	public void testBreakReadExpression() throws Exception {
		try (GdbAndConnection conn = startAndConnectGdb()) {
			conn.execute("""
					file bash
					ghidra trace start
					%s
					start"""
					.formatted(INSTRUMENT_STOPPED));
			RemoteMethod breakReadExpression = conn.getMethod("break_read_expression");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();

				breakReadExpression.invoke(Map.of("expression", "main"));

				String out = conn.executeCapture("info break");
				assertThat(out, containsString("main"));
				assertThat(out, containsString("read watchpoint"));
			}
		}
	}

	@Test
	public void testBreakWriteRange() throws Exception {
		try (GdbAndConnection conn = startAndConnectGdb()) {
			conn.execute("""
					file bash
					ghidra trace start
					%s
					start"""
					.formatted(INSTRUMENT_STOPPED));
			RemoteMethod breakWriteRange = conn.getMethod("break_write_range");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();

				TraceObject inf = Objects.requireNonNull(tb.obj("Inferiors[1]"));
				long address = Long.decode(conn.executeCapture("print/x &main").split("\\s+")[2]);
				AddressRange range = tb.range(address, address + 3); // length 4
				breakWriteRange.invoke(Map.of("inferior", inf, "range", range));

				String out = conn.executeCapture("info break");
				assertThat(out, containsString("0x%x".formatted(address)));
				assertThat(out, containsString("[4]"));
				assertThat(out, containsString("hw watchpoint"));
			}
		}
	}

	@Test
	public void testBreakWriteExpression() throws Exception {
		try (GdbAndConnection conn = startAndConnectGdb()) {
			conn.execute("""
					file bash
					ghidra trace start
					%s
					start"""
					.formatted(INSTRUMENT_STOPPED));
			RemoteMethod breakWriteExpression = conn.getMethod("break_write_expression");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();

				breakWriteExpression.invoke(Map.of("expression", "main"));

				String out = conn.executeCapture("info break");
				assertThat(out, containsString("main"));
				assertThat(out, containsString("hw watchpoint"));
			}
		}
	}

	@Test
	public void testBreakAccessRange() throws Exception {
		try (GdbAndConnection conn = startAndConnectGdb()) {
			conn.execute("""
					file bash
					ghidra trace start
					%s
					start"""
					.formatted(INSTRUMENT_STOPPED));
			RemoteMethod breakAccessRange = conn.getMethod("break_access_range");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();

				TraceObject inf = Objects.requireNonNull(tb.obj("Inferiors[1]"));
				long address = Long.decode(conn.executeCapture("print/x &main").split("\\s+")[2]);
				AddressRange range = tb.range(address, address + 3); // length 4
				breakAccessRange.invoke(Map.of("inferior", inf, "range", range));

				String out = conn.executeCapture("info break");
				assertThat(out, containsString("0x%x".formatted(address)));
				assertThat(out, containsString("[4]"));
				assertThat(out, containsString("acc watchpoint"));
			}
		}
	}

	@Test
	public void testBreakAccessExpression() throws Exception {
		try (GdbAndConnection conn = startAndConnectGdb()) {
			conn.execute("""
					file bash
					ghidra trace start
					%s
					start"""
					.formatted(INSTRUMENT_STOPPED));
			RemoteMethod breakAccessExpression = conn.getMethod("break_access_expression");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();

				breakAccessExpression.invoke(Map.of("expression", "main"));

				String out = conn.executeCapture("info break");
				assertThat(out, containsString("main"));
				assertThat(out, containsString("acc watchpoint"));
			}
		}
	}

	@Test
	public void testBreakEvent() throws Exception {
		try (GdbAndConnection conn = startAndConnectGdb()) {
			conn.execute("""
					file bash
					ghidra trace start
					%s
					start"""
					.formatted(INSTRUMENT_STOPPED));
			RemoteMethod breakEvent = conn.getMethod("break_event");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();

				breakEvent.invoke(Map.of("spec", "load"));

				String out = conn.executeCapture("info break");
				assertThat(out, containsString("load of library"));
				assertThat(out, containsString("catchpoint"));
			}
		}
	}

	@Test
	public void testToggleBreakpoint() throws Exception {
		try (GdbAndConnection conn = startAndConnectGdb()) {
			conn.execute("""
					file bash
					ghidra trace start
					%s
					break main
					run"""
					.formatted(INSTRUMENT_STOPPED));
			RemoteMethod toggleBreakpoint = conn.getMethod("toggle_breakpoint");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();
				conn.execute("ghidra trace tx-open Init 'ghidra trace put-breakpoints'");
				TraceObject bpt = Objects.requireNonNull(tb.obj("Breakpoints[1]"));

				toggleBreakpoint.invoke(Map.of("breakpoint", bpt, "enabled", false));

				String out = conn.executeCapture("info break");
				Tabular table = Tabular.parse(out);
				assertEquals("n", table.findRow("Num", "1").getCell("Enb"));
			}
		}
	}

	@Test
	public void testToggleBreakpointLocation() throws Exception {
		try (GdbAndConnection conn = startAndConnectGdb()) {
			conn.execute("""
					file bash
					ghidra trace start
					%s
					break main
					run"""
					.formatted(INSTRUMENT_STOPPED));
			RemoteMethod toggleBreakpointLocation = conn.getMethod("toggle_breakpoint_location");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();
				conn.execute("ghidra trace tx-open Init 'ghidra trace put-breakpoints'");
				// NB. Requires canonical path. Inf[1].Brk[1] is a link
				TraceObject loc = Objects.requireNonNull(tb.obj("Breakpoints[1][1]"));

				toggleBreakpointLocation.invoke(Map.of("location", loc, "enabled", false));

				String out = conn.executeCapture("info break");
				Tabular table = Tabular.parse(out);

				Row locRow = table.findRow("Num", "1.1");
				if (locRow != null) {
					/**
					 * Earlier versions split the breakpoint's only location out, so the location
					 * can be disabled while the breakpoint itself remains "enabled."
					 */
					assertEquals("n", locRow.getCell("Enb"));
				}
				else {
					/**
					 * Later versions recognize that disabling the only location disables the whole
					 * breakpoint.
					 */
					assertEquals("n", table.findRow("Num", "1").getCell("Enb"));
				}
			}
		}
	}

	@Test
	public void testDeleteBreakpoint() throws Exception {
		try (GdbAndConnection conn = startAndConnectGdb()) {
			conn.execute("""
					file bash
					ghidra trace start
					%s
					break main
					run"""
					.formatted(INSTRUMENT_STOPPED));
			RemoteMethod deleteBreakpoint = conn.getMethod("delete_breakpoint");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				waitStopped();
				conn.execute("ghidra trace tx-open Init 'ghidra trace put-breakpoints'");
				TraceObject bpt = Objects.requireNonNull(tb.obj("Breakpoints[1]"));

				deleteBreakpoint.invoke(Map.of("breakpoint", bpt));

				String out = conn.executeCapture("info break");
				assertEquals(1, out.strip().split("\n").length); // Header only
			}
		}
	}
}
