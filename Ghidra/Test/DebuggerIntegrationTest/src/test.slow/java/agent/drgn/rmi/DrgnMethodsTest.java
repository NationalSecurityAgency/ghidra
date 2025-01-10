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
package agent.drgn.rmi;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

import java.util.*;

import org.junit.Test;

import generic.Unique;
import generic.jar.ResourceFile;
import ghidra.app.plugin.core.debug.utils.ManagedDomainObject;
import ghidra.debug.api.tracermi.RemoteMethod;
import ghidra.framework.Application;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.RegisterValue;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.path.PathFilter;
import ghidra.trace.model.target.path.PathPattern;

public class DrgnMethodsTest extends AbstractDrgnTraceRmiTest {

	@Test
	public void testExecuteCapture() throws Exception {
		try (PythonAndConnection conn = startAndConnectDrgn()) {
			RemoteMethod execute = conn.getMethod("execute");
			assertEquals(false, execute.parameters().get("to_string").getDefaultValue());
			assertEquals("11\n",
				execute.invoke(Map.of(
					"cmd", "print(3+4*2)", 
					"to_string", true)));
		}
	}

	@Test
	public void testExecute() throws Exception {
		try (PythonAndConnection conn = startAndConnectDrgn()) {
			start(conn, null);
		}
		try (ManagedDomainObject mdo = openDomainObject(MDO)) {
			// Just confirm it's present
		}
	}

	@Test
	public void testRefreshProcesses() throws Exception {
		try (PythonAndConnection conn = startAndConnectDrgn()) {
			start(conn, null);
			txCreate(conn, "Processes");

			RemoteMethod attachCore = conn.getMethod("attach_core");
			RemoteMethod refreshProcesses = conn.getMethod("refresh_processes");
			try (ManagedDomainObject mdo = openDomainObject(MDO)) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				TraceObject processes = Objects.requireNonNull(tb.objAny0("Processes"));

				refreshProcesses.invoke(Map.of("node", processes));

				List<TraceObject> list = tb.trace.getObjectManager()
						.getValuePaths(Lifespan.at(getMaxSnap()), PathFilter.parse("Processes[]"))
						.map(p -> p.getDestination(null))
						.toList();
				assertEquals(1, list.size());
				
				ResourceFile rf = Application.getModuleDataFile("TestResources", CORE);
				attachCore.invoke(Map.of("processes", processes, "core", rf.getAbsolutePath()));
				refreshProcesses.invoke(Map.of("node", processes));
				
				list = tb.trace.getObjectManager()
						.getValuePaths(Lifespan.at(getMaxSnap()), PathFilter.parse("Processes[]"))
						.map(p -> p.getDestination(null))
						.toList();
				assertEquals(2, list.size());
				
			}
		}
	}

	@Test
	public void testRefreshEnvironment() throws Exception {
		try (PythonAndConnection conn = startAndConnectDrgn()) {
			String path = "Processes[].Environment";
			start(conn, null);
			txPut(conn, "all");

			RemoteMethod refreshEnvironment = conn.getMethod("refresh_environment");
			try (ManagedDomainObject mdo = openDomainObject(MDO)) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				TraceObject envobj = Objects.requireNonNull(tb.objAny0(path));

				refreshEnvironment.invoke(Map.of("node", envobj));

				assertEquals("drgn", envobj.getValue(0, "_debugger").getValue());
				assertEquals("X86_64", envobj.getValue(0, "_arch").getValue());
				assertEquals("Language.C", envobj.getValue(0, "_os").getValue());
				assertEquals("little", envobj.getValue(0, "_endian").getValue());
			}
		}
	}

	@Test
	public void testRefreshThreads() throws Exception {
		try (PythonAndConnection conn = startAndConnectDrgn()) {
			String path = "Processes[].Threads";
			start(conn, null);
			txCreate(conn, path);

			RemoteMethod refreshThreads = conn.getMethod("refresh_threads");
			try (ManagedDomainObject mdo = openDomainObject(MDO)) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				TraceObject threads = Objects.requireNonNull(tb.objAny0(path));

				refreshThreads.invoke(Map.of("node", threads));

				int listSize = tb.trace.getThreadManager().getAllThreads().size();
				assertEquals(1, listSize);
			}
		}
	}

	@Test
	public void testRefreshStack() throws Exception {
		try (PythonAndConnection conn = startAndConnectDrgn()) {
			String path = "Processes[].Threads[].Stack";
			start(conn, null);
			txPut(conn, "processes");

			RemoteMethod refreshStack = conn.getMethod("refresh_stack");
			try (ManagedDomainObject mdo = openDomainObject(MDO)) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				txPut(conn, "frames");
				TraceObject stack = Objects.requireNonNull(tb.objAny0(path));
				refreshStack.invoke(Map.of("node", stack));

				// Would be nice to control / validate the specifics
				List<TraceObject> list = tb.trace.getObjectManager()
						.getValuePaths(Lifespan.at(0),
							PathFilter.parse("Processes[].Threads[].Stack[]"))
						.map(p -> p.getDestination(null))
						.toList();
				assertEquals(7, list.size());
			}
		}
	}

	@Test
	public void testRefreshRegisters() throws Exception {
		try (PythonAndConnection conn = startAndConnectDrgn()) {
			String path = "Processes[].Threads[].Stack[].Registers";
			start(conn, null);
			conn.execute("ghidra_trace_txstart('Tx')");
			conn.execute("ghidra_trace_putreg()");
			conn.execute("ghidra_trace_delreg()");
			conn.execute("ghidra_trace_txcommit()");

			RemoteMethod refreshRegisters = conn.getMethod("refresh_registers");
			try (ManagedDomainObject mdo = openDomainObject(MDO)) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				TraceObject registers = Objects.requireNonNull(tb.objAny(path, Lifespan.at(0)));
				refreshRegisters.invoke(Map.of("node", registers));

				long snap = 0;
				AddressSpace t1f0 = tb.trace.getBaseAddressFactory()
						.getAddressSpace(registers.getCanonicalPath().toString());
				TraceMemorySpace regs = tb.trace.getMemoryManager().getMemorySpace(t1f0, false);
				RegisterValue rip = regs.getValue(snap, tb.reg("rip"));
				assertEquals("3a40cdf7ff7f0000", rip.getUnsignedValue().toString(16));
			}
		}
	}

	@Test
	public void testRefreshMappings() throws Exception {
		try (PythonAndConnection conn = startAndConnectDrgn()) {
			String path = "Processes[].Memory";
			start(conn, null);
			txCreate(conn, path);

			RemoteMethod refreshMappings = conn.getMethod("refresh_mappings");
			try (ManagedDomainObject mdo = openDomainObject(MDO)) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				TraceObject memory = Objects.requireNonNull(tb.objAny0(path));

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
		try (PythonAndConnection conn = startAndConnectDrgn()) {
			String path = "Processes[].Modules";
			start(conn, null);
			txCreate(conn, path);

			RemoteMethod refreshModules = conn.getMethod("refresh_modules");
			try (ManagedDomainObject mdo = openDomainObject(MDO)) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				TraceObject modules = Objects.requireNonNull(tb.objAny0(path));

				refreshModules.invoke(Map.of("node", modules));

				// Would be nice to control / validate the specifics
				Collection<? extends TraceModule> all = tb.trace.getModuleManager().getAllModules();
				TraceModule mod =
					Unique.assertOne(all.stream().filter(m -> m.getName().contains("helloWorld")));
				assertNotEquals(tb.addr(0), Objects.requireNonNull(mod.getBase()));
			}
		}
	}

	@Test
	public void testActivateThread() throws Exception {
		try (PythonAndConnection conn = startAndConnectDrgn()) {
			start(conn, null);
			txPut(conn, "processes");

			RemoteMethod activateThread = conn.getMethod("activate_thread");
			try (ManagedDomainObject mdo = openDomainObject(MDO)) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				txPut(conn, "threads");

				PathPattern pattern =
					PathFilter.parse("Processes[].Threads[]").getSingletonPattern();
				List<TraceObject> list = tb.trace.getObjectManager()
						.getValuePaths(Lifespan.at(0), pattern)
						.map(p -> p.getDestination(null))
						.toList();
				assertEquals(1, list.size());

				for (TraceObject t : list) {
					activateThread.invoke(Map.of("thread", t));
					String out = conn.executeCapture("print(util.selected_thread())").strip();
					List<String> indices = pattern.matchKeys(t.getCanonicalPath(), true);
					assertEquals("%s".formatted(indices.get(1)), out);
				}
			}
		}
	}

	private void start(PythonAndConnection conn, String obj) {
		conn.execute("from ghidradrgn.commands import *");
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
}
