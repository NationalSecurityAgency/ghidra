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
package agent.java.rmi;

import static org.junit.Assert.*;

import java.util.*;

import org.junit.Ignore;
import org.junit.Test;

import generic.Unique;
import ghidra.app.plugin.core.debug.utils.ManagedDomainObject;
import ghidra.debug.api.tracermi.RemoteMethod;
import ghidra.program.model.address.Address;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectValue;

@Ignore
public class JavaMethodsTest extends AbstractJavaTraceRmiTest {

	/**
	 * Because we control the target artifact, we know the steps precisely. NOTE: This must be the
	 * same at least for step_into and step_over, otherwise, we can't know for sure step_over
	 * actually behaves any differently than step_into. By matching with step_into, we can assure
	 * ourselves that step_over actually encountered an invoke* bytecode instruction, because if it
	 * didn't then step_into ought to fail.
	 */
	public void do2Steps(JshellAndConnection conn, RemoteMethod step, TraceObject thread) {
		step.invoke(Map.of("thread", thread));
		waitTxDone();
		txPut(conn, "Frames");
		waitForLocation("HelloWorld", "main", 3);

		step.invoke(Map.of("thread", thread));
		waitTxDone();
		txPut(conn, "Frames");
		waitForLocation("HelloWorld", "main", 5);
	}

	@Test
	public void testEvaluate() throws Exception {
		try (JshellAndConnection conn = startAndConnectJshell()) {
			conn.executeCapture(null);
			List<String> res = conn.executeCapture("3+4*2;");
			conn.execute("/exit");
			assertTrue(res.get(0).contains("11"));
		}
	}

	@Test
	public void testExecute() throws Exception {
		try (JshellAndConnection conn = startAndConnectJshell()) {
			start(conn, "HelloWorld.class");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
				// Just confirm it's present
			}
		}
	}

	@Test
	public void testRefreshEvents() throws Exception {
		try (JshellAndConnection conn = startAndConnectJshell()) {
			start(conn, "HelloWorld.class");

			RemoteMethod refreshEvents = conn.getMethod("refresh_events");
			RemoteMethod stepInto = conn.getMethod("step_into");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				txPut(conn, "Threads");

				TraceObject thread = waitForObject("VMs[].Threads[main]");
				stepInto.invoke(Map.of("thread", thread));
				waitTxDone();

				TraceObject events = waitForObject("VMs[].Events");
				refreshEvents.invoke(Map.of("container", events));
				waitTxDone();

				List<TraceObjectValue> eventVals = waitForValues("VMs[].Events[]");
				assertEquals(1, eventVals.size());
				assertTrue(eventVals.get(0).getEntryKey().contains("step request"));

				conn.execute("VirtualMachine vm = manager.getCurrentVM(); ");
				conn.execute(
					"MethodEntryRequest brkReq = vm.eventRequestManager().createMethodEntryRequest();");

				eventVals = waitForPass(() -> {
					refreshEvents.invoke(Map.of("container", events));
					List<TraceObjectValue> evs = waitForValues("VMs[].Events[]");
					assertEquals(2, evs.size());
					return evs;
				});
				assertTrue(eventVals.get(0).getEntryKey().contains("method entry request"));

			}
		}
	}

	@Test
	public void testRefreshBreakpoints() throws Exception {
		try (JshellAndConnection conn = startAndConnectJshell()) {
			start(conn, "HelloWorld.class");

			RemoteMethod refreshBreakpoints = conn.getMethod("refresh_breakpoints");
			RemoteMethod stepInto = conn.getMethod("step_into");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				txPut(conn, "Threads");

				TraceObject thread = waitForObject("VMs[].Threads[main]");
				stepInto.invoke(Map.of("thread", thread));
				waitTxDone();

				conn.execute("VirtualMachine vm = manager.getCurrentVM();");
				conn.execute("Location loc = manager.getCurrentLocation();");
				conn.execute(
					"BreakpointRequest brkReq = vm.eventRequestManager().createBreakpointRequest(loc);");

				TraceObject brkSet = waitForObject("VMs[].Breakpoints");
				List<TraceObjectValue> brks = waitForPass(() -> {
					refreshBreakpoints.invoke(Map.of("container", brkSet));
					List<TraceObjectValue> d = waitForValues("VMs[].Breakpoints[]");
					assertEquals(1, d.size());
					return d;
				});
				assertTrue(brks.get(0).getEntryKey().contains("breakpoint request"));

				conn.execute(
					"String path = \"VMs[OpenJDK 64-Bit Server VM].Classes[java.lang.Thread]\";");
				conn.execute(
					"ReferenceType reftype = (ReferenceType) jdiManager.objForPath(path);");
				conn.execute("Field field = reftype.fieldByName(\"tid\");");
				conn.execute(
					"AccessWatchpointRequest brkReq = vm.eventRequestManager().createAccessWatchpointRequest(field);");

				TraceObject brkSet2 = waitForObject("VMs[].Breakpoints");
				brks = waitForPass(() -> {
					refreshBreakpoints.invoke(Map.of("container", brkSet2));
					List<TraceObjectValue> d = waitForValues("VMs[].Breakpoints[]");
					assertEquals(2, d.size());
					return d;
				});
				assertTrue(brks.get(0).getEntryKey().contains("access watchpoint request"));
			}
		}
	}

	@Test
	public void testRefreshVMs() throws Exception {
		try (JshellAndConnection conn = startAndConnectJshell()) {
			start(conn, "HelloWorld.class");

			RemoteMethod refreshVM = conn.getMethod("refresh_vm");
			RemoteMethod refreshProcess = conn.getMethod("refresh_process");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				txPut(conn, "VMs");

				TraceObject vm = waitForObject("VMs[]");
				List<TraceObjectValue> children = waitForValues("VMs[].");
				int sz = children.size();
				refreshVM.invoke(Map.of("vm", vm));
				children = waitForValues("VMs[].");
				assertTrue(children.size() >= sz);
				List<TraceObjectValue> eventThread = waitForValues("VMs[]._event_thread");
				assertTrue(eventThread.get(0).getValue().toString().contains("main"));

				TraceObject proc = waitForObject("VMs[].Processes[]");
				refreshProcess.invoke(Map.of("process", proc));
				children = waitForValues("VMs[].Processes[].");
				assertTrue(children.get(0).getEntryKey().contains("Alive"));
				children = waitForValues("VMs[].Processes[].CommandLine");
				assertTrue(((String) children.get(0).getValue()).contains("HelloWorld"));
			}
		}
	}

	@Test
	public void testRefreshThreads() throws Exception {
		try (JshellAndConnection conn = startAndConnectJshell()) {
			start(conn, "HelloWorld.class");

			RemoteMethod refreshThreads = conn.getMethod("refresh_threads");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				txPut(conn, "VMs");

				TraceObject threads = waitForObject("VMs[].Threads");
				refreshThreads.invoke(Map.of("container", threads));
				List<TraceObjectValue> children = waitForValues("VMs[].Threads[]");
				assertEquals(4, children.size());
				assertTrue(children.get(children.size() - 1).getEntryKey().contains("main"));
			}
		}
	}

	@Test
	public void testRefreshStack() throws Exception {
		try (JshellAndConnection conn = startAndConnectJshell()) {
			start(conn, "HelloWorld.class");

			RemoteMethod brkEnter = conn.getMethod("break_enter_container");
			RemoteMethod setClsFilt = conn.getMethod("set_class_filter");
			RemoteMethod resume = conn.getMethod("resume_thread");
			RemoteMethod stepInto = conn.getMethod("step_into");
			RemoteMethod refreshStack = conn.getMethod("refresh_stack");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				txPut(conn, "Threads");
				TraceObject events = waitForObject("VMs[].Events");
				TraceObject thread = waitForObject("VMs[].Threads[main]");

				brkEnter.invoke(Map.of("container", events));
				TraceObject evtEnter = waitForObject("VMs[].Events[]");
				setClsFilt.invoke(Map.of(
					"event", evtEnter,
					"filter", "HelloWorld*",
					"exclude", false));

				resume.invoke(Map.of("thread", thread));
				waitTxDone();

				TraceObject stack = waitForObject("VMs[].Threads[main].Stack");
				refreshStack.invoke(Map.of("stack", stack));
				waitTxDone();
				waitForValuesPass("VMs[].Threads[main].Stack[]",
					frames -> assertEquals(1, frames.size()));

				// Because main is static, there is no preceding call to <init>
				// This class has no <clinit>, so we get main first!
				waitForLocation("HelloWorld", "main", 0);
				Address start = getPC();

				do2Steps(conn, stepInto, thread);
				stepInto.invoke(Map.of("thread", thread));
				waitTxDone();

				refreshStack.invoke(Map.of("stack", stack));
				waitTxDone();
				waitForValuesPass("VMs[].Threads[main].Stack[]", frames -> {
					assertEquals(2, frames.size());
				});
				waitForValuesPass("VMs[].Threads[main].Stack[].PC", pcs -> {
					assertEquals(2, pcs.size());
					assertEquals(start.add(5), pcs.get(1).getValue());
				});
			}
		}
	}

	@Test
	public void testRefreshRegisters() throws Exception {
		try (JshellAndConnection conn = startAndConnectJshell()) {
			start(conn, "HelloWorld.class");

			RemoteMethod refreshRegisters = conn.getMethod("refresh_registers");
			RemoteMethod stepInto = conn.getMethod("step_into");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				txPut(conn, "Threads");

				TraceObject thread = waitForObject("VMs[].Threads[main]");
				stepInto.invoke(Map.of("thread", thread));
				waitTxDone();

				for (int i = 0; i < 4; i++) {
					stepInto.invoke(Map.of("thread", thread));
					waitTxDone();
				}

				TraceObject regContainer = waitForObject("VMs[].Threads[main].Stack[0].Registers");
				refreshRegisters.invoke(Map.of("container", regContainer));
				List<TraceObjectValue> registers =
					waitForValues("VMs[].Threads[main].Stack[0].Registers[]");
				assertEquals(2, registers.size());
				assertTrue(registers.get(0).getEntryKey().contains("PC"));
				assertTrue(registers.get(1).getEntryKey().contains("return_address"));

				waitForObject("VMs[].Threads[main].Stack[1].Registers");
				refreshRegisters.invoke(Map.of("container", regContainer));
				registers = waitForValues("VMs[].Threads[main].Stack[1].Registers[]");
				assertEquals(1, registers.size());
				assertTrue(registers.get(0).getEntryKey().contains("PC"));
			}
		}
	}

	//@Test Too slow for testing.
	public void testRefreshMemory() throws Exception {
		try (JshellAndConnection conn = startAndConnectJshell()) {
			start(conn, "HelloWorld.class");

			RemoteMethod refreshMemory = conn.getMethod("refresh_memory");
			RemoteMethod stepInto = conn.getMethod("step_into");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				txPut(conn, "Threads");

				TraceObject thread = waitForObject("VMs[].Threads[main]");
				stepInto.invoke(Map.of("thread", thread));
				waitTxDone();

				List<TraceObjectValue> children = waitForValues("VMs[].Memory[]");
				assertTrue(children.size() < 100);

				TraceObject memory = waitForObject("VMs[].Memory");
				refreshMemory.invoke(Map.of("memory", memory));
				children = waitForValues("VMs[].Memory[]");
				assertTrue(children.size() > 100);
			}
		}
	}

	//@Test Too slow for testing.
	public void testRefreshClasses() throws Exception {
		try (JshellAndConnection conn = startAndConnectJshell()) {
			start(conn, "HelloWorld.class");

			RemoteMethod refreshClasses = conn.getMethod("refresh_reference_types");
			RemoteMethod stepInto = conn.getMethod("step_into");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				txPut(conn, "Threads");

				TraceObject thread = waitForObject("VMs[].Threads[main]");
				stepInto.invoke(Map.of("thread", thread));
				waitTxDone();

				List<TraceObjectValue> children = waitForValues("VMs[].Classes[]");
				assertEquals(1, children.size());

				TraceObject classes = waitForObject("VMs[].Classes");
				refreshClasses.invoke(Map.of("container", classes));
				children = waitForValues("VMs[].Classes[]");
				assertTrue(children.size() > 100);
			}
		}
	}

	@Test
	public void testRefreshModules() throws Exception {
		try (JshellAndConnection conn = startAndConnectJshell()) {
			start(conn, "HelloWorld.class");

			RemoteMethod refreshModules = conn.getMethod("refresh_modules");
			RemoteMethod stepInto = conn.getMethod("step_into");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				txPut(conn, "Threads");

				TraceObject thread = waitForObject("VMs[].Threads[main]");
				stepInto.invoke(Map.of("thread", thread));
				waitTxDone();

				List<TraceObjectValue> children = waitForValues("VMs[].ModuleRefs[]");
				assertTrue(children.size() < 100);
				int sz = children.size();

				TraceObject modules = waitForObject("VMs[].ModuleRefs");
				refreshModules.invoke(Map.of("container", modules));
				children = waitForValues("VMs[].ModuleRefs[]");
				assertEquals(sz, children.size());
			}
		}
	}

	@Test
	public void testActivate() throws Exception {
		try (JshellAndConnection conn = startAndConnectJshell()) {
			start(conn, "HelloWorld.class");

			RemoteMethod refreshThreads = conn.getMethod("refresh_threads");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				txPut(conn, "VMs");

				TraceObject threads = waitForObject("VMs[].Threads");
				refreshThreads.invoke(Map.of("container", threads));
				List<TraceObjectValue> children = waitForValues("VMs[].Threads[]");
				assertEquals(4, children.size());

				waitForPass(() -> {
					TraceObject obj = traceManager.getCurrentObject();
					assertFalse(obj == null);
					assertContainsString("[main]", obj.getCanonicalPath().toString());
				});

				conn.execute(
					"cmds.ghidraTraceActivate(\"VMs[OpenJDK 64-Bit Server VM].Threads[Finalizer]\")");
				waitTxDone();
				Thread.sleep(1000);  // Why?

				waitForPass(() -> {
					TraceObject obj = traceManager.getCurrentObject();
					assertFalse(obj == null);
					assertContainsString("[Finalizer]", obj.getCanonicalPath().toString());
				});
			}
		}
	}

	//@Test Unclear how to test
	public void testKill() throws Exception {
		try (JshellAndConnection conn = startAndConnectJshell()) {
			start(conn, "HelloWorld.class");

			RemoteMethod kill = conn.getMethod("kill");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				txPut(conn, "VMs");

				TraceObject vm = waitForObject("VMs[]");
				kill.invoke(Map.of("vm", vm));
				waitTxDone();
			}
		}
	}

	@Test
	@Ignore("Still a race condition between the last call to putFrames and the final assert")
	public void testStepInto() throws Exception {
		try (JshellAndConnection conn = startAndConnectJshell()) {
			start(conn, "HelloWorld.class");

			/**
			 * NOTE: If using break_load_container, you'd need to follow with set_source_filter
			 * using "HelloWorld*". I still haven't looked far enough to figure out what the exact
			 * match should be. (It's not "HelloWorld", but maybe it's "HelloWorld.class". I've just
			 * switched over to break_enter_container, instead.
			 */

			RemoteMethod brkEnter = conn.getMethod("break_enter_container");
			RemoteMethod setClsFilt = conn.getMethod("set_class_filter");
			RemoteMethod resume = conn.getMethod("resume_thread");
			RemoteMethod stepInto = conn.getMethod("step_into");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				txPut(conn, "Threads");
				TraceObject events = waitForObject("VMs[].Events");
				TraceObject thread = waitForObject("VMs[].Threads[main]");

				brkEnter.invoke(Map.of("container", events));
				TraceObject evtEnter = waitForObject("VMs[].Events[]");
				setClsFilt.invoke(Map.of(
					"event", evtEnter,
					"filter", "HelloWorld*",
					"exclude", false));

				resume.invoke(Map.of("thread", thread));
				waitTxDone();

				txPut(conn, "Frames");
				// Because main is static, there is no preceding call to <init>
				// This class has no <clinit>, so we get main first!
				waitForLocation("HelloWorld", "main", 0);
				Address start = waitForPC(pc -> assertNotEquals(0, pc.getOffset()));

				do2Steps(conn, stepInto, thread);

				stepInto.invoke(Map.of("thread", thread));
				waitTxDone();
				txPut(conn, "Frames");

				waitForLocation("java.io.PrintStream", "println", 0);
				waitForValuesPass("VMs[].Threads[main].Stack[0].Registers[return_address]",
					rets -> {
						long ret = Long.parseLong(Unique.assertOne(rets).castValue(), 16);
						assertEquals(start.getOffset() + 8, ret);
					});
			}
		}
	}

	@Test
	@Ignore("Still a race condition between the last call to putFrames and the final assert")
	public void testStepOver() throws Exception {
		try (JshellAndConnection conn = startAndConnectJshell()) {
			start(conn, "HelloWorld.class");

			RemoteMethod brkEnter = conn.getMethod("break_enter_container");
			RemoteMethod setClsFilt = conn.getMethod("set_class_filter");
			RemoteMethod resume = conn.getMethod("resume_thread");
			RemoteMethod stepOver = conn.getMethod("step_over");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				txPut(conn, "Threads");
				TraceObject events = waitForObject("VMs[].Events");
				TraceObject thread = waitForObject("VMs[].Threads[main]");

				brkEnter.invoke(Map.of("container", events));
				TraceObject evtEnter = waitForObject("VMs[].Events[]");
				setClsFilt.invoke(Map.of(
					"event", evtEnter,
					"filter", "HelloWorld*",
					"exclude", false));

				resume.invoke(Map.of("thread", thread));
				waitTxDone();

				txPut(conn, "Frames");
				waitForLocation("HelloWorld", "main", 0);
				Address start = waitForPC(pc -> assertNotEquals(0, pc.getOffset()));

				do2Steps(conn, stepOver, thread);

				stepOver.invoke(Map.of("thread", thread));
				waitTxDone();
				txPut(conn, "Frames");

				waitForLocation("HelloWorld", "main", 8);
				waitForPC(pc -> assertEquals(start.add(8), pc));
			}
		}
	}

	@Test
	@Ignore("Still a race condition between the last call to putFrames and the final assert")
	public void testStepOut() throws Exception {
		try (JshellAndConnection conn = startAndConnectJshell()) {
			start(conn, "HelloWorld.class");

			RemoteMethod brkEnter = conn.getMethod("break_enter_container");
			RemoteMethod setClsFilt = conn.getMethod("set_class_filter");
			RemoteMethod resume = conn.getMethod("resume_thread");
			RemoteMethod stepInto = conn.getMethod("step_into");
			RemoteMethod stepOut = conn.getMethod("step_out");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				txPut(conn, "Threads");
				TraceObject events = waitForObject("VMs[].Events");
				TraceObject thread = waitForObject("VMs[].Threads[main]");

				brkEnter.invoke(Map.of("container", events));
				TraceObject evtEnter = waitForObject("VMs[].Events[]");
				setClsFilt.invoke(Map.of(
					"event", evtEnter,
					"filter", "HelloWorld*",
					"exclude", false));

				resume.invoke(Map.of("thread", thread));
				waitTxDone();

				txPut(conn, "Frames");
				// Because main is static, there is no preceding call to <init>
				// This class has no <clinit>, so we get main first!
				waitForLocation("HelloWorld", "main", 0);
				Address start = waitForPC(pc -> assertNotEquals(0, pc.getOffset()));

				do2Steps(conn, stepInto, thread);

				stepInto.invoke(Map.of("thread", thread));
				waitTxDone();
				txPut(conn, "Frames");
				waitForLocation("java.io.PrintStream", "println", 0);

				stepOut.invoke(Map.of("thread", thread));
				waitTxDone();
				waitForLocation("HelloWorld", "main", 8);
				waitForPC(pc -> assertEquals(start.add(8), pc));
			}
		}
	}

	@Test
	public void testBreakByEvent() throws Exception {
		try (JshellAndConnection conn = startAndConnectJshell()) {
			start(conn, "HelloWorld.class");

			RemoteMethod stepInto = conn.getMethod("step_into");
			RemoteMethod resume = conn.getMethod("resume_thread");
			RemoteMethod breakOnEnter = conn.getMethod("break_enter_thread");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				txPut(conn, "Threads");
				TraceObject thread = waitForObject("VMs[].Threads[main]");

				stepInto.invoke(Map.of("thread", thread));
				waitTxDone();

				breakOnEnter.invoke(Map.of("thread", thread));
				waitTxDone();

				resume.invoke(Map.of("thread", thread));
				waitTxDone();

				List<TraceObjectValue> eventVals = waitForValues("VMs[].Events[]");
				assertEquals(2, eventVals.size());
				assertTrue(eventVals.get(0).getEntryKey().contains("method entry request"));

				List<TraceObjectValue> pcs =
					waitForValues("VMs[].Threads[main].Stack[].Location.Method");
				assertTrue(pcs.get(0).getValue().toString().contains("checkName"));
				assertTrue(pcs.get(1).getValue().toString().contains("<init>"));
			}
		}
	}

	@Test
	public void testBreakByLocation() throws Exception {
		try (JshellAndConnection conn = startAndConnectJshell()) {
			start(conn, "HelloWorld.class");

			RemoteMethod stepInto = conn.getMethod("step_into");
			RemoteMethod resume = conn.getMethod("resume_thread");
			RemoteMethod refreshMethod = conn.getMethod("refresh_method");
			RemoteMethod refreshLocations = conn.getMethod("refresh_locations");
			RemoteMethod breakOnExecute = conn.getMethod("break_location");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				txPut(conn, "Threads");
				TraceObject thread = waitForObject("VMs[].Threads[main]");

				stepInto.invoke(Map.of("thread", thread));
				waitTxDone();

				TraceObject access =
					waitForObject("VMs[].Classes[java.lang.Thread].Methods[checkAccess]");
				refreshMethod.invoke(Map.of("method", access));
				waitTxDone();
				TraceObject locCont =
					waitForObject("VMs[].Classes[java.lang.Thread].Methods[checkAccess].Locations");
				refreshLocations.invoke(Map.of("container", locCont));
				waitTxDone();
				List<TraceObjectValue> locations = waitForValues(
					"VMs[].Classes[java.lang.Thread].Methods[checkAccess].Locations[]");
				for (TraceObjectValue loc : locations) {
					breakOnExecute.invoke(Map.of("location", loc.getChild()));
					waitTxDone();
				}

				resume.invoke(Map.of("thread", thread));
				waitTxDone();

				List<TraceObjectValue> brkVals = waitForValues("VMs[].Breakpoints[]");
				assertEquals(4, brkVals.size());
				//assertTrue(eventVals.get(0).getEntryKey().contains("method entry request"));

				txPut(conn, "Frames");
				waitForValuesPass("VMs[].Threads[main].Stack[0]._display",
					pcs -> assertContainsString("checkAccess", pcs.get(0).getValue().toString()));
				;
			}
		}
	}

	@Test
	public void testBreakOnAccess() throws Exception {
		try (JshellAndConnection conn = startAndConnectJshell()) {
			start(conn, "HelloWorld.class");

			RemoteMethod stepInto = conn.getMethod("step_into");
			RemoteMethod resume = conn.getMethod("resume_thread");
			RemoteMethod refreshFields = conn.getMethod("refresh_canonical_fields");
			RemoteMethod breakOnAccess = conn.getMethod("break_access");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				txPut(conn, "Threads");
				TraceObject thread = waitForObject("VMs[].Threads[main]");

				stepInto.invoke(Map.of("thread", thread));
				waitTxDone();

				TraceObject fieldCont = waitForObject("VMs[].Classes[java.lang.Thread].Fields");
				refreshFields.invoke(Map.of("container", fieldCont));
				waitTxDone();
				List<TraceObjectValue> fields =
					waitForValues("VMs[].Classes[java.lang.Thread].Fields[NEW_THREAD_BINDINGS]");
				for (TraceObjectValue f : fields) {
					breakOnAccess.invoke(Map.of("field", f.getChild()));
					waitTxDone();
				}

				resume.invoke(Map.of("thread", thread));
				waitTxDone();

				List<TraceObjectValue> brkVals = waitForValues("VMs[].Breakpoints[]");
				assertEquals(1, brkVals.size());
				//assertTrue(eventVals.get(0).getEntryKey().contains("method entry request"));

				txPut(conn, "Frames");
				List<TraceObjectValue> pcs = waitForValues("VMs[].Threads[main].Stack[0]._display");
				assertTrue(pcs.get(0).getValue().toString().contains("<init>"));
			}
		}
	}

	@Test
	public void testToggleBreakpoint() throws Exception {
		try (JshellAndConnection conn = startAndConnectJshell()) {
			start(conn, "HelloWorld.class");

			RemoteMethod refreshBreakpoints = conn.getMethod("refresh_breakpoints");
			RemoteMethod toggleBreakpoint = conn.getMethod("toggle_breakpoint");
			RemoteMethod stepInto = conn.getMethod("step_into");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				txPut(conn, "Threads");

				TraceObject thread = waitForObject("VMs[].Threads[main]");
				stepInto.invoke(Map.of("thread", thread));
				waitTxDone();

				conn.execute("VirtualMachine vm = manager.getCurrentVM();");
				conn.execute("Location loc = manager.getCurrentLocation();");
				conn.execute(
					"BreakpointRequest brkReq = vm.eventRequestManager().createBreakpointRequest(loc);");

				TraceObject brkPts = waitForObject("VMs[].Breakpoints");
				List<TraceObjectValue> descs = waitForPass(() -> {
					refreshBreakpoints.invoke(Map.of("container", brkPts));
					List<TraceObjectValue> d = waitForValues("VMs[].Breakpoints[]._display");
					assertEquals(1, d.size());
					return d;
				});

				assertTrue(descs.get(0).getValue().toString().contains("breakpoint request"));
				assertTrue(descs.get(0).getValue().toString().contains("disabled"));

				TraceObject brk = waitForObject("VMs[].Breakpoints[]");
				toggleBreakpoint.invoke(Map.of("breakpoint", brk));

				refreshBreakpoints.invoke(Map.of("container", brkPts));
				descs = waitForValues("VMs[].Breakpoints[]._display");
				assertTrue(descs.get(0).getValue().toString().contains("enabled"));
			}
		}
	}

	@Test
	public void testDeleteBreakpoint() throws Exception {
		try (JshellAndConnection conn = startAndConnectJshell()) {
			start(conn, "HelloWorld.class");

			RemoteMethod refreshBreakpoints = conn.getMethod("refresh_breakpoints");
			RemoteMethod deleteBreakpoint = conn.getMethod("delete_breakpoint");
			RemoteMethod stepInto = conn.getMethod("step_into");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				txPut(conn, "Threads");

				TraceObject thread = waitForObject("VMs[].Threads[main]");
				stepInto.invoke(Map.of("thread", thread));
				waitTxDone();

				conn.execute("VirtualMachine vm = manager.getCurrentVM();");
				conn.execute("Location loc = manager.getCurrentLocation();");
				conn.execute(
					"BreakpointRequest brkReq = vm.eventRequestManager().createBreakpointRequest(loc);");

				TraceObject brkPts = waitForObject("VMs[].Breakpoints");
				waitForPass(() -> {
					refreshBreakpoints.invoke(Map.of("container", brkPts));
					List<TraceObjectValue> d = waitForValues("VMs[].Breakpoints[]._display");
					assertEquals(1, d.size());
				});

				TraceObject brk = waitForObject("VMs[].Breakpoints[]");
				deleteBreakpoint.invoke(Map.of("breakpoint", brk));

				waitForPass(() -> {
					TraceObject bpts = waitForObject("VMs[].Breakpoints");
					refreshBreakpoints.invoke(Map.of("container", bpts));
					Collection<? extends TraceObjectValue> elements =
						bpts.getElements(Lifespan.at(getMaxSnap()));
					assertTrue(elements.isEmpty());
				});
			}
		}
	}

	private void start(JshellAndConnection conn, String obj) {
		if (obj != null) {
			conn.execute("cmds.ghidraTraceStart(\"" + obj + "\");");
		}
		else {
			conn.execute("mds.ghidraTraceStart();");
		}
		conn.execute("cmds.ghidraTraceCreate(System.getenv());");
		conn.execute("cmds.ghidraTraceTxStart(\"Create snapshot\")");
		conn.execute("cmds.ghidraTraceNewSnap(\"Scripted snapshot\")");
		conn.execute("cmds.ghidraTraceTxCommit()");
	}

	private void txPut(JshellAndConnection conn, String obj) {
		conn.execute("cmds.ghidraTraceTxStart(\"Tx\");");
		conn.execute("cmds.ghidraTracePut" + obj + "();");
		conn.execute("cmds.ghidraTraceTxCommit();");
		waitTxDone();
	}
}
