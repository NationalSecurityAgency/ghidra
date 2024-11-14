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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.List;
import java.util.Map;

import org.junit.Ignore;
import org.junit.Test;

import generic.Unique;
import ghidra.app.plugin.core.debug.utils.ManagedDomainObject;
import ghidra.debug.api.tracermi.RemoteMethod;
import ghidra.program.model.address.AddressRange;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectValue;

@Ignore
public class JavaHooksTest extends AbstractJavaTraceRmiTest {

	@Test
	public void testOnStep() throws Exception {
		try (JshellAndConnection conn = startAndConnectJshell()) {
			start(conn, "HelloWorld.class");

			RemoteMethod refreshMethod = conn.getMethod("refresh_method");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				conn.execute("VirtualMachine vm = manager.getCurrentVM();");
				conn.execute("ThreadReference thread = manager.getCurrentThread();");
				conn.execute("EventRequestManager mgr = vm.eventRequestManager();");
				conn.execute(
					"StepRequest req = mgr.createStepRequest(thread, StepRequest.STEP_MIN, StepRequest.STEP_INTO);");
				conn.execute("req.enable();");
				conn.execute("vm.resume();");

				txPut(conn, "Threads");
				waitForObject("VMs[].Threads[main]");
				txPut(conn, "Frames");

				List<TraceObjectValue> pcs =
					waitForValues("VMs[].Threads[main].Stack[].Location.Method");
				assertTrue(pcs.get(0).getValue().toString().contains("<init>"));

				TraceObject checkName = pcs.get(0).getChild();
				refreshMethod.invoke(Map.of("method", checkName));
				waitTxDone();

				AddressRange range = Unique
						.assertOne(
							waitForValues(checkName.getCanonicalPath().extend("Range").toString()))
						.castValue();
				waitForPC(start -> start.equals(range.getMinAddress()));

				waitForValuesPass("VMs[]._display", vms -> assertContainsString("Step",
					vms.get(0).getValue().toString()));
			}
		}
	}

	@Test
	public void testOnMethodEntry() throws Exception {
		try (JshellAndConnection conn = startAndConnectJshell()) {
			start(conn, "HelloWorld.class");

			RemoteMethod stepInto = conn.getMethod("step_into");
			RemoteMethod resume = conn.getMethod("resume_thread");
			RemoteMethod breakOnEnter = conn.getMethod("break_enter_thread");
			RemoteMethod refreshMethod = conn.getMethod("refresh_method");
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

				txPut(conn, "Frames");

				List<TraceObjectValue> eventVals = waitForValues("VMs[].Events[]");
				assertEquals(2, eventVals.size());
				assertTrue(eventVals.get(0).getEntryKey().contains("method entry request"));

				List<TraceObjectValue> pcs =
					waitForValues("VMs[].Threads[main].Stack[].Location.Method");
				assertTrue(pcs.get(0).getValue().toString().contains("checkName"));
				assertTrue(pcs.get(1).getValue().toString().contains("<init>"));

				TraceObject checkName = pcs.get(0).getChild();
				refreshMethod.invoke(Map.of("method", checkName));
				waitTxDone();

				AddressRange range = Unique
						.assertOne(
							waitForValues(checkName.getCanonicalPath().extend("Range").toString()))
						.castValue();
				waitForPC(start -> start.equals(range.getMinAddress()));

				waitForValuesPass("VMs[]._display", vms -> assertContainsString("MethodEntry",
					vms.get(0).getValue().toString()));
			}
		}
	}

	@Test
	public void testOnMethodExit() throws Exception {
		try (JshellAndConnection conn = startAndConnectJshell()) {
			start(conn, "HelloWorld.class");

			RemoteMethod stepInto = conn.getMethod("step_into");
			RemoteMethod resume = conn.getMethod("resume_thread");
			RemoteMethod breakOnExit = conn.getMethod("break_exit_thread");
			RemoteMethod refreshMethod = conn.getMethod("refresh_method");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				txPut(conn, "Threads");
				TraceObject thread = waitForObject("VMs[].Threads[main]");

				stepInto.invoke(Map.of("thread", thread));
				waitTxDone();

				breakOnExit.invoke(Map.of("thread", thread));
				waitTxDone();

				resume.invoke(Map.of("thread", thread));
				waitTxDone();

				txPut(conn, "Frames");

				List<TraceObjectValue> eventVals = waitForValues("VMs[].Events[]");
				assertEquals(2, eventVals.size());
				assertTrue(eventVals.get(0).getEntryKey().contains("method exit request"));

				List<TraceObjectValue> pcs =
					waitForValues("VMs[].Threads[main].Stack[].Location.Method");
				assertTrue(pcs.get(0).getValue().toString().contains("checkName"));
				assertTrue(pcs.get(1).getValue().toString().contains("<init>"));

				TraceObject checkName = pcs.get(0).getChild();
				refreshMethod.invoke(Map.of("method", checkName));
				waitTxDone();

				AddressRange range = Unique
						.assertOne(
							waitForValues(checkName.getCanonicalPath().extend("Range").toString()))
						.castValue();
				waitForPC(start -> start.equals(range.getMaxAddress()));

				waitForValuesPass("VMs[]._display", vms -> assertContainsString("MethodExit",
					vms.get(0).getValue().toString()));
			}
		}
	}

	@Test
	public void testOnClassLoad() throws Exception {
		try (JshellAndConnection conn = startAndConnectJshell()) {
			start(conn, "HelloWorld.class");

			RemoteMethod stepInto = conn.getMethod("step_into");
			RemoteMethod resume = conn.getMethod("resume_thread");
			RemoteMethod breakLoad = conn.getMethod("break_load_container");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				txPut(conn, "Threads");
				TraceObject thread = waitForObject("VMs[].Threads[main]");

				stepInto.invoke(Map.of("thread", thread));
				waitTxDone();

				TraceObject events = waitForObject("VMs[].Events");
				breakLoad.invoke(Map.of("container", events));
				waitTxDone();

				resume.invoke(Map.of("thread", thread));
				waitTxDone();

				List<TraceObjectValue> eventVals = waitForValues("VMs[].Events[]");
				assertEquals(2, eventVals.size());
				assertTrue(eventVals.get(0).getEntryKey().contains("class prepare request"));

				waitForValuesPass("VMs[]._display", vms -> assertContainsString("ClassPrepare",
					vms.get(0).getValue().toString()));
			}
		}
	}

	@Test
	public void testOnThreadStart() throws Exception {
		try (JshellAndConnection conn = startAndConnectJshell()) {
			start(conn, "HelloWorld.class");

			RemoteMethod resume = conn.getMethod("resume_thread");
			RemoteMethod breakStart = conn.getMethod("break_started_container");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				txPut(conn, "Threads");
				TraceObject thread = waitForObject("VMs[].Threads[main]");

				TraceObject events = waitForObject("VMs[].Events");
				breakStart.invoke(Map.of("container", events));
				waitTxDone();

				resume.invoke(Map.of("thread", thread));
				waitTxDone();

				List<TraceObjectValue> eventVals = waitForValues("VMs[].Events[]");
				assertTrue(eventVals.get(0).getEntryKey().contains("thread start request"));

				waitForValuesPass("VMs[]._display", vms -> assertContainsString("ThreadStart",
					vms.get(0).getValue().toString()));
			}
		}
	}

	@Test
	public void testOnThreadDeath() throws Exception {
		try (JshellAndConnection conn = startAndConnectJshell()) {
			start(conn, "HelloWorld.class");

			RemoteMethod stepInto = conn.getMethod("step_into");
			RemoteMethod resume = conn.getMethod("resume_thread");
			RemoteMethod breakDeath = conn.getMethod("break_death_container");
			try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());
				txPut(conn, "Threads");
				TraceObject thread = waitForObject("VMs[].Threads[main]");

				stepInto.invoke(Map.of("thread", thread));
				waitTxDone();

				TraceObject events = waitForObject("VMs[].Events");
				breakDeath.invoke(Map.of("container", events));
				waitTxDone();

				resume.invoke(Map.of("thread", thread));
				waitTxDone();

				List<TraceObjectValue> eventVals = waitForValues("VMs[].Events[]");
				assertEquals(2, eventVals.size());
				assertTrue(eventVals.get(1).getEntryKey().contains("thread death request"));

				waitForValuesPass("VMs[]._display", vms -> assertContainsString("ThreadDeath",
					vms.get(0).getValue().toString()));
			}
		}
	}

	@Test
	public void testOnBreakpoint() throws Exception {
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

				txPut(conn, "Frames");
				waitForValuesPass("VMs[].Threads[main].Stack[0]._display",
					pcs -> assertContainsString("checkAccess", pcs.get(0).getValue().toString()));

				waitForValuesPass("VMs[]._display", vms -> assertContainsString("Breakpoint",
					vms.get(0).getValue().toString()));
			}
		}
	}

	@Test
	public void testOnAccessWatchpoint() throws Exception {
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

				txPut(conn, "Frames");
				List<TraceObjectValue> pcs = waitForValues("VMs[].Threads[main].Stack[0]._display");
				assertTrue(pcs.get(0).getValue().toString().contains("<init>"));

				waitForValuesPass("VMs[]._display", vms -> assertContainsString("AccessWatchpoint",
					vms.get(0).getValue().toString()));
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
